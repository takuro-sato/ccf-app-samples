package main

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"unsafe"

	pb "microsoft/attestation-container/protobuf"

	"golang.org/x/sys/unix"
	"google.golang.org/grpc"
)

var (
	port = flag.Int("port", 50051, "The server port")
)

type server struct {
	pb.UnimplementedAttestationContainerServer
}

// ------------------------- SNP report ------------------------------>

const (
	snpReportSize               = 1184
	sevSnpGuestMsgReport uint64 = 3223868161
)

// In C, FamilyID and ImageID should be unit128
type SNPAttestationReport struct {
	// version no. of this attestation report. Set to 1 for this specification.
	Version uint32 `json:"version"`
	// The guest SVN
	GuestSvn uint32 `json:"guest_svn"`
	// see table 8 - various settings
	Policy uint64 `json:"policy"`
	// as provided at launch    hex string of a 16-byte integer
	FamilyID string `json:"family_id"`
	// as provided at launch 	hex string of a 16-byte integer
	ImageID string `json:"image_id"`
	// the request VMPL for the attestation report
	VMPL          uint32 `json:"vmpl"`
	SignatureAlgo uint32 `json:"signature_algo"`
	// The install version of the firmware
	PlatformVersion uint64 `json:"platform_version"`
	// information about the platform see table 22
	PlatformInfo uint64 `json:"platform_info"`
	// 31 bits of reserved, must be zero, bottom bit indicates that the digest of the author key is present in AUTHOR_KEY_DIGEST. Set to the value of GCTX.AuthorKeyEn.
	AuthorKeyEn uint32 `json:"author_key_en"`
	// must be zero
	Reserved1 uint32 `json:"reserved1"`
	// Guest provided data.	64-byte
	ReportData string `json:"report_data"`
	// measurement calculated at launch 48-byte
	Measurement string `json:"measurement"`
	// data provided by the hypervisor at launch 32-byte
	HostData string `json:"host_data"`
	// SHA-384 digest of the ID public key that signed the ID block provided in SNP_LAUNCH_FINISH 48-byte
	IDKeyDigest string `json:"id_key_digest"`
	// SHA-384 digest of the Author public key that certified the ID key, if provided in SNP_LAUNCH_FINISH. Zeros if author_key_en is 1 (sounds backwards to me). 48-byte
	AuthorKeyDigest string `json:"author_key_digest"`
	// Report ID of this guest. 32-byte
	ReportID string `json:"report_id"`
	// Report ID of this guest's mmigration agent. 32-byte
	ReportIDMA string `json:"report_id_ma"`
	// Reported TCB version used to derive the VCEK that signed this report
	ReportedTCB uint64 `json:"reported_tcb"`
	// reserved 24-byte
	Reserved2 string `json:"reserved2"`
	// Identifier unique to the chip 64-byte
	ChipID string `json:"chip_id"`
	// The current commited SVN of the firware (version 2 report feature)
	CommittedSvn uint64 `json:"committed_svn"`
	// The current commited version of the firware
	CommittedVersion uint64 `json:"committed_version"`
	// The SVN that this guest was launched or migrated at
	LaunchSvn uint64 `json:"launch_svn"`
	// reserved 168-byte
	Reserved3 string `json:"reserved3"`
	// Signature of this attestation report. See table 23. 512-byte
	Signature string `json:"signature"`
}

func (r *SNPAttestationReport) DeserializeReport(report []uint8) error {

	if len(report) != snpReportSize {
		return fmt.Errorf("invalid snp report size")
	}

	r.Version = binary.LittleEndian.Uint32(report[0:4])
	r.GuestSvn = binary.LittleEndian.Uint32(report[4:8])
	r.Policy = binary.LittleEndian.Uint64(report[8:16])
	r.FamilyID = hex.EncodeToString(report[16:32])
	r.ImageID = hex.EncodeToString(report[32:48])
	r.VMPL = binary.LittleEndian.Uint32(report[48:52])
	r.SignatureAlgo = binary.LittleEndian.Uint32(report[52:56])
	r.PlatformVersion = binary.LittleEndian.Uint64(report[56:64])
	r.PlatformInfo = binary.LittleEndian.Uint64(report[64:72])
	r.AuthorKeyEn = binary.LittleEndian.Uint32(report[72:76])
	r.Reserved1 = binary.LittleEndian.Uint32(report[76:80])
	r.ReportData = hex.EncodeToString(report[80:144])
	r.Measurement = hex.EncodeToString(report[144:192])
	r.HostData = hex.EncodeToString(report[192:224])
	r.IDKeyDigest = hex.EncodeToString(report[224:272])
	r.AuthorKeyDigest = hex.EncodeToString(report[272:320])
	r.ReportID = hex.EncodeToString(report[320:352])
	r.ReportIDMA = hex.EncodeToString(report[352:384])
	r.ReportedTCB = binary.LittleEndian.Uint64(report[384:392])
	r.Reserved2 = hex.EncodeToString(report[392:416])
	r.ChipID = hex.EncodeToString(report[416:480])
	r.CommittedSvn = binary.LittleEndian.Uint64(report[480:488])
	r.CommittedVersion = binary.LittleEndian.Uint64(report[488:496])
	r.LaunchSvn = binary.LittleEndian.Uint64(report[496:504])
	r.Reserved3 = hex.EncodeToString(report[504:672])
	r.Signature = hex.EncodeToString(report[672:1184])

	return nil
}

type SEVSNPGuestRequest struct {
	ReqMsgType    uint8
	RspMsgType    uint8
	MsgVersion    uint8
	RequestLen    uint16
	RequestUaddr  uint64
	ResponseLen   uint16
	ResponseUaddr uint64
	Error         uint32 /* firmware error code on failure (see psp-sev.h) */
}

type MsgReportReq struct {
	ReportData [64]uint8
	VMPL       uint32
	Reserved   [28]uint8 // needs to be zero
}

/* from SEV-SNP Firmware ABI Specification Table 22 */
type MsgResponseResp struct {
	Status     uint32
	ReportSize uint32
	Reserved   [24]uint8
	Report     [1184]uint8
	Padding    [64]uint8 // padding to the size of SEV_SNP_REPORT_RSP_BUF_SZ (i.e., 1280 bytes)
}

const (
	SNP_MSG_TYPE_INVALID = 0
	SNP_MSG_CPUID_REQ    = 1
	SNP_MSG_CPUID_RSP    = 2
	SNP_MSG_KEY_REQ      = 3
	SNP_MSG_KEY_RSP      = 4
	SNP_MSG_REPORT_REQ   = 5
	SNP_MSG_REPORT_RSP   = 6
	SNP_MSG_EXPORT_REQ   = 7
	SNP_MSG_EXPORT_RSP   = 8
	SNP_MSG_IMPORT_REQ   = 9
	SNP_MSG_IMPORT_RSP   = 10
	SNP_MSG_ABSORB_REQ   = 11
	SNP_MSG_ABSORB_RSP   = 12
	SNP_MSG_VMRK_REQ     = 13
	SNP_MSG_VMRK_RSP     = 14
	SNP_MSG_TYPE_MAX     = 15
)

// <------------------------- SNP report ------------------------------

func FetchAttestationReportByte(reportData []byte) ([]byte, error) {
	path := "/dev/sev"
	fd, err := unix.Open(path, unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		fmt.Println("Can't open /dev/sev")
		return nil, err
	}

	var msgReportIn = new(MsgReportReq)
	// Need to improve
	for i := 0; i < 64 && i < len(reportData); i++ {
		msgReportIn.ReportData[i] = reportData[i]
	}
	var msgReportOut = new(MsgResponseResp)

	var payload = SEVSNPGuestRequest{
		ReqMsgType:    SNP_MSG_REPORT_REQ,
		RspMsgType:    SNP_MSG_REPORT_RSP,
		MsgVersion:    1,
		RequestLen:    uint16(96),
		RequestUaddr:  uint64(uintptr(unsafe.Pointer(&msgReportIn))),
		ResponseLen:   uint16(1280),
		ResponseUaddr: uint64(uintptr(unsafe.Pointer(&msgReportOut))),
		Error:         0,
	}

	_, _, errno := unix.Syscall(
		unix.SYS_IOCTL,
		uintptr(fd),
		uintptr(sevSnpGuestMsgReport),
		uintptr(unsafe.Pointer(&payload)),
	)

	if errno != 0 {
		fmt.Printf("ioctl failed:%v\n", errno)
		return nil, fmt.Errorf("ioctl failed:%v", errno)
	}

	reportBytes := (*MsgResponseResp)(unsafe.Pointer(&msgReportOut)).Report[:]
	return reportBytes, nil
}

func (s *server) FetchAttestation(ctx context.Context, in *pb.FetchAttestationRequest) (*pb.FetchAttestationReply, error) {
	log.Printf("Received: %v", in.GetPublicKey())

	reportData := []byte(in.GetPublicKey()) // Data for `report data` field in attestation report
	reportBytes, err := FetchAttestationReportByte(reportData)
	if err != nil {
		fmt.Println("Failed to fetch attestation report:", err)
		return nil, fmt.Errorf("failed to fetch attestation report")
	}
	var SNPReport SNPAttestationReport
	if err := SNPReport.DeserializeReport(reportBytes); err != nil {
		fmt.Println("Failed to deserialize attestation report")
		return nil, fmt.Errorf("failed to deserialize attestation report")
	}
	fmt.Printf("Deserialized attestation: %#v\n", SNPReport)
	return &pb.FetchAttestationReply{Attestation: "Attestation report: " + fmt.Sprintf("%#v\n", SNPReport)}, nil
}

func main() {
	fmt.Println("Attestation container started.")

	if _, err := os.Stat("/dev/sev"); err == nil {
		fmt.Println("/dev/sev is detected")
	} else if errors.Is(err, os.ErrNotExist) {
		fmt.Println("/dev/sev is not detected")
	} else {
		fmt.Println("Unknown error:", err)
	}

	reportData := []byte("public key")
	reportBytes, err := FetchAttestationReportByte(reportData)
	if err != nil {
		fmt.Println("Failed to fetch attestation report:", err)
	}
	var SNPReport SNPAttestationReport
	if err := SNPReport.DeserializeReport(reportBytes); err != nil {
		fmt.Println("Failed to deserialize attestation report")
	}
	fmt.Printf("Deserialized attestation: %#v\n", SNPReport)

	flag.Parse()
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", *port))
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	s := grpc.NewServer()
	pb.RegisterAttestationContainerServer(s, &server{})
	log.Printf("server listening at %v", lis.Addr())
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
