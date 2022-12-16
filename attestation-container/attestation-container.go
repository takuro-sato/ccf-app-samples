package main

import (
	"context"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"unsafe"

	pb "microsoft/attestation-container/protobuf"

	"github.com/Microsoft/confidential-sidecar-containers/pkg/attest"
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
	Report     [1184]byte
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

func (s *server) FetchAttestation(ctx context.Context, in *pb.FetchAttestationRequest) (*pb.FetchAttestationReply, error) {
	log.Printf("Received: %v", in.GetPublicKey())
	bytesForFakeReport := []byte("")
	reportData := []byte(in.GetPublicKey())
	attst, err := attest.FetchSNPReport(true, reportData, bytesForFakeReport)
	if err != nil {
		log.Fatalf("Failed to get SNP report")
	}
	fmt.Printf("Fetched attestation: %+v\n", attst)
	var SNPReport attest.SNPAttestationReport
	if err := SNPReport.DeserializeReport(attst); err != nil {
		log.Fatalf("failed to deserialize attestation report")
	}
	fmt.Printf("Deserialized attestation: %#v\n", SNPReport)
	return &pb.FetchAttestationReply{Attestation: "Attestation report: " + fmt.Sprintf("%#v\n", SNPReport)}, nil
}

func main() {
	fmt.Println("Attestation container started.")

	if _, err := os.Stat("/dev/sev"); err == nil {
		fmt.Println("/dev/sev detected")
	} else if errors.Is(err, os.ErrNotExist) {
		fmt.Println("/dev/sev detected")
	} else {
		fmt.Println("Unknown error:", err)
	}

	bytesForFakeReport := []byte("")
	reportData := []byte("public key")
	attst, err := attest.FetchSNPReport(true, reportData, bytesForFakeReport)
	if err != nil {
		log.Fatalf("Failed to get SNP report")
	}
	// fmt.Printf("Fetched attestation: %+v\n", attst)
	var SNPReport attest.SNPAttestationReport
	if err := SNPReport.DeserializeReport(attst); err != nil {
		log.Fatalf("failed to deserialize attestation report")
	}
	fmt.Printf("Deserialized attestation: %#v\n", SNPReport)

	path := "/dev/sev"
	fd, err := unix.Open(path, unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		fmt.Println("Can't open /dev/sev")
	} else {
		fmt.Println("fd:", fd)
	}

	var msgReportIn = new(MsgReportReq)
	var msgReportOut = new(MsgResponseResp)
	var payload = SEVSNPGuestRequest{
		ReqMsgType:    SNP_MSG_REPORT_REQ,
		RspMsgType:    SNP_MSG_REPORT_RSP,
		MsgVersion:    1,
		RequestLen:    uint16(unsafe.Sizeof(msgReportIn)),
		RequestUaddr:  uint64(uintptr(unsafe.Pointer(&msgReportIn))),
		ResponseLen:   uint16(unsafe.Sizeof(msgReportOut)),
		ResponseUaddr: uint64(uintptr(unsafe.Pointer(&msgReportOut))),
		Error:         0,
	}

	dummyStr := "050601006000000060c6b48eff7f00000005000000000000c0c6b48eff7f00000000000000000000"
	var dummy [40]uint8
	for i := 0; i < len(dummy); i++ {
		num, err := strconv.ParseInt(dummyStr[i*2:i*2+2], 16, 8)
		if err != nil {
			fmt.Println("parse error!", dummyStr[i*2:i*2+2])
		}
		dummy[i] = uint8(num)
	}
	fmt.Printf("Sizeof dummy : %v\ndummy : %v\n", len(dummy), dummy)
	dummy2, _ := hex.DecodeString(dummyStr)
	fmt.Printf("Sizeof dummy2: %v\ndummy2: %v\n", len(dummy2), dummy2)
	r1, r2, err := unix.Syscall(
		unix.SYS_IOCTL,
		uintptr(fd),
		uintptr(sevSnpGuestMsgReport),
		uintptr(unsafe.Pointer(&dummy2)),
	)

	fmt.Printf("Sizeof payload: %v\n", unsafe.Sizeof(payload))

	// r1, r2, err := unix.Syscall(
	// 	unix.SYS_IOCTL,
	// 	uintptr(fd),
	// 	uintptr(sevSnpGuestMsgReport),
	// 	uintptr(unsafe.Pointer(&payload)),
	// )

	if err != nil {
		fmt.Printf("ioctl failed:\n  %v\n  %v\n  %v\n", r1, r2, err)
	} else {
		fmt.Println("ioctl ok")
	}

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
