package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"

	pb "microsoft/attestation-container/protobuf"

	"github.com/Microsoft/confidential-sidecar-containers/pkg/attest"
	"google.golang.org/grpc"
)

var (
	port = flag.Int("port", 50051, "The server port")
)

type server struct {
	pb.UnimplementedAttestationContainerServer
}

func (s *server) FetchAttestation(ctx context.Context, in *pb.FetchAttestationRequest) (*pb.FetchAttestationReply, error) {
	log.Printf("Received: %v", in.GetPublicKey())
	inittimeDataBytes := []byte("Init time data bytes")
	runtimeDataBytes := []byte(in.GetPublicKey())
	attst, err := attest.FetchSNPReport(true, runtimeDataBytes, inittimeDataBytes)
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

	// inittimeDataBytes := []byte("Init time data bytes")
	// runtimeDataBytes := []byte("Pubkey String")
	// attst, err := attest.FetchSNPReport(true, runtimeDataBytes, inittimeDataBytes);
	// if err != nil {
	// 	log.Fatalf("Failed to get SNP report")
	// }
	// fmt.Printf("%+v\n", attst)
	// var SNPReport attest.SNPAttestationReport
	// if err := SNPReport.DeserializeReport(attst); err != nil {
	// 	log.Fatalf("failed to deserialize attestation report")
	// } else {
	// 	fmt.Printf("%#v\n", SNPReport)
	// }

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
