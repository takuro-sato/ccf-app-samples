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
	return &pb.FetchAttestationReply{Attestation: "Attestation report + collateral for public key " + in.GetPublicKey()}, nil
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
