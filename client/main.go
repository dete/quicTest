package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"crypto/tls"

	"github.com/quic-go/quic-go"
)

func main() {
	// Parse command-line arguments
	lengthArg := flag.Int("length", 0, "The length of the buffer to send")
	addressArg := flag.String("address", "localhost:4242", "The address of the server (with port)")
	flag.Parse()

	if *lengthArg <= 0 {
		log.Fatalf("Invalid length: %d. Must be a positive integer.\n", *lengthArg)
	}

	// Generate a random buffer of the specified length
	buffer := make([]byte, *lengthArg)
	rand.Read(buffer)

	// Dial the QUIC server
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true, // Skip verification for testing
		NextProtos:         []string{"quic-echo-example"},
	}

	quicConfig := &quic.Config{}

	session, err := quic.DialAddr(context.TODO(), *addressArg, tlsConfig, quicConfig)
	if err != nil {
		log.Fatalf("Failed to connect to server: %v", err)
	}
	defer session.CloseWithError(0, "client done")

	// Open a stream to the server
	stream, err := session.OpenStreamSync(context.TODO())
	if err != nil {
		log.Fatalf("Failed to open stream: %v", err)
	}
	defer stream.Close()

	// Start measuring time for round-trip
	start := time.Now()

	// Send the length of the buffer to the server
	length := int32(len(buffer))
	err = binary.Write(stream, binary.BigEndian, length)
	if err != nil {
		log.Fatalf("Failed to write length to stream: %v", err)
	}

	// Send the buffer data to the server
	_, err = stream.Write(buffer)
	if err != nil {
		log.Fatalf("Failed to send buffer data: %v", err)
	}

	// Read the hash from the server
	hashReceived := make([]byte, sha256.Size)
	n, err := stream.Read(hashReceived)

	if n != sha256.Size {
		log.Fatalf("Failed to read hash from server: %v", err)
	}

	// Calculate round-trip time
	elapsed := time.Since(start)
	log.Printf("Round-trip time: %s", elapsed)

	// Compute the hash locally
	hashCalculated := sha256.Sum256(buffer)

	// Compare the received hash with the calculated hash
	if string(hashCalculated[:]) == string(hashReceived) {
		fmt.Println("Okay")
	} else {
		fmt.Println("Hash mismatch")
	}

	os.Exit(0)
}
