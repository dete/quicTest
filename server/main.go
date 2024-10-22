package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"os"
	"time"

	"github.com/quic-go/quic-go"
)

// QUIC server configuration
const (
	address  = "localhost:4242"
	certFile = "server.cert"
	keyFile  = "server.key"
)

func handleSession(sess quic.Connection) {
	connectionCompleted := false

	defer func() {
		if !connectionCompleted {
			sess.CloseWithError(0, "Connection aborted")
		}
	}()

	//defer sess.CloseWithError(0, "connection closed")
	stream, err := sess.AcceptStream((context.TODO()))
	if err != nil {
		log.Printf("Failed to accept stream: %v\n", err)
		return
	}
	defer stream.Close()

	var length int32
	err = binary.Read(stream, binary.BigEndian, &length)
	if err != nil {
		log.Printf("Failed to read length: %v\n", err)
		return
	}

	buffer := make([]byte, length)
	_, err = io.ReadFull(stream, buffer)
	if err != nil {
		log.Printf("Failed to read data: %v\n", err)
		return
	}

	hash := sha256.Sum256(buffer)
	log.Printf("Hash value: %x\n", hash[:])
	_, err = stream.Write(hash[:])
	if err != nil {
		log.Printf("Failed to send hash: %v\n", err)
		return
	}

	// Ensure the stream is properly closed and flushed
	err = stream.Close()
	if err != nil {
		log.Printf("Failed to close stream: %v\n", err)
		return
	}

	connectionCompleted = true

	fmt.Printf("Processed %d bytes from client, sent back hash.\n", length)
}

func main() {
	// Generate self-signed certificate for testing if not present
	if _, err := os.Stat(certFile); os.IsNotExist(err) {
		err := generateSelfSignedCert(certFile, keyFile)
		if err != nil {
			log.Fatalf("Failed to generate self-signed certificate: %v", err)
		}
	}

	// Load TLS configuration for QUIC
	tlsConfig, err := generateTLSConfig(certFile, keyFile)
	if err != nil {
		log.Fatalf("Failed to load TLS configuration: %v", err)
	}

	listener, err := quic.ListenAddr(address, tlsConfig, nil)
	if err != nil {
		log.Fatalf("Failed to start QUIC listener: %v", err)
	}
	defer listener.Close()

	log.Printf("QUIC server listening on %s\n", address)

	for {
		// Accept new QUIC sessions
		sess, err := listener.Accept(context.TODO())
		if err != nil {
			log.Printf("Failed to accept session: %v\n", err)
			continue
		}

		// Handle the session in a goroutine
		go handleSession(sess)
	}
}

func generateTLSConfig(certFile, keyFile string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"quic-echo-example"},
	}, nil
}

func generateSelfSignedCert(certFile, keyFile string) error {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"QUIC Test Server"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return err
	}

	certOut, err := os.Create(certFile)
	if err != nil {
		return err
	}
	defer certOut.Close()

	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	keyOut, err := os.Create(keyFile)
	if err != nil {
		return err
	}
	defer keyOut.Close()

	pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})

	return nil
}
