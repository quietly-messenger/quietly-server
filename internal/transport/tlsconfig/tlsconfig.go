// Package tlsconfig loads the optional TLS settings shared by the Quietly
// binaries. PROTOCOL.md §1 requires TLS 1.3 on every client-facing connection;
// a deployment either sets TLS_CERT_FILE/TLS_KEY_FILE or terminates TLS in a
// reverse proxy in front of the process (documented in the README).
package tlsconfig

import (
	"crypto/tls"
	"errors"
	"os"
)

// FromEnv builds a TLS config from TLS_CERT_FILE and TLS_KEY_FILE. It returns
// (nil, nil) when neither is set.
func FromEnv() (*tls.Config, error) {
	certFile := os.Getenv("TLS_CERT_FILE")
	keyFile := os.Getenv("TLS_KEY_FILE")
	if certFile == "" && keyFile == "" {
		return nil, nil
	}
	if certFile == "" || keyFile == "" {
		return nil, errors.New("TLS_CERT_FILE and TLS_KEY_FILE must be set together")
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
	}, nil
}
