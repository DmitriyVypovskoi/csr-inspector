package csr

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParsePEMGeneratedAlgorithms(
	t *testing.T,
) {
	t.Parallel()

	tests := []struct {
		name          string
		createKey     func(*testing.T) any
		wantAlgorithm string
	}{
		{
			name: "RSA 2048",
			createKey: func(t *testing.T) any {
				t.Helper()

				key, err := rsa.GenerateKey(
					rand.Reader,
					2048,
				)
				if err != nil {
					t.Fatal(err)
				}

				return key
			},
			wantAlgorithm: "RSA",
		},
		{
			name: "ECDSA P-256",
			createKey: func(t *testing.T) any {
				t.Helper()

				key, err := ecdsa.GenerateKey(
					elliptic.P256(),
					rand.Reader,
				)
				if err != nil {
					t.Fatal(err)
				}

				return key
			},
			wantAlgorithm: "ECDSA",
		},
		{
			name: "Ed25519",
			createKey: func(t *testing.T) any {
				t.Helper()

				_, key, err := ed25519.GenerateKey(
					rand.Reader,
				)
				if err != nil {
					t.Fatal(err)
				}

				return key
			},
			wantAlgorithm: "ED25519",
		},
	}

	for _, test := range tests {
		test := test

		t.Run(
			test.name,
			func(t *testing.T) {
				t.Parallel()

				csrPEM := createTestCSR(
					t,
					test.createKey(t),
				)

				info, err := ParsePEM(csrPEM)
				if err != nil {
					t.Fatalf(
						"ParsePEM() error = %v",
						err,
					)
				}

				if info.PEMType != "CERTIFICATE REQUEST" {
					t.Errorf(
						"PEMType = %q, want CERTIFICATE REQUEST",
						info.PEMType,
					)
				}

				if info.Version != 0 {
					t.Errorf(
						"Version = %d, want 0",
						info.Version,
					)
				}

				if info.Subject.CommonName != "example.com" {
					t.Errorf(
						"CommonName = %q, want example.com",
						info.Subject.CommonName,
					)
				}

				if !containsString(
					info.SubjectAlternativeNames.DNSNames,
					"example.com",
				) {
					t.Errorf(
						"DNS SAN does not contain example.com: %v",
						info.SubjectAlternativeNames.DNSNames,
					)
				}

				algorithm := strings.ToUpper(
					info.PublicKey.Algorithm,
				)

				if !strings.Contains(
					algorithm,
					test.wantAlgorithm,
				) {
					t.Errorf(
						"PublicKey.Algorithm = %q, want %q",
						info.PublicKey.Algorithm,
						test.wantAlgorithm,
					)
				}

				if info.Signature.Verification !=
					VerificationValid {
					t.Errorf(
						"Verification = %q, want %q; details: %s",
						info.Signature.Verification,
						VerificationValid,
						info.Signature.VerificationError,
					)
				}
			},
		)
	}
}

func TestParsePEMFixtureAlgorithms(
	t *testing.T,
) {
	tests := []struct {
		name             string
		fileName         string
		wantAlgorithm    string
		wantVerification VerificationStatus
	}{
		{
			name:             "GOST 2012 256",
			fileName:         "gost-2012-256.csr",
			wantAlgorithm:    "GOST",
			wantVerification: VerificationUnsupported,
		},
		{
			name:             "RSA 512",
			fileName:         "rsa-512.csr",
			wantAlgorithm:    "RSA",
			wantVerification: VerificationUnsupported,
		},
	}

	for _, test := range tests {
		test := test

		t.Run(
			test.name,
			func(t *testing.T) {
				input := readFixture(
					t,
					test.fileName,
				)

				info, err := ParsePEM(input)
				if err != nil {
					t.Fatalf(
						"ParsePEM() error = %v",
						err,
					)
				}

				algorithm := strings.ToUpper(
					info.PublicKey.Algorithm,
				)

				if !strings.Contains(
					algorithm,
					test.wantAlgorithm,
				) {
					t.Errorf(
						"PublicKey.Algorithm = %q, want %q",
						info.PublicKey.Algorithm,
						test.wantAlgorithm,
					)
				}

				if info.Signature.Verification !=
					test.wantVerification {
					t.Errorf(
						"Verification = %q, want %q; details: %s",
						info.Signature.Verification,
						test.wantVerification,
						info.Signature.VerificationError,
					)
				}
			},
		)
	}
}

func TestParsePEMRSA512Finding(
	t *testing.T,
) {
	input := readFixture(
		t,
		"rsa-512.csr",
	)

	info, err := ParsePEM(input)
	if err != nil {
		t.Fatal(err)
	}

	if !hasFindingCode(
		info.Findings,
		"rsa_key_critically_small",
	) {
		t.Fatalf(
			"finding rsa_key_critically_small not found: %+v",
			info.Findings,
		)
	}
}

func TestParsePEMInvalidSignature(
	t *testing.T,
) {
	key, err := rsa.GenerateKey(
		rand.Reader,
		2048,
	)
	if err != nil {
		t.Fatal(err)
	}

	validPEM := createTestCSR(t, key)

	block, rest := pem.Decode(validPEM)
	if block == nil {
		t.Fatal("failed to decode generated CSR")
	}

	if len(rest) != 0 {
		t.Fatal("unexpected trailing data")
	}

	block.Bytes[len(block.Bytes)-1] ^= 0x01

	invalidPEM := pem.EncodeToMemory(block)

	info, err := ParsePEM(invalidPEM)
	if err != nil {
		t.Fatalf(
			"ParsePEM() error = %v",
			err,
		)
	}

	if info.Signature.Verification !=
		VerificationInvalid {
		t.Errorf(
			"Verification = %q, want %q",
			info.Signature.Verification,
			VerificationInvalid,
		)
	}
}

func TestParsePEMInputErrors(
	t *testing.T,
) {
	validCSR := createTestCSR(
		t,
		mustGenerateRSAKey(t),
	)

	tests := []struct {
		name      string
		input     []byte
		wantError error
	}{
		{
			name:      "empty input",
			input:     nil,
			wantError: ErrEmptyInput,
		},
		{
			name:      "plain text",
			input:     []byte("hello world"),
			wantError: ErrInvalidPEM,
		},
		{
			name: "trailing data",
			input: append(
				append([]byte(nil), validCSR...),
				[]byte("\nunexpected")...,
			),
			wantError: ErrTrailingData,
		},
		{
			name:      "certificate instead of CSR",
			input:     createTestCertificate(t),
			wantError: ErrUnsupportedPEMType,
		},
		{
			name:      "private key instead of CSR",
			input:     createTestPrivateKeyPEM(t),
			wantError: ErrUnsupportedPEMType,
		},
	}

	for _, test := range tests {
		test := test

		t.Run(
			test.name,
			func(t *testing.T) {
				_, err := ParsePEM(test.input)

				if !errors.Is(err, test.wantError) {
					t.Errorf(
						"error = %v, want errors.Is(%v)",
						err,
						test.wantError,
					)
				}
			},
		)
	}
}

func TestParsePEMMalformedASN1(
	t *testing.T,
) {
	input := pem.EncodeToMemory(
		&pem.Block{
			Type:  "CERTIFICATE REQUEST",
			Bytes: []byte("not valid ASN.1"),
		},
	)

	_, err := ParsePEM(input)
	if err == nil {
		t.Fatal("ParsePEM() returned nil error")
	}

	if errors.Is(err, ErrInvalidPEM) {
		t.Fatalf(
			"expected ASN.1 parsing error, got ErrInvalidPEM: %v",
			err,
		)
	}
}

func createTestCSR(
	t *testing.T,
	privateKey any,
) []byte {
	t.Helper()

	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			Country:      []string{"RU"},
			Organization: []string{"CSR Inspector"},
			CommonName:   "example.com",
		},
		DNSNames: []string{
			"example.com",
			"www.example.com",
		},
		IPAddresses: []net.IP{
			net.ParseIP("127.0.0.1"),
		},
		EmailAddresses: []string{
			"admin@example.com",
		},
	}

	der, err := x509.CreateCertificateRequest(
		rand.Reader,
		template,
		privateKey,
	)
	if err != nil {
		t.Fatalf(
			"CreateCertificateRequest() error = %v",
			err,
		)
	}

	return pem.EncodeToMemory(
		&pem.Block{
			Type:  "CERTIFICATE REQUEST",
			Bytes: der,
		},
	)
}

func createTestCertificate(
	t *testing.T,
) []byte {
	t.Helper()

	privateKey := mustGenerateRSAKey(t)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "certificate.example.com",
		},
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(time.Hour),

		KeyUsage: x509.KeyUsageDigitalSignature,

		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(
		rand.Reader,
		template,
		template,
		&privateKey.PublicKey,
		privateKey,
	)
	if err != nil {
		t.Fatalf(
			"CreateCertificate() error = %v",
			err,
		)
	}

	return pem.EncodeToMemory(
		&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: der,
		},
	)
}

func createTestPrivateKeyPEM(
	t *testing.T,
) []byte {
	t.Helper()

	privateKey := mustGenerateRSAKey(t)

	der, err := x509.MarshalPKCS8PrivateKey(
		privateKey,
	)
	if err != nil {
		t.Fatalf(
			"MarshalPKCS8PrivateKey() error = %v",
			err,
		)
	}

	return pem.EncodeToMemory(
		&pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: der,
		},
	)
}

func mustGenerateRSAKey(
	t *testing.T,
) *rsa.PrivateKey {
	t.Helper()

	key, err := rsa.GenerateKey(
		rand.Reader,
		2048,
	)
	if err != nil {
		t.Fatal(err)
	}

	return key
}

func readFixture(
	t *testing.T,
	name string,
) []byte {
	t.Helper()

	path := filepath.Join(
		"testdata",
		name,
	)

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf(
			"read fixture %q: %v",
			path,
			err,
		)
	}

	return data
}

func containsString(
	values []string,
	expected string,
) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}

	return false
}

func hasFindingCode(
	findings []Finding,
	code string,
) bool {
	for _, finding := range findings {
		if finding.Code == code {
			return true
		}
	}

	return false
}
