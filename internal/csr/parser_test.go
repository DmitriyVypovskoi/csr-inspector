package csr

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"slices"
	"strings"
	"testing"
)

const realOpenSSLCSRPEM = `-----BEGIN CERTIFICATE REQUEST-----
MIIFDTCCAvUCAQAwczELMAkGA1UEBhMCUlUxDzANBgNVBAgMBk1vc2NvdzEPMA0G
A1UEBwwGTW9zY293MRYwFAYDVQQKDA1DU1IgSW5zcGVjdG9yMRQwEgYDVQQLDAtE
ZXZlbG9wbWVudDEUMBIGA1UEAwwLZXhhbXBsZS5jb20wggIiMA0GCSqGSIb3DQEB
AQUAA4ICDwAwggIKAoICAQCWZ4KlhvaT0lzEFrBW5D1IgbSTk1n/yPVWKFU7hnoz
l3NIlFdiHjXPPClQvyf5j5h/mzOd8FlucTNuGl2DlSAWraCLr0X4bqrly9Q7Nht7
WLBIE+ruGkIfMH2kfU/Mci1gvUX98tWEyjqMUBOOXZAyszHTDeHaXvDwfkzbtN3d
14nAE3t+jBwF0XG8o6dwoL0425bUpw8jXA1fgFMs5vjk5V8mlEwr3w3k3vgm0E1e
Cia+B39kCCL6mhMUa2N0Nneps1BjGSc45iGqIuN6q9563dOZkPJE3LkMFFtPM1AX
zsWvmpobdnDUkEQSHX+1OHMOvR5X6KxNhi16UHpz8ZbFVAksIXmrQZhd7xG4PtSY
BrnJLR8OdsS11wfQd6igh9T9m3dTQ7rvJLOcTZo3gJK6QJPY5ew96LzuFF8hjnUw
+/EHVj4qRZH+TyGTPii5cl7k11xIu3WJvWu84v6LBG8JU+SWIv+OlYmzUwfP286M
Xr/Ihv1PfVlH3HstRePf+DcB+B3ews1wMQjE0ZOJGFDcQM4yYmXfCOB3RnbuMcQh
OUoLqH6xCORSHLcKRwXmuGVtUJWTLlDryWdGyJ9zU6Q/YrczhgYYdUQ75lUcKrRp
ymAh3s+aCc0sn2ej+mzzohXhn6Nmx5vwXMYYsy9wz8147GVmYgsaiwW1zFwfb6Ig
FwIDAQABoFUwUwYJKoZIhvcNAQkOMUYwRDBCBgNVHREEOzA5ggtleGFtcGxlLmNv
bYIPd3d3LmV4YW1wbGUuY29thwR/AAABhhNodHRwczovL2V4YW1wbGUuY29tMA0G
CSqGSIb3DQEBCwUAA4ICAQB6LtrDtRWh7N5z3zRU2Y1fjlURfUMx40sDfx/54s/U
+MkNxHDv8ZMKoFZo4GbJLj9qnLWifC+JxHIQ/SViKQlkfmL1CLM5Ced3NoSlWxMa
CeSqBBCncaqV8NDK/it1WgsWwwYR4F+9W+VGE+8+0I9eOe+TOep1OdFMEyk80OF6
3FM3phZR/odGEYS7buB20Ke5bncGa6HF7m/QYsIShhLkPXuK8RgG2xg8jzJyu8xG
LQetGUu6Xd0ZwDJw6oKd2c4zg7nt3ePT0oR324t1L/DLx5bjd4Ph6JcoTk88N/Bd
vJ2tZk8XLNtm7wqcnPxF0BsXrdZ3M5lfCLLRm/c7kNyqYPZifqJdPpZJN7NDRS76
TlmoD4HlJgshk1NePJ1uDk1BbKuJRvS52KaOzNXj83iKiFScFHAAAoFTeF45clG+
S4OaRw2u0yAm+iaw/Zx2klOsEzGtSwbxSmrVR7k1/xBgnQ4JLx1CHdfqhog0B7Qw
/kfw7V849Pa536GL+jMIdzu1IX5YEX7CpET9nIOJI/ZCuBiYD9GS7UOynKZwkidb
mGnkSAR+qhmwZwstqBjUyXD4xX46RoEtXN5pUJQpCp5qyrLcmo66jnairAr9TZls
EHoP9Pg37llkPHW/wxPp1IcfYHcL8UdxSTrhscVQDWVi68d7NBqa94XOItu7kViA
WA==
-----END CERTIFICATE REQUEST-----
`

func TestParsePEM(t *testing.T) {
	der := makeCSR(t)

	input := pem.EncodeToMemory(
		&pem.Block{
			Type:  pemTypeCertificateRequest,
			Bytes: der,
		},
	)

	info, err := ParsePEM(input)
	if err != nil {
		t.Fatalf("ParsePEM() error = %v", err)
	}

	if info.Subject.String !=
		"CN=example.com,O=Example LLC,C=DE" {
		t.Fatalf(
			"subject = %q",
			info.Subject.String,
		)
	}

	if info.PublicKey.Algorithm != "RSA" {
		t.Fatalf(
			"algorithm = %q",
			info.PublicKey.Algorithm,
		)
	}

	if info.PublicKey.Bits != 2048 {
		t.Fatalf(
			"bits = %d",
			info.PublicKey.Bits,
		)
	}

	if info.Signature.Verification != VerificationValid {
		t.Fatalf(
			"verification = %q",
			info.Signature.Verification,
		)
	}

	if len(info.SubjectAlternativeNames.DNSNames) != 2 {
		t.Fatalf(
			"DNS names = %#v",
			info.SubjectAlternativeNames.DNSNames,
		)
	}
}

func TestParsePEMAcceptsNewHeader(t *testing.T) {
	input := pem.EncodeToMemory(
		&pem.Block{
			Type:  pemTypeNewCertificateRequest,
			Bytes: makeCSR(t),
		},
	)

	info, err := ParsePEM(input)
	if err != nil {
		t.Fatalf("ParsePEM() error = %v", err)
	}

	if info.PEMType != pemTypeNewCertificateRequest {
		t.Fatalf(
			"PEMType = %q",
			info.PEMType,
		)
	}
}

func TestParsePEMRejectsRawBase64(t *testing.T) {
	input := []byte(
		base64.StdEncoding.EncodeToString(
			makeCSR(t),
		),
	)

	_, err := ParsePEM(input)

	if !errors.Is(err, ErrInvalidPEM) {
		t.Fatalf(
			"error = %v, want ErrInvalidPEM",
			err,
		)
	}
}

func TestParsePEMRejectsTrailingData(t *testing.T) {
	input := append(
		pem.EncodeToMemory(
			&pem.Block{
				Type:  pemTypeCertificateRequest,
				Bytes: makeCSR(t),
			},
		),
		[]byte("garbage")...,
	)

	_, err := ParsePEM(input)

	if !errors.Is(err, ErrTrailingData) {
		t.Fatalf(
			"error = %v, want ErrTrailingData",
			err,
		)
	}
}

func TestParsePEMReportsInvalidSignature(t *testing.T) {
	der := makeCSR(t)

	/*
		Меняем последний байт подписи.

		ASN.1 структура остаётся корректной,
		но криптографическая подпись больше не совпадает.
	*/
	der[len(der)-1] ^= 0x01

	input := pem.EncodeToMemory(
		&pem.Block{
			Type:  pemTypeCertificateRequest,
			Bytes: der,
		},
	)

	info, err := ParsePEM(input)
	if err != nil {
		t.Fatalf("ParsePEM() error = %v", err)
	}

	if info.Signature.Verification != VerificationInvalid {
		t.Fatalf(
			"verification = %q",
			info.Signature.Verification,
		)
	}
}

func TestParsePEMRealOpenSSLRequest(t *testing.T) {
	info, err := ParsePEM([]byte(realOpenSSLCSRPEM))
	if err != nil {
		t.Fatalf("ParsePEM() error = %v", err)
	}

	t.Run("PEM metadata", func(t *testing.T) {
		if info.PEMType != pemTypeCertificateRequest {
			t.Errorf(
				"PEMType = %q, want %q",
				info.PEMType,
				pemTypeCertificateRequest,
			)
		}

		/*
			OpenSSL отображает:

			    Version: 1 (0x0)

			При этом реальное значение version в PKCS#10 равно 0.
			Именно его возвращает crypto/x509.
		*/
		if info.Version != 0 {
			t.Errorf(
				"Version = %d, want 0",
				info.Version,
			)
		}
	})

	t.Run("subject", func(t *testing.T) {
		expected := []struct {
			oid   string
			value string
		}{
			{
				oid:   "2.5.4.6",
				value: "RU",
			},
			{
				oid:   "2.5.4.8",
				value: "Moscow",
			},
			{
				oid:   "2.5.4.7",
				value: "Moscow",
			},
			{
				oid:   "2.5.4.10",
				value: "CSR Inspector",
			},
			{
				oid:   "2.5.4.11",
				value: "Development",
			},
			{
				oid:   "2.5.4.3",
				value: "example.com",
			},
		}

		for _, item := range expected {
			if !subjectContains(
				info.Subject,
				item.oid,
				item.value,
			) {
				t.Errorf(
					"subject does not contain OID %s with value %q",
					item.oid,
					item.value,
				)
			}
		}
	})

	t.Run("RSA public key", func(t *testing.T) {
		if info.PublicKey.Algorithm != "RSA" {
			t.Errorf(
				"PublicKey.Algorithm = %q, want RSA",
				info.PublicKey.Algorithm,
			)
		}

		if info.PublicKey.Bits != 4096 {
			t.Errorf(
				"PublicKey.Bits = %d, want 4096",
				info.PublicKey.Bits,
			)
		}

		if info.PublicKey.RSA == nil {
			t.Fatal("PublicKey.RSA is nil")
		}

		if info.PublicKey.RSA.Exponent != 65537 {
			t.Errorf(
				"RSA exponent = %d, want 65537",
				info.PublicKey.RSA.Exponent,
			)
		}

		/*
			RSA 4096 содержит 512 байт modulus.

			Наш формат — два hex-символа на байт,
			разделённые двоеточиями.
		*/
		if got := hexByteCount(
			info.PublicKey.RSA.ModulusHex,
		); got != 512 {
			t.Errorf(
				"RSA modulus contains %d bytes, want 512",
				got,
			)
		}

		const expectedModulusPrefix = "96:67:82:A5:86:F6:93:D2"
		const expectedModulusSuffix = "B5:CC:5C:1F:6F:A2:20:17"

		if !strings.HasPrefix(
			info.PublicKey.RSA.ModulusHex,
			expectedModulusPrefix,
		) {
			t.Errorf(
				"RSA modulus prefix = %q, want %q",
				firstHexBytes(
					info.PublicKey.RSA.ModulusHex,
					8,
				),
				expectedModulusPrefix,
			)
		}

		if info.PublicKey.AlgorithmOID !=
			"1.2.840.113549.1.1.1" {
			t.Errorf(
				"PublicKey.AlgorithmOID = %q, want %q",
				info.PublicKey.AlgorithmOID,
				"1.2.840.113549.1.1.1",
			)
		}

		if info.PublicKey.DisplayName != "rsaEncryption" {
			t.Errorf(
				"PublicKey.DisplayName = %q, want %q",
				info.PublicKey.DisplayName,
				"rsaEncryption",
			)
		}

		if !strings.HasSuffix(
			info.PublicKey.RSA.ModulusHex,
			expectedModulusSuffix,
		) {
			t.Errorf(
				"RSA modulus suffix = %q, want %q",
				lastHexBytes(
					info.PublicKey.RSA.ModulusHex,
					8,
				),
				expectedModulusSuffix,
			)
		}
	})

	t.Run("subject alternative names", func(t *testing.T) {
		expectedDNSNames := []string{
			"example.com",
			"www.example.com",
		}

		if !slices.Equal(
			info.SubjectAlternativeNames.DNSNames,
			expectedDNSNames,
		) {
			t.Errorf(
				"DNSNames = %#v, want %#v",
				info.SubjectAlternativeNames.DNSNames,
				expectedDNSNames,
			)
		}

		expectedIPAddresses := []string{
			"127.0.0.1",
		}

		if !slices.Equal(
			info.SubjectAlternativeNames.IPAddresses,
			expectedIPAddresses,
		) {
			t.Errorf(
				"IPAddresses = %#v, want %#v",
				info.SubjectAlternativeNames.IPAddresses,
				expectedIPAddresses,
			)
		}

		expectedURIs := []string{
			"https://example.com",
		}

		if !slices.Equal(
			info.SubjectAlternativeNames.URIs,
			expectedURIs,
		) {
			t.Errorf(
				"URIs = %#v, want %#v",
				info.SubjectAlternativeNames.URIs,
				expectedURIs,
			)
		}

		if len(
			info.SubjectAlternativeNames.EmailAddresses,
		) != 0 {
			t.Errorf(
				"EmailAddresses = %#v, want empty",
				info.SubjectAlternativeNames.EmailAddresses,
			)
		}
	})

	t.Run("requested extensions", func(t *testing.T) {
		const subjectAlternativeNameOID = "2.5.29.17"

		extension, ok := findExtension(
			info.Extensions,
			subjectAlternativeNameOID,
		)
		if !ok {
			t.Fatal(
				"Subject Alternative Name extension is missing",
			)
		}

		if extension.Name != "Subject Alternative Name" {
			t.Errorf(
				"extension name = %q, want %q",
				extension.Name,
				"Subject Alternative Name",
			)
		}

		if extension.Critical {
			t.Error(
				"Subject Alternative Name extension is unexpectedly critical",
			)
		}

		/*
			В исходном PKCS#10 это extensionRequest attribute.

			Наш parser намеренно не дублирует его в Attributes,
			а переносит requested extensions в Info.Extensions.
		*/
		if len(info.Attributes) != 0 {
			t.Errorf(
				"Attributes = %#v, want no ordinary attributes",
				info.Attributes,
			)
		}
	})

	t.Run("signature", func(t *testing.T) {
		/*
			Это Go-наименование алгоритма.

			При текстовом выводе нашего сервиса позже преобразуем его в:

			    sha256WithRSAEncryption
		*/
		if info.Signature.Algorithm != "SHA256-RSA" {
			t.Errorf(
				"Signature.Algorithm = %q, want %q",
				info.Signature.Algorithm,
				"SHA256-RSA",
			)
		}

		if info.Signature.AlgorithmOID !=
			"1.2.840.113549.1.1.11" {
			t.Errorf(
				"Signature.AlgorithmOID = %q, want %q",
				info.Signature.AlgorithmOID,
				"1.2.840.113549.1.1.11",
			)
		}

		if info.Signature.DisplayName !=
			"sha256WithRSAEncryption" {
			t.Errorf(
				"Signature.DisplayName = %q, want %q",
				info.Signature.DisplayName,
				"sha256WithRSAEncryption",
			)
		}

		if info.Signature.HashAlgorithm != "SHA-256" {
			t.Errorf(
				"Signature.HashAlgorithm = %q, want SHA-256",
				info.Signature.HashAlgorithm,
			)
		}

		if info.Signature.KeyAlgorithm != "RSA" {
			t.Errorf(
				"Signature.KeyAlgorithm = %q, want RSA",
				info.Signature.KeyAlgorithm,
			)
		}

		if info.Signature.Verification != VerificationValid {
			t.Errorf(
				"Signature.Verification = %q, want %q; error: %s",
				info.Signature.Verification,
				VerificationValid,
				info.Signature.VerificationError,
			)
		}

		if info.Signature.VerificationError != "" {
			t.Errorf(
				"VerificationError = %q, want empty",
				info.Signature.VerificationError,
			)
		}

		/*
			Подпись RSA 4096 также имеет размер 512 байт.
		*/
		block, _ := pem.Decode(
			[]byte(realOpenSSLCSRPEM),
		)
		if block == nil {
			t.Fatal("failed to decode real OpenSSL CSR")
		}

		rawInfo, err := parseRawCSR(block.Bytes)
		if err != nil {
			t.Fatalf("parseRawCSR() error = %v", err)
		}

		signatureBytes := rawInfo.Request.Signature.Bytes

		if got := len(signatureBytes); got != 512 {
			t.Errorf(
				"signature contains %d bytes, want 512",
				got,
			)
		}

		expectedSignaturePrefix := []byte{
			0x7A, 0x2E, 0xDA, 0xC3,
			0xB5, 0x15, 0xA1, 0xEC,
		}

		if !bytes.HasPrefix(
			signatureBytes,
			expectedSignaturePrefix,
		) {
			t.Errorf(
				"signature prefix = % X, want % X",
				signatureBytes[:min(
					len(signatureBytes),
					len(expectedSignaturePrefix),
				)],
				expectedSignaturePrefix,
			)
		}

		expectedSignatureSuffix := []byte{
			0x22, 0xDB, 0xBB, 0x91,
			0x58, 0x80, 0x58,
		}

		if !bytes.HasSuffix(
			signatureBytes,
			expectedSignatureSuffix,
		) {
			start := max(
				0,
				len(signatureBytes)-len(expectedSignatureSuffix),
			)

			t.Errorf(
				"signature suffix = % X, want % X",
				signatureBytes[start:],
				expectedSignatureSuffix,
			)
		}
	})
}

func TestParsePEMUnsupportedAlgorithmStillReturnsCNAndSAN(
	t *testing.T,
) {
	block, _ := pem.Decode(
		[]byte(realOpenSSLCSRPEM),
	)
	if block == nil {
		t.Fatal("decode test CSR")
	}

	der := bytes.Clone(block.Bytes)

	rsaOID, err := asn1.Marshal(
		asn1.ObjectIdentifier{
			1, 2, 840, 113549, 1, 1, 1,
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	unknownOID, err := asn1.Marshal(
		asn1.ObjectIdentifier{
			1, 2, 840, 113549, 1, 1, 127,
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	if len(rsaOID) != len(unknownOID) {
		t.Fatal("test OIDs have different DER lengths")
	}

	index := bytes.Index(der, rsaOID)
	if index == -1 {
		t.Fatal("RSA public key OID not found")
	}

	copy(
		der[index:index+len(rsaOID)],
		unknownOID,
	)

	input := pem.EncodeToMemory(
		&pem.Block{
			Type:  pemTypeCertificateRequest,
			Bytes: der,
		},
	)

	info, err := ParsePEM(input)
	if err != nil {
		t.Fatalf("ParsePEM() error = %v", err)
	}

	if info.Subject.CommonName != "example.com" {
		t.Errorf(
			"CommonName = %q, want example.com",
			info.Subject.CommonName,
		)
	}

	if !slices.Equal(
		info.SubjectAlternativeNames.DNSNames,
		[]string{
			"example.com",
			"www.example.com",
		},
	) {
		t.Errorf(
			"DNSNames = %#v",
			info.SubjectAlternativeNames.DNSNames,
		)
	}

	if info.Signature.Verification !=
		VerificationUnsupported {
		t.Errorf(
			"verification = %q, want unsupported",
			info.Signature.Verification,
		)
	}

	if len(info.Warnings) == 0 {
		t.Error("expected verification warning")
	}
}

func makeCSR(t *testing.T) []byte {
	t.Helper()

	key, err := rsa.GenerateKey(
		rand.Reader,
		2048,
	)
	if err != nil {
		t.Fatal(err)
	}

	der, err := x509.CreateCertificateRequest(
		rand.Reader,
		&x509.CertificateRequest{
			Subject: pkix.Name{
				Country: []string{
					"DE",
				},
				Organization: []string{
					"Example LLC",
				},
				CommonName: "example.com",
			},
			DNSNames: []string{
				"example.com",
				"www.example.com",
			},
		},
		key,
	)
	if err != nil {
		t.Fatal(err)
	}

	return der
}

func subjectContains(
	subject DistinguishedName,
	oid string,
	value string,
) bool {
	for _, rdn := range subject.RDNs {
		for _, attribute := range rdn.Attributes {
			if attribute.OID == oid &&
				attribute.Value == value {
				return true
			}
		}
	}

	return false
}

func findExtension(
	extensions []ExtensionInfo,
	oid string,
) (ExtensionInfo, bool) {
	for _, extension := range extensions {
		if extension.OID == oid {
			return extension, true
		}
	}

	return ExtensionInfo{}, false
}

func hexByteCount(value string) int {
	if value == "" {
		return 0
	}

	return len(strings.Split(value, ":"))
}

func firstHexBytes(
	value string,
	count int,
) string {
	parts := strings.Split(value, ":")

	if len(parts) <= count {
		return value
	}

	return strings.Join(parts[:count], ":")
}

func lastHexBytes(
	value string,
	count int,
) string {
	parts := strings.Split(value, ":")

	if len(parts) <= count {
		return value
	}

	return strings.Join(
		parts[len(parts)-count:],
		":",
	)
}
