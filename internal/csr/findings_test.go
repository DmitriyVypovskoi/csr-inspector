package csr

import "testing"

func TestAnalyzeFindingsCleanCSR(
	t *testing.T,
) {
	info := &Info{
		Subject: DistinguishedName{
			CommonName: "example.com",
			String:     "CN=example.com",
			RDNs: []RelativeDistinguishedName{
				{},
			},
		},
		SubjectAlternativeNames: SubjectAlternativeNames{
			DNSNames: []string{
				"example.com",
				"www.example.com",
			},
		},
		PublicKey: PublicKeyInfo{
			Algorithm:   "RSA",
			DisplayName: "RSA",
			Bits:        2048,
		},
		Signature: SignatureInfo{
			Algorithm:     "SHA256-RSA",
			HashAlgorithm: "SHA-256",
		},
	}

	findings := analyzeFindings(info)

	if len(findings) != 0 {
		t.Fatalf(
			"got %d findings, want 0: %+v",
			len(findings),
			findings,
		)
	}
}

func TestAnalyzeFindingsWeakRSAAndSHA1(
	t *testing.T,
) {
	info := &Info{
		Subject: DistinguishedName{
			CommonName: "example.com",
			String:     "CN=example.com",
			RDNs: []RelativeDistinguishedName{
				{},
			},
		},
		PublicKey: PublicKeyInfo{
			Algorithm:   "RSA",
			DisplayName: "RSA",
			Bits:        1024,
		},
		Signature: SignatureInfo{
			Algorithm:     "SHA1-RSA",
			HashAlgorithm: "SHA-1",
		},
	}

	findings := analyzeFindings(info)

	assertFindingCode(
		t,
		findings,
		"rsa_key_too_small",
	)

	assertFindingCode(
		t,
		findings,
		"sha1_signature_algorithm",
	)

	assertFindingCode(
		t,
		findings,
		"san_missing",
	)
}

func TestAnalyzeFindingsCommonNameNotInSAN(
	t *testing.T,
) {
	info := &Info{
		Subject: DistinguishedName{
			CommonName: "example.com",
			String:     "CN=example.com",
			RDNs: []RelativeDistinguishedName{
				{},
			},
		},
		SubjectAlternativeNames: SubjectAlternativeNames{
			DNSNames: []string{
				"www.example.com",
			},
		},
	}

	findings := analyzeFindings(info)

	assertFindingCode(
		t,
		findings,
		"common_name_not_in_san",
	)
}

func TestAnalyzeFindingsDuplicateAndInvalidSAN(
	t *testing.T,
) {
	info := &Info{
		Subject: DistinguishedName{
			CommonName: "example.com",
			String:     "CN=example.com",
			RDNs: []RelativeDistinguishedName{
				{},
			},
		},
		SubjectAlternativeNames: SubjectAlternativeNames{
			DNSNames: []string{
				"example.com",
				"example.com",
				"127.0.0.1",
				"www.*.example.com",
			},
		},
	}

	findings := analyzeFindings(info)

	assertFindingCode(
		t,
		findings,
		"duplicate_san",
	)

	assertFindingCode(
		t,
		findings,
		"ip_address_in_dns_san",
	)

	assertFindingCode(
		t,
		findings,
		"invalid_wildcard_san",
	)
}

func assertFindingCode(
	t *testing.T,
	findings []Finding,
	expectedCode string,
) {
	t.Helper()

	for _, finding := range findings {
		if finding.Code == expectedCode {
			return
		}
	}

	t.Errorf(
		"finding %q was not found in %+v",
		expectedCode,
		findings,
	)
}
