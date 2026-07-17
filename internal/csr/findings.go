package csr

import (
	"fmt"
	"net"
	"sort"
	"strings"
)

type FindingSeverity string

const (
	FindingSeverityError   FindingSeverity = "error"
	FindingSeverityWarning FindingSeverity = "warning"
	FindingSeverityInfo    FindingSeverity = "info"
)

type Finding struct {
	Code     string          `json:"code"`
	Severity FindingSeverity `json:"severity"`
	Title    string          `json:"title"`
	Message  string          `json:"message"`
}

func finalizeInfo(info *Info) *Info {
	if info == nil {
		return nil
	}

	info.Findings = analyzeFindings(info)

	return info
}

func analyzeFindings(info *Info) []Finding {
	if info == nil {
		return nil
	}

	findings := make([]Finding, 0)

	findings = append(
		findings,
		analyzePublicKeyFindings(info)...,
	)

	findings = append(
		findings,
		analyzeSignatureFindings(info)...,
	)

	findings = append(
		findings,
		analyzeSubjectFindings(info)...,
	)

	findings = append(
		findings,
		analyzeSANFindings(info)...,
	)

	findings = append(
		findings,
		analyzeVersionFindings(info)...,
	)

	sort.SliceStable(
		findings,
		func(left int, right int) bool {
			leftRank := findingSeverityRank(
				findings[left].Severity,
			)

			rightRank := findingSeverityRank(
				findings[right].Severity,
			)

			if leftRank == rightRank {
				return findings[left].Code <
					findings[right].Code
			}

			return leftRank < rightRank
		},
	)

	if len(findings) == 0 {
		return nil
	}

	return findings
}

func analyzePublicKeyFindings(
	info *Info,
) []Finding {
	if !isRSAKey(info.PublicKey) {
		return nil
	}

	bits := info.PublicKey.Bits

	switch {
	case bits == 0:
		return nil

	case bits < 1024:
		return []Finding{
			{
				Code:     "rsa_key_critically_small",
				Severity: FindingSeverityError,
				Title:    "RSA key is critically small",
				Message: fmt.Sprintf(
					"The CSR uses a %d-bit RSA key. "+
						"This key size is insecure, and "+
						"self-signature verification was skipped. "+
						"Use an RSA key of at least 2048 bits.",
					bits,
				),
			},
		}

	case bits < 2048:
		return []Finding{
			{
				Code:     "rsa_key_too_small",
				Severity: FindingSeverityError,
				Title:    "RSA key is too small",
				Message: fmt.Sprintf(
					"The CSR uses a %d-bit RSA key. "+
						"Use an RSA key of at least 2048 bits.",
					bits,
				),
			},
		}

	default:
		return nil
	}
}

func analyzeSignatureFindings(
	info *Info,
) []Finding {
	signatureDescription := strings.Join(
		[]string{
			info.Signature.Algorithm,
			info.Signature.DisplayName,
			info.Signature.HashAlgorithm,
		},
		" ",
	)

	normalized := normalizeAlgorithmName(
		signatureDescription,
	)

	switch {
	case strings.Contains(normalized, "MD5"):
		return []Finding{
			{
				Code:     "md5_signature_algorithm",
				Severity: FindingSeverityError,
				Title:    "MD5 signature algorithm",
				Message: "The CSR uses MD5 as part of its " +
					"signature algorithm. MD5 is cryptographically " +
					"broken and should not be used.",
			},
		}

	case strings.Contains(normalized, "SHA1"):
		return []Finding{
			{
				Code:     "sha1_signature_algorithm",
				Severity: FindingSeverityWarning,
				Title:    "SHA-1 signature algorithm",
				Message: "The CSR uses SHA-1 as part of its " +
					"signature algorithm. SHA-1 is deprecated " +
					"and may be rejected by certificate authorities.",
			},
		}
	}

	return nil
}

func analyzeSubjectFindings(
	info *Info,
) []Finding {
	if len(info.Subject.RDNs) != 0 {
		return nil
	}

	if strings.TrimSpace(info.Subject.String) != "" {
		return nil
	}

	return []Finding{
		{
			Code:     "subject_empty",
			Severity: FindingSeverityInfo,
			Title:    "Subject is empty",
			Message: "The CSR does not contain any Subject " +
				"attributes. This can be valid for some profiles, " +
				"but many certificate authorities require Subject data.",
		},
	}
}

func analyzeSANFindings(
	info *Info,
) []Finding {
	findings := make([]Finding, 0)

	san := info.SubjectAlternativeNames

	if subjectAlternativeNamesEmpty(san) {
		findings = append(
			findings,
			Finding{
				Code:     "san_missing",
				Severity: FindingSeverityWarning,
				Title:    "Subject Alternative Name is missing",
				Message: "The CSR does not request a Subject " +
					"Alternative Name extension. For TLS server " +
					"certificates, DNS names and IP addresses " +
					"should normally be placed in SAN.",
			},
		)

		return findings
	}

	commonName := strings.TrimSpace(
		info.Subject.CommonName,
	)

	if commonName != "" &&
		!commonNameIncludedInSAN(commonName, san) {
		findings = append(
			findings,
			Finding{
				Code:     "common_name_not_in_san",
				Severity: FindingSeverityWarning,
				Title:    "Common Name is not included in SAN",
				Message: fmt.Sprintf(
					"The Common Name %q is not present among "+
						"the DNS names or IP addresses in SAN. "+
						"For TLS server certificates, SAN is "+
						"normally used for hostname validation.",
					commonName,
				),
			},
		)
	}

	findings = append(
		findings,
		findDuplicateSANFindings(san)...,
	)

	findings = append(
		findings,
		analyzeDNSSANFindings(san.DNSNames)...,
	)

	return findings
}

func findDuplicateSANFindings(
	san SubjectAlternativeNames,
) []Finding {
	findings := make([]Finding, 0)

	seen := make(map[string]struct{})
	reported := make(map[string]struct{})

	addValues := func(
		sanType string,
		values []string,
		normalize func(string) string,
	) {
		for _, value := range values {
			normalized := normalize(value)

			if normalized == "" {
				continue
			}

			key := sanType + "\x00" + normalized

			if _, exists := seen[key]; !exists {
				seen[key] = struct{}{}

				continue
			}

			if _, exists := reported[key]; exists {
				continue
			}

			reported[key] = struct{}{}

			findings = append(
				findings,
				Finding{
					Code:     "duplicate_san",
					Severity: FindingSeverityInfo,
					Title:    "Duplicate SAN value",
					Message: fmt.Sprintf(
						"The %s SAN value %q is listed more "+
							"than once.",
						sanType,
						value,
					),
				},
			)
		}
	}

	addValues(
		"DNS",
		san.DNSNames,
		normalizeDNSName,
	)

	addValues(
		"IP address",
		san.IPAddresses,
		normalizeIPAddress,
	)

	addValues(
		"email",
		san.EmailAddresses,
		func(value string) string {
			return strings.ToLower(
				strings.TrimSpace(value),
			)
		},
	)

	addValues(
		"URI",
		san.URIs,
		func(value string) string {
			return strings.TrimSpace(value)
		},
	)

	return findings
}

func analyzeDNSSANFindings(
	dnsNames []string,
) []Finding {
	findings := make([]Finding, 0)

	for _, dnsName := range dnsNames {
		trimmed := strings.TrimSpace(dnsName)

		if trimmed == "" {
			continue
		}

		if net.ParseIP(trimmed) != nil {
			findings = append(
				findings,
				Finding{
					Code:     "ip_address_in_dns_san",
					Severity: FindingSeverityWarning,
					Title:    "IP address is encoded as DNS SAN",
					Message: fmt.Sprintf(
						"%q is an IP address but is stored "+
							"as a DNS SAN. IP addresses should "+
							"use the IP Address SAN type.",
						trimmed,
					),
				},
			)
		}

		if strings.Contains(trimmed, "*") &&
			!validWildcardDNSName(trimmed) {
			findings = append(
				findings,
				Finding{
					Code:     "invalid_wildcard_san",
					Severity: FindingSeverityWarning,
					Title:    "Unusual wildcard DNS name",
					Message: fmt.Sprintf(
						"The DNS SAN %q contains a wildcard "+
							"in an unsupported or unusual "+
							"position. A conventional wildcard "+
							"name has the form *.example.com.",
						trimmed,
					),
				},
			)
		}
	}

	return findings
}

func commonNameIncludedInSAN(
	commonName string,
	san SubjectAlternativeNames,
) bool {
	if parsedIP := net.ParseIP(commonName); parsedIP != nil {
		commonNameIP := parsedIP.String()

		for _, ipAddress := range san.IPAddresses {
			if normalizeIPAddress(ipAddress) ==
				commonNameIP {
				return true
			}
		}

		return false
	}

	normalizedCommonName := normalizeDNSName(commonName)

	for _, dnsName := range san.DNSNames {
		if normalizeDNSName(dnsName) ==
			normalizedCommonName {
			return true
		}
	}

	return false
}

func subjectAlternativeNamesEmpty(
	san SubjectAlternativeNames,
) bool {
	return len(san.DNSNames) == 0 &&
		len(san.IPAddresses) == 0 &&
		len(san.EmailAddresses) == 0 &&
		len(san.URIs) == 0
}

func validWildcardDNSName(
	value string,
) bool {
	value = strings.TrimSpace(value)

	return strings.HasPrefix(value, "*.") &&
		strings.Count(value, "*") == 1 &&
		len(value) > 2
}

func normalizeDNSName(value string) string {
	value = strings.TrimSpace(value)
	value = strings.TrimSuffix(value, ".")

	return strings.ToLower(value)
}

func normalizeIPAddress(value string) string {
	parsed := net.ParseIP(
		strings.TrimSpace(value),
	)

	if parsed == nil {
		return strings.TrimSpace(value)
	}

	return parsed.String()
}

func normalizeAlgorithmName(value string) string {
	replacer := strings.NewReplacer(
		"-", "",
		"_", "",
		" ", "",
		"/", "",
	)

	return strings.ToUpper(
		replacer.Replace(value),
	)
}

func isRSAKey(publicKey PublicKeyInfo) bool {
	algorithm := strings.ToUpper(
		strings.TrimSpace(publicKey.Algorithm),
	)

	displayName := strings.ToUpper(
		strings.TrimSpace(publicKey.DisplayName),
	)

	return algorithm == "RSA" ||
		strings.Contains(displayName, "RSA")
}

func analyzeVersionFindings(
	info *Info,
) []Finding {
	if info.Version == 0 {
		return nil
	}

	return []Finding{
		{
			Code:     "unknown_pkcs10_version",
			Severity: FindingSeverityWarning,
			Title:    "Unknown PKCS#10 version",
			Message: fmt.Sprintf(
				"The CSR contains encoded version %d. "+
					"Standard PKCS#10 requests use encoded version 0.",
				info.Version,
			),
		},
	}
}

func findingSeverityRank(
	severity FindingSeverity,
) int {
	switch severity {
	case FindingSeverityError:
		return 0

	case FindingSeverityWarning:
		return 1

	case FindingSeverityInfo:
		return 2

	default:
		return 3
	}
}
