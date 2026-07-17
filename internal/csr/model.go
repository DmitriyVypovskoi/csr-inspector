package csr

type VerificationStatus string

const (
	VerificationValid       VerificationStatus = "valid"
	VerificationInvalid     VerificationStatus = "invalid"
	VerificationUnsupported VerificationStatus = "unsupported"
	VerificationNotVerified VerificationStatus = "not_verified"
)

type Info struct {
	PEMType                 string                  `json:"pem_type"`
	Version                 int                     `json:"version"`
	Subject                 DistinguishedName       `json:"subject"`
	SubjectAlternativeNames SubjectAlternativeNames `json:"subject_alternative_names"`
	PublicKey               PublicKeyInfo           `json:"public_key"`
	Attributes              []AttributeInfo         `json:"attributes"`
	Extensions              []ExtensionInfo         `json:"extensions"`
	Signature               SignatureInfo           `json:"signature"`
	Findings                []Finding               `json:"findings,omitempty"`
	Warnings                []string                `json:"warnings,omitempty"`
}

type DistinguishedName struct {
	String     string                      `json:"string"`
	CommonName string                      `json:"common_name,omitempty"`
	RDNs       []RelativeDistinguishedName `json:"rdns"`
}

type RelativeDistinguishedName struct {
	Attributes []NameAttribute `json:"attributes"`
}

type NameAttribute struct {
	OID   string `json:"oid"`
	Name  string `json:"name"`
	Value string `json:"value"`
}

type SubjectAlternativeNames struct {
	DNSNames       []string `json:"dns_names"`
	EmailAddresses []string `json:"email_addresses"`
	IPAddresses    []string `json:"ip_addresses"`
	URIs           []string `json:"uris"`
}

type PublicKeyInfo struct {
	Algorithm         string `json:"algorithm"`
	AlgorithmOID      string `json:"algorithm_oid"`
	DisplayName       string `json:"display_name"`
	Bits              int    `json:"bits"`
	FingerprintSHA256 string `json:"fingerprint_sha256,omitempty"`

	RSA     *RSAKeyInfo     `json:"rsa,omitempty"`
	ECDSA   *ECDSAKeyInfo   `json:"ecdsa,omitempty"`
	Ed25519 *Ed25519KeyInfo `json:"ed25519,omitempty"`
	DSA     *DSAKeyInfo     `json:"dsa,omitempty"`
	GOST    *GOSTKeyInfo    `json:"gost,omitempty"`
}

type RSAKeyInfo struct {
	Exponent   int    `json:"exponent"`
	ModulusHex string `json:"modulus_hex"`
}

type GOSTKeyInfo struct {
	Version string `json:"version"`

	ParameterSetOID  string `json:"parameter_set_oid,omitempty"`
	ParameterSetName string `json:"parameter_set_name,omitempty"`

	DigestOID  string `json:"digest_oid,omitempty"`
	DigestName string `json:"digest_name,omitempty"`

	EncryptionParameterSetOID  string `json:"encryption_parameter_set_oid,omitempty"`
	EncryptionParameterSetName string `json:"encryption_parameter_set_name,omitempty"`
}

type ECDSAKeyInfo struct {
	Curve          string `json:"curve"`
	PublicPointHex string `json:"public_point_hex"`
}

type Ed25519KeyInfo struct {
	PublicKeyHex string `json:"public_key_hex"`
}

type DSAKeyInfo struct {
	PHex string `json:"p_hex"`
	QHex string `json:"q_hex"`
	GHex string `json:"g_hex"`
	YHex string `json:"y_hex"`
}

type AttributeInfo struct {
	OID       string   `json:"oid"`
	Name      string   `json:"name"`
	Values    []string `json:"values,omitempty"`
	RawValues []string `json:"raw_values_hex"`
}

type ExtensionInfo struct {
	OID      string `json:"oid"`
	Name     string `json:"name"`
	Critical bool   `json:"critical"`
	ValueHex string `json:"value_hex,omitempty"`
}

type SignatureInfo struct {
	Algorithm         string             `json:"algorithm"`
	AlgorithmOID      string             `json:"algorithm_oid"`
	DisplayName       string             `json:"display_name"`
	HashAlgorithm     string             `json:"hash_algorithm,omitempty"`
	KeyAlgorithm      string             `json:"key_algorithm"`
	Verification      VerificationStatus `json:"verification"`
	VerificationError string             `json:"verification_error,omitempty"`
}
