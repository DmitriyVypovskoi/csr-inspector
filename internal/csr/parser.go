package csr

import (
	"bytes"
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"net"
	"strings"
)

var (
	ErrEmptyInput         = errors.New("CSR input is empty")
	ErrInvalidPEM         = errors.New("input is not a valid PEM encoded CSR")
	ErrUnsupportedPEMType = errors.New("unsupported PEM block type")
	ErrPEMHeaders         = errors.New("PEM headers are not allowed")
	ErrTrailingData       = errors.New("unexpected data after CSR PEM block")
)

const (
	pemTypeCertificateRequest = "CERTIFICATE REQUEST"

	pemTypeNewCertificateRequest = "NEW CERTIFICATE REQUEST"
)

var oidExtensionRequest = asn1.ObjectIdentifier{
	1, 2, 840, 113549, 1, 9, 14,
}

type rawCSRInfo struct {
	Request                 rawCertificationRequest
	PublicKeyIdentifier     pkix.AlgorithmIdentifier
	SubjectPublicKey        asn1.BitString
	RawSubjectPublicKeyInfo []byte
	Extensions              []pkix.Extension
}

type rawCertificationRequest struct {
	Info               rawCertificationRequestInfo
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Signature          asn1.BitString
}

type rawCertificationRequestInfo struct {
	Version              int
	Subject              asn1.RawValue
	SubjectPublicKeyInfo asn1.RawValue
	Attributes           asn1.RawValue `asn1:"tag:0"`
}

type signatureAlgorithmDescription struct {
	DisplayName   string
	HashAlgorithm string
	KeyAlgorithm  string
}

type rawSubjectPublicKeyInfo struct {
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}

type rawAttribute struct {
	Type   asn1.ObjectIdentifier
	Values []asn1.RawValue `asn1:"set"`
}

var oidSubjectAlternativeName = asn1.ObjectIdentifier{
	2, 5, 29, 17,
}

var publicKeyAlgorithmDisplayNames = map[string]string{
	"1.2.840.113549.1.1.1": "rsaEncryption",
	"1.2.840.10045.2.1":    "id-ecPublicKey",
	"1.2.840.10040.4.1":    "dsaEncryption",
	"1.3.101.112":          "ED25519",
	"1.3.101.110":          "X25519",
}

var gostParameterSetNames = map[string]string{
	// ГОСТ Р 34.10-2001
	"1.2.643.2.2.35.0": "GOST R 34.10-2001 Test ParamSet",
	"1.2.643.2.2.35.1": "GOST R 34.10-2001 CryptoPro A",
	"1.2.643.2.2.35.2": "GOST R 34.10-2001 CryptoPro B",
	"1.2.643.2.2.35.3": "GOST R 34.10-2001 CryptoPro C",
	"1.2.643.2.2.36.0": "GOST R 34.10-2001 CryptoPro XchA",
	"1.2.643.2.2.36.1": "GOST R 34.10-2001 CryptoPro XchB",

	// ГОСТ Р 34.10-2012, 256 бит
	"1.2.643.7.1.2.1.1.1": "TC26 GOST 3410-2012 256 ParamSet A",
	"1.2.643.7.1.2.1.1.2": "TC26 GOST 3410-2012 256 ParamSet B",
	"1.2.643.7.1.2.1.1.3": "TC26 GOST 3410-2012 256 ParamSet C",
	"1.2.643.7.1.2.1.1.4": "TC26 GOST 3410-2012 256 ParamSet D",

	// ГОСТ Р 34.10-2012, 512 бит
	"1.2.643.7.1.2.1.2.0": "TC26 GOST 3410-2012 512 Test ParamSet",
	"1.2.643.7.1.2.1.2.1": "TC26 GOST 3410-2012 512 ParamSet A",
	"1.2.643.7.1.2.1.2.2": "TC26 GOST 3410-2012 512 ParamSet B",
	"1.2.643.7.1.2.1.2.3": "TC26 GOST 3410-2012 512 ParamSet C",
}

var gostDigestNames = map[string]string{
	"1.2.643.2.2.30.1":  "GOST R 34.11-94 CryptoPro",
	"1.2.643.7.1.1.2.2": "GOST R 34.11-2012-256",
	"1.2.643.7.1.1.2.3": "GOST R 34.11-2012-512",
}

var gostEncryptionParameterSetNames = map[string]string{
	"1.2.643.2.2.31.0": "GOST 28147-89 Test ParamSet",
	"1.2.643.2.2.31.1": "GOST 28147-89 CryptoPro A",
	"1.2.643.2.2.31.2": "GOST 28147-89 CryptoPro B",
	"1.2.643.2.2.31.3": "GOST 28147-89 CryptoPro C",
	"1.2.643.2.2.31.4": "GOST 28147-89 CryptoPro D",
}

const (
	oidGOST2001PublicKey    = "1.2.643.2.2.19"
	oidGOST2012PublicKey256 = "1.2.643.7.1.1.1.1"
	oidGOST2012PublicKey512 = "1.2.643.7.1.1.1.2"
)

type gostPublicKeyParameters struct {
	PublicKeyParamSet  asn1.ObjectIdentifier
	DigestParamSet     asn1.ObjectIdentifier `asn1:"optional"`
	EncryptionParamSet asn1.ObjectIdentifier `asn1:"optional"`
}

func publicKeyAlgorithmDisplayName(
	oid asn1.ObjectIdentifier,
) string {
	oidString := oid.String()

	if name, ok := publicKeyAlgorithmDisplayNames[oidString]; ok {
		return name
	}

	/*
		Не теряем информацию о неизвестном алгоритме:
		в display_name вернётся хотя бы его OID.
	*/
	return oidString
}

func supportedByStandardLibrary(
	oid asn1.ObjectIdentifier,
) bool {
	switch oid.String() {
	case
		"1.2.840.113549.1.1.1", // RSA
		"1.2.840.10040.4.1",    // DSA
		"1.2.840.10045.2.1",    // EC
		"1.3.101.112":          // Ed25519
		return true

	default:
		return false
	}
}

func parseRawCSR(
	der []byte,
) (rawCSRInfo, error) {
	var request rawCertificationRequest

	rest, err := asn1.Unmarshal(der, &request)
	if err != nil {
		return rawCSRInfo{},
			fmt.Errorf("decode PKCS#10 request: %w", err)
	}

	if len(rest) != 0 {
		return rawCSRInfo{},
			errors.New("trailing ASN.1 data after CSR")
	}

	var publicKeyInfo rawSubjectPublicKeyInfo

	rest, err = asn1.Unmarshal(
		request.Info.SubjectPublicKeyInfo.FullBytes,
		&publicKeyInfo,
	)
	if err != nil {
		return rawCSRInfo{},
			fmt.Errorf(
				"decode SubjectPublicKeyInfo: %w",
				err,
			)
	}

	if len(rest) != 0 {
		return rawCSRInfo{},
			errors.New(
				"trailing ASN.1 data after SubjectPublicKeyInfo",
			)
	}

	extensions, err := parseRequestedExtensions(
		request.Info.Attributes,
	)
	if err != nil {
		return rawCSRInfo{}, err
	}

	return rawCSRInfo{
		Request:             request,
		PublicKeyIdentifier: publicKeyInfo.Algorithm,
		SubjectPublicKey:    publicKeyInfo.PublicKey,
		RawSubjectPublicKeyInfo: bytes.Clone(
			request.Info.SubjectPublicKeyInfo.FullBytes,
		),

		Extensions: extensions,
	}, nil
}

func parseUnsupportedPublicKey(
	identifier pkix.AlgorithmIdentifier,
) PublicKeyInfo {
	oid := identifier.Algorithm.String()

	info := PublicKeyInfo{
		Algorithm:    "Unknown",
		AlgorithmOID: oid,
		DisplayName:  oid,
	}

	switch oid {
	case "1.2.643.7.1.1.1.1":
		info.Algorithm = "GOST"
		info.DisplayName = "GOST R 34.10-2012-256"
		info.Bits = 256

	case "1.2.643.7.1.1.1.2":
		info.Algorithm = "GOST"
		info.DisplayName = "GOST R 34.10-2012-512"
		info.Bits = 512

	case "1.2.643.2.2.19":
		info.Algorithm = "GOST"
		info.DisplayName = "GOST R 34.10-2001"
		info.Bits = 256
	}

	return info
}

func parseUnsupportedSignature(
	identifier pkix.AlgorithmIdentifier,
) SignatureInfo {
	oid := identifier.Algorithm.String()

	result := SignatureInfo{
		Algorithm:         "Unknown",
		AlgorithmOID:      oid,
		DisplayName:       oid,
		KeyAlgorithm:      "Unknown",
		Verification:      VerificationUnsupported,
		VerificationError: "signature verification is not implemented for this algorithm",
	}

	switch oid {
	case "1.2.643.7.1.1.3.2":
		result.Algorithm = "GOST2012-256"
		result.DisplayName = "GOST R 34.10-2012-256"
		result.HashAlgorithm = "GOST R 34.11-2012-256"
		result.KeyAlgorithm = "GOST R 34.10-2012-256"

	case "1.2.643.7.1.1.3.3":
		result.Algorithm = "GOST2012-512"
		result.DisplayName = "GOST R 34.10-2012-512"
		result.HashAlgorithm = "GOST R 34.11-2012-512"
		result.KeyAlgorithm = "GOST R 34.10-2012-512"

	case "1.2.643.2.2.3":
		result.Algorithm = "GOST2001"
		result.DisplayName = "GOST R 34.10-2001"
		result.HashAlgorithm = "GOST R 34.11-94"
		result.KeyAlgorithm = "GOST R 34.10-2001"
	}

	return result
}

func parseRequestedExtensions(
	attributes asn1.RawValue,
) ([]pkix.Extension, error) {
	data := attributes.Bytes
	result := make([]pkix.Extension, 0)

	for len(data) != 0 {
		var attribute rawAttribute

		rest, err := asn1.Unmarshal(data, &attribute)
		if err != nil {
			return nil, fmt.Errorf(
				"decode CSR attribute: %w",
				err,
			)
		}

		data = rest

		if !attribute.Type.Equal(oidExtensionRequest) {
			continue
		}

		for _, value := range attribute.Values {
			var extensions []pkix.Extension

			rest, err := asn1.Unmarshal(
				value.FullBytes,
				&extensions,
			)
			if err != nil {
				return nil, fmt.Errorf(
					"decode extensionRequest: %w",
					err,
				)
			}

			if len(rest) != 0 {
				return nil, errors.New(
					"trailing ASN.1 data in extensionRequest",
				)
			}

			result = append(result, extensions...)
		}
	}

	return result, nil
}

func parseSANFromExtensions(
	extensions []pkix.Extension,
) (SubjectAlternativeNames, error) {
	result := SubjectAlternativeNames{
		DNSNames:       []string{},
		EmailAddresses: []string{},
		IPAddresses:    []string{},
		URIs:           []string{},
	}

	for _, extension := range extensions {
		if !extension.Id.Equal(
			oidSubjectAlternativeName,
		) {
			continue
		}

		var generalNames []asn1.RawValue

		rest, err := asn1.Unmarshal(
			extension.Value,
			&generalNames,
		)
		if err != nil {
			return SubjectAlternativeNames{},
				fmt.Errorf(
					"decode Subject Alternative Name: %w",
					err,
				)
		}

		if len(rest) != 0 {
			return SubjectAlternativeNames{},
				errors.New(
					"trailing ASN.1 data in Subject Alternative Name",
				)
		}

		for _, name := range generalNames {
			if name.Class != asn1.ClassContextSpecific {
				return SubjectAlternativeNames{},
					fmt.Errorf(
						"unexpected GeneralName class %d",
						name.Class,
					)
			}

			switch name.Tag {
			case 1:
				// rfc822Name
				result.EmailAddresses = append(
					result.EmailAddresses,
					string(name.Bytes),
				)

			case 2:
				// dNSName
				result.DNSNames = append(
					result.DNSNames,
					string(name.Bytes),
				)

			case 6:
				// uniformResourceIdentifier
				result.URIs = append(
					result.URIs,
					string(name.Bytes),
				)

			case 7:
				// iPAddress
				if len(name.Bytes) != net.IPv4len &&
					len(name.Bytes) != net.IPv6len {
					return SubjectAlternativeNames{},
						fmt.Errorf(
							"invalid SAN IP address length: %d",
							len(name.Bytes),
						)
				}

				result.IPAddresses = append(
					result.IPAddresses,
					net.IP(name.Bytes).String(),
				)

			default:
				/*
					Пока пропускаем:
					- otherName;
					- x400Address;
					- directoryName;
					- ediPartyName;
					- registeredID.

					Позже добавим отдельную модель для них.
				*/
			}
		}
	}

	return result, nil
}

func parseSubject(
	raw []byte,
) (DistinguishedName, error) {
	var sequence pkix.RDNSequence

	rest, err := asn1.Unmarshal(raw, &sequence)
	if err != nil {
		return DistinguishedName{},
			fmt.Errorf("decode subject: %w", err)
	}

	if len(rest) != 0 {
		return DistinguishedName{},
			errors.New("trailing ASN.1 data in subject")
	}

	var name pkix.Name
	name.FillFromRDNSequence(&sequence)

	result := DistinguishedName{
		String: name.String(),
		RDNs: make(
			[]RelativeDistinguishedName,
			0,
			len(sequence),
		),
	}

	for _, set := range sequence {
		attributes := make(
			[]NameAttribute,
			0,
			len(set),
		)

		for _, item := range set {
			value := formatASN1Value(item.Value)

			attributes = append(
				attributes,
				NameAttribute{
					OID:   item.Type.String(),
					Name:  oidName(item.Type),
					Value: value,
				},
			)

			if item.Type.Equal(
				asn1.ObjectIdentifier{2, 5, 4, 3},
			) && result.CommonName == "" {
				result.CommonName = value
			}
		}

		result.RDNs = append(
			result.RDNs,
			RelativeDistinguishedName{
				Attributes: attributes,
			},
		)
	}

	return result, nil
}

func parsePublicKey(
	publicKey any,
	identifier pkix.AlgorithmIdentifier,
) (PublicKeyInfo, error) {
	algorithmOID := identifier.Algorithm.String()
	displayName := publicKeyAlgorithmDisplayName(
		identifier.Algorithm,
	)

	switch key := publicKey.(type) {
	case *rsa.PublicKey:
		return PublicKeyInfo{
			Algorithm:    "RSA",
			AlgorithmOID: algorithmOID,
			DisplayName:  displayName,
			Bits:         key.N.BitLen(),
			RSA: &RSAKeyInfo{
				Exponent:   key.E,
				ModulusHex: formatHex(key.N.Bytes()),
			},
		}, nil

	case *ecdsa.PublicKey:
		publicPoint := elliptic.Marshal(
			key.Curve,
			key.X,
			key.Y,
		)

		return PublicKeyInfo{
			Algorithm:    "ECDSA",
			AlgorithmOID: algorithmOID,
			DisplayName:  displayName,
			Bits:         key.Curve.Params().BitSize,
			ECDSA: &ECDSAKeyInfo{
				Curve:          key.Curve.Params().Name,
				PublicPointHex: formatHex(publicPoint),
			},
		}, nil

	case ed25519.PublicKey:
		return PublicKeyInfo{
			Algorithm:    "Ed25519",
			AlgorithmOID: algorithmOID,
			DisplayName:  displayName,
			Bits:         len(key) * 8,
			Ed25519: &Ed25519KeyInfo{
				PublicKeyHex: formatHex(key),
			},
		}, nil

	case *dsa.PublicKey:
		return PublicKeyInfo{
			Algorithm:    "DSA",
			AlgorithmOID: algorithmOID,
			DisplayName:  displayName,
			Bits:         key.Parameters.P.BitLen(),
			DSA: &DSAKeyInfo{
				PHex: formatBigInt(key.Parameters.P),
				QHex: formatBigInt(key.Parameters.Q),
				GHex: formatBigInt(key.Parameters.G),
				YHex: formatBigInt(key.Y),
			},
		}, nil

	default:
		return PublicKeyInfo{}, fmt.Errorf(
			"unsupported public key type %T",
			publicKey,
		)
	}
}

func parseExtensions(
	extensions []pkix.Extension,
) []ExtensionInfo {
	result := make(
		[]ExtensionInfo,
		0,
		len(extensions),
	)

	for _, extension := range extensions {
		info := ExtensionInfo{
			OID:      extension.Id.String(),
			Name:     oidName(extension.Id),
			Critical: extension.Critical,
		}

		/*
			Известный SAN уже представлен в структурированном виде.
			Raw hex оставляем только для пока неизвестных расширений.
		*/
		if !extension.Id.Equal(
			oidSubjectAlternativeName,
		) {
			info.ValueHex = formatHex(extension.Value)
		}

		result = append(result, info)
	}

	return result
}

func parseSignature(
	request *x509.CertificateRequest,
	identifier pkix.AlgorithmIdentifier,
) SignatureInfo {
	description := describeSignatureAlgorithm(
		request.SignatureAlgorithm,
	)

	result := SignatureInfo{
		Algorithm:     request.SignatureAlgorithm.String(),
		AlgorithmOID:  identifier.Algorithm.String(),
		DisplayName:   description.DisplayName,
		HashAlgorithm: description.HashAlgorithm,
		KeyAlgorithm:  description.KeyAlgorithm,
	}

	/*
		Современные версии Go отказываются выполнять
		RSA-проверку с ключами меньше 1024 бит.

		Это не означает, что подпись математически неверна:
		проверка вообще не выполнялась. Поэтому не вызываем
		CheckSignature и не возвращаем статус invalid.
	*/
	if publicKey, ok := request.PublicKey.(*rsa.PublicKey); ok {
		if publicKey.N != nil {
			keyBits := publicKey.N.BitLen()

			if keyBits < 1024 {
				result.Verification = VerificationUnsupported
				result.VerificationError = fmt.Sprintf(
					"Self-signature verification was skipped "+
						"because the CSR uses an insecure "+
						"%d-bit RSA key.",
					keyBits,
				)

				return result
			}
		}
	}

	err := request.CheckSignature()

	var insecureAlgorithmError x509.InsecureAlgorithmError

	switch {
	case err == nil:
		result.Verification = VerificationValid

	case errors.Is(err, x509.ErrUnsupportedAlgorithm):
		/*
			Алгоритм не поддерживается стандартной
			библиотекой Go. Подпись не признана неверной —
			она просто не была проверена.
		*/
		result.Verification = VerificationUnsupported
		result.VerificationError =
			"Self-signature verification is not supported " +
				"for this algorithm."

	case errors.As(err, &insecureAlgorithmError):
		/*
			Go отказался проверять подпись из-за небезопасного
			алгоритма, например MD5.
		*/
		result.Verification = VerificationUnsupported
		result.VerificationError =
			"Self-signature verification was skipped because " +
				"the CSR uses an insecure signature algorithm."

	default:
		/*
			В этом случае алгоритм поддерживается и проверка
			действительно была выполнена, но подпись не совпала.

			Внутренний err.Error() в API не отдаём.
		*/
		result.Verification = VerificationInvalid
		result.VerificationError =
			"The CSR self-signature is mathematically invalid."
	}

	return result
}

func parseAttributes(
	der []byte,
) ([]AttributeInfo, error) {
	var request rawCertificationRequest

	rest, err := asn1.Unmarshal(der, &request)
	if err != nil {
		return nil, err
	}

	if len(rest) != 0 {
		return nil,
			errors.New("trailing ASN.1 data after CSR")
	}

	data := request.Info.Attributes.Bytes

	result := make([]AttributeInfo, 0)

	for len(data) != 0 {
		var attribute rawAttribute

		data, err = asn1.Unmarshal(data, &attribute)
		if err != nil {
			return nil, err
		}

		/*
				OpenSSL отображает extensionRequest не как обычный attribute,
				а в отдельной секции Requested Extensions.

				У нас extensions уже доступны через request.Extensions.
			Поэтому здесь extensionRequest пропускаем.
		*/
		if attribute.Type.Equal(oidExtensionRequest) {
			continue
		}

		item := AttributeInfo{
			OID:       attribute.Type.String(),
			Name:      oidName(attribute.Type),
			Values:    make([]string, 0, len(attribute.Values)),
			RawValues: make([]string, 0, len(attribute.Values)),
		}

		for _, value := range attribute.Values {
			if decoded, ok := decodeString(value); ok {
				item.Values = append(
					item.Values,
					decoded,
				)
			}

			item.RawValues = append(
				item.RawValues,
				formatHex(value.FullBytes),
			)
		}

		result = append(result, item)
	}

	return result, nil
}

func decodeString(
	value asn1.RawValue,
) (string, bool) {
	switch value.Tag {
	case asn1.TagUTF8String,
		asn1.TagPrintableString,
		asn1.TagT61String,
		asn1.TagIA5String,
		asn1.TagGeneralString,
		asn1.TagBMPString,
		asn1.TagNumericString:

		var decoded string

		rest, err := asn1.Unmarshal(
			value.FullBytes,
			&decoded,
		)

		return decoded, err == nil && len(rest) == 0

	default:
		return "", false
	}
}

func formatASN1Value(value any) string {
	switch typed := value.(type) {
	case string:
		return typed

	case []byte:
		return formatHex(typed)

	default:
		return fmt.Sprint(typed)
	}
}

func formatBigInt(value *big.Int) string {
	if value == nil {
		return ""
	}

	return formatHex(value.Bytes())
}

func formatHex(data []byte) string {
	if len(data) == 0 {
		return ""
	}

	encoded := strings.ToUpper(
		hex.EncodeToString(data),
	)

	var result strings.Builder

	result.Grow(
		len(encoded) + len(data) - 1,
	)

	for index := 0; index < len(encoded); index += 2 {
		if index != 0 {
			result.WriteByte(':')
		}

		result.WriteString(
			encoded[index : index+2],
		)
	}

	return result.String()
}

func oidName(oid asn1.ObjectIdentifier) string {
	if name, ok := oidNames[oid.String()]; ok {
		return name
	}

	return "Unknown"
}

var oidNames = map[string]string{
	"2.5.4.3":  "Common Name",
	"2.5.4.4":  "Surname",
	"2.5.4.5":  "Serial Number",
	"2.5.4.6":  "Country",
	"2.5.4.7":  "Locality",
	"2.5.4.8":  "State or Province",
	"2.5.4.10": "Organization",
	"2.5.4.11": "Organizational Unit",
	"2.5.4.42": "Given Name",
	"2.5.4.46": "DN Qualifier",

	"1.2.840.113549.1.9.1":  "Email Address",
	"1.2.840.113549.1.9.7":  "Challenge Password",
	"1.2.840.113549.1.9.14": "Extension Request",

	"0.9.2342.19200300.100.1.1":  "User ID",
	"0.9.2342.19200300.100.1.25": "Domain Component",

	"2.5.29.14": "Subject Key Identifier",
	"2.5.29.15": "Key Usage",
	"2.5.29.17": "Subject Alternative Name",
	"2.5.29.19": "Basic Constraints",
	"2.5.29.37": "Extended Key Usage",
}

func describeSignatureAlgorithm(
	algorithm x509.SignatureAlgorithm,
) signatureAlgorithmDescription {
	switch algorithm {
	case x509.MD2WithRSA:
		return signatureAlgorithmDescription{
			DisplayName:   "md2WithRSAEncryption",
			HashAlgorithm: "MD2",
			KeyAlgorithm:  "RSA",
		}

	case x509.MD5WithRSA:
		return signatureAlgorithmDescription{
			DisplayName:   "md5WithRSAEncryption",
			HashAlgorithm: "MD5",
			KeyAlgorithm:  "RSA",
		}

	case x509.SHA1WithRSA:
		return signatureAlgorithmDescription{
			DisplayName:   "sha1WithRSAEncryption",
			HashAlgorithm: "SHA-1",
			KeyAlgorithm:  "RSA",
		}

	case x509.SHA256WithRSA:
		return signatureAlgorithmDescription{
			DisplayName:   "sha256WithRSAEncryption",
			HashAlgorithm: "SHA-256",
			KeyAlgorithm:  "RSA",
		}

	case x509.SHA384WithRSA:
		return signatureAlgorithmDescription{
			DisplayName:   "sha384WithRSAEncryption",
			HashAlgorithm: "SHA-384",
			KeyAlgorithm:  "RSA",
		}

	case x509.SHA512WithRSA:
		return signatureAlgorithmDescription{
			DisplayName:   "sha512WithRSAEncryption",
			HashAlgorithm: "SHA-512",
			KeyAlgorithm:  "RSA",
		}

	case x509.SHA256WithRSAPSS:
		return signatureAlgorithmDescription{
			DisplayName:   "rsassaPss",
			HashAlgorithm: "SHA-256",
			KeyAlgorithm:  "RSA-PSS",
		}

	case x509.SHA384WithRSAPSS:
		return signatureAlgorithmDescription{
			DisplayName:   "rsassaPss",
			HashAlgorithm: "SHA-384",
			KeyAlgorithm:  "RSA-PSS",
		}

	case x509.SHA512WithRSAPSS:
		return signatureAlgorithmDescription{
			DisplayName:   "rsassaPss",
			HashAlgorithm: "SHA-512",
			KeyAlgorithm:  "RSA-PSS",
		}

	case x509.DSAWithSHA1:
		return signatureAlgorithmDescription{
			DisplayName:   "dsaWithSHA1",
			HashAlgorithm: "SHA-1",
			KeyAlgorithm:  "DSA",
		}

	case x509.DSAWithSHA256:
		return signatureAlgorithmDescription{
			DisplayName:   "dsa_with_SHA256",
			HashAlgorithm: "SHA-256",
			KeyAlgorithm:  "DSA",
		}

	case x509.ECDSAWithSHA1:
		return signatureAlgorithmDescription{
			DisplayName:   "ecdsa-with-SHA1",
			HashAlgorithm: "SHA-1",
			KeyAlgorithm:  "ECDSA",
		}

	case x509.ECDSAWithSHA256:
		return signatureAlgorithmDescription{
			DisplayName:   "ecdsa-with-SHA256",
			HashAlgorithm: "SHA-256",
			KeyAlgorithm:  "ECDSA",
		}

	case x509.ECDSAWithSHA384:
		return signatureAlgorithmDescription{
			DisplayName:   "ecdsa-with-SHA384",
			HashAlgorithm: "SHA-384",
			KeyAlgorithm:  "ECDSA",
		}

	case x509.ECDSAWithSHA512:
		return signatureAlgorithmDescription{
			DisplayName:   "ecdsa-with-SHA512",
			HashAlgorithm: "SHA-512",
			KeyAlgorithm:  "ECDSA",
		}

	case x509.PureEd25519:
		return signatureAlgorithmDescription{
			DisplayName:  "ED25519",
			KeyAlgorithm: "Ed25519",
		}

	default:
		return signatureAlgorithmDescription{
			DisplayName:  algorithm.String(),
			KeyAlgorithm: "Unknown",
		}
	}
}

func parseGOSTPublicKey(
	identifier pkix.AlgorithmIdentifier,
	publicKey asn1.BitString,
	rawSubjectPublicKeyInfo []byte,
) (PublicKeyInfo, error) {
	algorithmOID := identifier.Algorithm.String()

	result := PublicKeyInfo{
		Algorithm:    "GOST",
		AlgorithmOID: algorithmOID,
		FingerprintSHA256: fingerprintSHA256(
			rawSubjectPublicKeyInfo,
		),
	}

	expectedKeySize := 0

	switch algorithmOID {
	case oidGOST2001PublicKey:
		result.DisplayName = "GOST R 34.10-2001"
		result.Bits = 256
		expectedKeySize = 64

	case oidGOST2012PublicKey256:
		result.DisplayName = "GOST R 34.10-2012-256"
		result.Bits = 256
		expectedKeySize = 64

	case oidGOST2012PublicKey512:
		result.DisplayName = "GOST R 34.10-2012-512"
		result.Bits = 512
		expectedKeySize = 128

	default:
		return PublicKeyInfo{}, fmt.Errorf(
			"unsupported GOST public key algorithm OID %s",
			algorithmOID,
		)
	}

	/*
		Проверяем, что публичный ключ действительно содержит
		корректный OCTET STRING ожидаемой длины.
	*/
	_, err := decodeGOSTPublicKey(
		publicKey,
		expectedKeySize,
	)
	if err != nil {
		return PublicKeyInfo{}, err
	}

	parameters, err := parseGOSTPublicKeyParameters(
		identifier.Parameters,
	)
	if err != nil {
		return PublicKeyInfo{}, err
	}

	gostInfo := &GOSTKeyInfo{}

	switch algorithmOID {
	case oidGOST2001PublicKey:
		gostInfo.Version = "2001"

	case oidGOST2012PublicKey256,
		oidGOST2012PublicKey512:
		gostInfo.Version = "2012"
	}

	if len(parameters.PublicKeyParamSet) != 0 {
		gostInfo.ParameterSetOID =
			parameters.PublicKeyParamSet.String()

		gostInfo.ParameterSetName = oidNameOrValue(
			parameters.PublicKeyParamSet,
			gostParameterSetNames,
		)
	}

	if len(parameters.DigestParamSet) != 0 {
		gostInfo.DigestOID =
			parameters.DigestParamSet.String()

		gostInfo.DigestName = oidNameOrValue(
			parameters.DigestParamSet,
			gostDigestNames,
		)
	}

	if len(parameters.EncryptionParamSet) != 0 {
		gostInfo.EncryptionParameterSetOID =
			parameters.EncryptionParamSet.String()

		gostInfo.EncryptionParameterSetName =
			oidNameOrValue(
				parameters.EncryptionParamSet,
				gostEncryptionParameterSetNames,
			)
	}

	/*
		Некоторые корректные ГОСТ 2012 структуры не содержат
		digestParamSet. В таком случае алгоритм хеширования
		можно определить по размеру ключа.
	*/
	if gostInfo.DigestOID == "" {
		switch algorithmOID {
		case oidGOST2012PublicKey256:
			gostInfo.DigestOID = "1.2.643.7.1.1.2.2"
			gostInfo.DigestName =
				"GOST R 34.11-2012-256"

		case oidGOST2012PublicKey512:
			gostInfo.DigestOID = "1.2.643.7.1.1.2.3"
			gostInfo.DigestName =
				"GOST R 34.11-2012-512"
		}
	}

	result.GOST = gostInfo

	return result, nil
}

func isGOSTPublicKeyAlgorithm(
	oid asn1.ObjectIdentifier,
) bool {
	switch oid.String() {
	case oidGOST2001PublicKey,
		oidGOST2012PublicKey256,
		oidGOST2012PublicKey512:
		return true

	default:
		return false
	}
}

func oidNameOrValue(
	oid asn1.ObjectIdentifier,
	names map[string]string,
) string {
	if len(oid) == 0 {
		return ""
	}

	oidString := oid.String()

	if name, ok := names[oidString]; ok {
		return name
	}

	return oidString
}

func parseGOSTPublicKeyParameters(
	raw asn1.RawValue,
) (gostPublicKeyParameters, error) {
	if len(raw.FullBytes) == 0 {
		return gostPublicKeyParameters{}, nil
	}

	/*
		ГОСТ 2001 допускает отсутствие parameters или NULL.
	*/
	if raw.Class == asn1.ClassUniversal &&
		raw.Tag == asn1.TagNull {
		return gostPublicKeyParameters{}, nil
	}

	var parameters gostPublicKeyParameters

	rest, err := asn1.Unmarshal(
		raw.FullBytes,
		&parameters,
	)
	if err != nil {
		return gostPublicKeyParameters{},
			fmt.Errorf(
				"decode GOST public key parameters: %w",
				err,
			)
	}

	if len(rest) != 0 {
		return gostPublicKeyParameters{},
			errors.New(
				"trailing ASN.1 data after GOST public key parameters",
			)
	}

	if len(parameters.PublicKeyParamSet) == 0 {
		return gostPublicKeyParameters{},
			errors.New("GOST public key parameter set is missing")
	}

	return parameters, nil
}

func decodeGOSTPublicKey(
	publicKey asn1.BitString,
	expectedSize int,
) ([]byte, error) {
	if publicKey.BitLength != len(publicKey.Bytes)*8 {
		return nil, errors.New(
			"GOST public key contains unused bits",
		)
	}

	var keyBytes []byte

	rest, err := asn1.Unmarshal(
		publicKey.Bytes,
		&keyBytes,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"decode GOST public key OCTET STRING: %w",
			err,
		)
	}

	if len(rest) != 0 {
		return nil, errors.New(
			"trailing ASN.1 data after GOST public key",
		)
	}

	if len(keyBytes) != expectedSize {
		return nil, fmt.Errorf(
			"invalid GOST public key size: got %d bytes, want %d",
			len(keyBytes),
			expectedSize,
		)
	}

	return keyBytes, nil
}

func fingerprintSHA256(der []byte) string {
	sum := sha256.Sum256(der)

	return formatHex(sum[:])
}
