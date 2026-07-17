package csr

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

func ParsePEM(input []byte) (*Info, error) {
	data := bytes.TrimSpace(input)

	if len(data) == 0 {
		return nil, ErrEmptyInput
	}

	/*
		Проверяем только общий PEM-заголовок.

		Не проверяем здесь конкретно CERTIFICATE REQUEST,
		потому что сначала хотим декодировать блок и узнать
		его настоящий тип: CERTIFICATE, PRIVATE KEY и т.д.
	*/
	if !bytes.HasPrefix(
		data,
		[]byte("-----BEGIN "),
	) {
		return nil, ErrInvalidPEM
	}

	block, rest := pem.Decode(data)
	if block == nil {
		return nil, ErrInvalidPEM
	}

	if block.Type != pemTypeCertificateRequest &&
		block.Type != pemTypeNewCertificateRequest {
		return nil, &UnsupportedPEMTypeError{
			Type: block.Type,
		}
	}

	if len(block.Headers) != 0 {
		return nil, ErrPEMHeaders
	}

	if len(bytes.TrimSpace(rest)) != 0 {
		return nil, ErrTrailingData
	}

	rawInfo, err := parseRawCSR(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf(
			"parse PKCS#10 structure: %w",
			err,
		)
	}

	subject, err := parseSubject(
		rawInfo.Request.Info.Subject.FullBytes,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"parse subject: %w",
			err,
		)
	}

	san, err := parseSANFromExtensions(
		rawInfo.Extensions,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"parse Subject Alternative Name: %w",
			err,
		)
	}

	attributes, err := parseAttributes(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf(
			"parse attributes: %w",
			err,
		)
	}

	info := &Info{
		PEMType: block.Type,
		Version: rawInfo.Request.Info.Version,

		Subject: subject,

		SubjectAlternativeNames: san,

		Attributes: attributes,
		Extensions: parseExtensions(
			rawInfo.Extensions,
		),
	}

	/*
		Алгоритм публичного ключа не поддерживается
		стандартным crypto/x509.
	*/
	if !supportedByStandardLibrary(
		rawInfo.PublicKeyIdentifier.Algorithm,
	) {
		if isGOSTPublicKeyAlgorithm(
			rawInfo.PublicKeyIdentifier.Algorithm,
		) {
			gostPublicKey, gostErr :=
				parseGOSTPublicKey(
					rawInfo.PublicKeyIdentifier,
					rawInfo.SubjectPublicKey,
					rawInfo.RawSubjectPublicKeyInfo,
				)

			if gostErr != nil {
				info.PublicKey =
					parseUnsupportedPublicKey(
						rawInfo.PublicKeyIdentifier,
					)

				info.PublicKey.FingerprintSHA256 =
					fingerprintSHA256(
						rawInfo.
							RawSubjectPublicKeyInfo,
					)

				info.Warnings = append(
					info.Warnings,
					fmt.Sprintf(
						"GOST public key details "+
							"could not be parsed: %v",
						gostErr,
					),
				)
			} else {
				info.PublicKey = gostPublicKey
			}
		} else {
			info.PublicKey =
				parseUnsupportedPublicKey(
					rawInfo.PublicKeyIdentifier,
				)

			info.PublicKey.FingerprintSHA256 =
				fingerprintSHA256(
					rawInfo.RawSubjectPublicKeyInfo,
				)
		}

		info.Signature = parseUnsupportedSignature(
			rawInfo.Request.SignatureAlgorithm,
		)

		info.Warnings = append(
			info.Warnings,
			"CSR fields were parsed, but the "+
				"self-signature was not verified",
		)

		return finalizeInfo(info), nil
	}

	request, err := x509.ParseCertificateRequest(
		block.Bytes,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"parse supported PKCS#10 request: %w",
			err,
		)
	}

	publicKey, err := parsePublicKey(
		request.PublicKey,
		rawInfo.PublicKeyIdentifier,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"parse public key: %w",
			err,
		)
	}

	publicKey.FingerprintSHA256 = fingerprintSHA256(
		rawInfo.RawSubjectPublicKeyInfo,
	)

	info.PublicKey = publicKey

	info.Signature = parseSignature(
		request,
		rawInfo.Request.SignatureAlgorithm,
	)

	return finalizeInfo(info), nil
}
