/*
Copyright 2020 The cert-manager Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package pki

import (
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	stdpem "encoding/pem"
	goerrors "errors"
	"fmt"
	"net"
	"net/url"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"

	"github.com/cert-manager/cert-manager/internal/pem"
	"github.com/cert-manager/cert-manager/pkg/util/errors"
)

var errNotMLDSACSR = goerrors.New("not an MLDSA65 CSR")

// DecodePrivateKeyBytes will decode a PEM encoded private key into a crypto.Signer.
// It supports ECDSA, RSA, EdDSA and ML-DSA-65 private keys. All other types will return err.
func DecodePrivateKeyBytes(keyBytes []byte) (crypto.Signer, error) {
	// decode the private key pem
	block, _, err := pem.SafeDecodePrivateKey(keyBytes)
	if err != nil {
		return nil, errors.NewInvalidData("error decoding private key PEM block: %s", err.Error())
	}

	switch block.Type {
	case "PRIVATE KEY":
		// Try standard PKCS8 parsing first (RSA, ECDSA, Ed25519)
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err == nil {
			signer, ok := key.(crypto.Signer)
			if !ok {
				return nil, errors.NewInvalidData("error parsing pkcs#8 private key: invalid key type")
			}
			return signer, nil
		}

		// If standard PKCS8 parsing fails, try ML-DSA-65
		// ML-DSA keys are stored as raw bytes from PrivateKey.Bytes()
		mldsaKey := new(mldsa65.PrivateKey)
		if unmarshalErr := mldsaKey.UnmarshalBinary(block.Bytes); unmarshalErr == nil {
			// Successfully parsed as ML-DSA key
			return mldsaKey, nil
		}

		// If both failed, return the original PKCS8 error
		return nil, errors.NewInvalidData("error parsing pkcs#8 private key: %s", err.Error())

	case "EC PRIVATE KEY":
		key, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, errors.NewInvalidData("error parsing ecdsa private key: %s", err.Error())
		}

		return key, nil
	case "RSA PRIVATE KEY":
		key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, errors.NewInvalidData("error parsing rsa private key: %s", err.Error())
		}

		err = key.Validate()
		if err != nil {
			return nil, errors.NewInvalidData("rsa private key failed validation: %s", err.Error())
		}
		return key, nil
	case "MLDSA65 PRIVATE KEY":
		// Handle ML-DSA keys that might be encoded with custom header
		key := new(mldsa65.PrivateKey)
		err := key.UnmarshalBinary(block.Bytes)
		if err != nil {
			return nil, errors.NewInvalidData("error parsing ML-DSA-65 private key: %s", err.Error())
		}
		return key, nil
	default:
		return nil, errors.NewInvalidData("unknown private key type: %s", block.Type)
	}
}

func decodeMultipleCerts(certBytes []byte, decodeFn func([]byte) (*stdpem.Block, []byte, error)) ([]*x509.Certificate, error) {
	certs := []*x509.Certificate{}

	var block *stdpem.Block

	for {
		var err error

		// decode the tls certificate pem
		block, certBytes, err = decodeFn(certBytes)
		if err != nil {
			if err == pem.ErrNoPEMData {
				break
			}

			return nil, err
		}

		// parse the tls certificate
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, errors.NewInvalidData("error parsing X.509 certificate: %s", err.Error())
		}

		certs = append(certs, cert)
	}

	if len(certs) == 0 {
		return nil, errors.NewInvalidData("error decoding certificate PEM block: no valid certificates found")
	}

	return certs, nil
}

// DecodeX509CertificateChainBytes will decode a PEM encoded x509 Certificate chain with a tight
// size limit to reduce the risk of DoS attacks. If you need to decode many certificates, use
// DecodeX509CertificateSetBytes instead.
func DecodeX509CertificateChainBytes(certBytes []byte) ([]*x509.Certificate, error) {
	return decodeMultipleCerts(certBytes, pem.SafeDecodeCertificateChain)
}

// DecodeX509CertificateSetBytes will decode a concatenated set of PEM encoded x509 Certificates,
// with generous size limits to enable parsing of TLS trust bundles.
// If you need to decode a single certificate chain, use DecodeX509CertificateChainBytes instead.
func DecodeX509CertificateSetBytes(certBytes []byte) ([]*x509.Certificate, error) {
	return decodeMultipleCerts(certBytes, pem.SafeDecodeCertificateBundle)
}

// DecodeX509CertificateBytes will decode a PEM encoded x509 Certificate.
func DecodeX509CertificateBytes(certBytes []byte) (*x509.Certificate, error) {
	certs, err := DecodeX509CertificateSetBytes(certBytes)
	if err != nil {
		return nil, err
	}

	return certs[0], nil
}

// DecodeX509CertificateRequestBytes will decode a PEM encoded x509 Certificate Request.
func DecodeX509CertificateRequestBytes(csrBytes []byte) (*x509.CertificateRequest, error) {
	block, _, err := pem.SafeDecodeCSR(csrBytes)
	if err != nil {
		return nil, errors.NewInvalidData("error decoding certificate request PEM block: %s", err)
	}

	// Attempt MLDSA-specific parsing first so we can capture MLDSA CSRs even if
	// the standard library parser accepts them with incomplete information.
	if mldsaCSR, mldsaErr := parseMLDSA65CSR(block.Bytes); mldsaErr == nil {
		return mldsaCSR, nil
	} else if !goerrors.Is(mldsaErr, errNotMLDSACSR) {
		return nil, mldsaErr
	}

	// Fallback to the standard parser for non-MLDSA CSRs.
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, err
	}

	return csr, nil
}

// parseMLDSA65CSR parses an MLDSA65 CSR into an x509.CertificateRequest structure
// This is needed because the standard Go x509 library doesn't support MLDSA65 yet
func parseMLDSA65CSR(csrDER []byte) (*x509.CertificateRequest, error) {
	// Define the CSR structure
	type publicKeyInfo struct {
		Raw       asn1.RawContent
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}

	type tbsCertificateRequest struct {
		Raw           asn1.RawContent
		Version       int
		Subject       asn1.RawValue
		PublicKey     publicKeyInfo
		RawAttributes []asn1.RawValue `asn1:"tag:0,optional"`
	}

	type certificateRequest struct {
		Raw                asn1.RawContent
		TBSCSR             asn1.RawValue
		SignatureAlgorithm pkix.AlgorithmIdentifier
		SignatureValue     asn1.BitString
	}

	// Parse the CSR
	var csr certificateRequest
	rest, err := asn1.Unmarshal(csrDER, &csr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse MLDSA65 CSR: %w", err)
	}
	if len(rest) > 0 {
		return nil, fmt.Errorf("trailing data after CSR")
	}

	// Check if it's an MLDSA65 CSR by checking the signature algorithm OID
	mldsaOID := asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 17} // ML-DSA-65 OID
	if !csr.SignatureAlgorithm.Algorithm.Equal(mldsaOID) {
		return nil, errNotMLDSACSR
	}

	// Parse the certificationRequestInfo portion
	if !csr.TBSCSR.IsCompound || csr.TBSCSR.Tag != asn1.TagSequence {
		return nil, fmt.Errorf("malformed certificationRequestInfo")
	}
	var info tbsCertificateRequest
	if rest, err := asn1.Unmarshal(csr.TBSCSR.FullBytes, &info); err != nil {
		return nil, fmt.Errorf("failed to parse MLDSA65 CSR: %w", err)
	} else if len(rest) != 0 {
		return nil, fmt.Errorf("trailing data after certificationRequestInfo")
	}

	// Parse the subject
	var subject pkix.RDNSequence
	if rest, err := asn1.Unmarshal(info.Subject.FullBytes, &subject); err != nil {
		return nil, fmt.Errorf("failed to parse subject: %w", err)
	} else if len(rest) != 0 {
		return nil, fmt.Errorf("trailing data after subject")
	}

	var subjectName pkix.Name
	subjectName.FillFromRDNSequence(&subject)

	// Parse the public key
	if !info.PublicKey.Algorithm.Algorithm.Equal(mldsaOID) {
		return nil, fmt.Errorf("public key algorithm doesn't match MLDSA65")
	}

	pubKeyBytes := info.PublicKey.PublicKey.RightAlign()
	pubKey := new(mldsa65.PublicKey)
	if err := pubKey.UnmarshalBinary(pubKeyBytes); err != nil {
		return nil, fmt.Errorf("failed to unmarshal MLDSA65 public key: %w", err)
	}

	// Parse extensions from attributes
	var extensions []pkix.Extension
	var dnsNames []string
	var emailAddresses []string
	var ipAddresses []net.IP
	var uris []*url.URL

	// Parse attributes to extract extensions
	for _, rawAttr := range info.RawAttributes {
		var attr struct {
			Type   asn1.ObjectIdentifier
			Values []asn1.RawValue `asn1:"set"`
		}

		if rest, err := asn1.Unmarshal(rawAttr.FullBytes, &attr); err != nil || len(rest) != 0 {
			continue
		}

		// Check for extensionRequest OID
		extensionRequestOID := asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 14}
		if attr.Type.Equal(extensionRequestOID) && len(attr.Values) > 0 {
			// Parse extensions
			var exts []pkix.Extension
			if _, err := asn1.Unmarshal(attr.Values[0].FullBytes, &exts); err == nil {
				extensions = exts

				// Extract SANs if present
				for _, ext := range extensions {
					if ext.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 17}) { // subjectAltName OID
						gns, err := UnmarshalSANs(ext.Value)
						if err == nil {
							dnsNames = append(dnsNames, gns.DNSNames...)
							emailAddresses = append(emailAddresses, gns.RFC822Names...)
							ipAddresses = append(ipAddresses, gns.IPAddresses...)
							// Convert URI strings to *url.URL
							for _, uriStr := range gns.UniformResourceIdentifiers {
								if u, err := url.Parse(uriStr); err == nil {
									uris = append(uris, u)
								}
							}
						}
					}
				}
			}
		}
	}

	// Create the x509.CertificateRequest
	return &x509.CertificateRequest{
		Raw:                      csrDER,
		RawTBSCertificateRequest: csr.TBSCSR.FullBytes,
		RawSubjectPublicKeyInfo:  info.PublicKey.Raw,
		RawSubject:               info.Subject.FullBytes,

		Version:            info.Version,
		Signature:          csr.SignatureValue.RightAlign(),
		SignatureAlgorithm: x509.UnknownSignatureAlgorithm, // MLDSA65 is not in standard x509

		PublicKeyAlgorithm: x509.UnknownPublicKeyAlgorithm, // MLDSA65 is not in standard x509
		PublicKey:          pubKey,

		Subject: subjectName,

		Extensions:     extensions,
		DNSNames:       dnsNames,
		EmailAddresses: emailAddresses,
		IPAddresses:    ipAddresses,
		URIs:           uris,
	}, nil
}
