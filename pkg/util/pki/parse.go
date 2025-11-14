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

	"github.com/cert-manager/cert-manager/internal/pem"
	"github.com/cert-manager/cert-manager/pkg/util/errors"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

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

		// If standard PKCS8 parsing fails, try to parse as ML-DSA-65
		// ML-DSA keys are encoded in PKCS#8 format with OID 2.16.840.1.101.3.4.3.18
		mldsaKey, mldsaErr := parseMLDSAPKCS8PrivateKey(block.Bytes)
		if mldsaErr == nil {
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
	default:
		return nil, errors.NewInvalidData("unknown private key type: %s", block.Type)
	}
}

// parseMLDSAPKCS8PrivateKey parses a PKCS#8 encoded ML-DSA-65 private key.
// The PKCS#8 structure contains the ML-DSA OID and the raw private key bytes.
func parseMLDSAPKCS8PrivateKey(pkcs8Bytes []byte) (*mldsa65.PrivateKey, error) {
	// Parse the PKCS#8 structure
	var pkcs8 struct {
		Version    int
		Algo       pkix.AlgorithmIdentifier
		PrivateKey []byte
	}

	_, err := asn1.Unmarshal(pkcs8Bytes, &pkcs8)
	if err != nil {
		return nil, err
	}

	// Check if this is an ML-DSA-65 key (OID: 2.16.840.1.101.3.4.3.18)
	mldsaOID := asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 18}
	if !pkcs8.Algo.Algorithm.Equal(mldsaOID) {
		return nil, errors.NewInvalidData("not an ML-DSA-65 private key")
	}

	// Create ML-DSA key from the raw bytes
	key := new(mldsa65.PrivateKey)
	err = key.UnmarshalBinary(pkcs8.PrivateKey)
	if err != nil {
		return nil, err
	}

	return key, nil
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

	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, err
	}

	return csr, nil
}
