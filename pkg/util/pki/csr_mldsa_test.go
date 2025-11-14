/*
Copyright 2024 The cert-manager Authors.

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
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"net"
	"os"
	"testing"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

func TestEncodeMLDSA65CSR(t *testing.T) {
	// Generate ML-DSA-65 key pair
	pubKey, privKey, err := mldsa65.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ML-DSA-65 key pair: %v", err)
	}

	// Create a CSR template
	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			Country:            []string{"US"},
			Province:           []string{"California"},
			Locality:           []string{"San Francisco"},
			Organization:       []string{"Test Organization"},
			OrganizationalUnit: []string{"Engineering"},
			CommonName:         "test.example.com",
		},
		DNSNames:    []string{"test.example.com", "localhost", "*.example.com"},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		EmailAddresses: []string{"test@example.com"},
	}

	// Generate the CSR using our function
	csrBytes, err := encodeMLDSA65CSR(template, privKey)
	if err != nil {
		t.Fatalf("Failed to encode ML-DSA-65 CSR: %v", err)
	}

	// Verify the CSR structure
	t.Run("VerifyCSRStructure", func(t *testing.T) {
		// Parse the CSR to verify its structure
		var csr struct {
			CertificationRequestInfo asn1.RawValue
			SignatureAlgorithm       pkix.AlgorithmIdentifier
			Signature                asn1.BitString
		}
		
		rest, err := asn1.Unmarshal(csrBytes, &csr)
		if err != nil {
			t.Fatalf("Failed to unmarshal CSR: %v", err)
		}
		if len(rest) != 0 {
			t.Fatalf("Unexpected trailing data in CSR")
		}

		// Verify signature algorithm OID
		expectedOID := asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 18}
		if !csr.SignatureAlgorithm.Algorithm.Equal(expectedOID) {
			t.Fatalf("Expected ML-DSA-65 OID %v, got %v", expectedOID, csr.SignatureAlgorithm.Algorithm)
		}

		// Verify the signature
		if !mldsa65.Verify(pubKey, csr.CertificationRequestInfo.FullBytes, nil, csr.Signature.Bytes) {
			t.Fatalf("CSR signature verification failed")
		}

		t.Logf("✅ CSR structure is valid and signature verified")
	})

	// Save the CSR to a file for manual verification with OpenSSL
	t.Run("SaveCSRForOpenSSL", func(t *testing.T) {
		csrFile, err := os.Create("mldsa65_test.csr")
		if err != nil {
			t.Skipf("Could not create test CSR file: %v", err)
			return
		}
		defer csrFile.Close()

		err = pem.Encode(csrFile, &pem.Block{
			Type:  "CERTIFICATE REQUEST",
			Bytes: csrBytes,
		})
		if err != nil {
			t.Fatalf("Failed to encode CSR to PEM: %v", err)
		}

		t.Logf("✅ Saved test CSR to mldsa65_test.csr")
		t.Logf("   You can verify it with: openssl req -text -noout -in mldsa65_test.csr")
	})

	// Verify CSR info can be parsed
	t.Run("ParseCSRInfo", func(t *testing.T) {
		var csrInfo struct {
			Version    int
			Subject    asn1.RawValue
			PublicKey  asn1.RawValue
			Attributes []asn1.RawValue `asn1:"tag:0"`
		}

		// Get the CertificationRequestInfo from the CSR
		var csr struct {
			CertificationRequestInfo asn1.RawValue
			SignatureAlgorithm       pkix.AlgorithmIdentifier
			Signature                asn1.BitString
		}
		_, err := asn1.Unmarshal(csrBytes, &csr)
		if err != nil {
			t.Fatalf("Failed to unmarshal CSR: %v", err)
		}

		// Parse CertificationRequestInfo
		_, err = asn1.Unmarshal(csr.CertificationRequestInfo.FullBytes, &csrInfo)
		if err != nil {
			t.Fatalf("Failed to unmarshal CertificationRequestInfo: %v", err)
		}

		if csrInfo.Version != 0 {
			t.Fatalf("Expected CSR version 0, got %d", csrInfo.Version)
		}

		// Parse and verify subject
		var subject pkix.RDNSequence
		_, err = asn1.Unmarshal(csrInfo.Subject.FullBytes, &subject)
		if err != nil {
			t.Fatalf("Failed to unmarshal subject: %v", err)
		}

		name := pkix.Name{}
		name.FillFromRDNSequence(&subject)
		if name.CommonName != "test.example.com" {
			t.Fatalf("Expected CommonName 'test.example.com', got '%s'", name.CommonName)
		}

		// Verify attributes were included
		if len(csrInfo.Attributes) == 0 {
			t.Fatalf("Expected attributes in CSR, got none")
		}

		t.Logf("✅ CSR info parsed successfully")
		t.Logf("   Subject CN: %s", name.CommonName)
		t.Logf("   Attributes count: %d", len(csrInfo.Attributes))
	})
}

// TestMLDSA65CSRWithNoExtensions tests CSR generation without any extensions
func TestMLDSA65CSRWithNoExtensions(t *testing.T) {
	// Generate ML-DSA-65 key pair
	_, privKey, err := mldsa65.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ML-DSA-65 key pair: %v", err)
	}

	// Create a minimal CSR template
	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: "minimal.example.com",
		},
	}

	// Generate the CSR
	csrBytes, err := encodeMLDSA65CSR(template, privKey)
	if err != nil {
		t.Fatalf("Failed to encode minimal ML-DSA-65 CSR: %v", err)
	}

	// Verify the CSR structure
	var csr struct {
		CertificationRequestInfo asn1.RawValue
		SignatureAlgorithm       pkix.AlgorithmIdentifier
		Signature                asn1.BitString
	}
	
	_, err = asn1.Unmarshal(csrBytes, &csr)
	if err != nil {
		t.Fatalf("Failed to unmarshal minimal CSR: %v", err)
	}

	t.Logf("✅ Minimal CSR generated successfully")
}