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
	"encoding/pem"
	"net"
	"testing"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

// TestParseMLDSACertificateRequest tests parsing of ML-DSA certificate requests
func TestParseMLDSACertificateRequest(t *testing.T) {
	// Generate ML-DSA-65 key pair
	_, privKey, err := mldsa65.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ML-DSA-65 key pair: %v", err)
	}

	// Create a CSR template with various fields
	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			Country:            []string{"US"},
			Province:           []string{"California"},
			Locality:           []string{"San Francisco"},
			Organization:       []string{"Test Organization"},
			OrganizationalUnit: []string{"Engineering"},
			CommonName:         "test.example.com",
		},
		DNSNames:       []string{"test.example.com", "localhost", "*.example.com"},
		IPAddresses:    []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		EmailAddresses: []string{"test@example.com"},
	}

	// Generate the CSR using our ML-DSA encoding function
	csrBytes, err := encodeMLDSA65CSR(template, privKey)
	if err != nil {
		t.Fatalf("Failed to encode ML-DSA-65 CSR: %v", err)
	}

	// Encode to PEM
	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrBytes,
	})

	// Test parsing the CSR
	t.Run("ParseMLDSACSR", func(t *testing.T) {
		parsedCSR, err := DecodeX509CertificateRequestBytes(csrPEM)
		if err != nil {
			t.Fatalf("Failed to parse ML-DSA CSR: %v", err)
		}

		// Verify the parsed CSR fields
		if parsedCSR.Subject.CommonName != "test.example.com" {
			t.Errorf("Expected CommonName 'test.example.com', got '%s'", parsedCSR.Subject.CommonName)
		}

		if len(parsedCSR.DNSNames) != 3 {
			t.Errorf("Expected 3 DNS names, got %d", len(parsedCSR.DNSNames))
		}

		if len(parsedCSR.IPAddresses) != 2 {
			t.Errorf("Expected 2 IP addresses, got %d", len(parsedCSR.IPAddresses))
		}

		if len(parsedCSR.EmailAddresses) != 1 {
			t.Errorf("Expected 1 email address, got %d", len(parsedCSR.EmailAddresses))
		}

		// Verify the public key type
		if _, ok := parsedCSR.PublicKey.(*mldsa65.PublicKey); !ok {
			t.Errorf("Expected ML-DSA public key, got %T", parsedCSR.PublicKey)
		}

		t.Logf("✅ Successfully parsed ML-DSA CSR with all fields intact")
	})

	// Test signature verification
	t.Run("VerifyMLDSASignature", func(t *testing.T) {
		parsedCSR, err := DecodeX509CertificateRequestBytes(csrPEM)
		if err != nil {
			t.Fatalf("Failed to parse ML-DSA CSR: %v", err)
		}

		// Verify the signature using our custom CheckCSRSignature function
		err = CheckCSRSignature(parsedCSR)
		if err != nil {
			t.Fatalf("ML-DSA CSR signature verification failed: %v", err)
		}

		t.Logf("✅ ML-DSA CSR signature verified successfully")
	})

	// Test certificate template creation from CSR
	t.Run("CreateTemplateFromMLDSACSR", func(t *testing.T) {
		template, err := CertificateTemplateFromCSRPEM(csrPEM)
		if err != nil {
			t.Fatalf("Failed to create certificate template from ML-DSA CSR: %v", err)
		}

		// Verify template fields
		if template.Subject.CommonName != "test.example.com" {
			t.Errorf("Expected template CommonName 'test.example.com', got '%s'", template.Subject.CommonName)
		}

		if len(template.DNSNames) != 3 {
			t.Errorf("Expected 3 DNS names in template, got %d", len(template.DNSNames))
		}

		// Verify the public key was preserved
		if _, ok := template.PublicKey.(*mldsa65.PublicKey); !ok {
			t.Errorf("Expected ML-DSA public key in template, got %T", template.PublicKey)
		}

		t.Logf("✅ Successfully created certificate template from ML-DSA CSR")
	})
}

// TestMLDSASelfSignedCertificate tests creating a self-signed certificate with ML-DSA
func TestMLDSASelfSignedCertificate(t *testing.T) {
	// Generate ML-DSA-65 key pair
	pubKey, privKey, err := mldsa65.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ML-DSA-65 key pair: %v", err)
	}

	// Create a CSR
	csrTemplate := &x509.CertificateRequest{
		Subject: pkix.Name{
			Country:      []string{"US"},
			Organization: []string{"Test Org"},
			CommonName:   "selfsigned.example.com",
		},
		DNSNames: []string{"selfsigned.example.com"},
	}

	// Generate the CSR
	csrBytes, err := encodeMLDSA65CSR(csrTemplate, privKey)
	if err != nil {
		t.Fatalf("Failed to encode ML-DSA-65 CSR: %v", err)
	}

	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrBytes,
	})

	// Parse the CSR and create a certificate template
	parsedCSR, err := DecodeX509CertificateRequestBytes(csrPEM)
	if err != nil {
		t.Fatalf("Failed to parse ML-DSA CSR: %v", err)
	}

	certTemplate, err := CertificateTemplateFromCSRPEM(csrPEM)
	if err != nil {
		t.Fatalf("Failed to create certificate template: %v", err)
	}

	// Test public key extraction and comparison
	t.Run("PublicKeyOperations", func(t *testing.T) {
		// Test PublicKeyForPrivateKey
		extractedPubKey, err := PublicKeyForPrivateKey(privKey)
		if err != nil {
			t.Fatalf("Failed to extract public key from private key: %v", err)
		}

		mldsaPubKey, ok := extractedPubKey.(*mldsa65.PublicKey)
		if !ok {
			t.Fatalf("Expected ML-DSA public key, got %T", extractedPubKey)
		}

		// Test PublicKeysEqual
		equal, err := PublicKeysEqual(pubKey, mldsaPubKey)
		if err != nil {
			t.Fatalf("Failed to compare public keys: %v", err)
		}
		if !equal {
			t.Errorf("Public keys should be equal")
		}

		// Test comparing with CSR's public key
		equal, err = PublicKeysEqual(parsedCSR.PublicKey, extractedPubKey)
		if err != nil {
			t.Fatalf("Failed to compare CSR public key: %v", err)
		}
		if !equal {
			t.Errorf("CSR public key should match private key's public key")
		}

		t.Logf("✅ Public key operations work correctly with ML-DSA")
	})

	// Test self-signed certificate creation
	t.Run("CreateSelfSignedCertificate", func(t *testing.T) {
		// Sign the certificate (self-signed)
		certPEM, cert, err := SignCertificate(certTemplate, certTemplate, pubKey, privKey)
		if err != nil {
			t.Fatalf("Failed to sign ML-DSA certificate: %v", err)
		}

		if cert == nil {
			t.Fatalf("Certificate is nil")
		}

		if len(certPEM) == 0 {
			t.Fatalf("Certificate PEM is empty")
		}

		// Verify the certificate subject
		if cert.Subject.CommonName != "selfsigned.example.com" {
			t.Errorf("Expected CommonName 'selfsigned.example.com', got '%s'", cert.Subject.CommonName)
		}

		// Since it's self-signed, issuer should equal subject
		if cert.Issuer.CommonName != cert.Subject.CommonName {
			t.Errorf("Self-signed cert should have issuer == subject")
		}

		t.Logf("✅ Successfully created self-signed ML-DSA certificate")
		t.Logf("   Certificate CN: %s", cert.Subject.CommonName)
		t.Logf("   Serial Number: %s", cert.SerialNumber)
	})
}

// TestMLDSACSRWithMinimalFields tests parsing ML-DSA CSR with minimal fields
func TestMLDSACSRWithMinimalFields(t *testing.T) {
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

	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrBytes,
	})

	// Parse the minimal CSR
	parsedCSR, err := DecodeX509CertificateRequestBytes(csrPEM)
	if err != nil {
		t.Fatalf("Failed to parse minimal ML-DSA CSR: %v", err)
	}

	// Verify the parsed fields
	if parsedCSR.Subject.CommonName != "minimal.example.com" {
		t.Errorf("Expected CommonName 'minimal.example.com', got '%s'", parsedCSR.Subject.CommonName)
	}

	// Verify signature
	err = CheckCSRSignature(parsedCSR)
	if err != nil {
		t.Fatalf("Minimal ML-DSA CSR signature verification failed: %v", err)
	}

	t.Logf("✅ Minimal ML-DSA CSR parsed and verified successfully")
}
