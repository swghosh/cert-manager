package pki

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"testing"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
)

func TestCertificateTemplateFromCertificateRequest_MLDSA(t *testing.T) {
	key, err := GenerateMLDSA65PrivateKey()
	if err != nil {
		t.Fatalf("failed to generate MLDSA private key: %v", err)
	}

	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: "example.com",
		},
		DNSNames: []string{"example.com"},
	}

	derBytes, err := EncodeCSR(template, key)
	if err != nil {
		t.Fatalf("failed to encode MLDSA CSR: %v", err)
	}

	parsed, err := parseMLDSA65CSR(derBytes)
	if err != nil {
		t.Fatalf("failed to parse raw MLDSA CSR DER: %v", err)
	}
	if parsed.PublicKey == nil {
		t.Fatalf("parsed CSR has nil public key")
	}

	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: derBytes})

	decoded, err := DecodeX509CertificateRequestBytes(csrPEM)
	if err != nil {
		t.Fatalf("failed to decode MLDSA CSR: %v", err)
	}
	if decoded.SignatureAlgorithm != x509.UnknownSignatureAlgorithm {
		t.Fatalf("expected unknown signature algorithm, got %v", decoded.SignatureAlgorithm)
	}
	if _, ok := decoded.PublicKey.(*mldsa65.PublicKey); !ok {
		t.Fatalf("unexpected public key type: %T", decoded.PublicKey)
	}

	cr := &cmapi.CertificateRequest{}
	cr.Spec.Request = csrPEM

	if _, err := CertificateTemplateFromCertificateRequest(cr); err != nil {
		t.Fatalf("failed to build certificate template from MLDSA CSR: %v", err)
	}
}
