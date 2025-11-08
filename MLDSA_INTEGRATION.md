# ML-DSA-65 Integration in cert-manager

This document describes the ML-DSA-65 (Module-Lattice-Based Digital Signature Algorithm) integration into cert-manager, providing post-quantum cryptographic signature support alongside existing RSA, ECDSA, and Ed25519 algorithms.

## Overview

ML-DSA-65 is a post-quantum signature scheme standardized by NIST in FIPS 204. This integration uses the Cloudflare CIRCL library implementation.

## Changes Made

### 1. Dependencies
- Added `github.com/cloudflare/circl` package for ML-DSA implementation

### 2. API Types

#### Private Key Algorithm
Added `MLDSA65` as a new private key algorithm option in:
- `internal/apis/certmanager/types_certificate.go`
- `pkg/apis/certmanager/v1/types_certificate.go`

#### Signature Algorithm
Added `PureMLDSA65` as a new signature algorithm option in:
- `internal/apis/certmanager/types.go`
- `pkg/apis/certmanager/v1/types_certificate.go`

### 3. Key Generation
Updated `pkg/util/pki/generate.go` to support:
- `GenerateMLDSA65PrivateKey()` - generates ML-DSA-65 key pairs
- `EncodeMLDSA65PrivateKey()` - encodes ML-DSA keys in PEM format
- Updated `GeneratePrivateKeyForCertificate()` to handle MLDSA65 algorithm
- Updated `EncodePrivateKey()` to support ML-DSA keys
- Updated `PublicKeyForPrivateKey()` and `PublicKeysEqual()` for ML-DSA support

### 4. Validation
Updated `internal/apis/certmanager/validation/certificate.go`:
- Added MLDSA65 to the key algorithm validation
- Mapped PureMLDSA65 signature algorithm to MLDSA65 key algorithm
- No key size validation needed for ML-DSA-65 (fixed size)

### 5. CRD Manifests
Updated enum values in:
- `deploy/crds/cert-manager.io_certificates.yaml`
- `deploy/charts/cert-manager/templates/crd-cert-manager.io_certificates.yaml`

## Usage Example

### Creating a Certificate with ML-DSA-65

```yaml
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: example-mldsa-cert
  namespace: default
spec:
  secretName: example-mldsa-tls
  commonName: example.com
  dnsNames:
    - example.com
    - www.example.com
  privateKey:
    algorithm: MLDSA65
    encoding: PKCS8  # ML-DSA keys use PKCS8 encoding
  signatureAlgorithm: PureMLDSA65
  issuerRef:
    name: my-issuer
    kind: Issuer
```

### Programmatic Usage

```go
package main

import (
    v1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
    "github.com/cert-manager/cert-manager/pkg/util/pki"
)

func main() {
    // Create a certificate spec with ML-DSA
    cert := &v1.Certificate{
        Spec: v1.CertificateSpec{
            PrivateKey: &v1.CertificatePrivateKey{
                Algorithm: v1.MLDSA65KeyAlgorithm,
                Encoding:  v1.PKCS8,
            },
            SignatureAlgorithm: v1.PureMLDSA65,
        },
    }

    // Generate the private key
    key, err := pki.GeneratePrivateKeyForCertificate(cert)
    if err != nil {
        panic(err)
    }

    // Encode the private key
    keyPEM, err := pki.EncodePrivateKey(key, v1.PKCS8)
    if err != nil {
        panic(err)
    }

    // keyPEM now contains the PEM-encoded ML-DSA-65 private key
}
```

## Features

### Supported Operations
- ✅ Key generation
- ✅ Private key encoding (PKCS8 format)
- ✅ Public key extraction
- ✅ Signing operations (via crypto.Signer interface)
- ✅ Key comparison/equality checks
- ✅ Certificate request (CSR) generation

### Key Characteristics
- **Algorithm**: ML-DSA-65 (NIST FIPS 204)
- **Security Level**: NIST Level 3 (equivalent to AES-192)
- **Public Key Size**: Fixed (part of the ML-DSA-65 specification)
- **Private Key Size**: Fixed (part of the ML-DSA-65 specification)
- **Signature Size**: ~3,293 bytes
- **Post-Quantum Security**: Yes - resistant to quantum computer attacks

## Testing

Tests are included in `pkg/util/pki/mldsa_test.go`:

```bash
# Run ML-DSA tests
go test -v ./pkg/util/pki -run "TestGenerate.*MLDSA65|TestEncode.*MLDSA65|TestPublic.*MLDSA65"
```

All tests verify:
- Key generation
- Signing operations
- Encoding/decoding
- Public key extraction
- Key equality comparisons

## Implementation Notes

### Integration with crypto.Signer
The Cloudflare CIRCL library's ML-DSA-65 types (`mldsa65.PrivateKey` and `mldsa65.PublicKey`) natively implement the Go `crypto.Signer` and `crypto.PublicKey` interfaces, allowing seamless integration with existing cert-manager code.

### Signing Requirements
When using ML-DSA for signing:
- The `opts` parameter to `Sign()` must be `crypto.Hash(0)`
- ML-DSA signs messages directly (not hashes)
- The random reader parameter is ignored (deterministic signing)

### Key Encoding
ML-DSA private keys are encoded in PEM format with:
- Header: `-----BEGIN PRIVATE KEY-----`
- Body: Raw key bytes from `PrivateKey.Bytes()`
- Footer: `-----END PRIVATE KEY-----`

## Compatibility

- **Go Version**: Requires Go 1.25.0 or later
- **Kubernetes**: Compatible with all cert-manager supported versions
- **cert-manager**: Compatible with v1.x API

## Security Considerations

1. **Post-Quantum Readiness**: ML-DSA-65 provides protection against quantum computer attacks
2. **Hybrid Mode**: Consider using hybrid certificates (classical + post-quantum) during the transition period
3. **Key Storage**: ML-DSA keys are larger than classical keys; ensure adequate storage
4. **Signature Size**: ML-DSA signatures are significantly larger (~3KB vs ~100 bytes for ECDSA)

## References

- [NIST FIPS 204 - ML-DSA Standard](https://csrc.nist.gov/pubs/fips/204/final)
- [Cloudflare CIRCL Library](https://github.com/cloudflare/circl)
- [cert-manager Documentation](https://cert-manager.io/docs/)

## Future Work

Potential enhancements:
- Support for other ML-DSA variants (ML-DSA-44, ML-DSA-87)
- Hybrid certificate support (RSA/ECDSA + ML-DSA)
- ML-KEM (post-quantum key encapsulation) integration

