package snap

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
)

type credentials struct {
	// PrivateKey is the PEM-encoded RSA private key string used for signing.
	privateKey string

	// clientKey is the SNAP BI client identifier.
	clientKey string

	// DomainAPI is the base domain of the SNAP BI API (sandbox or production).
	domainAPI string

	authCode string
}

func (c *credentials) generateSignature(stringToSign string) (string, error) {
	block, _ := pem.Decode([]byte(c.privateKey))
	if block == nil {
		return "", errors.New("failed to decode PEM block containing private key")
	}

	var rsaPrivateKey *rsa.PrivateKey
	switch block.Type {
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return "", fmt.Errorf("parse PKCS#8 private key: %w", err)
		}
		var ok bool
		if rsaPrivateKey, ok = key.(*rsa.PrivateKey); !ok {
			return "", errors.New("private key is not RSA")
		}
	case "RSA PRIVATE KEY":
		key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return "", fmt.Errorf("parse PKCS#1 private key: %w", err)
		}
		rsaPrivateKey = key
	default:
		return "", fmt.Errorf("unsupported private key type: %s", block.Type)
	}

	hash := sha256.Sum256([]byte(stringToSign))

	sig, err := rsa.SignPKCS1v15(rand.Reader, rsaPrivateKey, crypto.SHA256, hash[:])
	if err != nil {
		return "", fmt.Errorf("signing failed: %w", err)
	}

	return base64.StdEncoding.EncodeToString(sig), nil
}
