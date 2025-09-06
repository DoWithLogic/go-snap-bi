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
	"time"
)

type Client struct {
	PrivateKey string
	ClientID   string
}

func NewClient(privateKey, clientID string) (c *Client, err error) {
	client := &Client{
		PrivateKey: privateKey,
		ClientID:   clientID,
	}

	if _, err := client.generateSignature(); err != nil {
		return c, err
	}

	return client, nil
}

func (c *Client) generateSignature() (signature string, err error) {
	block, _ := pem.Decode([]byte(c.PrivateKey))
	if block == nil {
		return signature, errors.New("failed to decode PEM block containing private key")
	}

	var rsaPrivateKey *rsa.PrivateKey
	switch block.Type {
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return signature, fmt.Errorf("parse PKCS#8 private key: %w", err)
		}
		var ok bool
		if rsaPrivateKey, ok = key.(*rsa.PrivateKey); !ok {
			return signature, errors.New("private key is not RSA")
		}
	case "RSA PRIVATE KEY":
		key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return signature, fmt.Errorf("parse PKCS#1 private key: %w", err)
		}
		rsaPrivateKey = key
	default:
		return signature, fmt.Errorf("unsupported private key type: %s", block.Type)
	}

	payload := fmt.Sprintf("%s|%s", c.ClientID, time.Now().Format(time.RFC3339))
	hash := sha256.Sum256([]byte(payload))

	generatedSignature, err := rsa.SignPKCS1v15(rand.Reader, rsaPrivateKey, crypto.SHA256, hash[:])
	if err != nil {
		return signature, fmt.Errorf("signing failed: %w", err)
	}

	return base64.StdEncoding.EncodeToString(generatedSignature), nil
}
