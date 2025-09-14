package snap

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"

	"github.com/DoWithLogic/go-snap-bi/types"
)

// Client provides access to SNAP BI APIs such as VirtualAccount and Registration.
// It handles authentication, request signing, and API communication.
type Client struct {
	// VirtualAccount provides methods for virtual account operations.
	VirtualAccount *virtualAccount

	// Registration provides methods for customer registration operations.
	Registration *registration
}

// New initializes a new SNAP BI client with the provided configuration.
//
// Parameters:
//   - clientType: Determines whether the client operates in B2B or B2B2C mode
//   - privateKey: PEM-encoded RSA private key string used for request signing
//   - clientKey: SNAP BI client identifier provided by the platform
//   - domainAPI: Base URL for the SNAP BI API (sandbox or production environment)
//   - opts: Optional configuration using ClientOption functions
//
// Returns:
//   - *Client: Configured SNAP BI client instance
//   - error: Validation or initialization errors
//
// Example:
//
//	client, err := snap.New(types.B2B, privateKey, "client123", "https://api.snap.com", snap.WithPartnerID("partner123"))
func New(clientType types.ClientType, privateKey, clientKey, domainAPI string, opts ...ClientOption) (*Client, error) {
	cfg := clientConfig{
		clientType: clientType,
		privateKey: privateKey,
		clientKey:  clientKey,
		domainAPI:  domainAPI,
	}

	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}

	// Validate private key early to catch configuration issues
	if _, err := cfg.parseRSAPrivateKeyFromPEM(); err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	// B2B2C requires authCode for token acquisition
	if clientType.Is(types.B2B2C) && cfg.authCode == nil {
		return nil, errors.New("auth code is required for B2B2C token acquisition")
	}

	transporter, err := NewTransporter(&TransporterConfig{DomainAPI: domainAPI})
	if err != nil {
		return nil, fmt.Errorf("failed to create transporter: %w", err)
	}

	tokenManager := newTokenManager(cfg, transporter)

	return &Client{
		VirtualAccount: &virtualAccount{tm: tokenManager},
		Registration:   &registration{tm: tokenManager},
	}, nil
}

// clientConfig holds authentication and client-specific configuration for SNAP BI API access.
type clientConfig struct {
	// clientType determines if the client is B2B or B2B2C.
	clientType types.ClientType

	// privateKey is the PEM-encoded RSA private key string used for signing requests.
	privateKey string

	// clientKey is the SNAP BI client identifier provided by the platform.
	clientKey string

	// domainAPI is the base URL for the SNAP BI API (sandbox or production).
	domainAPI string

	// partnerID is the partner identifier (required for transaction APIs).
	partnerID *string

	// channelID is the channel identifier (required for transaction APIs).
	channelID *string

	// authCode is the authorization code (required for B2B2C token acquisition).
	authCode *string
}

// parseRSAPrivateKeyFromPEM parses RSA private keys from PEM format.
// Supports both PKCS#1 and PKCS#8 private key formats.
//
// Returns:
//   - *rsa.PrivateKey: Parsed RSA private key
//   - error: Parsing or format validation errors
func (c *clientConfig) parseRSAPrivateKeyFromPEM() (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(c.privateKey))
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the key")
	}

	switch block.Type {
	case "RSA PRIVATE KEY": // PKCS#1 format
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	case "PRIVATE KEY": // PKCS#8 format
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		if rsaKey, ok := key.(*rsa.PrivateKey); ok {
			return rsaKey, nil
		}
		return nil, errors.New("parsed PKCS8 key is not an RSA key")
	default:
		// Try PKCS#8 as a fallback for unknown block types
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err == nil {
			if rsaKey, ok := key.(*rsa.PrivateKey); ok {
				return rsaKey, nil
			}
		}
		return nil, fmt.Errorf("unsupported private key type: %s", block.Type)
	}
}

// GenerateNonTransactionSignature generates X-SIGNATURE for non-transaction APIs.
// The signature is computed as: Base64(RSA-SHA256(privateKey, clientKey|timestamp))
//
// Parameters:
//   - timestamp: Current timestamp string
//
// Returns:
//   - string: Base64-encoded signature
//   - error: Key parsing or signing errors
func (c *clientConfig) GenerateNonTransactionSignature(timestamp string) (string, error) {
	priv, err := c.parseRSAPrivateKeyFromPEM()
	if err != nil {
		return "", fmt.Errorf("failed to parse private key for signing: %w", err)
	}

	stringToSign := fmt.Sprintf("%s|%s", c.clientKey, timestamp)
	sigBytes, err := rsaSignSHA256(priv, []byte(stringToSign))
	if err != nil {
		return "", fmt.Errorf("failed to sign data: %w", err)
	}

	return base64.StdEncoding.EncodeToString(sigBytes), nil
}

// GenerateTransactionSignature generates X-SIGNATURE for SNAP transaction APIs.
// The signature is computed as: Base64(RSA-SHA256(privateKey, method:endpoint:bodyHash:timestamp))
//
// Parameters:
//   - method: HTTP method (GET, POST, etc.)
//   - endpoint: API endpoint path
//   - body: Request body bytes
//   - timestamp: Current timestamp string
//
// Returns:
//   - string: Base64-encoded signature
//   - error: Key parsing or signing errors
func (c *clientConfig) GenerateTransactionSignature(method, endpoint string, body []byte, timestamp string) (string, error) {
	minified := minifyRequestBody(body)
	bodyHashHex := sha256HexLower(minified)

	priv, err := c.parseRSAPrivateKeyFromPEM()
	if err != nil {
		return "", fmt.Errorf("failed to parse private key for signing: %w", err)
	}

	stringToSign := fmt.Sprintf("%s:%s:%s:%s", method, endpoint, bodyHashHex, timestamp)
	sigBytes, err := rsaSignSHA256(priv, []byte(stringToSign))
	if err != nil {
		return "", fmt.Errorf("failed to sign data: %w", err)
	}

	return base64.StdEncoding.EncodeToString(sigBytes), nil
}

// minifyRequestBody compacts JSON body by removing unnecessary whitespace.
// If the body is not valid JSON, it trims whitespace from the string.
// Returns empty byte slice if no body content is provided.
func minifyRequestBody(requestBody []byte) []byte {
	if len(requestBody) == 0 {
		return []byte{}
	}

	var b bytes.Buffer
	if json.Valid(requestBody) {
		if err := json.Compact(&b, requestBody); err == nil {
			return b.Bytes()
		}
	}
	return []byte(strings.TrimSpace(string(requestBody)))
}

// rsaSignSHA256 signs data using RSA with SHA-256 hashing (PKCS#1 v1.5 padding).
//
// Parameters:
//   - priv: RSA private key
//   - data: Data to be signed
//
// Returns:
//   - []byte: Signature bytes
//   - error: Signing errors
func rsaSignSHA256(priv *rsa.PrivateKey, data []byte) ([]byte, error) {
	h := sha256.Sum256(data)
	return rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, h[:])
}

// sha256HexLower computes SHA-256 hash and returns lowercase hex-encoded digest.
func sha256HexLower(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

// ClientOption defines a function type for configuring clientConfig options.
type ClientOption func(*clientConfig)

// WithPartnerID sets the partner ID used in transaction APIs.
//
// Parameters:
//   - partnerID: Partner identifier provided by SNAP BI
func WithPartnerID(partnerID string) ClientOption {
	return func(cc *clientConfig) { cc.partnerID = &partnerID }
}

// WithChannelID sets the channel ID used in transaction APIs.
//
// Parameters:
//   - channelID: Channel identifier provided by SNAP BI
func WithChannelID(channelID string) ClientOption {
	return func(cc *clientConfig) { cc.channelID = &channelID }
}

// WithAuthCode sets the authorization code required for B2B2C token acquisition.
//
// Parameters:
//   - authCode: Authorization code obtained from SNAP BI OAuth flow
func WithAuthCode(authCode string) ClientOption {
	return func(cc *clientConfig) { cc.authCode = &authCode }
}

/*
B2B
// non transaction
*X-TIMESTAMP: 2020-01-01T00:00:00+07:00
*X-CLIENT-KEY: 962489e9-de5d-4eb7-92a4-b07d44d64bf4
*X-SIGNATURE: 07abc7c30d245c0ecce3ef6c2a9ac76cd9ffaf6d0d090773b429c2b97437dc72047f46d9890abb2d6d8af7594ea19787e79ec80e388e2f6225b449c2e4d82e7df50f37c301424aede785935703c1c70235ba4e59f589f571218ce2dce4c061e598f0f38d1ac57f3feb52cf0c31078e3ceee8d796c53983fe1d38ebd71155aaa613700dc21f5a57941b787f921af7d287e72687d5242eb3063d543d5f5923f76db008cf4f56fb9c618f7f4bc8366ae70d88705617487754563e629119013fa0549e6645b397524b3dd2fa7e7f3fe9faf0fbf77da59f566861a3c510241fd4416ab7d0eba42d998e1178da51d607e0ef866607c458837c762323be53827d86e875
*Content-Type: application/json

// transaction
*Content-type: application/json
**Authorization: Bearer gp9HjjEj813Y9JGoqwOeOPWbnt4CUpvIJbU1mMU4a11MNDZ7Sg5u9a"
*X-TIMESTAMP: 2020-12-17T10:55:00+07:00
*X-SIGNATURE: 85be817c55b2c135157c7e89f52499bf0c25ad6eeebe04a986e8c862561b19a5
ORIGIN: www.hostname.com
*X-PARTNER-ID: 82150823919040624621823174737537
*X-EXTERNAL-ID: 41807553358950093184162180797837
*CHANNEL-ID: 95221


b2b2c
// non transaction
*X-TIMESTAMP: 2020-01-01T00:00:00+07:00
*X-CLIENT-KEY: 962489e9-de5d-4eb7-92a4-b07d44d64bf4
*X-SIGNATURE: 07abc7c30d245c0ecce3ef6c2a9ac76cd9ffaf6d0d090773b429c2b97437dc72047f46d9890abb2d6d8af7594ea19787e79ec80e388e2f6225b449c2e4d82e7df50f37c301424aede785935703c1c70235ba4e59f589f571218ce2dce4c061e598f0f38d1ac57f3feb52cf0c31078e3ceee8d796c53983fe1d38ebd71155aaa613700dc21f5a57941b787f921af7d287e72687d5242eb3063d543d5f5923f76db008cf4f56fb9c618f7f4bc8366ae70d88705617487754563e629119013fa0549e6645b397524b3dd2fa7e7f3fe9faf0fbf77da59f566861a3c510241fd4416ab7d0eba42d998e1178da51d607e0ef866607c458837c762323be53827d86e875
*Content-Type: application/json

// transaction
*Content-type: application/json
*Authorization: Bearer gp9HjjEj813Y9JGoqwOeOPWbnt4CUpvIJbU1mMU4a11MNDZ7Sg5u9a"
*Authorization-Customer: Bearer fa8sjjEj813Y9JGoqwOeOPWbnt4CUpvIJbU1mMU4a11MNDZ7Sg5u9a"
*X-TIMESTAMP: 2020-12-23T09:10:11+07:00
*X-SIGNATURE: 85be817c55b2c135157c7e89f52499bf0c25ad6eeebe04a986e8c862561b19a5
ORIGIN: www.hostname.com
*X-PARTNER-ID: 82150823919040624621823174737537
*X-EXTERNAL-ID: 41807553358950093184162180797837
X-IP-ADDRESS: 172.24.281.24
*X-DEVICE-ID: 09864ADCASA
*CHANNEL-ID: 95221
X-LATITUDE: -6.108841
X-LONGITUDE: 106.7782137
*/
