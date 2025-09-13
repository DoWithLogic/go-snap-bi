package snap

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/DoWithLogic/snap/helpers"
	"github.com/DoWithLogic/snap/types"
)

// TokenType represents the type of SNAP BI token.
type TokenType int

const (
	TokenTypeB2B TokenType = iota
	TokenTypeB2B2C
)

// String returns string representation of TokenType for better debugging
func (tt TokenType) String() string {
	switch tt {
	case TokenTypeB2B:
		return "B2B"
	case TokenTypeB2B2C:
		return "B2B2C"
	default:
		return "Unknown"
	}
}

// IsValid checks if the token type is supported
func (tt TokenType) IsValid() bool {
	return tt == TokenTypeB2B || tt == TokenTypeB2B2C
}

// Token holds the raw token values and expiry info.
// Made public for better library usage but with clear documentation
type Token struct {
	AccessToken string
	TokenType   string
	ExpiresAt   time.Time

	// Only for B2B2C tokens
	RefreshToken string
	RefreshAt    time.Time
}

// IsExpired checks if the access token has expired
func (t *Token) IsExpired() bool {
	return time.Now().After(t.ExpiresAt)
}

// IsRefreshExpired checks if the refresh token has expired (B2B2C only)
func (t *Token) IsRefreshExpired() bool {
	return time.Now().After(t.RefreshAt)
}

// CanRefresh determines if the token can be refreshed
func (t *Token) CanRefresh() bool {
	return t.RefreshToken != "" && !t.IsRefreshExpired()
}

// TimeToExpiry returns duration until token expires
func (t *Token) TimeToExpiry() time.Duration {
	return time.Until(t.ExpiresAt)
}

// TokenManagerConfig holds configuration for TokenManager
type TokenManagerConfig struct {
	PrivateKey string
	ClientKey  string
	AuthCode   string // Required for B2B2C

	// Optional: Custom refresh buffer (default: 5 minutes before expiry)
	RefreshBuffer time.Duration
}

// Validate ensures the config has required fields
func (c *TokenManagerConfig) Validate() error {
	if c.PrivateKey == "" {
		return errors.New("private key is required")
	}
	if c.ClientKey == "" {
		return errors.New("client key is required")
	}
	if c.RefreshBuffer <= 0 {
		c.RefreshBuffer = 5 * time.Minute // Default buffer
	}
	return nil
}

// TokenProvider interface for dependency injection and testing
type TokenProvider interface {
	B2B(ctx context.Context, request *AccessTokenRequest) (*Token, error)
	B2B2C(ctx context.Context, request *AccessTokenB2B2CRequest) (*Token, error)
}

// TokenManager manages SNAP BI tokens with thread-safe operations
type TokenManager struct {
	mu sync.RWMutex

	tokens   map[TokenType]*Token
	provider TokenProvider
	creds    credentials
	config   TokenManagerConfig
}

// NewTokenManager creates a new token manager instance
func NewTokenManager(config TokenManagerConfig, transporter Transporter) (*TokenManager, error) {
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	creds := credentials{
		privateKey: config.PrivateKey,
		clientKey:  config.ClientKey,
		authCode:   config.AuthCode,
	}

	return &TokenManager{
		config:   config,
		creds:    creds,
		tokens:   make(map[TokenType]*Token),
		provider: newTokenProvider(creds, transporter),
	}, nil
}

// NewTokenManagerWithProvider creates a token manager with custom provider (useful for testing)
func NewTokenManagerWithProvider(config TokenManagerConfig, provider TokenProvider) (*TokenManager, error) {
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	creds := credentials{
		privateKey: config.PrivateKey,
		clientKey:  config.ClientKey,
		authCode:   config.AuthCode,
	}

	return &TokenManager{
		config:   config,
		creds:    creds,
		tokens:   make(map[TokenType]*Token),
		provider: provider,
	}, nil
}

// GetToken returns a valid token for the given type, refreshing if necessary
func (m *TokenManager) GetToken(ctx context.Context, tokenType TokenType) (string, error) {
	if !tokenType.IsValid() {
		return "", fmt.Errorf("unsupported token type: %v", tokenType)
	}

	// Try to get existing valid token
	if token := m.getValidToken(tokenType); token != nil {
		return token.AccessToken, nil
	}

	// Refresh or acquire new token
	return m.refreshToken(ctx, tokenType)
}

// GetTokenInfo returns the full token information (useful for debugging/monitoring)
func (m *TokenManager) GetTokenInfo(tokenType TokenType) (*Token, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	token, exists := m.tokens[tokenType]
	if !exists {
		return nil, false
	}

	// Return a copy to prevent external modification
	tokenCopy := *token
	return &tokenCopy, true
}

// InvalidateToken removes a token from the cache (useful for error handling)
func (m *TokenManager) InvalidateToken(tokenType TokenType) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.tokens, tokenType)
}

// InvalidateAllTokens removes all cached tokens
func (m *TokenManager) InvalidateAllTokens() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tokens = make(map[TokenType]*Token)
}

// getValidToken safely retrieves a valid token if it exists
func (m *TokenManager) getValidToken(tokenType TokenType) *Token {
	m.mu.RLock()
	defer m.mu.RUnlock()

	token, exists := m.tokens[tokenType]
	if !exists {
		return nil
	}

	// Check if token needs refresh (with buffer)
	if time.Now().Add(m.config.RefreshBuffer).After(token.ExpiresAt) {
		return nil
	}

	return token
}

// refreshToken handles the token refresh/acquisition logic
func (m *TokenManager) refreshToken(ctx context.Context, tokenType TokenType) (string, error) {
	// Use write lock for refresh operations
	m.mu.Lock()
	defer m.mu.Unlock()

	// Double-check pattern: token might have been refreshed while waiting for lock
	if token, exists := m.tokens[tokenType]; exists {
		if time.Now().Add(m.config.RefreshBuffer).Before(token.ExpiresAt) {
			return token.AccessToken, nil
		}
	}

	// Generate authentication headers
	headers, err := m.generateAuthHeaders()
	if err != nil {
		return "", fmt.Errorf("failed to generate auth headers: %w", err)
	}

	var newToken *Token

	switch tokenType {
	case TokenTypeB2B:
		newToken, err = m.refreshB2BToken(ctx, headers)
	case TokenTypeB2B2C:
		newToken, err = m.refreshB2B2CToken(ctx, headers)
	default:
		return "", fmt.Errorf("unsupported token type: %v", tokenType)
	}

	if err != nil {
		return "", fmt.Errorf("failed to refresh %v token: %w", tokenType, err)
	}

	m.tokens[tokenType] = newToken
	return newToken.AccessToken, nil
}

// generateAuthHeaders creates the required authentication headers
func (m *TokenManager) generateAuthHeaders() (http.Header, error) {
	timeStamp := helpers.NewTimeStamp()
	signature, err := m.creds.generateSignature(timeStamp)
	if err != nil {
		return nil, err
	}

	headers := make(http.Header)
	headers.Set("X-TIMESTAMP", timeStamp)
	headers.Set("X-CLIENT-KEY", m.creds.clientKey)
	headers.Set("X-SIGNATURE", signature)
	headers.Set("Content-Type", "application/json")

	return headers, nil
}

// refreshB2BToken handles B2B token refresh
func (m *TokenManager) refreshB2BToken(ctx context.Context, headers http.Header) (*Token, error) {
	request := &AccessTokenRequest{
		GrantType: types.ClientCredential,
		Params:    Params{Headers: headers},
	}

	return m.provider.B2B(ctx, request)
}

// refreshB2B2CToken handles B2B2C token refresh
func (m *TokenManager) refreshB2B2CToken(ctx context.Context, headers http.Header) (*Token, error) {
	// Check if we can use refresh token
	if existingToken, exists := m.tokens[TokenTypeB2B2C]; exists && existingToken.CanRefresh() {
		request := &AccessTokenB2B2CRequest{
			Params:       Params{Headers: headers},
			GrantType:    types.RefreshToken,
			RefreshToken: existingToken.RefreshToken,
		}
		return m.provider.B2B2C(ctx, request)
	}

	// Fall back to authorization code
	if m.config.AuthCode == "" {
		return nil, errors.New("auth code is required for B2B2C token acquisition")
	}

	request := &AccessTokenB2B2CRequest{
		Params:    Params{Headers: headers},
		GrantType: types.AuthorizationCode,
		AuthCode:  m.config.AuthCode,
	}

	return m.provider.B2B2C(ctx, request)
}

// TokenStats provides statistics about token usage (useful for monitoring)
type TokenStats struct {
	TokenType     TokenType     `json:"token_type"`
	HasToken      bool          `json:"has_token"`
	IsExpired     bool          `json:"is_expired,omitempty"`
	TimeToExpiry  time.Duration `json:"time_to_expiry,omitempty"`
	CanRefresh    bool          `json:"can_refresh,omitempty"`
	RefreshExpiry time.Duration `json:"refresh_expiry,omitempty"`
}

// GetStats returns statistics for all managed tokens
func (m *TokenManager) GetStats() map[TokenType]TokenStats {
	m.mu.RLock()
	defer m.mu.RUnlock()

	stats := make(map[TokenType]TokenStats)

	for _, tokenType := range []TokenType{TokenTypeB2B, TokenTypeB2B2C} {
		stat := TokenStats{
			TokenType: tokenType,
		}

		if token, exists := m.tokens[tokenType]; exists {
			stat.HasToken = true
			stat.IsExpired = token.IsExpired()
			stat.TimeToExpiry = token.TimeToExpiry()
			stat.CanRefresh = token.CanRefresh()
			if token.RefreshToken != "" {
				stat.RefreshExpiry = time.Until(token.RefreshAt)
			}
		}

		stats[tokenType] = stat
	}

	return stats
}

// tokenProviderImple implements the TokenProvider interface for SNAP BI token operations.
// It handles the actual HTTP requests to obtain access tokens from the SNAP BI API.
type tokenProviderImple struct {
	c credentials // SNAP BI API credentials (private key, client key, etc.)
	t Transporter // HTTP transport layer for making API calls
}

// newTokenProvider creates a new token provider instance with the specified credentials and transporter.
func newTokenProvider(c credentials, t Transporter) *tokenProviderImple {
	return &tokenProviderImple{c: c, t: t}
}

// B2B obtains a Business-to-Business (B2B) access token from the SNAP BI API.
// This method is used for server-to-server authentication where your application
// directly authenticates with SNAP BI using client credentials (private key + client key).
func (a *tokenProviderImple) B2B(ctx context.Context, request *AccessTokenRequest) (tokenData *Token, err error) {
	response := new(AccessTokenResponse)
	if err := a.t.Call(http.MethodPost, "/api/v1/access-token/b2b", types.AccessToken, request, response); err != nil {
		return tokenData, err
	}

	return response.toToken(), nil
}

// B2B2C obtains a Business-to-Business-to-Consumer (B2B2C) access token from the SNAP BI API.
// B2B2C tokens are used when your application needs to act on behalf of end users
// and typically have shorter lifespans but include refresh tokens for seamless renewal.
func (a *tokenProviderImple) B2B2C(ctx context.Context, request *AccessTokenB2B2CRequest) (tokenData *Token, err error) {
	response := new(AccessTokenB2B2CResponse)
	if err := a.t.Call(http.MethodPost, "/api/v1/access-token/b2b2c", types.AccessToken, request, response); err != nil {
		return tokenData, err
	}

	return response.toToken(), nil
}
