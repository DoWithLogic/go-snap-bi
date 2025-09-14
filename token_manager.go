package snap

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/DoWithLogic/go-snap-bi/helpers"
	"github.com/DoWithLogic/go-snap-bi/types"
)

// token represents an access token and related metadata for SNAP BI API authentication.
type token struct {
	// AccessToken is the actual bearer token string used for API authentication.
	AccessToken string

	// TokenType specifies the type of token (usually "Bearer").
	TokenType string

	// ExpiresAt is the expiration time of the access token.
	ExpiresAt time.Time

	// RefreshToken is available for B2B2C tokens to obtain new access tokens.
	RefreshToken string

	// RefreshAt is the expiration time of the refresh token (B2B2C only).
	RefreshAt time.Time
}

// IsExpired checks if the access token has expired.
func (t *token) IsExpired() bool { return time.Now().After(t.ExpiresAt) }

// IsRefreshExpired checks if the refresh token has expired (B2B2C only).
func (t *token) IsRefreshExpired() bool { return time.Now().After(t.RefreshAt) }

// CanRefresh determines if the token can be refreshed.
// Returns true if a refresh token exists and hasn't expired.
func (t *token) CanRefresh() bool { return t.RefreshToken != "" && !t.IsRefreshExpired() }

// TimeToExpiry returns the duration until the access token expires.
func (t *token) TimeToExpiry() time.Duration { return time.Until(t.ExpiresAt) }

// defaultRefreshBuffer is the time buffer used to check if a token needs refreshing.
// Tokens are refreshed before actual expiration to prevent API call failures.
var defaultRefreshBuffer = 1 * time.Minute

// tokenManager handles caching, refreshing, and acquisition of SNAP BI tokens.
// It ensures that valid authentication tokens are always available for API calls.
type tokenManager struct {
	mu sync.RWMutex // Protects concurrent access to the token

	// t holds the current active token.
	t *token

	// c holds the client configuration.
	c clientConfig

	// tp is the HTTP transporter used for API calls.
	tp Transporter
}

// newTokenManager creates a new token manager with the given client configuration and transporter.
func newTokenManager(c clientConfig, tp Transporter) *tokenManager {
	return &tokenManager{t: &token{}, c: c, tp: tp}
}

// getToken returns a valid access token, refreshing or acquiring a new one if necessary.
// It handles both B2B and B2B2C client types and ensures thread-safe token management.
func (t *tokenManager) getToken(ctx context.Context) (string, error) {
	if token := t.getValidToken(ctx); token != nil {
		return token.AccessToken, nil
	}
	return t.refreshOrAcquisitionToken(ctx)
}

// getValidToken returns the current token if it's valid and not near expiry.
// Returns nil if the token is expired or will expire within the refresh buffer period.
func (t *tokenManager) getValidToken(_ context.Context) *token {
	t.mu.RLock()
	defer t.mu.RUnlock()

	if time.Now().Add(defaultRefreshBuffer).After(t.t.ExpiresAt) {
		return nil
	}
	return t.t
}

// refreshOrAcquisitionToken refreshes an existing token or acquires a new one
// depending on the client type and current token state.
// Uses double-check locking pattern for thread safety.
func (t *tokenManager) refreshOrAcquisitionToken(ctx context.Context) (string, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	// Double-check pattern: another goroutine might have refreshed the token already
	if time.Now().Add(defaultRefreshBuffer).Before(t.t.ExpiresAt) {
		return t.t.AccessToken, nil
	}

	headers, err := t.generateTokenHeaders()
	if err != nil {
		return "", err
	}

	var request ParamsContainer
	switch t.c.clientType {
	case types.B2B:
		request = &AccessTokenRequest{
			GrantType: types.ClientCredential,
			Params:    Params{headers: headers},
		}
	case types.B2B2C:
		args := &AccessTokenB2B2CRequest{
			Params:       Params{headers: headers},
			GrantType:    types.RefreshToken,
			RefreshToken: t.t.RefreshToken,
		}
		if !t.t.CanRefresh() {
			args.GrantType = types.AuthorizationCode
			args.AuthCode = t.c.authCode
		}

		request = args
	default:
		return "", fmt.Errorf("unsupported client type: %v", t.c.clientType)
	}

	t.t, err = t.doTokenAcquisition(ctx, request)
	if err != nil {
		return "", err
	}

	return t.t.AccessToken, nil
}

// generateTokenHeaders builds mandatory headers for token acquisition API calls.
// Includes timestamp, signature, client key, and content type headers.
func (t *tokenManager) generateTokenHeaders() (http.Header, error) {
	timestamp := helpers.NewTimeStamp()
	signature, err := t.c.GenerateNonTransactionSignature(timestamp)
	if err != nil {
		return nil, err
	}

	headers := http.Header{}
	headers.Set(types.X_TIME_STAMP_KEY, timestamp)
	headers.Set(types.CONTENT_TYPE_KEY, types.MIMEApplicationJSON)
	headers.Set(types.X_CLIENT_KEY, t.c.clientKey)
	headers.Set(types.X_SIGNATURE_KEY, signature)

	return headers, nil
}

// doTokenAcquisition performs the actual API call to acquire or refresh a token.
// Handles both B2B and B2B2C token acquisition endpoints.
func (t *tokenManager) doTokenAcquisition(ctx context.Context, request ParamsContainer) (*token, error) {
	if t.c.clientType.Is(types.B2B) {
		response := new(AccessTokenResponse)
		if err := t.tp.CallWithContext(ctx, http.MethodPost, types.B2BToken, request, response); err != nil {
			return nil, err
		}

		return response.toToken(), nil
	}

	response := new(AccessTokenB2B2CResponse)
	if err := t.tp.CallWithContext(ctx, http.MethodPost, types.B2B2CToken, request, response); err != nil {
		return nil, err
	}

	return response.toToken(), nil
}

// buildTransactionHeaders constructs headers for transaction API calls.
// Includes authentication, signature, and client-specific headers.
// Validates required parameters based on client type (B2B vs B2B2C).
func (t *tokenManager) buildTransactionHeaders(
	ctx context.Context,
	method string,
	endpoint string,
	body []byte,
	request *Params,
) error {
	timestamp := helpers.NewTimeStamp()

	signature, err := t.c.GenerateTransactionSignature(method, endpoint, body, timestamp)
	if err != nil {
		return err
	}

	token, err := t.getToken(ctx)
	if err != nil {
		return err
	}

	headers := http.Header{}
	headers.Set(types.CONTENT_TYPE_KEY, types.MIMEApplicationJSON)
	headers.Set(types.AUTHORIZATION_KEY, fmt.Sprintf("Bearer %s", token))
	headers.Set(types.X_TIME_STAMP_KEY, timestamp)
	headers.Set(types.X_SIGNATURE_KEY, signature)

	// Set client-specific headers based on client type
	switch t.c.clientType {
	case types.B2B:
		if t.c.partnerID == nil {
			return fmt.Errorf("partner id is required for B2B transaction calls")
		}
		headers.Set(types.PARTNER_ID_KEY, *t.c.partnerID)

		if request.Origin != nil {
			headers.Set(types.ORIGIN_KEY, *request.Origin)
		}
		if request.ExternalID != nil {
			headers.Set(types.EXTERNAL_ID_KEY, *request.ExternalID)
		}
		if t.c.channelID == nil {
			return fmt.Errorf("channel id is required for B2B transaction calls")
		}
		headers.Set(types.CHANNEL_ID_KEY, *t.c.channelID)

	case types.B2B2C:
		if t.c.partnerID == nil {
			return fmt.Errorf("partner id is required for B2B2C transaction calls")
		}
		headers.Set(types.PARTNER_ID_KEY, *t.c.partnerID)

		if request.AuthorizationCustomer != nil {
			headers.Set(types.AUTHORIZATION_CUSTOMER_KEY, *request.AuthorizationCustomer)
		}
		if request.Origin != nil {
			headers.Set(types.ORIGIN_KEY, *request.Origin)
		}
		if request.ExternalID != nil {
			headers.Set(types.EXTERNAL_ID_KEY, *request.ExternalID)
		}
		if request.IPAddress != nil {
			headers.Set(types.IP_ADDRESS_KEY, *request.IPAddress)
		}
		if request.DeviceID != nil {
			headers.Set(types.DEVICE_ID_KEY, *request.DeviceID)
		}
		if t.c.channelID == nil {
			return fmt.Errorf("channel id is required for B2B2C transaction calls")
		}
		headers.Set(types.CHANNEL_ID_KEY, *t.c.channelID)
		if request.Latitude != nil {
			headers.Set(types.LATITUDE_KEY, *request.Latitude)
		}
		if request.Longitude != nil {
			headers.Set(types.LONGITUDE_KEY, *request.Longitude)
		}
	}
	request.setHeaders(headers)

	return nil
}
