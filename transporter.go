package snap

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"time"

	"github.com/DoWithLogic/go-snap-bi/types"
)

const (
	// defaultHTTPTimeout is the default timeout for HTTP requests to SNAP BI API
	defaultHTTPTimeout = 80 * time.Second

	// defaultRetryDelay is the delay between retry attempts
	defaultRetryDelay = 2 * time.Second

	// maxRetryAttempts is the maximum number of retry attempts allowed
	maxRetryAttempts = 3
)

// httpClient is the default HTTP client used for communication with SNAP BI APIs.
// Can be customized through TransporterConfig.
var defaultHTTPClient = &http.Client{
	Timeout: defaultHTTPTimeout,
}

// TransporterConfig defines configuration options for the HTTP transporter.
type TransporterConfig struct {
	// DomainAPI is the base URL for the SNAP BI API
	DomainAPI string

	// MaxNetworkRetries specifies maximum retry attempts for transient network errors.
	// If nil, defaults to 0 (no retries).
	MaxNetworkRetries *int64

	// HTTPClient allows custom HTTP client configuration.
	// If nil, uses the default client with 80s timeout.
	HTTPClient *http.Client

	// RetryDelay specifies the delay between retry attempts.
	// If zero, defaults to 2 seconds.
	RetryDelay time.Duration
}

// Validate ensures the configuration has required fields and sets defaults.
func (c *TransporterConfig) Validate() error {
	if c.DomainAPI == "" {
		return fmt.Errorf("domain API is required")
	}

	if c.HTTPClient == nil {
		c.HTTPClient = defaultHTTPClient
	}

	if c.RetryDelay == 0 {
		c.RetryDelay = defaultRetryDelay
	}

	return nil
}

// Transporter is the interface responsible for executing API calls to SNAP BI.
type Transporter interface {
	// Call performs an HTTP request against the SNAP BI API.
	Call(method string, path types.Path, requestType types.RequestType, params ParamsContainer, response any) error

	// CallWithContext performs an HTTP request with context support for cancellation and timeouts.
	CallWithContext(ctx context.Context, method string, path types.Path, params ParamsContainer, response any) error
}

// transporterImpl implements the Transporter interface for SNAP BI API communication.
type transporterImpl struct {
	domainAPI         string
	client            *http.Client
	maxNetworkRetries int64
	retryDelay        time.Duration
}

// NewTransporter creates a new Transporter instance with the specified configuration.
func NewTransporter(cfg *TransporterConfig) (Transporter, error) {
	if cfg == nil {
		return nil, fmt.Errorf("transporter config is required")
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	maxRetries := int64(0)
	if cfg.MaxNetworkRetries != nil {
		if *cfg.MaxNetworkRetries > maxRetryAttempts {
			return nil, fmt.Errorf("max network retries cannot exceed %d", maxRetryAttempts)
		}
		maxRetries = *cfg.MaxNetworkRetries
	}

	return &transporterImpl{
		domainAPI:         cfg.DomainAPI,
		client:            cfg.HTTPClient,
		maxNetworkRetries: maxRetries,
		retryDelay:        cfg.RetryDelay,
	}, nil
}

// Call executes an HTTP request to the SNAP BI API without context.
// This is a convenience method that uses context.Background().
func (t *transporterImpl) Call(method string, path types.Path, requestType types.RequestType, params ParamsContainer, response any) error {
	return t.CallWithContext(context.Background(), method, path, params, response)
}

// CallWithContext executes an HTTP request to the SNAP BI API with context support.
func (t *transporterImpl) CallWithContext(ctx context.Context, method string, path types.Path, params ParamsContainer, response any) error {
	// Prepare request body
	body, err := t.prepareRequestBody(params)
	if err != nil {
		return fmt.Errorf("prepare request body: %w", err)
	}

	// Create HTTP request
	req, err := t.createRequest(ctx, method, path, body, params)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	// Execute request with retries
	resp, err := t.executeWithRetry(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Handle response
	return t.handleResponse(resp, response)
}

// prepareRequestBody marshals the request parameters to JSON if needed.
func (t *transporterImpl) prepareRequestBody(params ParamsContainer) ([]byte, error) {
	if params == nil || t.isNilPointer(params) {
		return nil, nil
	}

	return json.Marshal(params)
}

// isNilPointer checks if the interface contains a nil pointer.
func (t *transporterImpl) isNilPointer(v interface{}) bool {
	rv := reflect.ValueOf(v)
	return rv.Kind() == reflect.Ptr && rv.IsNil()
}

// createRequest builds an HTTP request with proper headers and body.
func (t *transporterImpl) createRequest(ctx context.Context, method string, path types.Path, body []byte, params ParamsContainer) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, path.GenerateEndpoint(t.domainAPI), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}

	// Set default content type
	if contentType := req.Header.Get(types.CONTENT_TYPE_KEY); contentType == "" {
		req.Header.Set(types.CONTENT_TYPE_KEY, types.MIMEApplicationJSON)
	}

	// Apply custom headers from params
	if params != nil {
		if requestParams := params.GetParams(); requestParams.headers != nil {
			// Copy headers to avoid modifying the original
			for key, values := range requestParams.headers {
				req.Header[key] = append(req.Header[key], values...)
			}
		}
	}

	return req, nil
}

// executeWithRetry executes the HTTP request with retry logic for transient errors.
func (t *transporterImpl) executeWithRetry(req *http.Request) (*http.Response, error) {
	attempts := t.maxNetworkRetries + 1
	var lastErr error

	for i := int64(0); i < attempts; i++ {
		// Clone request body for retries since it can only be read once
		var body io.Reader
		if req.Body != nil {
			bodyBytes, err := io.ReadAll(req.Body)
			if err != nil {
				return nil, fmt.Errorf("read request body for retry: %w", err)
			}
			body = bytes.NewReader(bodyBytes)
			req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		}

		resp, err := t.client.Do(req)
		if err == nil {
			return resp, nil
		}

		lastErr = err

		// Don't retry on the last attempt
		if i < attempts-1 {
			select {
			case <-req.Context().Done():
				return nil, req.Context().Err()
			case <-time.After(t.retryDelay):
				// Reset body for next attempt
				if body != nil {
					req.Body = io.NopCloser(body)
				}
			}
		}
	}

	return nil, fmt.Errorf("http request failed after %d attempts: %w", attempts, lastErr)
}

// handleResponse processes the HTTP response and unmarshals JSON if needed.
func (t *transporterImpl) handleResponse(resp *http.Response, response any) error {
	// Check for HTTP errors
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		bodyBytes, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			return fmt.Errorf("http error %d: failed to read error response", resp.StatusCode)
		}
		return &HTTPError{
			StatusCode: resp.StatusCode,
			Body:       string(bodyBytes),
		}
	}

	// Decode response if a target struct is provided
	if response != nil {
		if err := json.NewDecoder(resp.Body).Decode(response); err != nil {
			return fmt.Errorf("decode response: %w", err)
		}
	}

	return nil
}

// HTTPError represents an HTTP error response from the SNAP BI API.
type HTTPError struct {
	StatusCode int    `json:"status_code"`
	Body       string `json:"body"`
}

// Error returns a formatted error message.
func (e *HTTPError) Error() string {
	return fmt.Sprintf("HTTP %d: %s", e.StatusCode, e.Body)
}

// IsClientError returns true if the error is a 4xx client error.
func (e *HTTPError) IsClientError() bool {
	return e.StatusCode >= 400 && e.StatusCode < 500
}

// IsServerError returns true if the error is a 5xx server error.
func (e *HTTPError) IsServerError() bool {
	return e.StatusCode >= 500 && e.StatusCode < 600
}

// IsUnauthorized returns true if the error is a 401 Unauthorized.
func (e *HTTPError) IsUnauthorized() bool {
	return e.StatusCode == http.StatusUnauthorized
}
