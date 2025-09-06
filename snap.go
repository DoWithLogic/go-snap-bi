package snap

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
	"net/http"
	"net/url"
	"reflect"
	"regexp"
	"strings"
	"time"

	"github.com/DoWithLogic/snap/v1/form"
)

// Transporter is an interface for making calls against a SNAP Service.
// This interface exists to enable mocking for during testing if needed.
type Transporter interface {
	Call(method, path, key string, params ParamsContainer, response ResponseSetter) error
	CallRaw(method, path, key string, body []byte, params *Params, v ResponseSetter) error
	SetMaxNetworkRetries(maxNetworkRetries int64)
}

// APIResponse encapsulates some common features of a response from the
type APIResponse struct {
	// Header contain a map of all HTTP header keys to values. Its behavior and
	// caveats are identical to that of http.Header.
	Header http.Header

	// RawJSON contains the response body as raw bytes.
	RawJSON []byte

	// RequestID contains a string that uniquely identifies the request.
	// Used for debugging or support purposes.
	RequestID string

	// Status is a status code and message. e.g. "200 OK"
	Status string

	// StatusCode is a status code as integer. e.g. 200
	StatusCode int

	duration *time.Duration
}

// SupportedFeature is an enumeration of supported SNAP endpoints.
type SupportedFeature string

const (
	Authorization SupportedFeature = "authorization"
	Registration  SupportedFeature = "registeration"
)

// requestMetrics contains the id and duration of the last request sent
type requestMetrics struct {
	RequestDurationMS *int     `json:"request_duration_ms"`
	RequestID         string   `json:"request_id"`
	Usage             []string `json:"usage"`
}

// requestTelemetry contains the payload sent in the
// `X-Snap-Client-Telemetry` header when TransporterConfig.EnableTelemetry = true.
type requestTelemetry struct {
	LastRequestMetrics requestMetrics `json:"last_request_metrics"`
}

// transporterImplementation is the internal implementation for making HTTP calls
type transporterImplementation struct {
	Type              SupportedFeature
	URL               string
	HTTPClient        *http.Client
	LeveledLogger     LeveledLoggerInterface
	MaxNetworkRetries int64

	enableTelemetry bool

	// networkRetriesSleep indicates whether the transporter should use the normal
	// sleep between retries.
	//
	// See also SetNetworkRetriesSleep.
	networkRetriesSleep bool

	requestMetricsBuffer chan requestMetrics
}

// the snap API only accepts GET / POST
func validateMethod(method string) error {
	if method != http.MethodPost && method != http.MethodGet && method != http.MethodDelete {
		return fmt.Errorf("method must be POST or GET. Received %s", method)
	}
	return nil
}

func extractParams(params ParamsContainer) (*form.Values, *Params, error) {
	var formValues *form.Values
	var commonParams *Params

	if params != nil {
		// This is a little unfortunate, but Go makes it impossible to compare
		// an interface value to nil without the use of the reflect package and
		// its true disciples insist that this is a feature and not a bug.
		//
		// Here we do invoke reflect because
		// (1) we have to reflect anyway to use encode with the form package, and
		// (2) the corresponding removal of boilerplate that this enables makes the small performance penalty worth it.
		reflectValue := reflect.ValueOf(params)

		if reflectValue.Kind() == reflect.Ptr && !reflectValue.IsNil() {
			commonParams = params.GetParams()
			formValues = &form.Values{}
			form.AppendTo(formValues, params)
		}
	}
	return formValues, commonParams, nil
}

func newAPIResponse(res *http.Response, resBody []byte, requestDuration *time.Duration) *APIResponse {
	return &APIResponse{
		Header:     res.Header,
		RawJSON:    resBody,
		RequestID:  res.Header.Get("Request-Id"),
		Status:     res.Status,
		StatusCode: res.StatusCode,
		duration:   requestDuration,
	}
}

// nopReadCloser's sole purpose is to give us a way to turn an `io.Reader` into
// an `io.ReadCloser` by adding a no-op implementation of the `Closer`
// interface. We need this because `http.Request`'s `Body` takes an
// `io.ReadCloser` instead of a `io.Reader`.
type nopReadCloser struct {
	io.Reader
}

func (nopReadCloser) Close() error { return nil }

func resetBodyReader(body *bytes.Buffer, req *http.Request) {
	// This might look a little strange, but we set the request's body
	// outside of `NewRequest` so that we can get a fresh version every
	// time.
	//
	// The background is that back in the era of old style HTTP, it was
	// safe to reuse `Request` objects, but with the addition of HTTP/2,
	// it's now only sometimes safe. Reusing a `Request` with a body will
	// break.
	//
	// See some details here:
	//
	//     https://github.com/golang/go/issues/19653#issuecomment-341539160
	//
	// To workaround the problem, we put a fresh `Body` onto the `Request`
	// every time we execute it, and this seems to empirically resolve the
	// problem.
	if body != nil {
		// We can safely reuse the same buffer that we used to encode our body,
		// but return a new reader to it everytime so that each read is from
		// the beginning.
		reader := bytes.NewReader(body.Bytes())

		req.Body = nopReadCloser{reader}

		// And also add the same thing to `Request.GetBody`, which allows
		// `net/http` to get a new body in cases like a redirect. This is
		// usually not used, but it doesn't hurt to set it in case it's
		// needed.
		req.GetBody = func() (io.ReadCloser, error) {
			reader := bytes.NewReader(body.Bytes())
			return nopReadCloser{reader}, nil
		}
	}
}

func (t *transporterImplementation) Call(method, path, key string, params ParamsContainer, response ResponseSetter) error {
	_, commonParams, err := extractParams(params)
	if err != nil {
		return err
	}

	var body []byte
	if params != nil && !(reflect.ValueOf(params).Kind() == reflect.Ptr && reflect.ValueOf(params).IsNil()) {
		body, err = json.Marshal(params)
		if err != nil {
			return err
		}
	}

	return t.CallRaw(method, path, key, body, commonParams, response)
}

func (t *transporterImplementation) CallRaw(method, path, key string, body []byte, params *Params, v ResponseSetter) error {
	if err := validateMethod(method); err != nil {
		return err
	}

	req, err := t.NewRequest(method, path, key, "application/json", params)
	if err != nil {
		return err
	}

	responseSetter := metricsResponseSetter{
		ResponseSetter: v,
		transporter:    t,
		params:         params,
	}

	if err := t.Do(req, bytes.NewBuffer(body), &responseSetter); err != nil {
		return err
	}

	return nil
}

// UnmarshalJSONVerbose unmarshals JSON, but in case of a failure logs and
// produces a more descriptive error.
func (s *transporterImplementation) UnmarshalJSONVerbose(statusCode int, body []byte, v interface{}) error {
	err := json.Unmarshal(body, v)
	if err != nil {
		// If we got invalid JSON back then something totally unexpected is
		// happening (caused by a bug on the server side). Put a sample of the
		// response body into the error message so we can get a better feel for
		// what the problem was.
		bodySample := string(body)
		if len(bodySample) > 500 {
			bodySample = bodySample[0:500] + " ..."
		}

		// Make sure a multi-line response ends up all on one line
		bodySample = strings.Replace(bodySample, "\n", "\\n", -1)

		newErr := fmt.Errorf("Couldn't deserialize JSON (response status: %v, body sample: '%s'): %v",
			statusCode, bodySample, err)
		s.LeveledLogger.Errorf("%s", newErr.Error())
		return newErr
	}

	return nil
}

// responseToError converts a SNAP response to an error.
func (s *transporterImplementation) responseToError(res *http.Response, resBody []byte) error {
	// First, we partially unmarshal just the error type
	var raw struct {
		Error *RawError `json:"error"`
	}
	if err := s.UnmarshalJSONVerbose(res.StatusCode, resBody, &raw); err != nil {
		return err
	}

	// need to return a generic error in this case
	if raw.Error == nil {
		err := errors.New(string(resBody))
		return err
	}

	return raw.Error
}

func (s *transporterImplementation) logError(statusCode int, err error) {
	if snapErr, ok := err.(redacter); ok {
		// The SNAP makes a distinction between errors that were
		// caused by invalid parameters or something else versus those
		// that occurred *despite* valid parameters, the latter coming
		// back with status 402.
		//
		// On a 402, log to info so as to not make an integration's log
		// noisy with error messages that they don't have much control
		// over.
		//
		// Note I use the constant 402 instead of an `http.Status*`
		// constant because technically 402 is "Payment required". The
		// Snap doesn't comply to the letter of the specification
		// and uses it in a broader sense.
		if statusCode == 402 {
			s.LeveledLogger.Infof("User-compelled request error from Snap (status %v): %v",
				statusCode, snapErr.redact())
		} else {
			s.LeveledLogger.Errorf("Request error from Snap (status %v): %v",
				statusCode, snapErr.redact())
		}
	} else {
		s.LeveledLogger.Errorf("Error decoding error from Snap: %v", err)
	}
}

func (s *transporterImplementation) maybeSetTelemetryHeader(req *http.Request) {
	if s.enableTelemetry {
		select {
		case metrics := <-s.requestMetricsBuffer:
			metricsJSON, err := json.Marshal(&requestTelemetry{LastRequestMetrics: metrics})
			if err == nil {
				req.Header.Set("X-Snap-Client-Telemetry", string(metricsJSON))
			} else {
				s.LeveledLogger.Warnf("Unable to encode client telemetry: %v", err)
			}
		default:
			// There are no metrics available, so don't send any.
			// This default case  needs to be here to prevent Do from blocking on an
			// empty requestMetricsBuffer.
		}
	}
}

// NewRequest is used by Call to generate an http.Request. It handles encoding
// parameters and attaching the appropriate headers.
func (s *transporterImplementation) NewRequest(method, path, key, contentType string, params *Params) (*http.Request, error) {
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}

	// Body is set later by `Do`.
	req, err := http.NewRequest(method, s.URL+path, nil)
	if err != nil {
		s.LeveledLogger.Errorf("Cannot create SNAP request: %v", err)
		return nil, err
	}

	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", key))
	req.Header.Add("Content-Type", contentType)

	if params != nil {
		if params.Context != nil {
			req = req.WithContext(params.Context)
		}

		for k, v := range params.Headers {
			for _, line := range v {
				// Use Set to override the default value possibly set before
				req.Header.Set(k, line)
			}
		}
	}

	return req, nil
}

// requestWithRetriesAndTelemetry uses s.HTTPClient to make an HTTP request,
// and handles retries, telemetry, and emitting log statements.  It attempts to
// avoid processing the *result* of the HTTP request. It receives a
// "handleResponse" func from the caller, and it defers to that to determine
// whether the request was a failure or success, and to convert the
// response/error into the appropriate type of error or an appropriate result
// type.
func (s *transporterImplementation) requestWithRetriesAndTelemetry(
	req *http.Request,
	body *bytes.Buffer,
	handleResponse func(*http.Response, error) (any, error),
) (*http.Response, any, *time.Duration, error) {
	s.LeveledLogger.Infof("Requesting %v %v%v", req.Method, req.URL.Host, req.URL.Path)
	s.maybeSetTelemetryHeader(req)
	var resp *http.Response
	var err error
	var requestDuration time.Duration
	var result any
	for retry := 0; ; {
		start := time.Now()
		resetBodyReader(body, req)

		resp, err = s.HTTPClient.Do(req)

		requestDuration = time.Since(start)
		s.LeveledLogger.Infof("Request completed in %v (retry: %v)", requestDuration, retry)

		result, err = handleResponse(resp, err)

		// If the response was okay, or an error that shouldn't be retried,
		// we're done, and it's safe to leave the retry loop.
		shouldRetry, noRetryReason := s.shouldRetry(err, req, resp, retry)

		if !shouldRetry {
			s.LeveledLogger.Infof("Not retrying request: %v", noRetryReason)
			break
		}

		sleepDuration := s.sleepTime(retry)
		retry++

		s.LeveledLogger.Warnf("Initiating retry %v for request %v %v%v after sleeping %v",
			retry, req.Method, req.URL.Host, req.URL.Path, sleepDuration)

		time.Sleep(sleepDuration)
	}

	if err != nil {
		return nil, nil, nil, err
	}

	return resp, result, &requestDuration, nil
}

// Regular expressions used to match a few error types that we know we don't
// want to retry. Unfortunately these errors aren't typed so we match on the
// error's message.
var (
	redirectsErrorRE = regexp.MustCompile(`stopped after \d+ redirects\z`)
	schemeErrorRE    = regexp.MustCompile(`unsupported protocol scheme`)
)

// Checks if an error is a problem that we should retry on. This includes both
// socket errors that may represent an intermittent problem and some special
// HTTP statuses.
//
// Returns a boolean indicating whether a client should retry. If false, a
// second string parameter is also returned with a short message indicating why
// no retry should occur. This can be used for logging/informational purposes.
func (s *transporterImplementation) shouldRetry(err error, req *http.Request, resp *http.Response, numRetries int) (bool, string) {
	if numRetries >= int(s.MaxNetworkRetries) {
		return false, "max retries exceeded"
	}

	// Don't retry if the context was canceled or its deadline was exceeded.
	if req.Context() != nil && req.Context().Err() != nil {
		switch req.Context().Err() {
		case context.Canceled:
			return false, "context canceled"
		case context.DeadlineExceeded:
			return false, "context deadline exceeded"
		default:
			return false, fmt.Sprintf("unknown context error: %v", req.Context().Err())
		}
	}

	// All errors from the Snap should implement the `retrier` interface.
	// Any other error comes from a different layer
	if err, ok := err.(retrier); ok {
		return err.canRetry(), "not retriable error"
	}

	// We retry most errors that come out of HTTP requests except for a curated
	// list that we know not to be retryable. This list is probably not
	// exhaustive, so it'd be okay to add new errors to it. It'd also be okay to
	// flip this to an inverted strategy of retrying only errors that we know
	// to be retryable in a future refactor, if a good methodology is found for
	// identifying that full set of errors.
	if err != nil {
		if urlErr, ok := err.(*url.Error); ok {
			// Don't retry too many redirects.
			if redirectsErrorRE.MatchString(urlErr.Error()) {
				return false, urlErr.Error()
			}

			// Don't retry invalid protocol scheme.
			if schemeErrorRE.MatchString(urlErr.Error()) {
				return false, urlErr.Error()
			}

			// Don't retry TLS certificate validation problems.
			if _, ok := urlErr.Err.(x509.UnknownAuthorityError); ok {
				return false, urlErr.Error()
			}
		}

		// Do retry every other type of non-Snap error.
		return true, ""
	}

	// 409 Conflict
	if resp.StatusCode == http.StatusConflict {
		return true, ""
	}

	// Retry on 500, 503, and other internal errors.
	//
	// in most cases when a 500 is returned,
	// would typically replay it anyway.
	if resp.StatusCode >= http.StatusInternalServerError {
		return true, ""
	}

	return false, "response not known to be safe for retry"
}

// defaultHTTPTimeout is the default timeout on the http.Client used by the library.
const defaultHTTPTimeout = 80 * time.Second

// maxNetworkRetriesDelay and minNetworkRetriesDelay defines sleep time in milliseconds between
// tries to send HTTP request again after network failure.
const maxNetworkRetriesDelay = 5000 * time.Millisecond
const minNetworkRetriesDelay = 500 * time.Millisecond

// The number of requestMetric objects to buffer for client telemetry. When the
// buffer is full, new requestMetrics are dropped.
const telemetryBufferSize = 16

// sleepTime calculates sleeping/delay time in milliseconds between failure and a new one request.
func (s *transporterImplementation) sleepTime(numRetries int) time.Duration {
	// We disable sleeping in some cases for tests.
	if !s.networkRetriesSleep {
		return 0 * time.Second
	}

	// Apply exponential backoff with minNetworkRetriesDelay on the
	// number of num_retries so far as inputs.
	delay := minNetworkRetriesDelay + minNetworkRetriesDelay*time.Duration(numRetries*numRetries)

	// Do not allow the number to exceed maxNetworkRetriesDelay.
	if delay > maxNetworkRetriesDelay {
		delay = maxNetworkRetriesDelay
	}

	// Apply some jitter by randomizing the value in the range of 75%-100%.
	jitter := rand.Int63n(int64(delay / 4))
	delay -= time.Duration(jitter)

	// But never sleep less than the base sleep seconds.
	if delay < minNetworkRetriesDelay {
		delay = minNetworkRetriesDelay
	}

	return delay
}

// Do is used by Call to execute an API request and parse the response. It uses
// the backend's HTTP client to execute the request and unmarshals the response
// into v. It also handles unmarshaling errors returned by the API.
func (s *transporterImplementation) Do(req *http.Request, body *bytes.Buffer, v ResponseSetter) error {
	handleResponse := func(res *http.Response, err error) (interface{}, error) {
		var resBody []byte
		if err == nil {
			resBody, err = ioutil.ReadAll(res.Body)
			res.Body.Close()
		}

		switch {
		case err != nil:
			s.LeveledLogger.Errorf("Request failed with error: %v", err)
		case res.StatusCode >= 400:
			err = s.responseToError(res, resBody)
			s.logError(res.StatusCode, err)
		}

		return resBody, err
	}

	res, result, requestDuration, err := s.requestWithRetriesAndTelemetry(req, body, handleResponse)
	if err != nil {
		return err
	}
	resBody := result.([]byte)
	s.LeveledLogger.Debugf("Response: %s", string(resBody))

	err = s.UnmarshalJSONVerbose(res.StatusCode, resBody, v)
	v.SetResponse(newAPIResponse(res, resBody, requestDuration))
	return err
}

func (t *transporterImplementation) maybeEnqueueTelemetryMetrics(requestID string, requestDuration *time.Duration, usage []string) {
	if !t.enableTelemetry || requestID == "" {
		return
	}

	// If there's no duration to report and no usage to report, don't bother
	if requestDuration == nil && len(usage) == 0 {
		return
	}

	metrics := requestMetrics{
		RequestID: requestID,
	}

	if requestDuration != nil {
		requestDurationMS := int(*requestDuration / time.Millisecond)
		metrics.RequestDurationMS = &requestDurationMS
	}

	if len(usage) > 0 {
		metrics.Usage = usage
	}

	select {
	case t.requestMetricsBuffer <- metrics:
	default:
	}
}

// ResponseSetter defines a type that contains an HTTP response from a SNAP
type ResponseSetter interface {
	SetResponse(response *APIResponse)
}

// UsageTransporter is a wrapper for snap.Transporter that sets the usage parameter
type UsageTransporter struct {
	T     Transporter
	Usage []string
}

func (u UsageTransporter) Call(method, path, key string, params ParamsContainer, response ResponseSetter) error {
	if r := reflect.ValueOf(params); r.Kind() == reflect.Ptr && !r.IsNil() {
		params.GetParams().InternalSetUsage(u.Usage)
	}

	return u.T.Call(method, path, key, params, response)
}

type metricsResponseSetter struct {
	ResponseSetter
	transporter *transporterImplementation
	params      *Params
}

func (s *metricsResponseSetter) SetResponse(response *APIResponse) {
	var usage []string
	if s.params != nil {
		usage = s.params.usage
	}
	s.transporter.maybeEnqueueTelemetryMetrics(response.RequestID, response.duration, usage)
	s.ResponseSetter.SetResponse(response)
}

func (s *metricsResponseSetter) UnmarshalJSON(b []byte) error {
	return json.Unmarshal(b, s.ResponseSetter)
}
