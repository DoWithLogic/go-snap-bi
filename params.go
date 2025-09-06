package snap

import (
	"context"
	"net/http"
	"net/url"

	"github.com/DoWithLogic/snap/v1/form"
)

// Contains constants for the names of parameters used for pagination in list APIs
const (
	EndingBefore  = "ending_before"
	StartingAfter = "starting_after"
)

// ExtraValues are extra parameters that are attached to an API request.
// They're implemented as a custom type so that they can have their own
// AppendTo implementation.
type ExtraValues struct {
	url.Values `form:"-" json:"-"` // See custom AppendTo implementation
}

// AppendTo implements custom form encoding for extra parameter values.
func (v ExtraValues) AppendTo(body *form.Values, keyParts []string) {
	for k, vs := range v.Values {
		for _, v := range vs {
			body.Add(form.FormatKey(append(keyParts, k)), v)
		}
	}
}

// Filters is a structure that contains a collection of filters for list-related APIs.
type Filters struct {
	f []*filter
}

// AddFilter adds a new filter with a given key, op and value.
func (f *Filters) AddFilter(key, op, value string) {
	f.f = append(f.f, &filter{Key: key, Op: op, Val: value})
}

type filter struct {
	Key, Op, Val string `form:"-" json:"-"`
}

// Params is the structure that contains the common properties
// of any *Params structure.
type Params struct {
	// Context used for request. It may carry deadlines, cancelation signals,
	// and other request-scoped values across API boundaries and between
	// processes.
	//
	// Note that a cancelled or timed out context does not provide any
	// guarantee whether the operation was or was not completed on Snap's API
	// servers. For certainty, you must either retry with the same idempotency
	// key or query the state of the API.
	Context context.Context `form:"-" json:"-"`

	Extra *ExtraValues `form:"*"  json:"-"`

	// Headers may be used to provide extra header lines on the HTTP request.
	Headers http.Header `form:"-" json:"-"`

	// Deprecated: Please use Metadata in the surrounding struct instead.
	Metadata map[string]string `form:"metadata" json:"-"`

	usage []string `form:"-" json:"-"` // Tracked behaviors
}

// ParamsContainer is a general interface for which all parameter structs
// should comply. They achieve this by embedding a Params struct and inheriting
// its implementation of this interface.
type ParamsContainer interface {
	GetParams() *Params
}

// InternalSetUsage sets the usage field on the Params struct, removing duplicates.
// Unstable: for internal Snap-go usage only.
func (p *Params) InternalSetUsage(usage []string) {
	// Optimization for nil or empty usage
	if len(usage) == 0 {
		return
	}

	// Use a map to track unique usage values
	usageMap := make(map[string]struct{})
	for _, u := range p.usage {
		usageMap[u] = struct{}{}
	}
	for _, u := range usage {
		usageMap[u] = struct{}{}
	}
	p.usage = p.usage[:0] // Reset the slice to avoid retaining old values
	for u := range usageMap {
		p.usage = append(p.usage, u)
	}
}
