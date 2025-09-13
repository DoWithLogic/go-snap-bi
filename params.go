package snap

import "net/http"

// ParamsContainer is a general interface for which all parameter structs
// should comply. They achieve this by embedding a Params struct and inheriting
// its implementation of this interface.
type ParamsContainer interface {
	GetParams() *Params
}

type Params struct {
	// Headers may be used to provide extra header lines on the HTTP request.
	Headers http.Header `form:"-" json:"-"`
}

// GetParams returns a Params struct (itself). It exists because any structs
// that embed Params will inherit it, and thus implement the ParamsContainer
// interface.
func (p *Params) GetParams() *Params {
	return p
}
