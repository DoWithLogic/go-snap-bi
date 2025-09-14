package snap

import "net/http"

// ParamsContainer is a general interface that all parameter structs
// must implement. This is achieved by embedding the Params struct
// and inheriting its implementation of this interface.
//
// Example:
//
//	type CreateTransactionParams struct {
//	    *snap.Params
//	    Amount int
//	}
type ParamsContainer interface {
	// GetParams returns the embedded Params object so that
	// common request headers and attributes can be accessed.
	GetParams() *Params
}

// Params holds common HTTP headers and request metadata
// that can be attached to all SNAP API requests.
//
// It is intended to be embedded inside specific parameter
// structs to provide shared functionality.
type Params struct {
	// headers stores additional HTTP headers to be sent with the request.
	// It is not serialized into form or JSON payloads.
	headers http.Header `form:"-" json:"-"`

	// AuthorizationCustomer contains the customer authorization token.
	// Passed as an HTTP header.
	AuthorizationCustomer *string `form:"-" json:"-"`

	// Origin specifies the origin of the request (e.g., domain).
	// Passed as an HTTP header.
	Origin *string `form:"-" json:"-"`

	// ExternalID is an optional external identifier for the request.
	// Passed as an HTTP header.
	ExternalID *string `form:"-" json:"-"`

	// IPAddress holds the client IP address.
	// Passed as an HTTP header.
	IPAddress *string `form:"-" json:"-"`

	// DeviceID uniquely identifies the client device.
	// Passed as an HTTP header.
	DeviceID *string `form:"-" json:"-"`

	// Latitude specifies the client latitude position.
	// Passed as an HTTP header.
	Latitude *string `form:"-" json:"-"`

	// Longitude specifies the client longitude position.
	// Passed as an HTTP header.
	Longitude *string `form:"-" json:"-"`
}

// GetParams returns the Params object itself.
// Any struct that embeds Params automatically implements
// the ParamsContainer interface through this method.
func (p *Params) GetParams() *Params { return p }

// setHeaders sets the underlying HTTP headers for the request.
func (p *Params) setHeaders(h http.Header) { p.headers = h }

// SetAuthorizationCustomer sets the AuthorizationCustomer header value.
func (p *Params) SetAuthorizationCustomer(val string) { p.AuthorizationCustomer = &val }

// SetOrigin sets the Origin header value.
func (p *Params) SetOrigin(origin string) { p.Origin = &origin }

// SetExternalID sets the ExternalID header value.
func (p *Params) SetExternalID(externalID string) { p.ExternalID = &externalID }

// SetIPAddress sets the IPAddress header value.
func (p *Params) SetIPAddress(ipAddress string) { p.IPAddress = &ipAddress }

// SetDeviceID sets the DeviceID header value.
func (p *Params) SetDeviceID(deviceID string) { p.DeviceID = &deviceID }

// SetLatitude sets the Latitude header value.
func (p *Params) SetLatitude(latitude string) { p.Latitude = &latitude }

// SetLongitude sets the Longitude header value.
func (p *Params) SetLongitude(longitude string) { p.Longitude = &longitude }
