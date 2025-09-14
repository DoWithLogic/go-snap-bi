package types

type Path string

const (
	RegistrationCardBind      Path = "/v1.0/registration-card-bind"
	RegistrationCardBindLimit Path = "/v1.0/registration-card-inquiry"
	B2BToken                  Path = "/api/v1/access-token/b2b"
	B2B2CToken                Path = "/api/v1/access-token/b2b2c"
)

func (p Path) GenerateEndpoint(domainAPI string) string { return domainAPI + p.String() }
func (p Path) String() string                           { return string(p) }
