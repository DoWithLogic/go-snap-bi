package types

type GrantType string

const (
	ClientCredential  GrantType = "client_credentials"
	AuthorizationCode GrantType = "authorization_code"
	RefreshToken      GrantType = "refresh_token"
)
