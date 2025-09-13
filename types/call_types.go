package types

type RequestType string

const (
	Transaction RequestType = "transaction"
	AccessToken RequestType = "access_token"
)
