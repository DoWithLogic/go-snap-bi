package snap

import "encoding/json"

type retrier interface {
	canRetry() bool
}

type redacter interface {
	redact() error
}

type RawError struct {
	Code    string `json:"responseCode"`
	Message string `json:"responseMessage"`
}

func (e *RawError) Error() string {
	ret, _ := json.Marshal(e)
	return string(ret)
}

func (e *RawError) redact() error {
	return e
}

func (e *RawError) canRetry() bool {
	return false
}
