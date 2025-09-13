package helpers

import "time"

func NewTimeStamp() string {
	return time.Now().Format(time.RFC3339)
}
