package types

type ClientType int

const (
	B2B ClientType = iota + 1
	B2B2C
)

func (c ClientType) Is(ct ClientType) bool { return c == ct }
