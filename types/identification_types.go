package types

type IdentificationType string

const (
	Passport IdentificationType = "01"
	KTP      IdentificationType = "02"
	TKTP     IdentificationType = "03"
	SIM      IdentificationType = "04"
	Others   IdentificationType = "99"
)
