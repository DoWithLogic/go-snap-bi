package snap

type virtualAccount struct {
	c  credentials
	t  Transporter
	tm *TokenManager
}
