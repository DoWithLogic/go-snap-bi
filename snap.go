package snap

import (
	"fmt"
	"time"

	"github.com/DoWithLogic/snap/helpers"
)

type Client struct {
	VirtualAccount *virtualAccount
}

// NewClient creates and returns a new Client configured with the given
// private key and client ID.
//
// The private key must be a valid RSA key in PEM format (either PKCS#1
// or PKCS#8). Upon initialization, the function attempts to generate
// a test signature using the current timestamp to validate the key.
func NewClient(privateKey, clientKey, domainAPI, authCode string) (*Client, error) {
	creds := credentials{
		privateKey: privateKey,
		clientKey:  clientKey,
		domainAPI:  domainAPI,
		authCode:   authCode,
	}

	if _, err := creds.generateSignature(fmt.Sprintf("%s|%s", creds.clientKey, helpers.NewTimeStamp())); err != nil {
		return nil, err
	}

	tmConfig := TokenManagerConfig{
		PrivateKey:    privateKey,
		ClientKey:     clientKey,
		AuthCode:      authCode,
		RefreshBuffer: 1 * time.Minute,
	}

	transpoter, err := NewTransporter(&TransporterConfig{DomainAPI: domainAPI})
	if err != nil {
		return nil, err
	}

	tokenManager, err := NewTokenManager(tmConfig, transpoter)
	if err != nil {
		return nil, err
	}

	client := &Client{
		VirtualAccount: &virtualAccount{c: creds, t: transpoter, tm: tokenManager},
	}

	return client, nil
}
