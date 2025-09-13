package snap

import (
	"strconv"
	"time"

	"github.com/DoWithLogic/snap/v1/types"
)

type (
	AccessTokenRequest struct {
		Params
		GrantType      types.GrantType      `json:"grantType"`
		AdditionalInfo types.AdditionalInfo `json:"additionalInfo"`
	}

	AccessTokenResponse struct {
		ResponseCode    string               `json:"responseCode"`
		ResponseMessage string               `json:"responseMessage"`
		AccessToken     string               `json:"accessToken"`
		TokenType       string               `json:"tokenType"`
		ExpiresIn       string               `json:"expiresIn"`
		AdditionalInfo  types.AdditionalInfo `json:"additionalInfo"`
	}
)

func (a AccessTokenResponse) toToken() *Token {
	expiresIn, _ := strconv.Atoi(a.ExpiresIn)

	return &Token{
		AccessToken: a.AccessToken,
		TokenType:   a.TokenType,
		ExpiresAt:   time.Now().Add(time.Duration(expiresIn) * time.Second),
	}
}

type (
	AccessTokenB2B2CRequest struct {
		Params
		GrantType      types.GrantType      `json:"grantType"`
		AuthCode       string               `json:"authCode"`
		RefreshToken   string               `json:"refreshToken"`
		AdditionalInfo types.AdditionalInfo `json:"additionalInfo"`
	}

	AccessTokenB2B2CResponse struct {
		ResponseCode           string               `json:"responseCode"`
		ResponseMessage        string               `json:"responseMessage"`
		AccessToken            string               `json:"accessToken"`
		TokenType              string               `json:"tokenType"`
		AccessTokenExpiryTime  string               `json:"accessTokenExpiryTime"`
		RefreshToken           string               `json:"refreshToken"`
		RefreshTokenExpiryTime string               `json:"refreshTokenExpiryTime"`
		AdditionalInfo         types.AdditionalInfo `json:"additionalInfo"`
	}
)

func (a AccessTokenB2B2CResponse) toToken() *Token {
	accessExp, _ := time.Parse(time.RFC3339, a.AccessTokenExpiryTime)
	refreshExp, _ := time.Parse(time.RFC3339, a.RefreshTokenExpiryTime)

	return &Token{
		AccessToken:  a.AccessToken,
		TokenType:    a.TokenType,
		ExpiresAt:    accessExp,
		RefreshToken: a.RefreshToken,
		RefreshAt:    refreshExp,
	}
}
