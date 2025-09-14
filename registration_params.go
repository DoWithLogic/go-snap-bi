package snap

import (
	"encoding/json"

	"github.com/DoWithLogic/go-snap-bi/types"
)

type CardType string

const (
	Debit           CardType = "D"
	Credit          CardType = "C"
	ElectronicMoney CardType = "UE"
)

type Flag string

const (
	YES Flag = "YES"
	NO  Flag = "NO"
)

type CardBindRequest struct {
	Params
	PartnerReferenceNo *string                   `json:"partnerReferenceNo,omitempty"`
	AccountName        *string                   `json:"accountName,omitempty"`
	CardData           string                    `json:"cardData"`
	BankAccountNo      *string                   `json:"bankAccountNo,omitempty"`
	BankCardNo         string                    `json:"bankCardNo"`
	BankCardType       *CardType                 `json:"bankCardType,omitempty"`
	DateOfBirth        *string                   `json:"dateOfBirth,omitempty"`
	Email              *string                   `json:"email,omitempty"`
	ExpiredDateTime    *string                   `json:"expiredDatetime,omitempty"`
	ExpiryDate         *string                   `json:"expiryDate,omitempty"`
	IdentificationNo   *string                   `json:"identificationNo,omitempty"`
	IdentificationType *types.IdentificationType `json:"identificationType,omitempty"`
	CustIDMerchant     string                    `json:"custIdMerchant"`
	IsBindAndPay       *string                   `json:"isBindAndPay,omitempty"`
	MerchantID         *string                   `json:"merchantId,omitempty"`
	TerminalID         *string                   `json:"terminalId,omitempty"`
	JourneyID          *string                   `json:"journeyId,omitempty"`
	SubMerchantID      *string                   `json:"subMerchantId,omitempty"`
	ExternalStoreID    *string                   `json:"externalStoreId,omitempty"`
	Limit              *float64                  `json:"limit,omitempty"`
	MerchantLogoURL    *string                   `json:"merchantLogoUrl,omitempty"`
	PhoneNo            *string                   `json:"phoneNo,omitempty"`
	SendOtpFlag        *Flag                     `json:"sendOtpFlag,omitempty"`
	Type               *string                   `json:"type,omitempty"`
	AdditionalInfo     *types.AdditionalInfo     `json:"additionalInfo,omitempty"`
}

func (c CardBindRequest) JSON() []byte {
	byteJSON, _ := json.Marshal(c)

	return byteJSON
}

type CardBindResponse struct {
	ResponseCode       string                `json:"responseCode"`
	ResponseMessage    string                `json:"responseMessage"`
	ReferenceNo        *string               `json:"referenceNo,omitempty"`
	PartnerReferenceNo *string               `json:"partnerReferenceNo,omitempty"`
	BankCardToken      string                `json:"bankCardToken"`
	ChargeToken        *string               `json:"chargeToken,omitempty"`
	RandomString       *string               `json:"randomString,omitempty"`
	TokenExpiryTime    *string               `json:"tokenExpiryTime,omitempty"`
	AdditionalInfo     *types.AdditionalInfo `json:"additionalInfo,omitempty"`
}

type CardBindLimitRequest struct {
	Params
	PartnerReferenceNo string                `json:"partnerReferenceNo"`
	BankAccountNo      string                `json:"bankAccountNo"`
	BankCardNo         string                `json:"bankCardNo"`
	Limit              string                `json:"limit"`
	BankCardToken      string                `json:"bankCardToken"`
	Otp                string                `json:"otp"`
	AdditionalInfo     *types.AdditionalInfo `json:"additionalInfo,omitempty"`
}

func (c CardBindLimitRequest) JSON() []byte {
	byteJSON, _ := json.Marshal(c)

	return byteJSON
}

type CardBindLimitResponse struct {
	ResponseCode       string                `json:"responseCode"`
	ResponseMessage    string                `json:"responseMessage"`
	ReferenceNo        string                `json:"referenceNo"`
	PartnerReferenceNo string                `json:"partnerReferenceNo"`
	AdditionalInfo     *types.AdditionalInfo `json:"additionalInfo,omitempty"`
}
