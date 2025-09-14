package types

// MIME types for content negotiation.
const (
	MIMEApplicationJSON                  = "application/json"
	MIMEApplicationJSONCharsetUTF8       = MIMEApplicationJSON + "; charset=UTF-8"
	MIMEApplicationJavaScript            = "application/javascript"
	MIMEApplicationJavaScriptCharsetUTF8 = MIMEApplicationJavaScript + "; charset=UTF-8"
	MIMEApplicationXML                   = "application/xml"
	MIMEApplicationXMLCharsetUTF8        = MIMEApplicationXML + "; charset=UTF-8"
	MIMETextXML                          = "text/xml"
	MIMETextXMLCharsetUTF8               = MIMETextXML + "; charset=UTF-8"
	MIMEApplicationForm                  = "application/x-www-form-urlencoded"
	MIMEApplicationProtobuf              = "application/protobuf"
	MIMEApplicationMsgpack               = "application/msgpack"
	MIMETextHTML                         = "text/html"
	MIMETextHTMLCharsetUTF8              = MIMETextHTML + "; charset=UTF-8"
	MIMETextPlain                        = "text/plain"
	MIMETextPlainCharsetUTF8             = MIMETextPlain + "; charset=UTF-8"
	MIMEMultipartForm                    = "multipart/form-data"
	MIMEOctetStream                      = "application/octet-stream"
)

const (
	X_TIME_STAMP_KEY           = "X-TIMESTAMP"
	X_CLIENT_KEY               = "X-CLIENT-KEY"
	X_SIGNATURE_KEY            = "X-SIGNATURE"
	GRANT_TYPE_KEY             = "grantType"
	CONTENT_TYPE_KEY           = "Content-Type"
	AUTHORIZATION_KEY          = "Authorization"
	AUTHORIZATION_CUSTOMER_KEY = "Authorization-Customer"
	ORIGIN_KEY                 = "ORIGIN"
	PARTNER_ID_KEY             = "X-PARTNER-ID"
	EXTERNAL_ID_KEY            = "X-EXTERNAL-ID"
	CHANNEL_ID_KEY             = "CHANNEL-ID"
	IP_ADDRESS_KEY             = "X-IP-ADDRESS"
	DEVICE_ID_KEY              = "X-DEVICE-ID"
	LATITUDE_KEY               = "X-LATITUDE"
	LONGITUDE_KEY              = "X-LONGITUDE"
)
