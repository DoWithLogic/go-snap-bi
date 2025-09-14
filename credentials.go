package snap

// func (c *credentials) GetB2BHeadersMap() (map[string]string, error) {
// 	timestamp := helpers.NewTimeStamp()
// 	signature, err := c.GenerateNonTransactionSignature(timestamp)
// 	if err != nil {
// 		return nil, err
// 	}

// 	return map[string]string{
// 		types.CONTENT_TYPE_KEY: types.MIMEApplicationJSON,
// 		types.X_TIME_STAMP_KEY: timestamp,
// 		types.X_CLIENT_KEY:     c.clientKey,
// 		types.X_SIGNATURE_KEY:  signature,
// 	}, nil
// }

// func (c *credentials) GetB2B2CHeadersMap(grantType types.GrantType) (map[string]string, error) {
// 	timestamp := helpers.NewTimeStamp()
// 	signature, err := c.GenerateNonTransactionSignature(timestamp)
// 	if err != nil {
// 		return nil, err
// 	}

// 	return map[string]string{
// 		types.CONTENT_TYPE_KEY: types.MIMEApplicationJSON,
// 		types.X_TIME_STAMP_KEY: timestamp,
// 		types.X_CLIENT_KEY:     c.clientKey,
// 		types.X_SIGNATURE_KEY:  signature,
// 		types.GRANT_TYPE_KEY:   grantType.String(),
// 	}, nil
// }
