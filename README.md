# go-snap-bi 
**go-snap-bi** is an unofficial API wrapper for **SNAP (Standard Open API Pembayaran Indonesia)**. This Go library simplifies payment gateway integration with clean and efficient API calls.

## 🚧 Work in Progress
go-snap-bi is a work in progress aiming to simplify integrations with the SNAP payment gateway using Go. We are actively building new features, expanding the API coverage, and improving the developer experience.

## ✨ Features 
- Seamless integration with the SNAP API
- Easy-to-use methods for payment processing
- Secure API requests using API keys

## 🏗️ Getting Started
1. Install the package:
```bash
go get github.com/DoWithLogic/go-snap-bi
```
2. Basic Usage Example:
```go
import (
    "github.com/DoWithLogic/go-snap-bi"
    "github.com/DoWithLogic/go-snap-bi/types"
    "context"
    "fmt"
)

func main(){
    privateKey := `-----BEGIN RSA PRIVATE KEY-----MIIEpAIBAAKCAQEA3...`
    client, err := snap.New(
	        types.B2B,
	        privateKey,
	        "sandbox-client-key",
	        "https://api-sandbox.snap.com",
	        snap.WithPartnerID("test-partner"),
	        snap.WithChannelID("test-channel"),
        )
    
    if err != nil{
        panic(err)
    }

    response, err := client.Registration.CardBind(context.Background(), request)
    if err != nil{
        panic(err)
    }

    fmt.Println(response)
}






```
Here’s a simple example demonstrating how to use go-snap-bi to create a payment request:

## 🦄 TODOs 
- [ ] [Registrasi](https://apidevportal.aspi-indonesia.or.id/api-services/registrasi)
- [ ] [Informasi Saldo](https://apidevportal.aspi-indonesia.or.id/api-services/informasi-saldo)
- [ ] [Riwayat Transaksi](https://apidevportal.aspi-indonesia.or.id/api-services/riwayat-transaksi)
- [ ] [Transfer Kredit](https://apidevportal.aspi-indonesia.or.id/api-services/transfer-kredit)
- [ ] [Transfer Debit](https://apidevportal.aspi-indonesia.or.id/api-services/transfer-debit)