// Minimal integration example: a PocketBase binary with the SMS login
// extension mounted and a production provider wired in.
//
//	go run ./example serve
package main

import (
	"log"

	authsms "github.com/Ahogeyi/pocketbase-sms-login"

	"github.com/pocketbase/pocketbase"
)

// aliyunProvider is where a production SMS gateway plugs in. Implement the
// one-method interface with your vendor's SDK; until SetProvider is called
// the routes only mount with the explicit RELAY_SMS_DEBUG=1 DEV opt-in.
type aliyunProvider struct{}

func (aliyunProvider) Send(phone, code string) error {
	// Your vendor call here.
	log.Printf("production delivery to %s: %s", phone, code)
	return nil
}

func main() {
	app := pocketbase.New()

	authsms.SetProvider(aliyunProvider{})
	authsms.Register(app)

	if err := app.Start(); err != nil {
		log.Fatal(err)
	}
}
