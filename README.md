# pocketbase-sms-login

Phone-number one-time-code login for [PocketBase](https://pocketbase.io) — a plain Go package in PocketBase's sanctioned `Register(app)` extension form (see PocketBase discussion [#7612](https://github.com/pocketbase/pocketbase/discussions/7612): plugins are ordinary Go modules, versioned via `go.mod`).

```
POST /api/auth/sms/request  {"phone":"138…"}   → creates/reuses the user, issues a 6-digit OTP
POST /api/auth/sms/verify   {"phone","code"}   → standard PocketBase auth response (token + record)
```

## Design decisions

- **Fail-closed DEV mode.** Without a provider AND without an explicit `RELAY_SMS_DEBUG=1`, the routes are not mounted at all — a production deployment can never hand out codes in log plaintext by accident. With the DEV opt-in the code is written to the log and echoed as `debug_code` for local end-to-end testing.
- **One phone number = one account.** A phone that never logged in gets a provisioned user with a reserved non-deliverable e-mail and an unguessable password; the OTP is its only login.
- **Anti-abuse budgets, all process-local:**
  - request: 3 codes / 10 min per phone, 15 / 10 min per IP;
  - verify: 10 / 10 min per phone, 30 / 10 min per IP;
  - per-OTP attempt budget: after 5 failed verifications the OTP is destroyed, so even the correct code is dead — brute-forcing the 10⁶ space within the 5-minute TTL is hopeless;
  - OTPs are consumed on use (replay finds nothing to match) and stored via PocketBase's own `_otps` table (5-minute TTL, automatic cleanup);
  - the limiter map is ceiling-bounded and sweeps expired windows.
- Phone format: mainland-China mobile (`^1[3-9]\d{9}$`) — the only audience the built-in pattern serves; adjust `phonePattern` for other regions.

## Requirements

| Component | Version |
|---|---|
| Go | ≥ 1.27 (per `go.mod`) |
| PocketBase | v0.40.x — developed and tested against v0.40.4 |

## Install

```go
import (
    "log"

    authsms "github.com/Ahogeyi/pocketbase-sms-login"
    "github.com/pocketbase/pocketbase"
)

func main() {
    app := pocketbase.New()
    authsms.SetProvider(myProvider{}) // your SMS gateway; optional for DEV
    authsms.Register(app)
    if err := app.Start(); err != nil { log.Fatal(err) }
}
```

The users collection needs a `phone` text field (PocketBase's Admin UI or a migration — see `example/`). A runnable integration skeleton lives in [`example/main.go`](example/main.go).

### Provider interface

```go
type SmsProvider interface {
    Send(phone, code string) error
}
```

Call `SetProvider` before `Register`. Without it, DEV delivery requires `RELAY_SMS_DEBUG=1`.

## Status

Running in production behind a paid SMS gateway; only the pluggable provider seam ships in this repo — bring your own vendor.

## License

Apache-2.0 — see [LICENSE](LICENSE). Third-party components: [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
