# Third-party notices

pocketbase-sms-login is distributed under [Apache-2.0](LICENSE). This
extension is a pure library and embeds no third-party source; the components
involved in its build (`go.mod` requirements) are:

| Component | License | Role |
| --- | --- | --- |
| [PocketBase](https://github.com/pocketbase/pocketbase) v0.40.4 | MIT | Host framework (Register/hooks/OTP storage all come from its public API) |

The authoritative transitive list for any produced binary is the consumer's
own `go.mod` / `go.sum`.
