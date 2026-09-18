# Contributing

Thanks for looking at this extension — it is deliberately small and focused.

## Development

```bash
go vet ./... && go test ./...   # green is the merge bar (CI adds -race)
go build -o /dev/null ./example       # the integration example must keep compiling
```

- The extension follows PocketBase's own convention (discussion #7612): a plain
  Go package exposing `Register(app core.App)`, versioned as an ordinary
  `go.mod` dependency. Don't introduce host-private mechanisms.
- **Red line**: without a provider AND without an explicit `RELAY_SMS_DEBUG=1`,
  the routes must stay unmounted (fail-closed). No change may make DEV
  delivery reachable on a production default.
- Changes to the limiter/attempt-budget semantics must update the guard tests
  in `authsms_guard_test.go`.

## Commits

One logical step per commit, `feat:` / `fix:` / `docs:` / `chore:` / `security:`;
sign your commits (`git commit -s`, DCO).

## PocketBase upgrades

1. Bump the pin in `go.mod`.
2. `go vet ./... && go test ./...` — fix whatever the new minor broke.
3. Bump the extension's **minor**, add a row to the compatibility table in
   the README, and name both versions (extension + PocketBase) in the release.
