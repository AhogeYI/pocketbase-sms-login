## What

<!-- One paragraph: what this PR does and why. -->

## Verification

- [ ] `go vet ./... && go test ./...` green (CI adds `-race`)
- [ ] fail-closed semantics intact (no provider + no DEV switch = routes unmounted)
- [ ] budget/rate-limit changes carry updated guard tests

## Refs

<!-- Issue numbers or discussion links. -->
