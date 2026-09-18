# 贡献指南

感谢关注！这是一个面向 PocketBase 的登录渠道扩展，保持小而专注。

## 开发

```bash
go vet ./... && go test ./...   # 全绿是合并前提
```

- 扩展遵循 PocketBase 官方口径（discussion #7612）：普通 Go 包 + `Register(app core.App)`，
  版本走 go.mod；不要引入宿主私有机制。
- **红线**：无 provider 且未显式 `RELAY_SMS_DEBUG=1` 时路由不挂载（fail-closed）——
  任何改动不得让 DEV 投递在生产默认可达。
- 限流/尝试预算语义改动请同步更新 `authsms_guard_test.go` 的守卫用例。

## 提交

一个逻辑步骤一个提交，格式 `feat:` / `fix:` / `docs:` / `chore:` / `security:`。
签名提交（`git commit -s`，DCO）。
