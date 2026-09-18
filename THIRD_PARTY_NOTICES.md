# 第三方组件与许可证

pocketbase-sms-login 自身以 [Apache-2.0](LICENSE) 发布。本扩展为纯库，不随分发物内嵌第三方源码；
以下为其构建（go.mod 依赖）所涉及的第三方组件：

| 组件 | 许可证 | 说明 |
| --- | --- | --- |
| [PocketBase](https://github.com/pocketbase/pocketbase) v0.40.4 | MIT | 宿主框架（扩展的 Register/钩子/OTP 存储均来自其公开 API） |

运行时镜像或使用方二进制中的完整传递依赖清单以 `go.mod` / `go.sum` 为准。
