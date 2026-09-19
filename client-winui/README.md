# Wpyw Mail WinUI 3 客户端

这是独立于服务端的 Windows 客户端，使用 C# + WinUI 3 + Windows App SDK。

默认连接本机服务端：`http://127.0.0.1:8787/api`。登录页可以改成远程 API 地址。

## 本地运行

```powershell
dotnet restore .\client-winui\WpywMail.Client.csproj
dotnet build .\client-winui\WpywMail.Client.csproj -c Debug -p:Platform=x64
dotnet run --project .\client-winui\WpywMail.Client.csproj -c Debug -p:Platform=x64
```

客户端第一版包含：登录、收件箱/已发送等文件夹、搜索、邮件阅读、写信入队、刷新和退出登录。

服务端需要先启动 `server-native`，并确保 API 地址可访问。真正部署到公网时，建议为 API 单独配置 HTTPS 入口；不要把 SMTP/IMAP 端口放进 Cloudflare Tunnel 的普通 HTTP 路由。
