using System.Text.Json;

namespace WpywMail.Native;

public static class Program
{
    public static async Task Main()
    {
        var settingsPath = Path.Combine(AppContext.BaseDirectory, "appsettings.json");
        if (!File.Exists(settingsPath)) throw new FileNotFoundException("请将 appsettings.example.json 复制为 appsettings.json 并填写密码。", settingsPath);
        var config = JsonSerializer.Deserialize<AppConfig>(await File.ReadAllTextAsync(settingsPath), new JsonSerializerOptions(JsonSerializerDefaults.Web)) ?? throw new InvalidOperationException("无法读取 appsettings.json");
        if (config.AdminPassword.Length < 12 || config.AdminPassword.Contains("replace-with", StringComparison.OrdinalIgnoreCase)) throw new InvalidOperationException("请在 appsettings.json 设置至少 12 位 AdminPassword。");
        AppLog.Configure(config);
        var store = new FileStore(config);
        using var cancellation = new CancellationTokenSource();
        Console.CancelKeyPress += (_, e) => { e.Cancel = true; cancellation.Cancel(); };
        var api = new ApiServer(config, store);
        var smtp = new SmtpServer(config, store);
        var queue = new DeliveryQueue(config, store);
        AppLog.Info($"中文邮箱服务正在启动，域名：{config.Domain}，主机名：{config.Hostname}");
        await Task.WhenAll(api.RunAsync(cancellation.Token), smtp.RunAsync(cancellation.Token), queue.RunAsync(cancellation.Token));
    }
}
