using System.Text;

namespace WpywMail.Native;

public static class AppLog
{
    private static readonly object Gate = new();
    private static string path = "";

    public static void Configure(AppConfig config)
    {
        Directory.CreateDirectory(config.DataDirectory);
        path = Path.Combine(config.DataDirectory, "service.log");
        Info("日志系统已启动。");
    }

    public static void Info(string message) => Write("信息", message);
    public static void Warn(string message) => Write("警告", message);
    public static void Error(string message) => Write("错误", message);

    private static void Write(string level, string message)
    {
        var line = $"{DateTimeOffset.Now:yyyy-MM-dd HH:mm:ss zzz} [{level}] {message}";
        Console.WriteLine(line);
        if (string.IsNullOrWhiteSpace(path)) return;
        try
        {
            lock (Gate) File.AppendAllText(path, line + Environment.NewLine, new UTF8Encoding(false));
        }
        catch { }
    }
}
