using System.Text;

namespace WpywMail.Native;

/// <summary>极简日志：控制台 + 文件（超过阈值自动滚动一次）。</summary>
public static class AppLog
{
    private const long MaxBytes = 20 * 1024 * 1024;
    private static readonly object Gate = new();
    private static string path = "";
    private static bool consoleEnabled = true;

    public static void Configure(AppConfig config, bool enableConsole = true)
    {
        Directory.CreateDirectory(config.DataDirectory);
        path = Path.Combine(config.DataDirectory, "service.log");
        consoleEnabled = enableConsole;
        Roll();
        Info($"日志系统已启动（版本 {BuildInfo.Version}）。");
    }

    public static void Info(string message) => Write("信息", message);
    public static void Warn(string message) => Write("警告", message);
    public static void Error(string message) => Write("错误", message);

    private static void Write(string level, string message)
    {
        var line = $"{DateTimeOffset.Now:yyyy-MM-dd HH:mm:ss zzz} [{level}] {message}";
        if (consoleEnabled)
        {
            try { Console.WriteLine(line); } catch { }
        }
        if (string.IsNullOrWhiteSpace(path)) return;
        try
        {
            lock (Gate) File.AppendAllText(path, line + Environment.NewLine, new UTF8Encoding(false));
        }
        catch { }
    }

    private static void Roll()
    {
        try
        {
            if (!File.Exists(path)) return;
            var info = new FileInfo(path);
            if (info.Length < MaxBytes) return;
            var backup = path + ".1";
            if (File.Exists(backup)) File.Delete(backup);
            File.Move(path, backup);
        }
        catch { }
    }
}
