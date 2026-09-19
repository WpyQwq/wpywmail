using System.Diagnostics;
using System.Reflection;
using System.IO.Compression;

namespace WpywMail.Installer;

internal static class Program
{
    public static int Main()
    {
        try
        {
            var root = Path.Combine(Path.GetTempPath(), "WpywMailInstaller", Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(root);
            using var resource = Assembly.GetExecutingAssembly().GetManifestResourceStream("WpywMail.Installer.Payload.zip") ?? throw new InvalidOperationException("安装包内容缺失。");
            var zip = Path.Combine(root, "payload.zip");
            using (var output = File.Create(zip)) resource.CopyTo(output);
            ZipFile.ExtractToDirectory(zip, root);
            File.Delete(zip);

            var script = Path.Combine(root, "install.ps1");
            var psi = new ProcessStartInfo
            {
                FileName = "powershell.exe",
                Arguments = $"-NoProfile -ExecutionPolicy Bypass -File \"{script}\"",
                WorkingDirectory = root,
                UseShellExecute = true,
                Verb = "runas",
            };
            using var process = Process.Start(psi) ?? throw new InvalidOperationException("无法启动安装程序。");
            process.WaitForExit();
            if (process.ExitCode != 0)
            {
                Console.Error.WriteLine($"安装程序返回错误代码：{process.ExitCode}");
            }
            return process.ExitCode;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine(ex.Message);
            Console.Error.WriteLine("安装程序无法启动。");
            Console.Error.WriteLine("请记录上面的错误信息，然后按任意键退出。");
            try { Console.ReadKey(intercept: true); } catch { }
            return 1;
        }
    }
}
