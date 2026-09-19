using Microsoft.UI.Xaml;

namespace WpywMail.Client;

public partial class App : Application
{
    public static Window? MainWindow { get; private set; }

    public App()
    {
        UnhandledException += (_, args) =>
        {
            try { File.AppendAllText(Path.Combine(Path.GetTempPath(), "WpywMail.Client-error.log"), $"{DateTime.Now:O}\r\n{args.Exception}\r\n\r\n"); } catch { }
        };
        AppDomain.CurrentDomain.UnhandledException += (_, args) =>
        {
            try { File.AppendAllText(Path.Combine(Path.GetTempPath(), "WpywMail.Client-error.log"), $"{DateTime.Now:O}\r\n{args.ExceptionObject}\r\n\r\n"); } catch { }
        };
        InitializeComponent();
    }

    protected override void OnLaunched(LaunchActivatedEventArgs args)
    {
        MainWindow = new MainWindow();
        MainWindow.Activate();
    }
}
