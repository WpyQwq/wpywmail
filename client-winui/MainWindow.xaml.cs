using System.Collections.ObjectModel;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;
using Windows.System;

namespace WpywMail.Client;

public sealed partial class MainWindow : Window
{
    private readonly ObservableCollection<MailSummary> messages = [];
    private ApiClient api = new();
    private string folder = "inbox";
    private CancellationTokenSource? searchCancellation;

    public MainWindow()
    {
        InitializeComponent();
        MessageList.ItemsSource = messages;
    }

    private async void LoginButton_Click(object sender, RoutedEventArgs e) => await LoginAsync();

    private async void PasswordBox_KeyDown(object sender, KeyRoutedEventArgs e)
    {
        if (e.Key == VirtualKey.Enter) await LoginAsync();
    }

    private async Task LoginAsync()
    {
        var email = EmailBox.Text.Trim();
        var password = PasswordBox.Password;
        if (string.IsNullOrWhiteSpace(email) || string.IsNullOrWhiteSpace(password))
        {
            LoginStatus.Text = "请输入邮箱和密码。";
            return;
        }

        LoginButton.IsEnabled = false;
        LoginStatus.Text = "正在连接邮箱服务…";
        try
        {
            api.SetBaseUrl(ApiUrlBox.Text);
            var result = await api.LoginAsync(email, password);
            api.SetToken(result.Token);
            AccountText.Text = result.User.Email;
            LoginView.Visibility = Visibility.Collapsed;
            ShellView.Visibility = Visibility.Visible;
            LoginStatus.Text = "";
            await RefreshAsync();
        }
        catch (Exception ex)
        {
            LoginStatus.Text = ex.Message.Contains("无法连接", StringComparison.OrdinalIgnoreCase)
                ? "无法连接服务端，请检查地址、端口和服务状态。"
                : ex.Message;
        }
        finally { LoginButton.IsEnabled = true; }
    }

    private async Task RefreshAsync()
    {
        try
        {
            var me = await api.GetMeAsync();
            InboxCount.Text = me.Stats.Unread > 0 ? me.Stats.Unread.ToString() : "";
            await LoadFolderAsync(folder, SearchBox.Text);
            ConnectionText.Text = "已连接";
            ConnectionText.Foreground = (Microsoft.UI.Xaml.Media.Brush)Application.Current.Resources["AccentBrush"];
        }
        catch (Exception ex)
        {
            ConnectionText.Text = ex.Message;
            ConnectionText.Foreground = (Microsoft.UI.Xaml.Media.Brush)Application.Current.Resources["DangerBrush"];
        }
    }

    private async Task LoadFolderAsync(string selectedFolder, string query = "")
    {
        try
        {
            var result = await api.GetMessagesAsync(selectedFolder, query);
            messages.Clear();
            foreach (var message in result) messages.Add(message);
            FolderTitle.Text = selectedFolder switch
            {
                "sent" => "已发送",
                "drafts" => "草稿",
                "archive" => "归档",
                "trash" => "垃圾箱",
                _ => "收件箱"
            };
            FolderSubtitle.Text = messages.Count == 0 ? "暂无邮件" : $"{messages.Count} 封邮件";
        }
        catch (Exception ex)
        {
            ConnectionText.Text = ex.Message;
            ConnectionText.Foreground = (Microsoft.UI.Xaml.Media.Brush)Application.Current.Resources["DangerBrush"];
        }
    }

    private async void FolderButton_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not Button button || button.Tag is not string selectedFolder) return;
        folder = selectedFolder;
        EmptyReadingPane.Visibility = Visibility.Visible;
        ReadingPane.Visibility = Visibility.Collapsed;
        await LoadFolderAsync(folder, SearchBox.Text);
    }

    private async void MessageList_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (MessageList.SelectedItem is not MailSummary summary) return;
        try
        {
            var message = await api.GetMessageAsync(summary.Id);
            ReadingSubject.Text = message.Subject;
            ReadingInitials.Text = message.Initials;
            ReadingFrom.Text = message.From;
            ReadingDate.Text = message.Date.ToLocalTime().ToString("yyyy-MM-dd HH:mm");
            ReadingBody.Text = message.Text;
            EmptyReadingPane.Visibility = Visibility.Collapsed;
            ReadingPane.Visibility = Visibility.Visible;
            summary.Unread = false;
            MessageList.SelectedItem = null;
        }
        catch (Exception ex) { ConnectionText.Text = ex.Message; }
    }

    private async void RefreshButton_Click(object sender, RoutedEventArgs e) => await RefreshAsync();

    private async void SearchBox_TextChanged(object sender, TextChangedEventArgs e)
    {
        searchCancellation?.Cancel();
        searchCancellation = new CancellationTokenSource();
        var token = searchCancellation.Token;
        try
        {
            await Task.Delay(260, token);
            await LoadFolderAsync(folder, SearchBox.Text);
        }
        catch (OperationCanceledException) { }
    }

    private async void LogoutButton_Click(object sender, RoutedEventArgs e)
    {
        await api.LogoutAsync();
        messages.Clear();
        ShellView.Visibility = Visibility.Collapsed;
        LoginView.Visibility = Visibility.Visible;
        PasswordBox.Password = "";
        LoginStatus.Text = "已退出登录。";
    }

    private async void SettingsButton_Click(object sender, RoutedEventArgs e)
    {
        ConfigResponse config;
        try { config = await api.GetConfigAsync(); }
        catch (Exception ex)
        {
            ConnectionText.Text = ex.Message;
            ConnectionText.Foreground = (Microsoft.UI.Xaml.Media.Brush)Application.Current.Resources["DangerBrush"];
            return;
        }
        var newPassword = new PasswordBox { PlaceholderText = "新密码（至少 12 位）", MinWidth = 360 };
        var content = new StackPanel { Spacing = 12, Width = 430 };
        content.Children.Add(new TextBlock { Text = $"账户\n{config.Account}", Foreground = (Microsoft.UI.Xaml.Media.Brush)Application.Current.Resources["TextSecondaryBrush"] });
        content.Children.Add(new TextBlock { Text = $"域名：{config.Domain}\n主机名：{config.Hostname}\nSMTP：{config.Protocols.Smtp}    提交端口：{config.Protocols.Submission}", Foreground = (Microsoft.UI.Xaml.Media.Brush)Application.Current.Resources["TextTertiaryBrush"] });
        content.Children.Add(new Border { Height = 1, Background = (Microsoft.UI.Xaml.Media.Brush)Application.Current.Resources["StrokeBrush"] });
        content.Children.Add(new TextBlock { Text = "修改密码", FontWeight = Microsoft.UI.Text.FontWeights.SemiBold });
        content.Children.Add(newPassword);

        var dialog = new ContentDialog
        {
            Title = "账户与服务",
            Content = content,
            PrimaryButtonText = "保存密码",
            CloseButtonText = "关闭",
            DefaultButton = ContentDialogButton.Close,
            XamlRoot = Content.XamlRoot
        };
        if (await dialog.ShowAsync() != ContentDialogResult.Primary || string.IsNullOrWhiteSpace(newPassword.Password)) return;
        if (newPassword.Password.Length < 12)
        {
            ConnectionText.Text = "密码至少需要 12 位。";
            ConnectionText.Foreground = (Microsoft.UI.Xaml.Media.Brush)Application.Current.Resources["DangerBrush"];
            return;
        }
        try
        {
            await api.ChangePasswordAsync(newPassword.Password);
            ConnectionText.Text = "密码已更新。下次登录请使用新密码。";
            ConnectionText.Foreground = (Microsoft.UI.Xaml.Media.Brush)Application.Current.Resources["AccentBrush"];
        }
        catch (Exception ex)
        {
            ConnectionText.Text = ex.Message;
            ConnectionText.Foreground = (Microsoft.UI.Xaml.Media.Brush)Application.Current.Resources["DangerBrush"];
        }
    }

    private async void ComposeButton_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new ContentDialog
        {
            Title = "写信",
            PrimaryButtonText = "发送",
            CloseButtonText = "取消",
            DefaultButton = ContentDialogButton.Primary,
            XamlRoot = Content.XamlRoot,
            Content = new ComposeView()
        };
        if (await dialog.ShowAsync() != ContentDialogResult.Primary || dialog.Content is not ComposeView compose) return;
        if (string.IsNullOrWhiteSpace(compose.ToBox.Text) || string.IsNullOrWhiteSpace(compose.SubjectBox.Text) || string.IsNullOrWhiteSpace(compose.BodyBox.Text))
        {
            ConnectionText.Text = "收件人、主题和正文不能为空。";
            return;
        }

        try
        {
            await api.SendMessageAsync(compose.ToBox.Text, compose.SubjectBox.Text, compose.BodyBox.Text);
            ConnectionText.Text = "邮件已加入发送队列。";
            if (folder == "sent") await LoadFolderAsync(folder, SearchBox.Text);
        }
        catch (Exception ex) { ConnectionText.Text = ex.Message; }
    }
}

public sealed class ComposeView : StackPanel
{
    public TextBox ToBox { get; } = new() { PlaceholderText = "收件人，例如 someone@example.com" };
    public TextBox SubjectBox { get; } = new() { PlaceholderText = "主题" };
    public TextBox BodyBox { get; } = new() { PlaceholderText = "正文", AcceptsReturn = true, TextWrapping = TextWrapping.Wrap, MinHeight = 180 };

    public ComposeView()
    {
        Spacing = 10;
        Width = 520;
        Children.Add(ToBox);
        Children.Add(SubjectBox);
        Children.Add(BodyBox);
    }
}
