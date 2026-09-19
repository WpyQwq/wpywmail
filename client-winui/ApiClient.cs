using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;

namespace WpywMail.Client;

public sealed class ApiClient
{
    private readonly HttpClient http = new() { Timeout = TimeSpan.FromSeconds(12) };
    private readonly JsonSerializerOptions json = new(JsonSerializerDefaults.Web);
    private string token = "";

    public string BaseUrl { get; private set; }

    public ApiClient(string baseUrl = "http://127.0.0.1:8787/api")
    {
        BaseUrl = NormalizeBaseUrl(baseUrl);
    }

    public void SetBaseUrl(string baseUrl) => BaseUrl = NormalizeBaseUrl(baseUrl);

    public async Task<LoginResponse> LoginAsync(string email, string password, CancellationToken cancellationToken = default)
    {
        using var response = await http.PostAsJsonAsync($"{BaseUrl}/login", new { email, password }, json, cancellationToken);
        return await ReadOrThrow<LoginResponse>(response, cancellationToken);
    }

    public async Task<MeResponse> GetMeAsync(CancellationToken cancellationToken = default) =>
        await SendAsync<MeResponse>(HttpMethod.Get, "/me", cancellationToken: cancellationToken);

    public async Task<ConfigResponse> GetConfigAsync(CancellationToken cancellationToken = default) =>
        await SendAsync<ConfigResponse>(HttpMethod.Get, "/config", cancellationToken: cancellationToken);

    public async Task<IReadOnlyList<MailSummary>> GetMessagesAsync(string folder, string query = "", CancellationToken cancellationToken = default)
    {
        var url = $"/messages?folder={Uri.EscapeDataString(folder)}";
        if (!string.IsNullOrWhiteSpace(query)) url += $"&q={Uri.EscapeDataString(query)}";
        var result = await SendAsync<MessageListResponse>(HttpMethod.Get, url, cancellationToken: cancellationToken);
        return result.Messages;
    }

    public async Task<MailMessage> GetMessageAsync(string id, CancellationToken cancellationToken = default)
    {
        var result = await SendAsync<MessageDetailResponse>(HttpMethod.Get, $"/messages/{Uri.EscapeDataString(id)}", cancellationToken: cancellationToken);
        return result.Message;
    }

    public async Task SendMessageAsync(string to, string subject, string text, CancellationToken cancellationToken = default) =>
        await SendAsync<object>(HttpMethod.Post, "/send", new { to, subject, text }, cancellationToken);

    public async Task ChangePasswordAsync(string password, CancellationToken cancellationToken = default) =>
        await SendAsync<object>(HttpMethod.Post, "/account/password", new { password }, cancellationToken);

    public async Task LogoutAsync(CancellationToken cancellationToken = default)
    {
        try { await SendAsync<object>(HttpMethod.Post, "/logout", cancellationToken: cancellationToken); }
        finally { token = ""; }
    }

    public void SetToken(string value)
    {
        token = value;
        http.DefaultRequestHeaders.Authorization = string.IsNullOrWhiteSpace(token) ? null : new AuthenticationHeaderValue("Bearer", token);
    }

    private async Task<T> SendAsync<T>(HttpMethod method, string path, object? body = null, CancellationToken cancellationToken = default)
    {
        using var request = new HttpRequestMessage(method, $"{BaseUrl}{path}");
        if (body is not null) request.Content = JsonContent.Create(body, options: json);
        using var response = await http.SendAsync(request, cancellationToken);
        return await ReadOrThrow<T>(response, cancellationToken);
    }

    private async Task<T> ReadOrThrow<T>(HttpResponseMessage response, CancellationToken cancellationToken)
    {
        if (response.IsSuccessStatusCode)
        {
            var result = await response.Content.ReadFromJsonAsync<T>(json, cancellationToken);
            return result ?? throw new InvalidOperationException("服务端返回了空响应");
        }

        var message = await response.Content.ReadAsStringAsync(cancellationToken);
        try
        {
            var error = JsonSerializer.Deserialize<Dictionary<string, string>>(message, json);
            if (error?.TryGetValue("error", out var detail) == true) throw new InvalidOperationException(detail);
        }
        catch (JsonException) { }
        throw new InvalidOperationException($"服务端返回 HTTP {(int)response.StatusCode}");
    }

    private static string NormalizeBaseUrl(string value)
    {
        var url = string.IsNullOrWhiteSpace(value) ? "http://127.0.0.1:8787/api" : value.Trim().TrimEnd('/');
        return url.EndsWith("/api", StringComparison.OrdinalIgnoreCase) ? url : $"{url}/api";
    }
}
