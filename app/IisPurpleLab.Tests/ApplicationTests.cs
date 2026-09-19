using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using IisPurpleLab;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using Xunit;

namespace IisPurpleLab.Tests;

public sealed class CaptureLauncher : IProcessLauncher
{
    public ConcurrentQueue<LaunchSpec> Launches { get; } = new();
    private int nextPid = 4000;
    public Task<LaunchResult> Run(LaunchSpec spec, Action<LaunchStarted> started, CancellationToken cancellation)
    {
        Launches.Enqueue(spec); var time = DateTimeOffset.UtcNow;
        started(new(Interlocked.Increment(ref nextPid), time, time.AddMilliseconds(1)));
        return Task.FromResult(new LaunchResult(0, "MOCK: no process executed", ""));
    }
}
public sealed class LabFactory(bool vulnerable = false) : WebApplicationFactory<Program>
{
    public const string Password = "Synthetic-Test-Only-Password-42";
    public string DataRoot { get; } = Path.Combine(Path.GetTempPath(), "iis-purple-tests", Guid.NewGuid().ToString("N"));
    public CaptureLauncher Launcher { get; } = new();
    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.ConfigureAppConfiguration((_, config) => config.AddInMemoryCollection(new Dictionary<string, string?> {
            ["PurpleLab:DataRoot"] = DataRoot, ["PurpleLab:Vulnerable"] = vulnerable.ToString(),
            ["PurpleLab:Acknowledgement"] = "I_ACCEPT_DISPOSABLE_LOCAL_LAB", ["PurpleLab:SeedPassword"] = Password
        }));
        builder.ConfigureServices(services => {
            services.RemoveAll<IProcessLauncher>(); services.AddSingleton<IProcessLauncher>(Launcher);
        });
    }
    public async Task<HttpClient> Login(string user = "alice")
    {
        var client = CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });
        client.DefaultRequestHeaders.Add("X-PurpleLab-Request", "1");
        var response = await client.PostAsJsonAsync("/api/login", new { username = user, password = Password });
        Assert.Equal(HttpStatusCode.OK, response.StatusCode); return client;
    }
    public JsonElement[] Events() => File.ReadAllLines(Path.Combine(DataRoot, "events", "application.jsonl"))
        .Select(s => JsonDocument.Parse(s).RootElement.Clone()).ToArray();
    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);
        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
        if (disposing && Directory.Exists(DataRoot)) Directory.Delete(DataRoot, true);
    }
}
public sealed class ApplicationTests
{
    [Theory]
    [InlineData(false, 403)] [InlineData(true, 200)]
    public async Task SameBolaRequestIsAllowedOnlyInDeliberateVulnerableMode(bool vulnerable, int expected)
    {
        using var app = new LabFactory(vulnerable); using var client = await app.Login();
        var result = await client.GetAsync("/api/tickets/2001"); Assert.Equal(expected, (int)result.StatusCode);
        var record = Assert.Single(app.Events(), e => e.GetProperty("action").GetString() == "ticket_access");
        Assert.False(record.GetProperty("policy_allowed").GetBoolean());
        Assert.Equal("alice", record.GetProperty("actor").GetString()); Assert.Empty(app.Launcher.Launches);
    }
    [Theory]
    [InlineData("alice",1001)] [InlineData("alice",2002)] [InlineData("bob",2001)] [InlineData("admin",2001)]
    public async Task SameTenantSharedAndAdministratorAreAllowed(string user, int ticket)
    {
        using var app = new LabFactory(); using var client = await app.Login(user);
        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync($"/api/tickets/{ticket}")).StatusCode);
        Assert.True(app.Events().Last().GetProperty("policy_allowed").GetBoolean());
    }
    [Fact]
    public async Task AttachmentAndListEnforceServerIdentityPolicy()
    {
        using var app = new LabFactory(); using var alice = await app.Login();
        alice.DefaultRequestHeaders.Add("X-Actor", "admin");
        Assert.Equal(HttpStatusCode.Forbidden, (await alice.GetAsync("/api/attachments/1")).StatusCode);
        var tickets = await alice.GetFromJsonAsync<Ticket[]>("/api/tickets"); Assert.DoesNotContain(tickets!, t => t.Id == 2001);
        using var bob = await app.Login("bob"); Assert.Equal(HttpStatusCode.OK, (await bob.GetAsync("/api/attachments/1")).StatusCode);
    }
    [Fact]
    public async Task LoginAndMutatingRequestsRequireRealCookieAndLocalRequestHeader()
    {
        using var app = new LabFactory(); using var client = app.CreateClient();
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.GetAsync("/api/tickets/1001")).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await client.PostAsJsonAsync("/api/login", new { username = "alice", password = LabFactory.Password })).StatusCode);
        client.DefaultRequestHeaders.Add("X-PurpleLab-Request", "1");
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.PostAsJsonAsync("/api/login", new { username = "alice", password = "wrong" })).StatusCode);
        Assert.DoesNotContain("wrong", File.ReadAllText(Path.Combine(app.DataRoot, "events", "application.jsonl")));
    }
    [Fact]
    public async Task OversizedRequestsAreRejectedBeforeAuthenticationAndIisHasTheSameLimit()
    {
        using var app = new LabFactory(); using var client = app.CreateClient();
        client.DefaultRequestHeaders.Add("X-PurpleLab-Request", "1");
        var response = await client.PostAsJsonAsync("/api/login", new { username = "alice", password = new string('a', 4096) });
        Assert.Equal(HttpStatusCode.RequestEntityTooLarge, response.StatusCode);
        Assert.False(File.Exists(Path.Combine(app.DataRoot, "events", "application.jsonl")));
        Assert.Empty(app.Launcher.Launches);
        // TestServer cannot prove native IIS enforcement; assert the IIS configuration separately.
        Assert.Equal(4096, app.Services.GetRequiredService<IOptions<IISServerOptions>>().Value.MaxRequestBodySize);
    }
    [Fact]
    public async Task RequestIdsAreServerGeneratedAndPasswordIsNotLogged()
    {
        using var app = new LabFactory(); using var client = await app.Login();
        client.DefaultRequestHeaders.Add("X-Request-ID", "attacker-chosen");
        var response = await client.GetAsync("/api/tickets/1001");
        var id = response.Headers.GetValues("X-Request-ID").Single(); Assert.NotEqual("attacker-chosen", id);
        Assert.True(Guid.TryParseExact(id, "N", out _));
        Assert.Equal(id, app.Events().Last().GetProperty("request_id").GetString());
        Assert.Equal("attacker-chosen", app.Events().Last().GetProperty("client_request_id").GetString());
        Assert.DoesNotContain(LabFactory.Password, File.ReadAllText(Path.Combine(app.DataRoot, "events", "application.jsonl")));
    }
    [Theory]
    [InlineData("monthly & whoami & rem ")] [InlineData("x|whoami")] [InlineData("../escape")]
    [InlineData("=formula")] [InlineData("line\nbreak")] [InlineData("x%COMSPEC%")]
    public async Task HardenedReportsRejectShellAndPathSyntaxWithoutLaunching(string title)
    {
        using var app = new LabFactory(); using var client = await app.Login();
        var result = await client.PostAsJsonAsync("/api/reports", new ReportRequest(1001, title));
        Assert.Equal(HttpStatusCode.BadRequest, result.StatusCode); Assert.Empty(app.Launcher.Launches);
        Assert.Equal("denied", app.Events().Last().GetProperty("outcome").GetString());
    }
    [Fact]
    public async Task VulnerableBoundaryActuallyInterpolatesTheSamePayloadIntoShellCommand()
    {
        using var app = new LabFactory(true); using var client = await app.Login();
        const string payload = "monthly & whoami & rem ";
        Assert.Equal(HttpStatusCode.OK, (await client.PostAsJsonAsync("/api/reports", new ReportRequest(1001, payload))).StatusCode);
        var launch = Assert.Single(app.Launcher.Launches); Assert.EndsWith("cmd.exe", launch.Image);
        Assert.Contains(payload, launch.ShellArguments); Assert.Empty(launch.Arguments);
        var record = Assert.Single(app.Events(), e => e.GetProperty("action").GetString() == "process_launch");
        foreach (var field in new[] { "request_id", "job_id", "child_pid", "parent_pid", "parent_start", "launch_start", "launch_end", "command_line", "host" })
            Assert.NotEqual(JsonValueKind.Null, record.GetProperty(field).ValueKind);
    }
    [Fact]
    public async Task ManagedReportAndDownloadPreserveResourceAuthorization()
    {
        using var app = new LabFactory(); using var bob = await app.Login("bob"); using var alice = await app.Login();
        var response = await bob.PostAsJsonAsync("/api/reports", new ReportRequest(2001, "Monthly service"));
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<JsonElement>(); var job = body.GetProperty("job_id").GetString();
        Assert.Equal(HttpStatusCode.Forbidden, (await alice.GetAsync($"/api/exports/{job}")).StatusCode);
        var csv = await bob.GetStringAsync($"/api/exports/{job}"); Assert.Contains("2001,Monthly service", csv);
        Assert.Empty(app.Launcher.Launches);
        Assert.Equal(HttpStatusCode.Forbidden, (await alice.PostAsJsonAsync("/api/reports", new ReportRequest(2001, "Monthly service"))).StatusCode);
    }
    [Fact]
    public async Task LegitimateHelperUsesFixedExecutableAndSeparatedArguments()
    {
        using var app = new LabFactory(); using var client = await app.Login();
        var result = await client.PostAsJsonAsync("/api/reports", new ReportRequest(1001, "Monthly service", true));
        Assert.Equal(HttpStatusCode.OK, result.StatusCode);
        var launch = Assert.Single(app.Launcher.Launches); Assert.EndsWith("IisPurpleLab.exe", launch.Image);
        Assert.Null(launch.ShellArguments); Assert.Equal("--helper-export", launch.Arguments[0]); Assert.Equal("Monthly service", launch.Arguments[2]);
        Assert.StartsWith(Path.Combine(app.DataRoot, "exports"), launch.Arguments[1]);
    }
    [Fact]
    public async Task ConcurrentLaunchesHaveIndependentRequestJobAndChildIdentities()
    {
        using var app = new LabFactory(); using var client = await app.Login();
        await Task.WhenAll(Enumerable.Range(0, 8).Select(i => client.PostAsJsonAsync("/api/reports", new ReportRequest(1001, "Export " + i, true))));
        var records = app.Events().Where(e => e.GetProperty("action").GetString() == "process_launch").ToArray();
        Assert.Equal(8, records.Length);
        foreach (var key in new[] { "request_id", "job_id", "child_pid" }) Assert.Equal(8, records.Select(r => r.GetProperty(key).ToString()).Distinct().Count());
    }
    [Fact]
    public void VulnerableModeRequiresExplicitAcknowledgement()
    {
        var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> { ["PurpleLab:Vulnerable"] = "true" }).Build();
        Assert.Throws<InvalidOperationException>(() => LabSettings.Read(config));
    }
    [Fact]
    public async Task RealLauncherRefusesNonWindowsExecution()
    {
        if (OperatingSystem.IsWindows()) return; // Real execution stays in the disposable VM, including on Windows CI.
        await Assert.ThrowsAsync<PlatformNotSupportedException>(() => new WindowsProcessLauncher().Run(
            new("cmd.exe", [], Path.GetTempPath(), new Dictionary<string, string>()), _ => Assert.Fail("Must not start"), CancellationToken.None));
    }
}
