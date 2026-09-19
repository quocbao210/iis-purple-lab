using System.Diagnostics;
using System.Text.Json;

namespace IisPurpleLab;

public sealed class SecurityEvents(LabSettings settings)
{
    private readonly object gate = new();
    public string FilePath { get; } = Path.Combine(settings.DataRoot, "events", "application.jsonl");
    public void Write(HttpContext context, string action, string outcome, Ticket? ticket = null,
                      IReadOnlyDictionary<string, object?>? extra = null)
    {
        Actor? actor = context.User.Identity?.IsAuthenticated == true ? Actor.From(context.User) : null;
        var suppliedId = context.Request.Headers["X-Request-ID"].FirstOrDefault();
        var untrustedId = suppliedId == null ? null : new string(suppliedId.Where(c => !char.IsControl(c)).Take(128).ToArray());
        var fields = new Dictionary<string, object?> {
            ["source"] = "application", ["timestamp"] = DateTimeOffset.UtcNow.ToString("O"),
            ["host"] = Environment.MachineName, ["action"] = action, ["outcome"] = outcome,
            ["request_id"] = context.TraceIdentifier,
            ["client_request_id"] = untrustedId,
            ["actor"] = actor?.Name, ["actor_tenant"] = actor?.Tenant, ["role"] = actor?.Role,
            ["resource_id"] = ticket?.Id.ToString(), ["resource_tenant"] = ticket?.Tenant,
            ["shared_with"] = ticket?.SharedWith, ["policy_allowed"] = actor != null && ticket != null ? AccessPolicy.CanRead(actor, ticket) : null,
            ["pid"] = Environment.ProcessId, ["parent_pid"] = Environment.ProcessId,
            ["parent_start"] = Process.GetCurrentProcess().StartTime.ToUniversalTime().ToString("O"),
            ["app_root"] = settings.AppRoot, ["data_root"] = settings.DataRoot
        };
        if (extra != null) foreach (var (key, value) in extra) fields[key] = value;
        lock (gate) File.AppendAllText(FilePath, JsonSerializer.Serialize(fields) + "\n");
    }
}
