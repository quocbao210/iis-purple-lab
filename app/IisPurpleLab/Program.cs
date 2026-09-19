using System.Diagnostics;
using System.Net;
using System.Security.Claims;
using System.Security.Principal;
using IisPurpleLab;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.AspNetCore.Server.IIS;
using Microsoft.Extensions.Options;

if (args.FirstOrDefault() == "--helper-export") return ReportService.RunHelper(args);
var builder = WebApplication.CreateBuilder(args);
builder.WebHost.ConfigureKestrel(options => options.Limits.MaxRequestBodySize = 4096);
builder.Services.AddSingleton(sp => LabSettings.Read(sp.GetRequiredService<IConfiguration>()));
builder.Services.AddSingleton<LabStore>();
builder.Services.AddSingleton<SecurityEvents>();
builder.Services.AddSingleton<IProcessLauncher, WindowsProcessLauncher>();
builder.Services.AddSingleton<ReportService>();
builder.Services.AddDataProtection().SetApplicationName("IIS Purple Lab");
builder.Services.AddSingleton<IConfigureOptions<KeyManagementOptions>, LabKeyStorage>();
builder.Services.Configure<IISServerOptions>(options => {
    options.AutomaticAuthentication = false;
    // In-process IIS does not use Kestrel's limits, including for chunked requests.
    options.MaxRequestBodySize = 4096;
});
builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme).AddCookie(options => {
    options.Cookie.Name = "IisPurpleLab.Session";
    options.Cookie.HttpOnly = true; options.Cookie.SameSite = SameSiteMode.Strict;
    options.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
    options.ExpireTimeSpan = TimeSpan.FromMinutes(30); options.SlidingExpiration = false;
    options.Events.OnRedirectToLogin = ctx => { ctx.Response.StatusCode = 401; return Task.CompletedTask; };
    options.Events.OnRedirectToAccessDenied = ctx => { ctx.Response.StatusCode = 403; return Task.CompletedTask; };
});
builder.Services.AddAuthorization();
var app = builder.Build();
_ = app.Services.GetRequiredService<LabStore>();
app.Use(async (context, next) => {
    context.TraceIdentifier = Guid.NewGuid().ToString("N");
    context.Response.Headers["X-Request-ID"] = context.TraceIdentifier;
    context.Response.Headers["Cache-Control"] = "no-store";
    context.Response.Headers["X-Content-Type-Options"] = "nosniff";
    var peer = context.Connection.RemoteIpAddress;
    if (peer != null && !IPAddress.IsLoopback(peer)) { context.Response.StatusCode = 403; return; }
    if (context.Request.ContentLength > 4096) { context.Response.StatusCode = 413; return; }
    if (HttpMethods.IsPost(context.Request.Method) && context.Request.Headers["X-PurpleLab-Request"] != "1") {
        context.Response.StatusCode = 400; return;
    }
    await next(context);
});
app.UseAuthentication(); app.UseAuthorization();
app.MapGet("/", () => Results.Content("IIS Purple Lab synthetic support portal. See /health and the repository's scenarios/run.py client.", "text/plain"));
app.MapGet("/health", (LabSettings settings) => {
    string? identity = null; bool? admin = null; bool? system = null;
    if (OperatingSystem.IsWindows()) {
        using var token = WindowsIdentity.GetCurrent(); identity = token.Name; system = token.IsSystem;
        admin = new WindowsPrincipal(token).IsInRole(WindowsBuiltInRole.Administrator);
    }
    return Results.Ok(new { status = "ok", process_id = Environment.ProcessId,
        process_name = Process.GetCurrentProcess().ProcessName, windows_identity = identity, is_admin = admin,
        is_system = system, mode = settings.Vulnerable ? "vulnerable" : "hardened", data_root = settings.DataRoot });
});
app.MapPost("/api/login", async (HttpContext context, LoginRequest request, LabStore store, SecurityEvents events) => {
    if (request.Username == null || request.Password == null || request.Username.Length > 80 || request.Password.Length > 200) return Results.BadRequest();
    var user = store.Authenticate(request.Username, request.Password);
    if (user == null) { events.Write(context, "login", "denied"); return Results.Unauthorized(); }
    var identity = new ClaimsIdentity([new(ClaimTypes.Name, user.Name), new("tenant", user.Tenant), new(ClaimTypes.Role, user.Role)], CookieAuthenticationDefaults.AuthenticationScheme);
    context.User = new ClaimsPrincipal(identity);
    await context.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, context.User);
    events.Write(context, "login", "allowed");
    return Results.Ok(new { user = user.Name, tenant = user.Tenant, role = user.Role });
});
app.MapPost("/api/logout", async (HttpContext context) => { await context.SignOutAsync(); return Results.Ok(); }).RequireAuthorization();
app.MapGet("/api/tickets", (HttpContext context, LabStore store) => Results.Ok(store.GetTickets().Where(t => AccessPolicy.CanRead(Actor.From(context.User), t)))).RequireAuthorization();
app.MapGet("/api/tickets/{id:int}", (int id, HttpContext context, LabStore store, LabSettings settings, SecurityEvents events) => {
    var ticket = store.GetTicket(id); if (ticket == null) return Results.NotFound();
    var allowed = settings.Vulnerable || AccessPolicy.CanRead(Actor.From(context.User), ticket);
    events.Write(context, "ticket_access", allowed ? "allowed" : "denied", ticket);
    return allowed ? Results.Ok(ticket) : Results.StatusCode(403);
}).RequireAuthorization();
app.MapGet("/api/attachments/{id:int}", (int id, HttpContext context, LabStore store, LabSettings settings, SecurityEvents events) => {
    var attachment = store.GetAttachment(id); if (attachment == null) return Results.NotFound();
    var ticket = store.GetTicket(attachment.TicketId)!;
    var allowed = settings.Vulnerable || AccessPolicy.CanRead(Actor.From(context.User), ticket);
    events.Write(context, "attachment_access", allowed ? "allowed" : "denied", ticket,
        new Dictionary<string, object?> { ["attachment_id"] = id });
    return allowed ? Results.File(attachment.Content, "text/plain", attachment.Name) : Results.StatusCode(403);
}).RequireAuthorization();
app.MapPost("/api/reports", async (ReportRequest request, HttpContext context, LabStore store, LabSettings settings, SecurityEvents events, ReportService reports) => {
    var ticket = store.GetTicket(request.TicketId); if (ticket == null) return Results.NotFound();
    var allowed = settings.Vulnerable || AccessPolicy.CanRead(Actor.From(context.User), ticket);
    if (!allowed) { events.Write(context, "report_request", "denied", ticket); return Results.StatusCode(403); }
    return await reports.Generate(context, ticket, request);
}).RequireAuthorization();
app.MapGet("/api/exports/{job}", (string job, HttpContext context, LabStore store, LabSettings settings, SecurityEvents events) => {
    if (!Guid.TryParseExact(job, "N", out _)) return Results.NotFound();
    var export = store.GetExport(job); if (export == null) return Results.NotFound();
    var ticket = store.GetTicket(export.Value.TicketId)!;
    var allowed = settings.Vulnerable || AccessPolicy.CanRead(Actor.From(context.User), ticket);
    events.Write(context, "export_access", allowed ? "allowed" : "denied", ticket, new Dictionary<string, object?> { ["job_id"] = job });
    return allowed ? Results.File(Path.Combine(settings.ExportRoot, export.Value.Filename), "text/csv", export.Value.Filename) : Results.StatusCode(403);
}).RequireAuthorization();
app.Run();
return 0;

public sealed record LoginRequest(string Username, string Password);
public partial class Program { }
