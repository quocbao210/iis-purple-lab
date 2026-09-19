using System.Diagnostics;
using System.Text;
using System.Text.RegularExpressions;

namespace IisPurpleLab;

public sealed record LaunchSpec(string Image, IReadOnlyList<string> Arguments, string WorkingDirectory,
                                IReadOnlyDictionary<string, string> Environment, string? ShellArguments = null)
{
    public string CommandLine => Image + " " + (ShellArguments ?? string.Join(" ", Arguments.Select(a => "\"" + a.Replace("\"", "\\\"") + "\"")));
}
public sealed record LaunchStarted(int ChildPid, DateTimeOffset Start, DateTimeOffset End);
public sealed record LaunchResult(int ExitCode, string Output, string Error);
public interface IProcessLauncher
{
    Task<LaunchResult> Run(LaunchSpec spec, Action<LaunchStarted> started, CancellationToken cancellation);
}
public sealed class WindowsProcessLauncher : IProcessLauncher
{
    public async Task<LaunchResult> Run(LaunchSpec spec, Action<LaunchStarted> started, CancellationToken cancellation)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("Native process scenarios require the disposable Windows VM.");
        var info = new ProcessStartInfo(spec.Image) { UseShellExecute = false, CreateNoWindow = true,
            RedirectStandardOutput = true, RedirectStandardError = true, WorkingDirectory = spec.WorkingDirectory };
        if (spec.ShellArguments != null) info.Arguments = spec.ShellArguments;
        else foreach (var arg in spec.Arguments) info.ArgumentList.Add(arg);
        foreach (var (key, value) in spec.Environment) info.Environment[key] = value;
        var begin = DateTimeOffset.UtcNow;
        using var process = Process.Start(info) ?? throw new InvalidOperationException("Process did not start.");
        started(new(process.Id, begin, DateTimeOffset.UtcNow));
        var output = ReadBounded(process.StandardOutput, cancellation);
        var error = ReadBounded(process.StandardError, cancellation);
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellation);
        timeout.CancelAfter(TimeSpan.FromSeconds(20));
        try { await process.WaitForExitAsync(timeout.Token); }
        catch (OperationCanceledException) { if (!process.HasExited) process.Kill(entireProcessTree: true); throw; }
        return new(process.ExitCode, await output, await error);
    }
    private static async Task<string> ReadBounded(StreamReader reader, CancellationToken token)
    {
        var result = new StringBuilder(); var buffer = new char[1024]; int count;
        while ((count = await reader.ReadAsync(buffer.AsMemory(), token)) > 0)
            if (result.Length < 16384) result.Append(buffer, 0, Math.Min(count, 16384 - result.Length));
        return result.ToString();
    }
}
public sealed record ReportRequest(int TicketId, string Title, bool Helper = false);
public sealed class ReportService(LabSettings settings, IProcessLauncher launcher, SecurityEvents events, LabStore store)
{
    public static bool ValidTitle(string? title) => title != null && Regex.IsMatch(title, "\\A[A-Za-z0-9 _-]{1,60}\\z", RegexOptions.CultureInvariant);
    public async Task<IResult> Generate(HttpContext context, Ticket ticket, ReportRequest request)
    {
        var title = request.Title;
        if (title == null || title.Length > 512 || title.Contains('\r') || title.Contains('\n') || title.Contains('\0')) {
            events.Write(context, "report_request", "denied", ticket, new Dictionary<string, object?> { ["reason"] = "invalid_length_or_controls" });
            return Results.BadRequest(new { error = "Title must contain 1 to 512 printable characters." });
        }
        var job = Guid.NewGuid().ToString("N");
        var fields = new Dictionary<string, object?> { ["job_id"] = job, ["report_title"] = title };
        if ((!settings.Vulnerable || request.Helper) && !ValidTitle(title)) {
            events.Write(context, "report_request", "denied", ticket, fields);
            return Results.BadRequest(new { error = "Title must contain 1 to 60 letters, digits, spaces, underscores or hyphens." });
        }
        events.Write(context, "report_request", "allowed", ticket, fields);
        var output = Path.Combine(settings.ExportRoot, job + ".csv");
        LaunchSpec? spec = null;
        if (request.Helper) {
            spec = new(Path.Combine(settings.AppRoot, "IisPurpleLab.exe"), ["--helper-export", output, title], settings.WorkRoot,
                new Dictionary<string, string> { ["PurpleLab__DataRoot"] = settings.DataRoot });
        } else if (settings.Vulnerable) {
            // Intentional, isolated CWE-78 teaching flaw. Never reuse this pattern in a real application.
            spec = new(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "cmd.exe"),
                [], settings.WorkRoot, new Dictionary<string, string> { ["PURPLELAB_WORK"] = settings.WorkRoot },
                $"/d /c echo {title}>\"{output}\"");
        }
        if (spec == null) {
            await File.WriteAllTextAsync(output, $"ticket_id,title\n{ticket.Id},{title}\n", context.RequestAborted);
            store.SaveExport(job, ticket.Id, Path.GetFileName(output));
            events.Write(context, "report_completed", "completed", ticket, fields);
            return Results.Ok(new { job_id = job, request_id = context.TraceIdentifier, export = Path.GetFileName(output), helper = false });
        }
        try {
            var result = await launcher.Run(spec, start => {
                events.Write(context, "process_launch", "started", ticket, new Dictionary<string, object?> {
                    ["job_id"] = job, ["child_pid"] = start.ChildPid, ["launch_start"] = start.Start.ToString("O"),
                    ["launch_end"] = start.End.ToString("O"), ["image"] = spec.Image,
                    ["command_line"] = spec.CommandLine
                });
            }, context.RequestAborted);
            fields["exit_code"] = result.ExitCode;
            if (result.ExitCode == 0 && File.Exists(output)) store.SaveExport(job, ticket.Id, Path.GetFileName(output));
            events.Write(context, "report_completed", result.ExitCode == 0 ? "completed" : "failed", ticket, fields);
            return Results.Json(new { job_id = job, request_id = context.TraceIdentifier, exit_code = result.ExitCode,
                output = result.Output, error = result.Error, export = File.Exists(output) ? Path.GetFileName(output) : null }, statusCode: result.ExitCode == 0 ? 200 : 422);
        } catch (PlatformNotSupportedException) {
            events.Write(context, "process_launch", "unavailable", ticket, fields);
            return Results.Json(new { error = "Native Windows process execution is unavailable; use the VM runbook." }, statusCode: 501);
        } catch (OperationCanceledException) {
            events.Write(context, "report_completed", "timeout", ticket, fields);
            return Results.Json(new { error = "Report process timed out or request was cancelled." }, statusCode: 504);
        } catch (System.ComponentModel.Win32Exception) {
            events.Write(context, "process_launch", "failed", ticket, fields);
            return Results.Json(new { error = "Process could not be started. Check native deployment and prevention evidence." }, statusCode: 502);
        }
    }
    public static int RunHelper(string[] args)
    {
        if (args.Length != 3 || !ValidTitle(args[2])) return 2;
        var root = Environment.GetEnvironmentVariable("PurpleLab__DataRoot");
        if (string.IsNullOrEmpty(root)) return 2;
        var exportRoot = Path.GetFullPath(Path.Combine(root, "exports")) + Path.DirectorySeparatorChar;
        var output = Path.GetFullPath(args[1]);
        if (!output.StartsWith(exportRoot, StringComparison.OrdinalIgnoreCase) || Path.GetExtension(output) != ".csv") return 2;
        File.WriteAllText(output, "title,status\n" + args[2] + ",synthetic export\n");
        return 0;
    }
}
