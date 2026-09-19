using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Identity;
using Microsoft.Data.Sqlite;

namespace IisPurpleLab;

public sealed record LabUser(string Name, string Tenant, string Role, string PasswordHash);
public sealed record Ticket(int Id, string Tenant, string Subject, string Body, string[] SharedWith);
public sealed record Attachment(int Id, int TicketId, string Name, byte[] Content);
public sealed record Actor(string Name, string Tenant, string Role)
{
    public static Actor From(ClaimsPrincipal user) => new(user.Identity!.Name!,
        user.FindFirstValue("tenant")!, user.FindFirstValue(ClaimTypes.Role)!);
}

public static class AccessPolicy
{
    public static bool CanRead(Actor actor, Ticket ticket) => actor.Role == "admin" ||
        actor.Tenant == ticket.Tenant || ticket.SharedWith.Contains(actor.Tenant, StringComparer.Ordinal);
}

public sealed class LabSettings
{
    public required string DataRoot { get; init; }
    public required bool Vulnerable { get; init; }
    public string AppRoot => AppContext.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar);
    public string WorkRoot => Path.Combine(DataRoot, "work");
    public string ExportRoot => Path.Combine(DataRoot, "exports");
    public static LabSettings Read(IConfiguration config)
    {
        var vulnerable = config.GetValue<bool>("PurpleLab:Vulnerable");
        if (vulnerable && config["PurpleLab:Acknowledgement"] != "I_ACCEPT_DISPOSABLE_LOCAL_LAB")
            throw new InvalidOperationException("Vulnerable mode requires explicit disposable local lab acknowledgement.");
        var settings = new LabSettings {
            DataRoot = Path.GetFullPath(config["PurpleLab:DataRoot"] ?? "state"), Vulnerable = vulnerable
        };
        foreach (var path in new[] { settings.DataRoot, settings.WorkRoot, settings.ExportRoot,
                     Path.Combine(settings.DataRoot, "events") }) Directory.CreateDirectory(path);
        return settings;
    }
}

public sealed class LabStore
{
    private readonly string connectionString;
    private readonly PasswordHasher<LabUser> hasher = new();
    public LabStore(LabSettings settings, IConfiguration config)
    {
        connectionString = new SqliteConnectionStringBuilder {
            DataSource = Path.Combine(settings.DataRoot, "lab.db"), ForeignKeys = true
        }.ToString();
        using var db = Open();
        using var cmd = db.CreateCommand();
        cmd.CommandText = """
            PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS users(name TEXT PRIMARY KEY, tenant TEXT NOT NULL, role TEXT NOT NULL, hash TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS tickets(id INTEGER PRIMARY KEY, tenant TEXT NOT NULL, subject TEXT NOT NULL, body TEXT NOT NULL, shared_with TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS attachments(id INTEGER PRIMARY KEY, ticket_id INTEGER NOT NULL REFERENCES tickets(id), name TEXT NOT NULL, content BLOB NOT NULL);
            CREATE TABLE IF NOT EXISTS exports(job_id TEXT PRIMARY KEY, ticket_id INTEGER NOT NULL REFERENCES tickets(id), filename TEXT NOT NULL);
            """;
        cmd.ExecuteNonQuery();
        cmd.CommandText = "SELECT COUNT(*) FROM users";
        if (Convert.ToInt64(cmd.ExecuteScalar()) > 0) return;
        var password = config["PurpleLab:SeedPassword"];
        if (string.IsNullOrEmpty(password)) {
            password = Convert.ToBase64String(RandomNumberGenerator.GetBytes(24));
            var secretFile = Path.Combine(settings.DataRoot, "bootstrap-password.txt");
            File.WriteAllText(secretFile, password);
            if (!OperatingSystem.IsWindows()) File.SetUnixFileMode(secretFile, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }
        if (password.Length < 16) throw new InvalidOperationException("Seed password must have at least 16 characters.");
        using var transaction = db.BeginTransaction();
        foreach (var (name, tenant, role) in new[] { ("alice", "north", "user"), ("bob", "south", "user"), ("admin", "operations", "admin") }) {
            var user = new LabUser(name, tenant, role, "");
            Execute(db, transaction, "INSERT INTO users VALUES($a,$b,$c,$d)", name, tenant, role, hasher.HashPassword(user, password));
        }
        Execute(db, transaction, "INSERT INTO tickets VALUES($a,$b,$c,$d,$e)", 1001, "north", "Printer invoice", "Synthetic north customer record", "");
        Execute(db, transaction, "INSERT INTO tickets VALUES($a,$b,$c,$d,$e)", 2001, "south", "Private service case", "Synthetic south private record", "");
        Execute(db, transaction, "INSERT INTO tickets VALUES($a,$b,$c,$d,$e)", 2002, "south", "Shared integration case", "Synthetic shared troubleshooting", "north");
        Execute(db, transaction, "INSERT INTO attachments VALUES($a,$b,$c,$d)", 1, 2001, "synthetic-note.txt", System.Text.Encoding.UTF8.GetBytes("SYNTHETIC south ticket attachment\n"));
        transaction.Commit();
    }
    private SqliteConnection Open() { var db = new SqliteConnection(connectionString); db.Open(); return db; }
    private static void Execute(SqliteConnection db, SqliteTransaction transaction, string sql, params object[] values)
    {
        using var cmd = db.CreateCommand(); cmd.Transaction = transaction; cmd.CommandText = sql;
        for (var i = 0; i < values.Length; i++) cmd.Parameters.AddWithValue("$" + (char)('a' + i), values[i]);
        cmd.ExecuteNonQuery();
    }
    public LabUser? Authenticate(string name, string password)
    {
        using var db = Open(); using var cmd = db.CreateCommand();
        cmd.CommandText = "SELECT name,tenant,role,hash FROM users WHERE name=$name";
        cmd.Parameters.AddWithValue("$name", name);
        using var r = cmd.ExecuteReader();
        if (!r.Read()) return null;
        var user = new LabUser(r.GetString(0), r.GetString(1), r.GetString(2), r.GetString(3));
        return hasher.VerifyHashedPassword(user, user.PasswordHash, password) == PasswordVerificationResult.Failed ? null : user;
    }
    public Ticket? GetTicket(int id)
    {
        using var db = Open(); using var cmd = db.CreateCommand();
        cmd.CommandText = "SELECT id,tenant,subject,body,shared_with FROM tickets WHERE id=$id"; cmd.Parameters.AddWithValue("$id", id);
        using var r = cmd.ExecuteReader(); return r.Read() ? ReadTicket(r) : null;
    }
    public IReadOnlyList<Ticket> GetTickets()
    {
        using var db = Open(); using var cmd = db.CreateCommand();
        cmd.CommandText = "SELECT id,tenant,subject,body,shared_with FROM tickets ORDER BY id";
        using var r = cmd.ExecuteReader(); var list = new List<Ticket>(); while (r.Read()) list.Add(ReadTicket(r)); return list;
    }
    private static Ticket ReadTicket(SqliteDataReader r) => new(r.GetInt32(0), r.GetString(1), r.GetString(2), r.GetString(3), r.GetString(4).Split(',', StringSplitOptions.RemoveEmptyEntries));
    public Attachment? GetAttachment(int id)
    {
        using var db = Open(); using var cmd = db.CreateCommand();
        cmd.CommandText = "SELECT id,ticket_id,name,content FROM attachments WHERE id=$id"; cmd.Parameters.AddWithValue("$id", id);
        using var r = cmd.ExecuteReader(); return r.Read() ? new(r.GetInt32(0), r.GetInt32(1), r.GetString(2), (byte[])r[3]) : null;
    }
    public void SaveExport(string job, int ticket, string filename)
    {
        using var db = Open(); using var cmd = db.CreateCommand();
        cmd.CommandText = "INSERT INTO exports VALUES($job,$ticket,$filename)";
        cmd.Parameters.AddWithValue("$job", job); cmd.Parameters.AddWithValue("$ticket", ticket); cmd.Parameters.AddWithValue("$filename", filename); cmd.ExecuteNonQuery();
    }
    public (int TicketId, string Filename)? GetExport(string job)
    {
        using var db = Open(); using var cmd = db.CreateCommand();
        cmd.CommandText = "SELECT ticket_id,filename FROM exports WHERE job_id=$job"; cmd.Parameters.AddWithValue("$job", job);
        using var r = cmd.ExecuteReader(); return r.Read() ? (r.GetInt32(0), r.GetString(1)) : null;
    }
}
