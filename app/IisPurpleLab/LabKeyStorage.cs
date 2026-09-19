using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.AspNetCore.DataProtection.Repositories;
using Microsoft.Extensions.Options;

namespace IisPurpleLab;

// Keep the lab's cookie keys within the same owned state/ACL boundary as its data.
public sealed class LabKeyStorage(LabSettings settings, ILoggerFactory loggerFactory) : IConfigureOptions<KeyManagementOptions>
{
    public void Configure(KeyManagementOptions options)
    {
        var directory = Directory.CreateDirectory(Path.Combine(settings.DataRoot, "keys"));
        if (!OperatingSystem.IsWindows())
            File.SetUnixFileMode(directory.FullName, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        options.XmlRepository = new FileSystemXmlRepository(directory, loggerFactory);
    }
}
