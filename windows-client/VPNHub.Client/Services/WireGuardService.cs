using System.Diagnostics;
using System.ServiceProcess;
using System.Text.RegularExpressions;

namespace VPNHub.Client.Services;

public sealed partial class WireGuardService
{
    private readonly string _wireGuardExe;

    public WireGuardService()
    {
        _wireGuardExe = FindWireGuardExecutable();
    }

    public bool IsWireGuardInstalled =>
        File.Exists(_wireGuardExe);

    public string ExecutablePath => _wireGuardExe;

    public async Task ConnectAsync(
        string profileName,
        byte[] configBytes,
        CancellationToken cancellationToken = default)
    {
        EnsureInstalled();
        ArgumentNullException.ThrowIfNull(configBytes);

        if (configBytes.Length == 0)
        {
            throw new InvalidDataException(
                "Configuração WireGuard vazia.");
        }

        var tunnelName = TunnelName(profileName);

        if (ServiceExists(tunnelName))
        {
            await DisconnectAsync(
                profileName,
                cancellationToken);
        }

        var runtimeDirectory = Path.Combine(
            Environment.GetFolderPath(
                Environment.SpecialFolder.LocalApplicationData),
            "VPNHub",
            "Runtime",
            Guid.NewGuid().ToString("N"));

        Directory.CreateDirectory(runtimeDirectory);

        var configPath = Path.Combine(
            runtimeDirectory,
            tunnelName + ".conf");

        try
        {
            await File.WriteAllBytesAsync(
                configPath,
                configBytes,
                cancellationToken);

            await RunWireGuardAsync(
                "/installtunnelservice",
                configPath,
                cancellationToken);

            await WaitForStatusAsync(
                tunnelName,
                ServiceControllerStatus.Running,
                TimeSpan.FromSeconds(15),
                cancellationToken);

            if (!await DeletePlaintextAsync(
                    configPath,
                    runtimeDirectory,
                    cancellationToken))
            {
                await DisconnectAsync(
                    profileName,
                    cancellationToken);

                throw new IOException(
                    "O túnel iniciou, mas a configuração temporária " +
                    "não pôde ser removida. O serviço foi desligado.");
            }
        }
        catch
        {
            TryDelete(configPath);
            TryDeleteDirectory(runtimeDirectory);
            throw;
        }
    }

    public async Task DisconnectAsync(
        string profileName,
        CancellationToken cancellationToken = default)
    {
        EnsureInstalled();

        var tunnelName = TunnelName(profileName);

        if (!ServiceExists(tunnelName))
        {
            return;
        }

        await RunWireGuardAsync(
            "/uninstalltunnelservice",
            tunnelName,
            cancellationToken);
    }

    public TunnelState GetState(string profileName)
    {
        var tunnelName = TunnelName(profileName);

        try
        {
            using var service = new ServiceController(
                ServiceName(tunnelName));

            return service.Status switch
            {
                ServiceControllerStatus.Running =>
                    TunnelState.Connected,
                ServiceControllerStatus.StartPending =>
                    TunnelState.Connecting,
                ServiceControllerStatus.StopPending =>
                    TunnelState.Disconnecting,
                _ => TunnelState.Disconnected
            };
        }
        catch (InvalidOperationException)
        {
            return TunnelState.Disconnected;
        }
    }

    public static string TunnelName(string profileName)
    {
        var cleaned = UnsafeTunnelChars()
            .Replace(profileName, "_")
            .Trim('_', '-', ' ');

        if (string.IsNullOrWhiteSpace(cleaned))
        {
            cleaned = "Profile";
        }

        if (cleaned.Length > 42)
        {
            cleaned = cleaned[..42];
        }

        return "VPNHub_" + cleaned;
    }

    private static string ServiceName(string tunnelName) =>
        "WireGuardTunnel$" + tunnelName;

    private static bool ServiceExists(string tunnelName)
    {
        var serviceName = ServiceName(tunnelName);
        var services = ServiceController.GetServices();

        try
        {
            return services.Any(service => string.Equals(
                service.ServiceName,
                serviceName,
                StringComparison.OrdinalIgnoreCase));
        }
        finally
        {
            foreach (var service in services)
            {
                service.Dispose();
            }
        }
    }

    private static async Task WaitForStatusAsync(
        string tunnelName,
        ServiceControllerStatus status,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        await Task.Run(
            () =>
            {
                using var service = new ServiceController(
                    ServiceName(tunnelName));

                service.WaitForStatus(status, timeout);
            },
            cancellationToken);
    }

    private async Task RunWireGuardAsync(
        string command,
        string argument,
        CancellationToken cancellationToken)
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = _wireGuardExe,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        };

        startInfo.ArgumentList.Add(command);
        startInfo.ArgumentList.Add(argument);

        using var process = Process.Start(startInfo)
            ?? throw new InvalidOperationException(
                "Não foi possível iniciar WireGuard.");

        var stdoutTask = process.StandardOutput.ReadToEndAsync(
            cancellationToken);
        var stderrTask = process.StandardError.ReadToEndAsync(
            cancellationToken);

        await process.WaitForExitAsync(cancellationToken);

        var stdout = await stdoutTask;
        var stderr = await stderrTask;

        if (process.ExitCode != 0)
        {
            var detail = string.Join(
                " ",
                new[] { stderr.Trim(), stdout.Trim() }
                    .Where(value => value.Length > 0));

            throw new InvalidOperationException(
                $"WireGuard retornou código {process.ExitCode}" +
                (detail.Length > 0 ? $": {detail}" : "."));
        }
    }

    private static async Task<bool> DeletePlaintextAsync(
        string configPath,
        string runtimeDirectory,
        CancellationToken cancellationToken)
    {
        for (var attempt = 0; attempt < 30; attempt++)
        {
            cancellationToken.ThrowIfCancellationRequested();

            try
            {
                if (File.Exists(configPath))
                {
                    File.Delete(configPath);
                }

                if (!File.Exists(configPath))
                {
                    TryDeleteDirectory(runtimeDirectory);
                    return true;
                }
            }
            catch (IOException)
            {
                // WireGuard may briefly hold the config while starting.
            }
            catch (UnauthorizedAccessException)
            {
                // Retry briefly; fail closed if plaintext remains.
            }

            await Task.Delay(
                TimeSpan.FromMilliseconds(100),
                cancellationToken);
        }

        return !File.Exists(configPath);
    }

    private static void TryDelete(string path)
    {
        try
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
        catch
        {
            // Best-effort cleanup after an already-failed operation.
        }
    }

    private static void TryDeleteDirectory(string path)
    {
        try
        {
            if (Directory.Exists(path))
            {
                Directory.Delete(path, recursive: true);
            }
        }
        catch
        {
            // Best-effort cleanup after an already-failed operation.
        }
    }

    private void EnsureInstalled()
    {
        if (!IsWireGuardInstalled)
        {
            throw new FileNotFoundException(
                "WireGuard for Windows não foi encontrado. " +
                "Instale o cliente oficial antes de usar VPNHub Client.",
                _wireGuardExe);
        }
    }

    private static string FindWireGuardExecutable()
    {
        var candidates = new[]
        {
            Path.Combine(
                Environment.GetFolderPath(
                    Environment.SpecialFolder.ProgramFiles),
                "WireGuard",
                "wireguard.exe"),
            Path.Combine(
                Environment.GetFolderPath(
                    Environment.SpecialFolder.ProgramFilesX86),
                "WireGuard",
                "wireguard.exe")
        };

        return candidates.FirstOrDefault(File.Exists)
            ?? candidates[0];
    }

    [GeneratedRegex(@"[^A-Za-z0-9_-]+")]
    private static partial Regex UnsafeTunnelChars();
}

public enum TunnelState
{
    Disconnected,
    Connecting,
    Connected,
    Disconnecting
}
