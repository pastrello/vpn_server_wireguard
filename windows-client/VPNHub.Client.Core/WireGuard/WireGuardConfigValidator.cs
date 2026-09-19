using System.Text.RegularExpressions;

namespace VPNHub.Client.Core.WireGuard;

public static partial class WireGuardConfigValidator
{
    private static readonly HashSet<string> InterfaceKeys =
        new(StringComparer.OrdinalIgnoreCase)
        {
            "PrivateKey",
            "Address",
            "DNS",
            "MTU"
        };

    private static readonly HashSet<string> PeerKeys =
        new(StringComparer.OrdinalIgnoreCase)
        {
            "PublicKey",
            "PresharedKey",
            "AllowedIPs",
            "Endpoint",
            "PersistentKeepalive"
        };

    public static void Validate(string config)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(config);

        string? section = null;
        var hasInterface = false;
        var hasPrivateKey = false;
        var hasPeer = false;
        var hasPublicKey = false;
        var hasPresharedKey = false;

        foreach (var rawLine in config.Replace("\r\n", "\n").Split('\n'))
        {
            var line = rawLine.Trim();

            if (line.Length == 0 || line.StartsWith('#') || line.StartsWith(';'))
            {
                continue;
            }

            if (line.StartsWith('[') && line.EndsWith(']'))
            {
                section = line[1..^1].Trim();

                if (section.Equals(
                        "Interface",
                        StringComparison.OrdinalIgnoreCase))
                {
                    hasInterface = true;
                    continue;
                }

                if (section.Equals(
                        "Peer",
                        StringComparison.OrdinalIgnoreCase))
                {
                    hasPeer = true;
                    continue;
                }

                throw new InvalidDataException(
                    $"Seção WireGuard não permitida: [{section}].");
            }

            var match = KeyValueLine().Match(line);

            if (!match.Success || section is null)
            {
                throw new InvalidDataException(
                    $"Linha WireGuard inválida: {line}");
            }

            var key = match.Groups["key"].Value;

            if (section.Equals(
                    "Interface",
                    StringComparison.OrdinalIgnoreCase))
            {
                if (!InterfaceKeys.Contains(key))
                {
                    throw new InvalidDataException(
                        $"Diretiva [Interface] não permitida: {key}.");
                }

                hasPrivateKey |= key.Equals(
                    "PrivateKey",
                    StringComparison.OrdinalIgnoreCase);
            }
            else if (section.Equals(
                         "Peer",
                         StringComparison.OrdinalIgnoreCase))
            {
                if (!PeerKeys.Contains(key))
                {
                    throw new InvalidDataException(
                        $"Diretiva [Peer] não permitida: {key}.");
                }

                hasPublicKey |= key.Equals(
                    "PublicKey",
                    StringComparison.OrdinalIgnoreCase);
                hasPresharedKey |= key.Equals(
                    "PresharedKey",
                    StringComparison.OrdinalIgnoreCase);
            }
        }

        if (!hasInterface || !hasPrivateKey)
        {
            throw new InvalidDataException(
                "Configuração sem [Interface]/PrivateKey.");
        }

        if (!hasPeer || !hasPublicKey)
        {
            throw new InvalidDataException(
                "Configuração sem [Peer]/PublicKey.");
        }

        if (!hasPresharedKey)
        {
            throw new InvalidDataException(
                "VPNHub exige PresharedKey no perfil.");
        }
    }

    [GeneratedRegex(
        @"^(?<key>[A-Za-z][A-Za-z0-9]*)\s*=\s*(?<value>.+)$",
        RegexOptions.CultureInvariant)]
    private static partial Regex KeyValueLine();
}
