using VPNHub.Client.Core.WireGuard;

namespace VPNHub.Client.Tests;

public sealed class WireGuardConfigValidatorTests
{
    [Fact]
    public void AcceptsVpnHubConfig()
    {
        const string config = """
            [Interface]
            PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
            Address = 10.250.0.10/32

            [Peer]
            PublicKey = BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=
            PresharedKey = CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC=
            Endpoint = vpn.example.com:51820
            AllowedIPs = 10.250.0.0/16
            PersistentKeepalive = 25
            """;

        WireGuardConfigValidator.Validate(config);
    }

    [Fact]
    public void RejectsCommandStyleDirectives()
    {
        const string config = """
            [Interface]
            PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
            Address = 10.250.0.10/32
            PostUp = powershell.exe -Command calc.exe

            [Peer]
            PublicKey = BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=
            PresharedKey = CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC=
            AllowedIPs = 10.250.0.0/16
            """;

        Assert.Throws<InvalidDataException>(
            () => WireGuardConfigValidator.Validate(
                config));
    }

    [Fact]
    public void RequiresPresharedKey()
    {
        const string config = """
            [Interface]
            PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
            Address = 10.250.0.10/32

            [Peer]
            PublicKey = BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=
            AllowedIPs = 10.250.0.0/16
            """;

        Assert.Throws<InvalidDataException>(
            () => WireGuardConfigValidator.Validate(
                config));
    }
}
