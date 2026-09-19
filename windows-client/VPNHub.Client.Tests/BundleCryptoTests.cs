using System.Security.Cryptography;
using System.Text;
using VPNHub.Client.Core.Security;

namespace VPNHub.Client.Tests;

public sealed class BundleCryptoTests
{
    private const string Config = """
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

    [Fact]
    public void ProtectAndUnprotectRoundTrip()
    {
        var bundle = BundleCrypto.Protect(
            "Notebook",
            Config,
            "correct horse battery staple");

        var plaintext = BundleCrypto.UnprotectBytes(
            bundle,
            "correct horse battery staple");

        try
        {
            Assert.Equal(
                Config,
                Encoding.UTF8.GetString(plaintext));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
        }
    }

    [Fact]
    public void WrongPasswordIsRejected()
    {
        var bundle = BundleCrypto.Protect(
            "Notebook",
            Config,
            "password-one");

        Assert.Throws<UnauthorizedAccessException>(
            () => BundleCrypto.UnprotectBytes(
                bundle,
                "password-two"));
    }

    [Fact]
    public void TamperedCiphertextIsRejected()
    {
        var bundle = BundleCrypto.Protect(
            "Notebook",
            Config,
            "password-one");

        var bytes = Convert.FromBase64String(
            bundle.Ciphertext);
        bytes[0] ^= 0x01;

        var tampered = bundle with
        {
            Ciphertext = Convert.ToBase64String(bytes)
        };

        Assert.Throws<UnauthorizedAccessException>(
            () => BundleCrypto.UnprotectBytes(
                tampered,
                "password-one"));
    }

    [Fact]
    public void ProfileNameIsAuthenticatedMetadata()
    {
        var bundle = BundleCrypto.Protect(
            "Notebook",
            Config,
            "password-one");

        var renamed = bundle with
        {
            ProfileName = "Attacker"
        };

        Assert.Throws<UnauthorizedAccessException>(
            () => BundleCrypto.UnprotectBytes(
                renamed,
                "password-one"));
    }
}
