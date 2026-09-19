using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Konscious.Security.Cryptography;
using VPNHub.Client.Core.Models;

namespace VPNHub.Client.Core.Security;

public static class BundleCrypto
{
    public const int CurrentVersion = 1;
    public const int DefaultMemoryKiB = 64 * 1024;
    public const int DefaultIterations = 3;
    public const int DefaultParallelism = 2;

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = true
    };

    public static VpnHubBundle Protect(
        string profileName,
        string wireGuardConfig,
        string password)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(wireGuardConfig);

        var bytes = Encoding.UTF8.GetBytes(wireGuardConfig);

        try
        {
            return Protect(profileName, bytes, password);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }

    public static VpnHubBundle Protect(
        string profileName,
        ReadOnlySpan<byte> wireGuardConfig,
        string password)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(profileName);
        ArgumentException.ThrowIfNullOrWhiteSpace(password);

        if (wireGuardConfig.IsEmpty)
        {
            throw new ArgumentException(
                "Configuração WireGuard vazia.",
                nameof(wireGuardConfig));
        }

        var salt = RandomNumberGenerator.GetBytes(16);
        var nonce = RandomNumberGenerator.GetBytes(12);
        var tag = new byte[16];
        var plaintext = wireGuardConfig.ToArray();
        var ciphertext = new byte[plaintext.Length];
        var passwordBytes = Encoding.UTF8.GetBytes(password);
        byte[]? key = null;

        try
        {
            var kdf = new KdfParameters(
                "Argon2id",
                DefaultMemoryKiB,
                DefaultIterations,
                DefaultParallelism);

            key = DeriveKey(passwordBytes, salt, kdf);

            using var aes = new AesGcm(key, tag.Length);
            aes.Encrypt(
                nonce,
                plaintext,
                ciphertext,
                tag,
                AssociatedData(profileName));

            return new VpnHubBundle(
                CurrentVersion,
                profileName,
                DateTimeOffset.UtcNow,
                kdf,
                Convert.ToBase64String(salt),
                Convert.ToBase64String(nonce),
                Convert.ToBase64String(ciphertext),
                Convert.ToBase64String(tag));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
            CryptographicOperations.ZeroMemory(passwordBytes);

            if (key is not null)
            {
                CryptographicOperations.ZeroMemory(key);
            }
        }
    }

    public static byte[] UnprotectBytes(
        VpnHubBundle bundle,
        string password)
    {
        ArgumentNullException.ThrowIfNull(bundle);
        ArgumentException.ThrowIfNullOrWhiteSpace(password);

        if (bundle.Version != CurrentVersion)
        {
            throw new InvalidDataException(
                $"Versão de bundle não suportada: {bundle.Version}.");
        }

        if (bundle.Kdf is null)
        {
            throw new InvalidDataException(
                "Bundle sem parâmetros KDF.");
        }

        if (!string.Equals(
                bundle.Kdf.Algorithm,
                "Argon2id",
                StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException(
                $"KDF não suportado: {bundle.Kdf.Algorithm}.");
        }

        ValidateKdfLimits(bundle.Kdf);

        var salt = Decode(bundle.Salt, "salt");
        var nonce = Decode(bundle.Nonce, "nonce");
        var ciphertext = Decode(bundle.Ciphertext, "ciphertext");
        var tag = Decode(bundle.Tag, "tag");

        if (salt.Length < 16 || nonce.Length != 12 || tag.Length != 16)
        {
            throw new InvalidDataException(
                "Parâmetros criptográficos inválidos no bundle.");
        }

        var plaintext = new byte[ciphertext.Length];
        var passwordBytes = Encoding.UTF8.GetBytes(password);
        byte[]? key = null;

        try
        {
            key = DeriveKey(
                passwordBytes,
                salt,
                bundle.Kdf);

            using var aes = new AesGcm(key, tag.Length);

            try
            {
                aes.Decrypt(
                    nonce,
                    ciphertext,
                    tag,
                    plaintext,
                    AssociatedData(bundle.ProfileName));
            }
            catch (CryptographicException exc)
            {
                CryptographicOperations.ZeroMemory(plaintext);

                throw new UnauthorizedAccessException(
                    "Senha incorreta ou bundle corrompido.",
                    exc);
            }

            return plaintext;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(passwordBytes);

            if (key is not null)
            {
                CryptographicOperations.ZeroMemory(key);
            }
        }
    }

    public static string Serialize(VpnHubBundle bundle) =>
        JsonSerializer.Serialize(bundle, JsonOptions);

    public static VpnHubBundle Deserialize(string json)
    {
        var bundle = JsonSerializer.Deserialize<VpnHubBundle>(
            json,
            JsonOptions);

        if (bundle is null)
        {
            throw new InvalidDataException(
                "Arquivo .vpnhub inválido.");
        }

        if (string.IsNullOrWhiteSpace(bundle.ProfileName))
        {
            throw new InvalidDataException(
                "Bundle sem nome de perfil.");
        }

        return bundle;
    }

    private static byte[] DeriveKey(
        byte[] password,
        byte[] salt,
        KdfParameters parameters)
    {
        ValidateKdfLimits(parameters);

        var argon2 = new Argon2id(password)
        {
            Salt = salt,
            MemorySize = parameters.MemoryKiB,
            Iterations = parameters.Iterations,
            DegreeOfParallelism = parameters.Parallelism
        };

        return argon2.GetBytes(32);
    }

    private static void ValidateKdfLimits(KdfParameters parameters)
    {
        if (parameters.MemoryKiB is < 16 * 1024 or > 1024 * 1024)
        {
            throw new InvalidDataException(
                "Memória Argon2id fora dos limites aceitos.");
        }

        if (parameters.Iterations is < 1 or > 20)
        {
            throw new InvalidDataException(
                "Iterações Argon2id fora dos limites aceitos.");
        }

        if (parameters.Parallelism is < 1 or > 16)
        {
            throw new InvalidDataException(
                "Paralelismo Argon2id fora dos limites aceitos.");
        }
    }

    private static byte[] AssociatedData(string profileName) =>
        Encoding.UTF8.GetBytes(
            $"VPNHubBundle:v{CurrentVersion}:{profileName}");

    private static byte[] Decode(string value, string field)
    {
        try
        {
            return Convert.FromBase64String(value);
        }
        catch (FormatException exc)
        {
            throw new InvalidDataException(
                $"Campo {field} não é Base64 válido.",
                exc);
        }
    }
}
