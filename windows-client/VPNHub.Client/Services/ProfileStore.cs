using VPNHub.Client.Core.Models;
using VPNHub.Client.Core.Security;

namespace VPNHub.Client.Services;

public sealed class ProfileStore
{
    public string RootDirectory { get; } = Path.Combine(
        Environment.GetFolderPath(
            Environment.SpecialFolder.LocalApplicationData),
        "VPNHub",
        "Profiles");

    public ProfileStore()
    {
        Directory.CreateDirectory(RootDirectory);
    }

    public IReadOnlyList<ProfileEntry> List()
    {
        var profiles = new List<ProfileEntry>();

        foreach (var path in Directory.EnumerateFiles(
                     RootDirectory,
                     "*.vpnhub",
                     SearchOption.TopDirectoryOnly))
        {
            try
            {
                var json = File.ReadAllText(path);
                var bundle = BundleCrypto.Deserialize(json);
                profiles.Add(
                    new ProfileEntry(
                        bundle.ProfileName,
                        path,
                        bundle.CreatedAtUtc));
            }
            catch
            {
                // A corrupt profile is skipped in the UI. It is never
                // decrypted merely to enumerate available profiles.
            }
        }

        return profiles
            .OrderBy(profile => profile.ProfileName)
            .ToArray();
    }

    public VpnHubBundle Load(ProfileEntry profile)
    {
        var json = File.ReadAllText(profile.Path);
        return BundleCrypto.Deserialize(json);
    }

    public string Save(VpnHubBundle bundle)
    {
        var fileName =
            SafeFileName(bundle.ProfileName) + ".vpnhub";
        var path = Path.Combine(RootDirectory, fileName);
        File.WriteAllText(
            path,
            BundleCrypto.Serialize(bundle));

        return path;
    }

    public void Delete(ProfileEntry profile)
    {
        if (File.Exists(profile.Path))
        {
            File.Delete(profile.Path);
        }
    }

    private static string SafeFileName(string value)
    {
        var invalid = Path.GetInvalidFileNameChars();
        var chars = value
            .Select(ch => invalid.Contains(ch) ? '_' : ch)
            .ToArray();

        var result = new string(chars).Trim();

        if (string.IsNullOrWhiteSpace(result))
        {
            throw new InvalidDataException(
                "Nome de perfil inválido.");
        }

        return result;
    }
}

public sealed record ProfileEntry(
    string ProfileName,
    string Path,
    DateTimeOffset CreatedAtUtc)
{
    public override string ToString() => ProfileName;
}
