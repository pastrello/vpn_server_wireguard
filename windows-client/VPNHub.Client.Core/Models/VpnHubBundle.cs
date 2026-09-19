namespace VPNHub.Client.Core.Models;

public sealed record KdfParameters(
    string Algorithm,
    int MemoryKiB,
    int Iterations,
    int Parallelism
);

public sealed record VpnHubBundle(
    int Version,
    string ProfileName,
    DateTimeOffset CreatedAtUtc,
    KdfParameters Kdf,
    string Salt,
    string Nonce,
    string Ciphertext,
    string Tag
);
