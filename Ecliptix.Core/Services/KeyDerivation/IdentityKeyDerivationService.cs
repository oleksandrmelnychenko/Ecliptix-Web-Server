using System.Security.Cryptography;
using Ecliptix.SecureProtocol.Domain.Protocol;
using Ecliptix.SharedKernel;
using Ecliptix.SharedKernel.Failures;
using Ecliptix.SharedKernel.Failures.Sodium;

namespace Ecliptix.Core.Services.KeyDerivation;

public interface IIdentityKeyDerivationService
{
    Task<Result<EcliptixSystemIdentityKeys, KeySplittingFailure>> DeriveIdentityKeysFromMasterKeyAsync(
        SodiumSecureMemoryHandle masterKeyHandle,
        Guid accountId);
}

internal sealed class IdentityKeyDerivationService : IIdentityKeyDerivationService
{
    private const int MasterKeyReadSize = 32;
    private const string ErrorMessageMasterKeyReadFailed = "Failed to read master key";
    private const string ErrorMessageIdentityKeysCreationFailed = "Failed to create identity keys";
    private const string ErrorMessageUnexpectedError = "Unexpected error during identity key derivation";

    public async Task<Result<EcliptixSystemIdentityKeys, KeySplittingFailure>> DeriveIdentityKeysFromMasterKeyAsync(
        SodiumSecureMemoryHandle masterKeyHandle,
        Guid accountId)
    {
        Result<byte[], SodiumFailure> readResult = masterKeyHandle.ReadBytes(MasterKeyReadSize);
        if (readResult.IsErr)
        {
            SodiumFailure error = readResult.UnwrapErr();
            return Result<EcliptixSystemIdentityKeys, KeySplittingFailure>.Err(
                KeySplittingFailure.KeyDerivationFailed($"{ErrorMessageMasterKeyReadFailed}: {error.Message}"));
        }

        byte[] masterKeyBytes = readResult.Unwrap();
        ProtocolServerAdapter protocol = new();

        try
        {
            Result<Unit, EcliptixProtocolFailure> initResult = protocol.Initialize();
            if (initResult.IsErr)
            {
                return Result<EcliptixSystemIdentityKeys, KeySplittingFailure>.Err(
                    KeySplittingFailure.KeyDerivationFailed($"{ErrorMessageIdentityKeysCreationFailed}: {initResult.UnwrapErr().Message}"));
            }

            Result<ProtocolIdentity, EcliptixProtocolFailure> identityResult =
                protocol.CreateIdentity(masterKeyBytes, accountId);
            if (identityResult.IsErr)
            {
                return Result<EcliptixSystemIdentityKeys, KeySplittingFailure>.Err(
                    KeySplittingFailure.KeyDerivationFailed($"{ErrorMessageIdentityKeysCreationFailed}: {identityResult.UnwrapErr().Message}"));
            }

            ProtocolIdentity identity = identityResult.Unwrap();
            Result<byte[], EcliptixProtocolFailure> edPkResult = protocol.GetPublicEd25519(identity);
            Result<byte[], EcliptixProtocolFailure> xPkResult = protocol.GetPublicX25519(identity);

            if (edPkResult.IsErr || xPkResult.IsErr)
            {
                string msg = edPkResult.IsErr
                    ? edPkResult.UnwrapErr().Message
                    : xPkResult.UnwrapErr().Message;
                identity.Dispose();
                return Result<EcliptixSystemIdentityKeys, KeySplittingFailure>.Err(
                    KeySplittingFailure.KeyDerivationFailed($"{ErrorMessageIdentityKeysCreationFailed}: {msg}"));
            }

            return Result<EcliptixSystemIdentityKeys, KeySplittingFailure>.Ok(
                new EcliptixSystemIdentityKeys(identity, edPkResult.Unwrap(), xPkResult.Unwrap()));
        }
        catch (Exception ex)
        {
            return Result<EcliptixSystemIdentityKeys, KeySplittingFailure>.Err(
                KeySplittingFailure.KeyDerivationFailed(ErrorMessageUnexpectedError, ex));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(masterKeyBytes);
            protocol.Dispose();
        }
    }
}

/// <summary>
/// Minimal identity bundle backed by the protocol server (native).
/// </summary>
public sealed class EcliptixSystemIdentityKeys : IDisposable
{
    public EcliptixSystemIdentityKeys(ProtocolIdentity identity, byte[] publicEd25519, byte[] publicX25519)
    {
        Identity = identity;
        PublicEd25519 = publicEd25519;
        PublicX25519 = publicX25519;
    }

    public ProtocolIdentity Identity { get; }
    public byte[] PublicEd25519 { get; }
    public byte[] PublicX25519 { get; }

    public void Dispose()
    {
        Identity.Dispose();
    }
}
