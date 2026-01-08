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

    public Task<Result<EcliptixSystemIdentityKeys, KeySplittingFailure>> DeriveIdentityKeysFromMasterKeyAsync(
        SodiumSecureMemoryHandle masterKeyHandle,
        Guid accountId)
    {
        Result<byte[], SodiumFailure> readResult = masterKeyHandle.ReadBytes(MasterKeyReadSize);
        if (readResult.IsErr)
        {
            SodiumFailure error = readResult.UnwrapErr();
            return Task.FromResult(Result<EcliptixSystemIdentityKeys, KeySplittingFailure>.Err(
                KeySplittingFailure.KeyDerivationFailed($"{ErrorMessageMasterKeyReadFailed}: {error.Message}")));
        }

        byte[] masterKeyBytes = readResult.Unwrap();
        ProtocolServerAdapter protocol = new();

        try
        {
            Result<Unit, EcliptixProtocolFailure> initResult = protocol.Initialize();
            if (initResult.IsErr)
            {
                return Task.FromResult(Result<EcliptixSystemIdentityKeys, KeySplittingFailure>.Err(
                    KeySplittingFailure.KeyDerivationFailed($"{ErrorMessageIdentityKeysCreationFailed}: {initResult.UnwrapErr().Message}")));
            }

            Result<ProtocolIdentity, EcliptixProtocolFailure> identityResult =
                protocol.CreateIdentity(masterKeyBytes, accountId);
            if (identityResult.IsErr)
            {
                return Task.FromResult(Result<EcliptixSystemIdentityKeys, KeySplittingFailure>.Err(
                    KeySplittingFailure.KeyDerivationFailed($"{ErrorMessageIdentityKeysCreationFailed}: {identityResult.UnwrapErr().Message}")));
            }

            ProtocolIdentity identity = identityResult.Unwrap();
            Result<byte[], EcliptixProtocolFailure> edPkResult = protocol.GetPublicEd25519(identity);
            Result<byte[], EcliptixProtocolFailure> xPkResult = protocol.GetPublicX25519(identity);

            if (!edPkResult.IsErr && !xPkResult.IsErr)
            {
                return Task.FromResult(Result<EcliptixSystemIdentityKeys, KeySplittingFailure>.Ok(
                    new EcliptixSystemIdentityKeys(identity)));
            }

            string msg = edPkResult.IsErr
                ? edPkResult.UnwrapErr().Message
                : xPkResult.UnwrapErr().Message;
            identity.Dispose();
            return Task.FromResult(Result<EcliptixSystemIdentityKeys, KeySplittingFailure>.Err(
                KeySplittingFailure.KeyDerivationFailed($"{ErrorMessageIdentityKeysCreationFailed}: {msg}")));
        }
        catch (Exception ex)
        {
            return Task.FromResult(Result<EcliptixSystemIdentityKeys, KeySplittingFailure>.Err(
                KeySplittingFailure.KeyDerivationFailed(ErrorMessageUnexpectedError, ex)));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(masterKeyBytes);
            protocol.Dispose();
        }
    }
}

public sealed class EcliptixSystemIdentityKeys(ProtocolIdentity identity)
    : IDisposable
{
    public ProtocolIdentity Identity { get; } = identity;

    public void Dispose()
    {
        Identity.Dispose();
    }
}
