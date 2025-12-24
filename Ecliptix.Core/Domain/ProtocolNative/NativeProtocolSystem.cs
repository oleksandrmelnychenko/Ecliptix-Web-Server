using System;
using Ecliptix.Utilities;

namespace Ecliptix.Core.Domain.ProtocolNative;

/// <summary>
/// Thin convenience layer around the native hybrid/PQ protocol bindings for server-side use.
/// </summary>
public static class NativeProtocolSystem
{
    public static Result<Unit, EcliptixProtocolFailure> Initialize()
    {
        EcliptixErrorCode result = EcliptixNativeInterop.ecliptix_initialize();
        return result == EcliptixErrorCode.Success
            ? Result<Unit, EcliptixProtocolFailure>.Ok(Unit.Value)
            : Result<Unit, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.Generic(
                    $"Failed to initialize native protocol: {EcliptixNativeInterop.ErrorCodeToString(result)}"));
    }

    public static void Shutdown() => EcliptixNativeInterop.ecliptix_shutdown();

    public static Result<EcliptixIdentityKeysWrapper, EcliptixProtocolFailure> CreateIdentity()
        => EcliptixIdentityKeysWrapper.Create();

    public static Result<EcliptixIdentityKeysWrapper, EcliptixProtocolFailure> CreateIdentityFromSeed(byte[] seed)
        => EcliptixIdentityKeysWrapper.CreateFromSeed(seed);

    public static Result<EcliptixIdentityKeysWrapper, EcliptixProtocolFailure> CreateIdentityFromSeed(
        byte[] seed,
        string membershipId)
        => EcliptixIdentityKeysWrapper.CreateFromSeed(seed, membershipId);

    public static Result<NativeProtocolSession, EcliptixProtocolFailure> CreateSessionAdapter(
        EcliptixIdentityKeysWrapper identity,
        Action<uint>? onProtocolStateChanged = null)
    {
        Result<NativeProtocolSession, EcliptixProtocolFailure> sessionResult = NativeProtocolSession.Create(identity);
        if (sessionResult.IsErr)
        {
            return sessionResult;
        }
        NativeProtocolSession session = sessionResult.Unwrap();
        session.SetEventHandler(onProtocolStateChanged);
        return Result<NativeProtocolSession, EcliptixProtocolFailure>.Ok(session);
    }

    public static Result<NativeProtocolSession, EcliptixProtocolFailure> CreateSessionFromRoot(
        EcliptixIdentityKeysWrapper identity,
        byte[] rootKey,
        byte[] peerBundle,
        bool isInitiator,
        Action<uint>? onProtocolStateChanged = null)
    {
        Result<NativeProtocolSession, EcliptixProtocolFailure> sessionResult =
            NativeProtocolSession.CreateFromRoot(identity, rootKey, peerBundle, isInitiator);
        if (sessionResult.IsErr)
        {
            return sessionResult;
        }
        NativeProtocolSession session = sessionResult.Unwrap();
        session.SetEventHandler(onProtocolStateChanged);
        return Result<NativeProtocolSession, EcliptixProtocolFailure>.Ok(session);
    }

    public static Result<byte[], EcliptixProtocolFailure> DeriveRootFromOpaqueSessionKey(
        byte[] opaqueSessionKey,
        byte[] userContext)
        => EcliptixProtocolSystemWrapper.DeriveRootFromOpaqueSessionKey(opaqueSessionKey, userContext);

    public static Result<Unit, EcliptixProtocolFailure> ValidateEnvelopeHybridRequirements(byte[] encryptedEnvelope)
        => EcliptixProtocolSystemWrapper.ValidateEnvelopeHybridRequirements(encryptedEnvelope);

    public static string GetVersion() => EcliptixNativeInterop.GetVersion();
}
