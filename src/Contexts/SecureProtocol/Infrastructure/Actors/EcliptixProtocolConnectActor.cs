using Akka.Actor;
using Akka.Event;
using Akka.Persistence;
using Ecliptix.IdentityAccess.Domain.Actors.VerificationFlow;
using Ecliptix.IdentityAccess.Domain.Memberships.ActorEvents;
using Ecliptix.Protobuf.Common;
using Ecliptix.Protobuf.Protocol;
using Ecliptix.Protobuf.SecureProtocol;
using ProtobufPublicKeyBundle = Ecliptix.Protobuf.Protocol.PublicKeyBundle;
using Ecliptix.SharedKernel;
using Ecliptix.SharedKernel.Actors;
using Google.Protobuf;
using System.Security.Cryptography;
using Ecliptix.SecureProtocol.Domain.Protocol;
using Unit = Ecliptix.SharedKernel.Unit;

namespace Ecliptix.SecureProtocol.Infrastructure.Actors;

public sealed class EcliptixProtocolConnectActor(uint connectId) : PersistentActor, IWithTimers
{
    private static readonly TimeSpan IdleTimeout = TimeSpan.FromMinutes(ActorConstants.Timeouts.IdleTimeoutMinutes);
    private static readonly TimeSpan MinSnapshotInterval = TimeSpan.FromSeconds(30);
    private const int MaxRecoveryRetries = ActorConstants.Recovery.MaxRetries;
    private const string RecoveryRetryTimerKey = ActorConstants.Recovery.RetryTimerKey;

    private EcliptixSessionState? _state;
    private readonly Dictionary<PubKeyExchangeType, ProtocolSession> _sessions = new();
    private readonly IProtocolServer _protocolServer = new ProtocolServerAdapter();
    private ProtocolIdentity? _identity;
    private byte[]? _identitySeed;
    private byte[]? _cachedKyberPublicKey;
    private int _recoveryRetryCount;
    private bool _savingFinalSnapshot;
    private bool _pendingMessageDeletion;
    private bool _pendingSnapshotDeletion;
    private PubKeyExchangeType? _currentExchangeType;
    private DateTimeOffset _lastSnapshotTime = DateTimeOffset.MinValue;

    public ITimerScheduler Timers { get; set; } = null!;

    public override string PersistenceId { get; } = $"{ActorConstants.ActorNamePrefixes.Connect}{connectId}";

    protected override bool ReceiveRecover(object message)
    {
        switch (message)
        {
            case SnapshotOffer { Snapshot: EcliptixSessionState state }:
                _state = state;
                HydrateIdentitySeedFromState(state);
                return true;
            case EcliptixSessionState state:
                _state = state;
                HydrateIdentitySeedFromState(state);
                return true;
            case RecoveryCompleted:
                if (_state != null)
                {
                    if (IsIdentitySeedOnlyState(_state))
                    {
                        Context.GetLogger()
                            .Debug("[RECOVERY] Identity seed restored without handshake for ConnectId {0}", connectId);
                        return true;
                    }

                    AttemptSystemRecreation();
                }

                return true;
            default:
                return false;
        }
    }

    protected override bool ReceiveCommand(object message)
    {
        switch (message)
        {
            case InitializeProtocolWithMasterKeyCommand cmd:
                HandleAuthenticatedProtocolInitialization(cmd);
                return true;
            case DeriveSharedSecretCommand cmd:
                HandleInitialKeyExchange(cmd);
                return true;
            case EncryptPayloadCommand cmd:
                HandleEncrypt(cmd);
                return true;
            case DecryptSecureEnvelopeCommand cmd:
                HandleDecrypt(cmd);
                return true;
            case EncryptPayloadComponentsCommand cmd:
                HandleEncryptComponents(cmd);
                return true;
            case DecryptPayloadWithHeaderCommand cmd:
                HandleDecryptWithHeader(cmd);
                return true;
            case CleanupProtocolForTypeCommand cmd:
                HandleCleanupProtocolForType(cmd);
                return true;
            case ProtocolCleanupRequiredEvent evt:
                HandleProtocolCleanupRequired(evt);
                return true;
            case RestoreProtocolSessionCommand:
                HandleRestoreSecrecyChannelState();
                return true;
            case GetProtocolStateQuery:
                HandleGetProtocolState();
                return true;
            case GetConnectionKyberPublicKeyQuery:
                HandleGetConnectionKyberPublicKey();
                return true;
            case KeepAlive:
                return true;
            case RetryRecoveryMessage:
                AttemptSystemRecreation();
                return true;

            case ReceiveTimeout:
                SaveFinalSnapshot();
                return true;

            case SaveSnapshotSuccess success:
                if (!_savingFinalSnapshot)
                {
                    return true;
                }

                _pendingMessageDeletion = true;
                _pendingSnapshotDeletion = true;

                DeleteMessages(success.Metadata.SequenceNr);
                DeleteSnapshots(new SnapshotSelectionCriteria(success.Metadata.SequenceNr - 1));

                return true;
            case SaveSnapshotFailure:
                return true;

            case DeleteMessagesSuccess:
                if (!_savingFinalSnapshot || !_pendingMessageDeletion)
                {
                    return true;
                }

                _pendingMessageDeletion = false;
                TryCompleteShutdown();

                return true;
            case DeleteSnapshotsSuccess:
                if (!_savingFinalSnapshot || !_pendingSnapshotDeletion)
                {
                    return true;
                }

                _pendingSnapshotDeletion = false;
                TryCompleteShutdown();

                return true;

            case DeleteMessagesFailure failure:
                Context.GetLogger().Warning("[PERSISTENCE-DELETE-MSG-FAILED] Failed to delete messages. " +
                                            "PersistenceId: {0}, Error: {1}. This is non-critical - continuing operation.",
                    PersistenceId, failure.Cause?.Message ?? "Unknown");
                if (!_savingFinalSnapshot || !_pendingMessageDeletion)
                {
                    return true;
                }

                _pendingMessageDeletion = false;
                TryCompleteShutdown();

                return true;

            case DeleteSnapshotsFailure failure:
                Context.GetLogger().Warning("[PERSISTENCE-DELETE-SNAP-FAILED] Failed to delete snapshots. " +
                                            "PersistenceId: {0}, Error: {1}. This is non-critical - continuing operation.",
                    PersistenceId, failure.Cause?.Message ?? "Unknown");

                if (!_savingFinalSnapshot || !_pendingSnapshotDeletion)
                {
                    return true;
                }

                _pendingSnapshotDeletion = false;
                TryCompleteShutdown();
                return true;

            default:
                return false;
        }
    }

    protected override void PreStart()
    {
        base.PreStart();
        Result<Unit, EcliptixProtocolFailure> initResult = _protocolServer.Initialize();
        if (initResult.IsErr)
        {
            Context.GetLogger().Error(
                "[PROTOCOL-INIT] Failed to initialize protocol server for ConnectId {ConnectId}: {Message}",
                connectId,
                initResult.UnwrapErr().Message);
            throw new InvalidOperationException("Protocol server initialization failed");
        }
        Context.System.EventStream.Subscribe(Self, typeof(ProtocolCleanupRequiredEvent));
    }

    protected override void PostStop()
    {
        Timers.CancelAll();
        DisposeAllSessions();
        DisposeIdentity();
        _protocolServer.Shutdown();
        _protocolServer.Dispose();
        base.PostStop();
    }

    private void HandleRestoreSecrecyChannelState()
    {
        if (_currentExchangeType == PubKeyExchangeType.ServerStreaming)
        {
            Sender.Tell(
                Result<RestoreSecrecyChannelResponse, EcliptixProtocolFailure>.Ok(CreateSessionNotFoundResponse()));
            return;
        }

        Option<ProtocolSession> primarySessionOpt = GetPrimarySession();
        if (!primarySessionOpt.IsSome || _state == null || _state.NativeState.IsEmpty)
        {
            if (!primarySessionOpt.IsSome && _state != null && !IsIdentitySeedOnlyState(_state))
            {
                Context.GetLogger().Warning(
                    "[SERVER-RESTORE] Inconsistent state detected (state exists but no DataCenter session). " +
                    "Clearing state for connectId: {0}", connectId);

                byte[]? seedToPreserve = _identitySeed ?? (_state.IdentitySeed.IsEmpty ? null : _state.IdentitySeed.ToByteArray());
                DisposeAllSessions();
                _state = null;
                _currentExchangeType = null;
                SaveSnapshot(new EcliptixSessionState
                {
                    ConnectId = connectId,
                    IdentitySeed = seedToPreserve != null ? ByteString.CopyFrom(seedToPreserve) : ByteString.Empty
                });
            }

            Sender.Tell(
                Result<RestoreSecrecyChannelResponse, EcliptixProtocolFailure>.Ok(CreateSessionNotFoundResponse()));
            return;
        }

        ProtocolSession primarySession = primarySessionOpt.Value!;
        uint sendingIndex = _state?.SendingChainIndex ?? 0;
        uint receivingIndex = _state?.ReceivingChainIndex ?? 0;

        RestoreSecrecyChannelResponse reply = new()
        {
            ReceivingChainLength = receivingIndex,
            SendingChainLength = sendingIndex,
            Status = RestoreSecrecyChannelResponse.Types.RestoreStatus.SessionResumed
        };

        Sender.Tell(Result<RestoreSecrecyChannelResponse, EcliptixProtocolFailure>.Ok(reply));
    }

    private void HandleGetProtocolState()
    {
        Context.GetLogger().Debug("[GET-PROTOCOL-STATE] Retrieving session state for ConnectId: {ConnectId}",
            connectId);

        if (_state == null)
        {
            Sender.Tell(new GetProtocolStateResponse(null));
            return;
        }

        GetProtocolStateResponse reply = new(_state);
        Sender.Tell(reply);

        Context.GetLogger().Debug("[GET-PROTOCOL-STATE] Session state retrieved for ConnectId: {ConnectId}", connectId);
    }

    private void HandleGetConnectionKyberPublicKey()
    {
        Context.GetLogger().Info("[GET-KYBER-KEY] Starting for ConnectId {0}, identity exists: {1}",
            connectId, _identity != null);

        if (_cachedKyberPublicKey is { Length: > 0 })
        {
            Context.GetLogger().Info("[GET-KYBER-KEY] Using cached Kyber key for ConnectId {0}, length: {1}",
                connectId, _cachedKyberPublicKey.Length);
            string cachedPrefix = FormatKeyPrefix(_cachedKyberPublicKey);
            Context.GetLogger().Info("[GET-KYBER-KEY] Kyber public key prefix for ConnectId {0}: {1}",
                connectId, cachedPrefix);
            PersistIdentitySeedIfNeeded();
            Sender.Tell(Result<byte[], EcliptixProtocolFailure>.Ok(_cachedKyberPublicKey));
            return;
        }

        Result<ProtocolIdentity, EcliptixProtocolFailure> identityResult = EnsureIdentity();
        if (identityResult.IsErr)
        {
            Context.GetLogger().Warning("[GET-KYBER-KEY] EnsureIdentity failed for ConnectId {0}: {1}",
                connectId, identityResult.UnwrapErr().Message);
            Sender.Tell(Result<byte[], EcliptixProtocolFailure>.Err(identityResult.UnwrapErr()));
            return;
        }

        Context.GetLogger().Info("[GET-KYBER-KEY] Identity ensured for ConnectId {0}, getting Kyber key",
            connectId);

        Result<byte[], EcliptixProtocolFailure> kyberResult =
            _protocolServer.GetPublicKyber(identityResult.Unwrap());

        if (kyberResult.IsErr)
        {
            Context.GetLogger().Warning("[GET-KYBER-KEY] GetPublicKyber failed for ConnectId {0}: {1}",
                connectId, kyberResult.UnwrapErr().Message);
        }
        else
        {
            _cachedKyberPublicKey = kyberResult.Unwrap();
            Context.GetLogger().Info("[GET-KYBER-KEY] Got Kyber key for ConnectId {0}, length: {1}",
                connectId, kyberResult.Unwrap().Length);
            string prefix = FormatKeyPrefix(kyberResult.Unwrap());
            Context.GetLogger().Info("[GET-KYBER-KEY] Kyber public key prefix for ConnectId {0}: {1}",
                connectId, prefix);
        }

        PersistIdentitySeedIfNeeded();
        Sender.Tell(kyberResult);
    }

    private void HandleNewAnonymousSession(DeriveSharedSecretCommand cmd)
    {
        Result<(ProtocolSession Session, EcliptixSessionState State, PubKeyExchange Reply), EcliptixProtocolFailure>
            sessionResult = CreateNewAnonymousSession(cmd.ConnectId, cmd.PubKeyExchange);

        if (sessionResult.IsErr)
        {
            Sender.Tell(Result<DeriveSharedSecretResponse, EcliptixProtocolFailure>.Err(sessionResult.UnwrapErr()));
            return;
        }

        (ProtocolSession session, EcliptixSessionState newState, PubKeyExchange reply) = sessionResult.Unwrap();

        IActorRef? originalSender = Sender;
        PubKeyExchangeType exchangeType = cmd.PubKeyExchange.OfType;

        if (exchangeType == PubKeyExchangeType.DataCenterEphemeralConnect)
        {
            PersistNewEphemeralSession(exchangeType, session, newState, reply, originalSender);
        }
        else
        {
            HandleNewNonPersistentSession(exchangeType, session, reply, originalSender);
        }
    }

    private void PersistNewEphemeralSession(PubKeyExchangeType exchangeType, ProtocolSession session,
        EcliptixSessionState newState, PubKeyExchange reply, IActorRef originalSender)
    {
        Persist(newState, state =>
        {
            _state = state;
            ReplaceSession(exchangeType, session);
            _currentExchangeType = exchangeType;

            Context.SetReceiveTimeout(IdleTimeout);

            originalSender.Tell(
                Result<DeriveSharedSecretResponse, EcliptixProtocolFailure>.Ok(new DeriveSharedSecretResponse(reply)));
            MaybeSaveSnapshot();
        });
    }

    private void HandleNewNonPersistentSession(PubKeyExchangeType exchangeType, ProtocolSession session,
        PubKeyExchange reply, IActorRef originalSender)
    {
        ReplaceSession(exchangeType, session);
        _currentExchangeType = exchangeType;

        Context.SetReceiveTimeout(null);

        originalSender.Tell(
            Result<DeriveSharedSecretResponse, EcliptixProtocolFailure>.Ok(new DeriveSharedSecretResponse(reply)));
    }

    private bool TryHandleExistingAnonymousSession(DeriveSharedSecretCommand cmd, ProtocolSession existingSession)
    {
        Context.GetLogger().Info(ActorConstants.LogMessages.UsingExistingSession, cmd.ConnectId, cmd.PubKeyExchange.OfType);

        if (IsSessionStale(existingSession))
        {
            Context.GetLogger().Info(ActorConstants.LogMessages.SystemDetectedFreshHandshake);
            DisposeAllSessions();
            _state = null;
            SaveSnapshot(new EcliptixSessionState());
            return false;
        }

        if (IsClientHandshakeDifferent(cmd.PubKeyExchange))
        {
            Context.GetLogger().Info(
                "[SESSION-REFRESH] Client initiated fresh handshake with different keys. Disposing old session for ConnectId {0}",
                cmd.ConnectId);
            DisposeAllSessions();
            _state = null;
            SaveSnapshot(new EcliptixSessionState
            {
                ConnectId = connectId,
                IdentitySeed = ByteString.CopyFrom(_identitySeed ?? [])
            });
            return false;
        }

        ProtobufPublicKeyBundle clientBundle = ProtobufPublicKeyBundle.Parser.ParseFrom(cmd.PubKeyExchange.Payload);
        byte[] clientKyberPublicKey = clientBundle.KyberPublicKey.ToByteArray();

        Result<byte[], EcliptixProtocolFailure> handshakeResult =
            _protocolServer.BeginHandshakeWithKyber(existingSession, cmd.ConnectId, cmd.PubKeyExchange.OfType, clientKyberPublicKey);

        if (handshakeResult.IsErr)
        {

            existingSession.Dispose();
            _sessions.Remove(cmd.PubKeyExchange.OfType);
            Sender.Tell(Result<DeriveSharedSecretResponse, EcliptixProtocolFailure>.Err(handshakeResult.UnwrapErr()));
            return true;
        }

        Result<Unit, EcliptixProtocolFailure> completeResult =
            _protocolServer.CompleteHandshakeAuto(existingSession, cmd.PubKeyExchange.ToByteArray());
        if (completeResult.IsErr)
        {

            existingSession.Dispose();
            _sessions.Remove(cmd.PubKeyExchange.OfType);
            Sender.Tell(Result<DeriveSharedSecretResponse, EcliptixProtocolFailure>.Err(completeResult.UnwrapErr()));
            return true;
        }

        if (cmd.PubKeyExchange.OfType == PubKeyExchangeType.DataCenterEphemeralConnect)
        {
            UpdateStateFromExistingSession(existingSession, handshakeResult.Unwrap());
        }

        ConfigureSessionTimeout(cmd.PubKeyExchange.OfType);

        PubKeyExchange pubKeyReply = PubKeyExchange.Parser.ParseFrom(handshakeResult.Unwrap());
        Sender.Tell(Result<DeriveSharedSecretResponse, EcliptixProtocolFailure>.Ok(new DeriveSharedSecretResponse(pubKeyReply)));

        return true;
    }

    private bool IsSessionStale(ProtocolSession session)
    {
        try
        {
            Result<bool, EcliptixProtocolFailure> hasConn = _protocolServer.HasConnection(session);
            return hasConn.IsErr || hasConn.Unwrap() == false;
        }
        catch (InvalidOperationException)
        {
            return true;
        }
    }

    private void UpdateStateFromExistingSession(ProtocolSession session, byte[] peerHandshake)
    {
        if (_state == null)
        {
            return;
        }

        PubKeyExchange parsed = PubKeyExchange.Parser.ParseFrom(peerHandshake);
        Result<EcliptixSessionState, EcliptixProtocolFailure> newStateResult =
            ExportSessionState(session, _state, parsed);

        if (newStateResult.IsErr)
        {
            Context.GetLogger().Warning(
                "[STATE-EXPORT-FAILED] Failed to export protocol state after handshake for ConnectId: {0}. Error: {1}",
                connectId,
                newStateResult.UnwrapErr().Message);
            return;
        }

        Persist(newStateResult.Unwrap(), state =>
        {
            _state = state;
            MaybeSaveSnapshot();
        });
    }

    private void HandleInitialKeyExchange(DeriveSharedSecretCommand cmd)
    {
        bool existingSessionFound = _sessions.TryGetValue(cmd.PubKeyExchange.OfType, out ProtocolSession? existingSession)
                                    && _state != null;

        if (existingSessionFound && IsClientHandshakeDifferent(cmd.PubKeyExchange))
        {
            Context.GetLogger().Info(
                "[FRESH-HANDSHAKE] Client keys differ from recovered state for ConnectId {0}",
                cmd.ConnectId);
            DisposeAllSessions();
            _state = null;
            existingSessionFound = false;
        }

        switch (existingSessionFound)
        {
            case true when IsAuthenticatedSession():
                HandleAuthenticatedToAnonymousTransition();
                break;
            case true when TryHandleExistingAnonymousSession(cmd, existingSession!):
                return;
        }

        HandleNewAnonymousSession(cmd);
    }

    private void ProcessAndReplyToExistingSession(InitializeProtocolWithMasterKeyCommand cmd, ProtocolSession existingSession)
    {
        PubKeyExchangeType exchangeType = cmd.ClientPubKeyExchange.OfType;

        ProtobufPublicKeyBundle clientBundle = ProtobufPublicKeyBundle.Parser.ParseFrom(cmd.ClientPubKeyExchange.Payload);
        byte[] clientKyberPublicKey = clientBundle.KyberPublicKey.ToByteArray();

        if (clientKyberPublicKey.Length == 0)
        {
            CryptographicOperations.ZeroMemory(cmd.RootKey);
            Context.GetLogger().Warning(
                "[AUTH-HANDSHAKE] Client did not provide Kyber public key for existing session. ConnectId: {0}",
                cmd.ConnectId);
            Sender.Tell(Result<InitializeProtocolWithMasterKeyResponse, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.Decode(
                    "Client must provide Kyber public key for post-quantum hybrid authenticated handshake")));
            return;
        }

        Result<byte[], EcliptixProtocolFailure> handshakeResult =
            _protocolServer.BeginHandshakeWithKyber(existingSession, cmd.ConnectId, exchangeType, clientKyberPublicKey);
        if (handshakeResult.IsErr)
        {
            CryptographicOperations.ZeroMemory(cmd.RootKey);
            existingSession.Dispose();
            _sessions.Remove(exchangeType);
            Sender.Tell(Result<InitializeProtocolWithMasterKeyResponse, EcliptixProtocolFailure>.Err(handshakeResult.UnwrapErr()));
            return;
        }

        Result<Unit, EcliptixProtocolFailure> completeResult =
            _protocolServer.CompleteHandshake(existingSession, cmd.ClientPubKeyExchange.ToByteArray(), cmd.RootKey);
        CryptographicOperations.ZeroMemory(cmd.RootKey);

        if (completeResult.IsErr)
        {
            existingSession.Dispose();
            _sessions.Remove(exchangeType);
            Sender.Tell(Result<InitializeProtocolWithMasterKeyResponse, EcliptixProtocolFailure>.Err(completeResult.UnwrapErr()));
            return;
        }

        PubKeyExchange pubKeyReply = PubKeyExchange.Parser.ParseFrom(handshakeResult.Unwrap());

        if (exchangeType == PubKeyExchangeType.DataCenterEphemeralConnect)
        {
            PersistExistingEphemeralSession(existingSession, pubKeyReply, Sender, exchangeType);
        }
        else
        {
            HandleExistingNonPersistentSession(pubKeyReply, exchangeType, Sender);
        }
    }

    private void PersistExistingEphemeralSession(ProtocolSession existingSession, PubKeyExchange pubKeyReply, IActorRef sender, PubKeyExchangeType exchangeType)
    {
        Result<EcliptixSessionState, EcliptixProtocolFailure> newStateResult =
            ExportSessionState(existingSession, _state, pubKeyReply);

        if (newStateResult.IsOk)
        {
            Persist(newStateResult.Unwrap(), state =>
            {
                _state = state;
                _currentExchangeType = exchangeType;
                Context.SetReceiveTimeout(IdleTimeout);
                sender.Tell(
                    Result<InitializeProtocolWithMasterKeyResponse, EcliptixProtocolFailure>.Ok(
                        new InitializeProtocolWithMasterKeyResponse(pubKeyReply)));
                MaybeSaveSnapshot();
            });
        }
        else
        {
            sender.Tell(Result<InitializeProtocolWithMasterKeyResponse, EcliptixProtocolFailure>.Err(newStateResult.UnwrapErr()));
        }
    }

    private void HandleExistingNonPersistentSession(PubKeyExchange pubKeyReply, PubKeyExchangeType exchangeType, IActorRef sender)
    {
        _currentExchangeType = exchangeType;
        Context.SetReceiveTimeout(null);

        sender.Tell(
            Result<InitializeProtocolWithMasterKeyResponse, EcliptixProtocolFailure>.Ok(
                new InitializeProtocolWithMasterKeyResponse(pubKeyReply)));
    }
    private bool TryHandleExistingAuthenticatedSession(InitializeProtocolWithMasterKeyCommand cmd, ProtocolSession existingSession)
    {
        if (_state != null && !_state.IdentitySeed.IsEmpty)
        {
            ProcessAndReplyToExistingSession(cmd, existingSession);
            return true;
        }

        HandleKeyMismatch(cmd.ClientPubKeyExchange.OfType);
        return false;
    }

    private void HandleNewAuthenticatedSession(InitializeProtocolWithMasterKeyCommand cmd)
    {
        Result<(ProtocolSession Session, EcliptixSessionState State, PubKeyExchange Reply), EcliptixProtocolFailure>
            sessionResult = CreateNewAuthenticatedSession(cmd.ConnectId, cmd.AccountId, cmd.MembershipId,
                cmd.ClientPubKeyExchange, cmd.RootKey);

        if (sessionResult.IsErr)
        {
            Sender.Tell(Result<InitializeProtocolWithMasterKeyResponse, EcliptixProtocolFailure>.Err(sessionResult.UnwrapErr()));
            return;
        }

        (ProtocolSession system, EcliptixSessionState newState, PubKeyExchange reply) = sessionResult.Unwrap();
        IActorRef originalSender = Sender;
        PubKeyExchangeType exchangeType = cmd.ClientPubKeyExchange.OfType;

        if (exchangeType == PubKeyExchangeType.DataCenterEphemeralConnect)
        {
            PersistNewAuthenticatedEphemeralSession(exchangeType, system, newState, reply, originalSender);
        }
        else
        {
            HandleNewAuthenticatedNonPersistentSession(exchangeType, system, reply, originalSender);
        }
    }

    private void PersistNewAuthenticatedEphemeralSession(PubKeyExchangeType exchangeType, ProtocolSession session,
        EcliptixSessionState newState, PubKeyExchange reply, IActorRef originalSender)
    {
        Persist(newState, state =>
        {
            _state = state;
            ReplaceSession(exchangeType, session);
            _currentExchangeType = exchangeType;
            Context.SetReceiveTimeout(IdleTimeout);

            SaveSnapshot(_state);

            originalSender.Tell(
                Result<InitializeProtocolWithMasterKeyResponse, EcliptixProtocolFailure>.Ok(
                    new InitializeProtocolWithMasterKeyResponse(reply)));
        });
    }

    private void HandleNewAuthenticatedNonPersistentSession(PubKeyExchangeType exchangeType, ProtocolSession session,
        PubKeyExchange reply, IActorRef originalSender)
    {
        ReplaceSession(exchangeType, session);
        _currentExchangeType = exchangeType;
        Context.SetReceiveTimeout(null);

        originalSender.Tell(
            Result<InitializeProtocolWithMasterKeyResponse, EcliptixProtocolFailure>.Ok(
                new InitializeProtocolWithMasterKeyResponse(reply)));
    }

    private void HandleKeyMismatch(PubKeyExchangeType exchangeType)
    {
        Context.GetLogger().Warning(
            "[PROTOCOL] Identity key mismatch for ConnectId {ConnectId}, ExchangeType {ExchangeType} - creating new session.",
            connectId, exchangeType);

        _sessions.Remove(exchangeType);

        _state = null;
        _currentExchangeType = null;
        SaveSnapshot(new EcliptixSessionState());

    }

    private void HandleAuthenticatedProtocolInitialization(InitializeProtocolWithMasterKeyCommand cmd)
    {
        PubKeyExchangeType exchangeType = cmd.ClientPubKeyExchange.OfType;

        if (_sessions.TryGetValue(exchangeType, out ProtocolSession? existingSystem)
            && _state != null
            && TryHandleExistingAuthenticatedSession(cmd, existingSystem))
        {
            return;
        }

        HandleNewAuthenticatedSession(cmd);
    }

    private void HandleEncrypt(EncryptPayloadCommand cmd)
    {
        if (!_sessions.TryGetValue(cmd.PubKeyExchangeType, out ProtocolSession? system))
        {
            Option<ProtocolSession> primaryProtocolSystemOpt = GetPrimarySession();
            if (!primaryProtocolSystemOpt.IsSome || _state == null)
            {
                Sender.Tell(
                    Result<SecureEnvelope, EcliptixProtocolFailure>.Err(
                        EcliptixProtocolFailure.StateMismatch(
                            $"Protocol state desynchronized: no protocol system found for exchange type {cmd.PubKeyExchangeType}")));
                return;
            }

            system = primaryProtocolSystemOpt.Value!;
        }

        Result<byte[], EcliptixProtocolFailure> sendResult = _protocolServer.SendMessage(system, cmd.Payload);
        if (sendResult.IsErr)
        {
            Sender.Tell(Result<SecureEnvelope, EcliptixProtocolFailure>.Err(sendResult.UnwrapErr()));
            return;
        }

        SecureEnvelope envelope = SecureEnvelope.Parser.ParseFrom(sendResult.Unwrap());
        Result<EcliptixSessionState, EcliptixProtocolFailure> newStateResult = ExportSessionState(system, _state, envelope);
        if (newStateResult.IsErr)
        {
            Sender.Tell(Result<SecureEnvelope, EcliptixProtocolFailure>.Err(newStateResult.UnwrapErr()));
            return;
        }

        EcliptixSessionState newState = newStateResult.Unwrap();
        IActorRef? originalSender = Sender;

        if (cmd.PubKeyExchangeType == PubKeyExchangeType.DataCenterEphemeralConnect)
        {
            Persist(newState, state =>
            {
                _state = state;
                originalSender.Tell(Result<SecureEnvelope, EcliptixProtocolFailure>.Ok(envelope));
                MaybeSaveSnapshot();
            });
        }
        else
        {
            _state = newState;
            originalSender.Tell(Result<SecureEnvelope, EcliptixProtocolFailure>.Ok(envelope));
        }
    }

    private void HandleDecrypt(DecryptSecureEnvelopeCommand actorEvent)
    {
        if (!_sessions.TryGetValue(actorEvent.PubKeyExchangeType, out ProtocolSession? session))
        {
            Option<ProtocolSession> primaryProtocolSystemOpt = GetPrimarySession();
            if (!primaryProtocolSystemOpt.IsSome || _state == null)
            {
                Sender.Tell(
                    Result<byte[], EcliptixProtocolFailure>.Err(
                        EcliptixProtocolFailure.StateMismatch(
                            $"Protocol state desynchronized: no protocol system found for exchange type {actorEvent.PubKeyExchangeType}")));
                return;
            }

            session = primaryProtocolSystemOpt.Value!;
        }

        byte[] envelopeBytes = actorEvent.SecureEnvelope.ToByteArray();
        Result<Unit, EcliptixProtocolFailure> validate =
            _protocolServer.ValidateEnvelopeHybridRequirements(envelopeBytes);
        if (validate.IsErr)
        {
            HandleDecryptionError(validate.UnwrapErr(), connectId);
            return;
        }

        Result<byte[], EcliptixProtocolFailure> result = _protocolServer.ReceiveMessage(session, envelopeBytes);
        if (result.IsErr)
        {
            HandleDecryptionError(result.UnwrapErr(), connectId);
            return;
        }

        IActorRef? originalSender = Sender;
        Result<EcliptixSessionState, EcliptixProtocolFailure> newStateResult = ExportSessionState(session, _state, actorEvent.SecureEnvelope);
        if (newStateResult.IsErr)
        {
            HandleDecryptionError(newStateResult.UnwrapErr(), connectId);
            return;
        }

        if (actorEvent.PubKeyExchangeType == PubKeyExchangeType.DataCenterEphemeralConnect)
        {
            Persist(newStateResult.Unwrap(), state =>
            {
                _state = state;
                originalSender.Tell(Result<byte[], EcliptixProtocolFailure>.Ok(result.Unwrap()));
                MaybeSaveSnapshot();
            });
        }
        else
        {
            _state = newStateResult.Unwrap();
            originalSender.Tell(Result<byte[], EcliptixProtocolFailure>.Ok(result.Unwrap()));
        }
    }

    private void HandleCleanupProtocolForType(CleanupProtocolForTypeCommand cmd)
    {
        if (_sessions.TryGetValue(cmd.ExchangeType, out ProtocolSession? system))
        {
            system?.Dispose();
            _sessions.Remove(cmd.ExchangeType);

            Sender.Tell(Result<Unit, EcliptixProtocolFailure>.Ok(Unit.Value));
        }
        else
        {
            Sender.Tell(Result<Unit, EcliptixProtocolFailure>.Ok(Unit.Value));
        }
    }

    private void HandleProtocolCleanupRequired(ProtocolCleanupRequiredEvent evt)
    {
        if (evt.ConnectId != connectId)
        {
            return;
        }

        if (!IsAuthenticatedSession())
        {
            return;
        }

        DisposeAllSessions();
        _currentExchangeType = null;

        _state = null;

        _savingFinalSnapshot = true;
        _pendingMessageDeletion = true;
        _pendingSnapshotDeletion = true;

        SaveSnapshot(new EcliptixSessionState());
    }

    private void MaybeSaveSnapshot()
    {
        if (_currentExchangeType != PubKeyExchangeType.DataCenterEphemeralConnect || _state == null)
        {
            return;
        }

        DateTimeOffset now = DateTimeOffset.UtcNow;
        if (now - _lastSnapshotTime < MinSnapshotInterval)
        {
            return;
        }

        _lastSnapshotTime = now;
        SaveSnapshot(_state);
        Context.GetLogger().Debug(
            "[SNAPSHOT-SAVE] Snapshot saved. ConnectId: {0}, SeqNr: {1}, Sending: {2}, Receiving: {3}",
            connectId, LastSequenceNr,
            _state.SendingChainIndex,
            _state.ReceivingChainIndex);
    }

    private void SaveFinalSnapshot()
    {
        if (_state != null &&
            _currentExchangeType == PubKeyExchangeType.DataCenterEphemeralConnect &&
            !_savingFinalSnapshot)
        {
            _savingFinalSnapshot = true;
            SaveSnapshot(_state);
        }
        else if (_state != null && IsIdentitySeedOnlyState(_state) && !_savingFinalSnapshot)
        {
            _savingFinalSnapshot = true;
            SaveSnapshot(_state);
        }
        else if (!_savingFinalSnapshot)
        {
            _savingFinalSnapshot = true;
            SaveSnapshot(new EcliptixSessionState());
        }
        else
        {
            Context.Stop(Self);
        }
    }

    private void TryCompleteShutdown()
    {
        if (!_pendingMessageDeletion && !_pendingSnapshotDeletion)
        {
            Context.Stop(Self);
        }
    }

    private void DisposeAllSessions()
    {
        foreach (ProtocolSession session in _sessions.Values)
        {
            session?.Dispose();
        }

        _sessions.Clear();
    }

    private void DisposeIdentity()
    {
        _identity?.Dispose();
        _identity = null;

        if (_identitySeed != null)
        {
            CryptographicOperations.ZeroMemory(_identitySeed);
            _identitySeed = null;
        }

        if (_cachedKyberPublicKey != null)
        {
            CryptographicOperations.ZeroMemory(_cachedKyberPublicKey);
            _cachedKyberPublicKey = null;
        }
    }

    private void AttemptSystemRecreation()
    {
        if (_state == null)
        {
            Context.GetLogger()
                .Warning(ActorConstants.RecoveryLogMessages.NoStateAvailable, connectId);
            return;
        }

        if (IsIdentitySeedOnlyState(_state))
        {
            Context.GetLogger()
                .Debug("[RECOVERY] Identity seed present but no handshake for ConnectId {0}. Skipping recreation.",
                    connectId);
            return;
        }

        if (_state.PeerHandshakeMessage == null)
        {
            Context.GetLogger()
                .Warning(ActorConstants.RecoveryLogMessages.PeerHandshakeMessageNull, connectId);
            byte[]? seedToPreserve = _identitySeed ?? (_state.IdentitySeed.IsEmpty ? null : _state.IdentitySeed.ToByteArray());
            _state = null;
            _currentExchangeType = null;
            SaveSnapshot(new EcliptixSessionState
            {
                ConnectId = connectId,
                IdentitySeed = seedToPreserve != null ? ByteString.CopyFrom(seedToPreserve) : ByteString.Empty
            });
            return;
        }

        PubKeyExchangeType exchangeType = _state.PeerHandshakeMessage.OfType;

        if (exchangeType == PubKeyExchangeType.ServerStreaming)
        {
            _state = null;
            _currentExchangeType = null;
            SaveSnapshot(new EcliptixSessionState());
            return;
        }

        if (Serilog.Log.IsEnabled(Serilog.Events.LogEventLevel.Debug))
        {
            int attempt = _recoveryRetryCount + 1;
            Context.GetLogger()
                .Debug(
                    ActorConstants.RecoveryLogMessages.AttemptingSystemRecreation,
                    attempt,
                    MaxRecoveryRetries,
                    connectId);
        }

        Result<ProtocolSession, EcliptixProtocolFailure> sessionResult = RecreateSessionFromState(exchangeType);

        if (sessionResult.IsOk)
        {
            ReplaceSession(exchangeType, sessionResult.Unwrap());
            _recoveryRetryCount = 0;
        }
        else
        {
            _recoveryRetryCount++;
            EcliptixProtocolFailure failure = sessionResult.UnwrapErr();

            if (failure.FailureType == EcliptixProtocolFailureType.StateMismatch)
            {
                Context.GetLogger().Warning(
                    "[RECOVERY] State mismatch detected after restore for ConnectId {0}: {1}. Clearing state.",
                    connectId,
                    failure.Message);

                byte[]? seedToPreserve = _identitySeed ?? (_state?.IdentitySeed.IsEmpty == false ? _state.IdentitySeed.ToByteArray() : null);
                DisposeAllSessions();
                _state = null;
                _currentExchangeType = null;
                _recoveryRetryCount = 0;

                SaveSnapshot(new EcliptixSessionState
                {
                    ConnectId = connectId,
                    IdentitySeed = seedToPreserve != null ? ByteString.CopyFrom(seedToPreserve) : ByteString.Empty
                });
                return;
            }

            Context.GetLogger()
                .Warning(
                    ActorConstants.RecoveryLogMessages.FailedToRecreateSystem,
                    connectId,
                    _recoveryRetryCount,
                    MaxRecoveryRetries,
                    failure.Message);

            if (_recoveryRetryCount < MaxRecoveryRetries)
            {
                int delaySeconds = (int)Math.Pow(2, _recoveryRetryCount - 1) * 5;
                Timers.StartSingleTimer(
                    RecoveryRetryTimerKey,
                    new RetryRecoveryMessage(),
                    TimeSpan.FromSeconds(delaySeconds));
            }
            else
            {
                Context.GetLogger()
                    .Error(ActorConstants.RecoveryLogMessages.MaxRetriesExceeded, connectId);

                byte[]? seedToPreserve = _identitySeed ?? (_state?.IdentitySeed.IsEmpty == false ? _state.IdentitySeed.ToByteArray() : null);
                DisposeAllSessions();
                _state = null;
                _currentExchangeType = null;

                SaveSnapshot(new EcliptixSessionState
                {
                    ConnectId = connectId,
                    IdentitySeed = seedToPreserve != null ? ByteString.CopyFrom(seedToPreserve) : ByteString.Empty
                });
            }
        }
    }

    private bool IsAuthenticatedSession()
    {
        return _state != null &&
               _state.AccountId != null &&
               _state.AccountId.Length > 0;
    }

    private Option<ProtocolSession> GetPrimarySession()
    {
        return _sessions.TryGetValue(PubKeyExchangeType.DataCenterEphemeralConnect,
            out ProtocolSession? session)
            ? Option<ProtocolSession>.Some(session)
            : Option<ProtocolSession>.None;
    }

    private void ReplaceSession(PubKeyExchangeType exchangeType, ProtocolSession session)
    {
        if (_sessions.TryGetValue(exchangeType, out ProtocolSession? existing))
        {
            existing.Dispose();
        }

        _sessions[exchangeType] = session;
    }

    private void HandleEncryptComponents(EncryptPayloadComponentsCommand cmd)
    {

        if (!_sessions.TryGetValue(cmd.ExchangeType, out ProtocolSession? session))
        {
            Option<ProtocolSession> primarySessionOpt = GetPrimarySession();
            if (!primarySessionOpt.IsSome || _state == null)
            {
                Sender.Tell(
                    Result<(EnvelopeMetadata Header, byte[] EncryptedPayload), EcliptixProtocolFailure>.Err(
                        EcliptixProtocolFailure.StateMismatch(
                            $"Protocol state desynchronized: no protocol system found for exchange type {cmd.ExchangeType}")));
                return;
            }

            session = primarySessionOpt.Value!;
        }

        Result<byte[], EcliptixProtocolFailure> sendResult = _protocolServer.SendMessage(session, cmd.Payload);
        if (sendResult.IsErr)
        {
            Sender.Tell(Result<(EnvelopeMetadata, byte[]), EcliptixProtocolFailure>.Err(sendResult.UnwrapErr()));
            return;
        }

        SecureEnvelope envelope = SecureEnvelope.Parser.ParseFrom(sendResult.Unwrap());
        Result<EcliptixSessionState, EcliptixProtocolFailure> newStateResult = ExportSessionState(session, _state, envelope);
        if (newStateResult.IsErr)
        {
            Sender.Tell(Result<(byte[] MetaData, byte[] EncryptedPayload), EcliptixProtocolFailure>.Err(newStateResult.UnwrapErr()));
            return;
        }

        IActorRef? originalSender = Sender;
        if (cmd.ExchangeType == PubKeyExchangeType.DataCenterEphemeralConnect)
        {
            Persist(newStateResult.Unwrap(), state =>
            {
                _state = state;
                originalSender.Tell(Result<(byte[] MetaData, byte[] EncryptedPayload), EcliptixProtocolFailure>.Ok(
                    (envelope.MetaData.ToByteArray(), envelope.EncryptedPayload.ToByteArray())));
                MaybeSaveSnapshot();
            });
        }
        else
        {
            _state = newStateResult.Unwrap();
            originalSender.Tell(Result<(byte[] MetaData, byte[] EncryptedPayload), EcliptixProtocolFailure>.Ok(
                (envelope.MetaData.ToByteArray(), envelope.EncryptedPayload.ToByteArray())));
        }
    }

    private void HandleDecryptWithHeader(DecryptPayloadWithHeaderCommand cmd)
    {
        if (!_sessions.TryGetValue(cmd.ExchangeType, out ProtocolSession? session))
        {
            Option<ProtocolSession> primaryProtocolSystemOpt = GetPrimarySession();
            if (!primaryProtocolSystemOpt.IsSome || _state == null)
            {
                Sender.Tell(
                    Result<byte[], EcliptixProtocolFailure>.Err(
                        EcliptixProtocolFailure.StateMismatch(
                            $"Protocol state desynchronized: no protocol system found for exchange type {cmd.ExchangeType}")));
                return;
            }

            session = primaryProtocolSystemOpt.Value!;
        }

        SecureEnvelope envelope = new()
        {
            MetaData = ByteString.CopyFrom(cmd.Metadata),
            EncryptedPayload = ByteString.CopyFrom(cmd.EncryptedPayload)
        };

        Result<Unit, EcliptixProtocolFailure> validate =
            _protocolServer.ValidateEnvelopeHybridRequirements(envelope.ToByteArray());
        if (validate.IsErr)
        {
            HandleDecryptionError(validate.UnwrapErr(), connectId);
            return;
        }

        Result<byte[], EcliptixProtocolFailure> result = _protocolServer.ReceiveMessage(session, envelope.ToByteArray());
        if (result.IsErr)
        {
            HandleDecryptionError(result.UnwrapErr(), connectId);
            return;
        }

        Result<EcliptixSessionState, EcliptixProtocolFailure> newStateResult = ExportSessionState(session, _state, envelope);
        if (newStateResult.IsErr)
        {
            HandleDecryptionError(newStateResult.UnwrapErr(), connectId);
            return;
        }

        IActorRef? originalSender = Sender;
        if (cmd.ExchangeType == PubKeyExchangeType.DataCenterEphemeralConnect)
        {
            Persist(newStateResult.Unwrap(), state =>
            {
                _state = state;
                originalSender.Tell(Result<byte[], EcliptixProtocolFailure>.Ok(result.Unwrap()));
                MaybeSaveSnapshot();
            });
        }
        else
        {
            _state = newStateResult.Unwrap();
            originalSender.Tell(Result<byte[], EcliptixProtocolFailure>.Ok(result.Unwrap()));
        }
    }

    private void HandleAuthenticatedToAnonymousTransition()
    {
        DisposeAllSessions();
        DisposeIdentity();
        _state = null;
        SaveSnapshot(new EcliptixSessionState());
    }

    private static RestoreSecrecyChannelResponse CreateSessionNotFoundResponse()
    {
        return new RestoreSecrecyChannelResponse
        {
            Status = RestoreSecrecyChannelResponse.Types.RestoreStatus.SessionNotFound,
            ReceivingChainLength = ActorConstants.Constants.Zero,
            SendingChainLength = ActorConstants.Constants.Zero
        };
    }

    private static bool IsIndexDesyncError(EcliptixProtocolFailure error)
    {
        if (error.FailureType == EcliptixProtocolFailureType.IndexDesynchronized ||
            error.FailureType == EcliptixProtocolFailureType.ChainIndexMismatch)
        {
            return true;
        }

        string message = error.Message;
        if (error.InnerException?.Message is { Length: > 0 } innerMessage)
        {
            message = $"{message} {innerMessage}";
        }

        return message.Contains("message index", StringComparison.OrdinalIgnoreCase) ||
               message.Contains("nonce/index", StringComparison.OrdinalIgnoreCase) ||
               message.Contains("index too far", StringComparison.OrdinalIgnoreCase) ||
               message.Contains("index too old", StringComparison.OrdinalIgnoreCase) ||
               message.Contains("index binding failed", StringComparison.OrdinalIgnoreCase) ||
               message.Contains("chain index", StringComparison.OrdinalIgnoreCase);
    }

    private void HandleDecryptionError(EcliptixProtocolFailure error, uint connectId)
    {
        Context.GetLogger().Error(
            "[SERVER-DECRYPT-ERROR] Decryption failed. ConnectId: {0}, ErrorType: {1}, Message: {2}",
            connectId, error.FailureType, error.Message);

        bool isHeaderAuthFailure = error.FailureType == EcliptixProtocolFailureType.HeaderAuthenticationFailed;
        bool isMetadataAuthFailure =
            error.Message.Contains("failed to decrypt metadata", StringComparison.OrdinalIgnoreCase) ||
            error.Message.Contains("authentication tag verification failed", StringComparison.OrdinalIgnoreCase) ||
            (error.InnerException?.Message?.Contains("authentication tag verification failed", StringComparison.OrdinalIgnoreCase)
             ?? false);
        bool isIndexDesync = IsIndexDesyncError(error);
        bool clearSession = isHeaderAuthFailure ||
                            error.FailureType == EcliptixProtocolFailureType.SessionAuthenticationFailed ||
                            error.FailureType == EcliptixProtocolFailureType.StateMismatch ||
                            isIndexDesync;

        if ((isHeaderAuthFailure || isMetadataAuthFailure) &&
            _currentExchangeType == PubKeyExchangeType.DataCenterEphemeralConnect)
        {
            Context.GetLogger().Warning(
                "[SERVER-STATE-DESYNC] Authenticated channel header auth failed for ConnectId {0} - forcing master key resync fallback.",
                connectId);

            DisposeAllSessions();
            _state = null;
            _currentExchangeType = null;

            SaveSnapshot(new EcliptixSessionState());

            Sender.Tell(Result<byte[], EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.Generic("master_key_shares_not_found")));
            return;
        }

        if (clearSession)
        {
            Context.GetLogger()
                .Warning(
                    "[SERVER-STATE-DESYNC] Header authentication failed for ConnectId {0} - protocol state desynchronized. Clearing state to force re-handshake.",
                    connectId);
            DisposeAllSessions();
            _state = null;
            _currentExchangeType = null;

            SaveSnapshot(new EcliptixSessionState());

            if (isHeaderAuthFailure)
            {
                Sender.Tell(Result<byte[], EcliptixProtocolFailure>.Err(
                    EcliptixProtocolFailure.StateMismatch(
                        "Protocol state desynchronized after server restart - re-handshake required")));
                return;
            }
        }

        Sender.Tell(Result<byte[], EcliptixProtocolFailure>.Err(error));
    }

    private Result<(ProtocolSession Session, EcliptixSessionState State, PubKeyExchange Reply),
            EcliptixProtocolFailure>
        CreateNewAuthenticatedSession(uint connectId, Guid accountId, Guid membershipId,
            PubKeyExchange clientPubKeyExchange, byte[] rootKey)
    {
        Result<ProtocolIdentity, EcliptixProtocolFailure> identityResult = EnsureIdentity(accountId);
        if (identityResult.IsErr)
        {
            return Result<(ProtocolSession, EcliptixSessionState, PubKeyExchange), EcliptixProtocolFailure>
                .Err(identityResult.UnwrapErr());
        }

        LogCachedKyberPrefix("HANDSHAKE-KYBER");

        Result<ProtocolSession, EcliptixProtocolFailure> sessionResult =
            _protocolServer.CreateSession(identityResult.Unwrap(), OnProtocolStateChanged);

        _identity?.Detach();
        _identity = null;

        if (sessionResult.IsErr)
        {
            CryptographicOperations.ZeroMemory(rootKey);
            return Result<(ProtocolSession, EcliptixSessionState, PubKeyExchange), EcliptixProtocolFailure>
                .Err(sessionResult.UnwrapErr());
        }

        ProtocolSession session = sessionResult.Unwrap();

        ProtobufPublicKeyBundle clientBundle = ProtobufPublicKeyBundle.Parser.ParseFrom(clientPubKeyExchange.Payload);
        byte[] clientKyberPublicKey = clientBundle.KyberPublicKey.ToByteArray();

        if (clientKyberPublicKey.Length == 0)
        {
            CryptographicOperations.ZeroMemory(rootKey);
            Context.GetLogger().Warning(
                "[AUTH-HANDSHAKE] Client did not provide Kyber public key for authenticated handshake. ConnectId: {0}, AccountId: {1}",
                connectId, accountId);
            return Result<(ProtocolSession, EcliptixSessionState, PubKeyExchange), EcliptixProtocolFailure>
                .Err(EcliptixProtocolFailure.Decode(
                    "Client must provide Kyber public key for post-quantum hybrid authenticated handshake"));
        }

        Result<byte[], EcliptixProtocolFailure> handshakeResult = _protocolServer.BeginHandshakeWithKyber(
            session, connectId, clientPubKeyExchange.OfType, clientKyberPublicKey);
        if (handshakeResult.IsErr)
        {
            CryptographicOperations.ZeroMemory(rootKey);
            return Result<(ProtocolSession, EcliptixSessionState, PubKeyExchange), EcliptixProtocolFailure>
                .Err(handshakeResult.UnwrapErr());
        }

        Result<Unit, EcliptixProtocolFailure> completeResult =
            _protocolServer.CompleteHandshake(session, clientPubKeyExchange.ToByteArray(), rootKey);
        CryptographicOperations.ZeroMemory(rootKey);
        if (completeResult.IsErr)
        {
            return Result<(ProtocolSession, EcliptixSessionState, PubKeyExchange), EcliptixProtocolFailure>
                .Err(completeResult.UnwrapErr());
        }

        PubKeyExchange reply = PubKeyExchange.Parser.ParseFrom(handshakeResult.Unwrap());
        Result<EcliptixSessionState, EcliptixProtocolFailure> stateToPersistResult =
            ExportSessionState(session, _state, reply, membershipId, accountId);
        if (stateToPersistResult.IsErr)
        {
            return Result<(ProtocolSession, EcliptixSessionState, PubKeyExchange), EcliptixProtocolFailure>
                .Err(stateToPersistResult.UnwrapErr());
        }

        return Result<(ProtocolSession, EcliptixSessionState, PubKeyExchange), EcliptixProtocolFailure>
            .Ok((session, stateToPersistResult.Unwrap(), reply));
    }

    private void ConfigureSessionTimeout(PubKeyExchangeType exchangeType)
    {
        if (exchangeType == PubKeyExchangeType.DataCenterEphemeralConnect)
        {
            _currentExchangeType = exchangeType;
            Context.SetReceiveTimeout(IdleTimeout);
        }
        else
        {
            _currentExchangeType = exchangeType;
            Context.SetReceiveTimeout(null);
        }
    }

    private Result<(ProtocolSession Session, EcliptixSessionState State, PubKeyExchange Reply),
            EcliptixProtocolFailure>
        CreateNewAnonymousSession(uint connectId, PubKeyExchange pubKeyExchange)
    {
        Result<ProtocolIdentity, EcliptixProtocolFailure> identityResult = EnsureIdentity();
        if (identityResult.IsErr)
        {
            return Result<(ProtocolSession, EcliptixSessionState, PubKeyExchange), EcliptixProtocolFailure>
                .Err(identityResult.UnwrapErr());
        }

        LogCachedKyberPrefix("HANDSHAKE-KYBER");

        Result<ProtocolSession, EcliptixProtocolFailure> sessionResult =
            _protocolServer.CreateSession(identityResult.Unwrap(), OnProtocolStateChanged);

        _identity?.Detach();
        _identity = null;

        if (sessionResult.IsErr)
        {
            return Result<(ProtocolSession, EcliptixSessionState, PubKeyExchange), EcliptixProtocolFailure>
                .Err(sessionResult.UnwrapErr());
        }

        ProtocolSession session = sessionResult.Unwrap();

        ProtobufPublicKeyBundle clientBundle = ProtobufPublicKeyBundle.Parser.ParseFrom(pubKeyExchange.Payload);
        byte[] clientKyberPublicKey = clientBundle.KyberPublicKey.ToByteArray();

        Result<byte[], EcliptixProtocolFailure> replyResult = _protocolServer.BeginHandshakeWithKyber(
            session, connectId, pubKeyExchange.OfType, clientKyberPublicKey);
        if (replyResult.IsErr)
        {
            return Result<(ProtocolSession, EcliptixSessionState, PubKeyExchange), EcliptixProtocolFailure>
                .Err(replyResult.UnwrapErr());
        }

        Result<Unit, EcliptixProtocolFailure> completeResult =
            _protocolServer.CompleteHandshakeAuto(session, pubKeyExchange.ToByteArray());
        if (completeResult.IsErr)
        {
            return Result<(ProtocolSession, EcliptixSessionState, PubKeyExchange), EcliptixProtocolFailure>
                .Err(completeResult.UnwrapErr());
        }

        PubKeyExchange reply = PubKeyExchange.Parser.ParseFrom(replyResult.Unwrap());
        Result<EcliptixSessionState, EcliptixProtocolFailure> stateToPersistResult =
            ExportSessionState(session, _state, reply);
        if (stateToPersistResult.IsErr)
        {
            return Result<(ProtocolSession, EcliptixSessionState, PubKeyExchange), EcliptixProtocolFailure>
                .Err(stateToPersistResult.UnwrapErr());
        }

        return Result<(ProtocolSession, EcliptixSessionState, PubKeyExchange), EcliptixProtocolFailure>
            .Ok((session, stateToPersistResult.Unwrap(), reply));
    }

    private Result<ProtocolIdentity, EcliptixProtocolFailure> EnsureIdentity(Guid? accountId = null)
    {
        if (_identity != null)
        {
            Context.GetLogger().Info("[ENSURE-IDENTITY] Identity already exists for ConnectId {0}",
                connectId);
            return Result<ProtocolIdentity, EcliptixProtocolFailure>.Ok(_identity);
        }

        if (_identitySeed == null || _identitySeed.Length == 0)
        {
            _identitySeed = new byte[32];
            RandomNumberGenerator.Fill(_identitySeed);
            _cachedKyberPublicKey = null;
            Context.GetLogger().Info("[ENSURE-IDENTITY] Generated new identity seed for ConnectId {0}",
                connectId);
        }
        else
        {
            Context.GetLogger().Info("[ENSURE-IDENTITY] Using existing identity seed for ConnectId {0}",
                connectId);
        }

        Context.GetLogger().Info("[ENSURE-IDENTITY] Creating identity for ConnectId {0}, accountId: {1}",
            connectId, accountId?.ToString() ?? "null");

        Result<ProtocolIdentity, EcliptixProtocolFailure> createResult = _protocolServer.CreateIdentity(_identitySeed, accountId);

        if (createResult.IsOk)
        {
            _identity = createResult.Unwrap();
            Context.GetLogger().Info("[ENSURE-IDENTITY] Identity created successfully for ConnectId {0}",
                connectId);
        }
        else
        {
            Context.GetLogger().Warning("[ENSURE-IDENTITY] Failed to create identity for ConnectId {0}: {1}",
                connectId, createResult.UnwrapErr().Message);
        }

        return createResult;
    }

    private void HydrateIdentitySeedFromState(EcliptixSessionState state)
    {
        if (_identitySeed != null && _identitySeed.Length > 0)
        {
            return;
        }

        if (!state.IdentitySeed.IsEmpty)
        {
            _identitySeed = state.IdentitySeed.ToByteArray();
            _cachedKyberPublicKey = null;
        }
    }

    private void PersistIdentitySeedIfNeeded()
    {
        if (_identitySeed == null || _identitySeed.Length == 0)
        {
            return;
        }

        if (_state is { IdentitySeed: { IsEmpty: false } })
        {
            return;
        }

        EcliptixSessionState seedState = new()
        {
            ConnectId = connectId,
            IdentitySeed = ByteString.CopyFrom(_identitySeed)
        };

        Persist(seedState, state => { _state = state; });
    }

    private void LogCachedKyberPrefix(string stage)
    {
        if (_cachedKyberPublicKey is not { Length: > 0 })
        {
            return;
        }

        string prefix = FormatKeyPrefix(_cachedKyberPublicKey);
        Context.GetLogger().Info("[{0}] Kyber public key prefix for ConnectId {1}: {2}", stage, connectId, prefix);
    }

    private static string FormatKeyPrefix(byte[] key, int prefixLength = 8)
    {
        int length = Math.Min(prefixLength, key.Length);
        return Convert.ToHexString(key.AsSpan(0, length)).ToLowerInvariant();
    }

    private static bool IsIdentitySeedOnlyState(EcliptixSessionState state)
    {
        if (state.IdentitySeed.IsEmpty)
        {
            return false;
        }

        bool hasHandshake = state.PeerHandshakeMessage != null && !state.PeerHandshakeMessage.Payload.IsEmpty;
        return !hasHandshake && state.NativeState.IsEmpty;
    }

    private bool IsClientHandshakeDifferent(PubKeyExchange incomingHandshake)
    {
        if (_state?.PeerHandshakeMessage == null || _state.PeerHandshakeMessage.Payload.IsEmpty)
        {
            return false;
        }

        try
        {
            ProtobufPublicKeyBundle incomingBundle =
                ProtobufPublicKeyBundle.Parser.ParseFrom(incomingHandshake.Payload);

            ProtobufPublicKeyBundle recoveredBundle =
                ProtobufPublicKeyBundle.Parser.ParseFrom(_state.PeerHandshakeMessage.Payload);

            if (!incomingBundle.EphemeralX25519PublicKey.Equals(recoveredBundle.EphemeralX25519PublicKey))
            {
                Context.GetLogger().Debug(
                    "[KEY-MISMATCH] Incoming ephemeral: {0}, Recovered ephemeral: {1}",
                    Convert.ToHexString(incomingBundle.EphemeralX25519PublicKey.Span[..8]),
                    Convert.ToHexString(recoveredBundle.EphemeralX25519PublicKey.Span[..8]));
                return true;
            }

            if (!incomingBundle.KyberCiphertext.IsEmpty && !recoveredBundle.KyberCiphertext.IsEmpty)
            {
                if (!incomingBundle.KyberCiphertext.Equals(recoveredBundle.KyberCiphertext))
                {
                    return true;
                }
            }

            return false;
        }
        catch (Exception ex)
        {
            Context.GetLogger().Warning(
                "[KEY-COMPARE-ERROR] Failed to compare handshake bundles: {0}", ex.Message);
            return true;
        }
    }

    private Result<EcliptixSessionState, EcliptixProtocolFailure> ExportSessionState(
        ProtocolSession session,
        EcliptixSessionState? current,
        IMessage? peerHandshake,
        Guid? membershipId = null,
        Guid? accountId = null)
    {
        Result<byte[], EcliptixProtocolFailure> exportResult = _protocolServer.ExportState(session);
        if (exportResult.IsErr)
        {
            return Result<EcliptixSessionState, EcliptixProtocolFailure>.Err(exportResult.UnwrapErr());
        }

        PubKeyExchange? handshake = peerHandshake switch
        {
            PubKeyExchange pk => pk,
            null => current?.PeerHandshakeMessage,
            _ => current?.PeerHandshakeMessage
        };

        uint sendingIndex = current?.SendingChainIndex ?? 0;
        uint receivingIndex = current?.ReceivingChainIndex ?? 0;
        Result<(uint Sending, uint Receiving), EcliptixProtocolFailure> indicesResult =
            _protocolServer.GetChainIndices(session);
        if (indicesResult.IsOk)
        {
            (sendingIndex, receivingIndex) = indicesResult.Unwrap();
        }
        else
        {
            Context.GetLogger().Warning(
                "[CHAIN-INDICES] Failed to read chain indices for ConnectId {0}: {1}",
                connectId, indicesResult.UnwrapErr().Message);
        }

        return Result<EcliptixSessionState, EcliptixProtocolFailure>.Ok(new EcliptixSessionState
        {
            ConnectId = connectId,
            MembershipId = membershipId.HasValue
                ? Helpers.GuidToByteString(membershipId.Value)
                : current?.MembershipId ?? ByteString.Empty,
            AccountId = accountId.HasValue
                ? Helpers.GuidToByteString(accountId.Value)
                : current?.AccountId ?? ByteString.Empty,
            PeerHandshakeMessage = handshake ?? new PubKeyExchange(),
            NativeState = ByteString.CopyFrom(exportResult.Unwrap()),
            IdentitySeed = ByteString.CopyFrom(_identitySeed ?? Array.Empty<byte>()),
            SendingChainIndex = sendingIndex,
            ReceivingChainIndex = receivingIndex
        });
    }

    private Result<ProtocolSession, EcliptixProtocolFailure> RecreateSessionFromState(
        PubKeyExchangeType exchangeType)
    {
        if (_state == null || _state.NativeState.IsEmpty || _state.IdentitySeed.IsEmpty)
        {
            return Result<ProtocolSession, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.StateMismatch("Protocol state desynchronized: missing native state or identity seed"));
        }

        _identitySeed = _state.IdentitySeed.ToByteArray();
        _cachedKyberPublicKey = null;
        Result<ProtocolIdentity, EcliptixProtocolFailure> identityResult =
            EnsureIdentity(_state.AccountId.IsEmpty ? null : Helpers.FromByteStringToGuid(_state.AccountId));
        if (identityResult.IsErr)
        {
            return Result<ProtocolSession, EcliptixProtocolFailure>.Err(identityResult.UnwrapErr());
        }

        Result<ProtocolSession, EcliptixProtocolFailure> importResult = _protocolServer.ImportState(
            identityResult.Unwrap(),
            _state.NativeState.ToByteArray(),
            OnProtocolStateChanged);

        _identity?.Dispose();
        _identity = null;

        if (importResult.IsErr)
        {
            return importResult;
        }

        ProtocolSession session = importResult.Unwrap();
        Result<Unit, EcliptixProtocolFailure> validationResult = ValidateRestoredSessionIndices(session);
        if (validationResult.IsErr)
        {
            session.Dispose();
            return Result<ProtocolSession, EcliptixProtocolFailure>.Err(validationResult.UnwrapErr());
        }

        return Result<ProtocolSession, EcliptixProtocolFailure>.Ok(session);
    }

    private Result<Unit, EcliptixProtocolFailure> ValidateRestoredSessionIndices(ProtocolSession session)
    {
        if (_state == null)
        {
            return Result<Unit, EcliptixProtocolFailure>.Ok(Unit.Value);
        }

        Result<(uint Sending, uint Receiving), EcliptixProtocolFailure> indicesResult =
            _protocolServer.GetChainIndices(session);

        if (indicesResult.IsErr)
        {
            EcliptixProtocolFailure failure = indicesResult.UnwrapErr();
            return Result<Unit, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.StateMismatch(
                    $"Failed to read chain indices after restore: {failure.Message}",
                    failure.InnerException));
        }

        (uint sending, uint receiving) = indicesResult.Unwrap();

        if (sending > ActorConstants.Validation.MaxChainIndex ||
            receiving > ActorConstants.Validation.MaxChainIndex)
        {
            return Result<Unit, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.StateMismatch(
                    $"Restored chain indices out of range (sending={sending}, receiving={receiving})"));
        }

        if (sending != _state.SendingChainIndex || receiving != _state.ReceivingChainIndex)
        {
            return Result<Unit, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.StateMismatch(
                    $"Restored chain indices mismatch (state {_state.SendingChainIndex}/{_state.ReceivingChainIndex} vs native {sending}/{receiving})"));
        }

        return Result<Unit, EcliptixProtocolFailure>.Ok(Unit.Value);
    }

    private void OnProtocolStateChanged(uint _)
    {

    }

    public static Props Build(uint connectId) => Props.Create(() => new EcliptixProtocolConnectActor(connectId));
}
