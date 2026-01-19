using Akka.Actor;
using Akka.Event;
using Akka.Persistence;
using Ecliptix.SharedKernel.Logging;
using Serilog;
using Ecliptix.IdentityAccess.Domain.Actors.VerificationFlow;
using Ecliptix.Protobuf.Protocol;
using Ecliptix.Protobuf.SecureProtocol;
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
    private int _recoveryRetryCount;
    private bool _savingFinalSnapshot;
    private bool _pendingMessageDeletion;
    private bool _pendingSnapshotDeletion;
    private PubKeyExchangeType? _currentExchangeType;
    private DateTimeOffset _lastSnapshotTime = DateTimeOffset.UtcNow;
    private bool _hasSnapshotTime;
    private byte[]? _cachedPreKeyBundle;

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
                            .Debug($"{LogTags.Recovery.General} Identity seed restored without handshake for ConnectId {0}", connectId);
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
            case InitializeAuthenticatedSessionCommand command:
                HandleAuthenticatedProtocolInitialization(command);
                return true;
            case DeriveSharedSecretCommand command:
                HandleInitialKeyExchange(command);
                return true;
            case EncryptPayloadCommand command:
                HandleEncrypt(command);
                return true;
            case DecryptSecureEnvelopeCommand command:
                HandleDecrypt(command);
                return true;
            case CleanupProtocolForTypeCommand command:
                HandleCleanupProtocolForType(command);
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
            case GetPreKeyBundleQuery:
                HandleGetPreKeyBundle();
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
                Context.GetLogger().Warning($"{LogTags.Persistence.DeleteMessageFailed} Failed to delete messages. " +
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
                Context.GetLogger().Warning($"{LogTags.Persistence.DeleteSnapshotFailed} Failed to delete snapshots. " +
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
                LogTags.Protocol.Init + " Failed to initialize protocol server for ConnectId {ConnectId}: {Message}",
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
                    $"{LogTags.Session.ServerRestore} Inconsistent state detected (state exists but no DataCenter session). " +
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
        Context.GetLogger().Debug(LogTags.Protocol.GetState + " Retrieving session state for ConnectId: {ConnectId}",
            connectId);

        if (_state == null)
        {
            Sender.Tell(new GetProtocolStateResponse(null));
            return;
        }

        GetProtocolStateResponse reply = new(_state);
        Sender.Tell(reply);

        Context.GetLogger().Debug(LogTags.Protocol.GetState + " Session state retrieved for ConnectId: {ConnectId}", connectId);
    }

    private void HandleGetPreKeyBundle()
    {
        Context.GetLogger().Info(
            $"{LogTags.Protocol.GetKyberKey} Creating prekey bundle for ConnectId {0}, identity exists: {1}",
            connectId, _identity != null);

        Result<ProtocolIdentity, EcliptixProtocolFailure> identityResult = EnsureIdentity();
        if (identityResult.IsErr)
        {
            Context.GetLogger().Warning(
                $"{LogTags.Protocol.GetKyberKey} EnsureIdentity failed for ConnectId {0}: {1}",
                connectId, identityResult.UnwrapErr().Message);
            Sender.Tell(Result<byte[], EcliptixProtocolFailure>.Err(identityResult.UnwrapErr()));
            return;
        }

        Result<byte[], EcliptixProtocolFailure> bundleResult =
            _protocolServer.CreatePreKeyBundle(identityResult.Unwrap());

        if (bundleResult.IsErr)
        {
            Context.GetLogger().Warning(
                $"{LogTags.Protocol.GetKyberKey} CreatePreKeyBundle failed for ConnectId {0}: {1}",
                connectId, bundleResult.UnwrapErr().Message);
        }
        else
        {
            _cachedPreKeyBundle = bundleResult.Unwrap();
            string bundleHash = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(_cachedPreKeyBundle))[..16];
            Serilog.Log.Information(
                "[PROTOCOL-ACTOR] Cached prekey bundle for ConnectId={ConnectId}, length={Length}, hash={Hash}",
                connectId, _cachedPreKeyBundle.Length, bundleHash);
        }

        PersistIdentitySeedIfNeeded();
        Sender.Tell(bundleResult);
    }

    private void HandleNewAnonymousSession(DeriveSharedSecretCommand command)
    {
        Serilog.Log.Information(
            "[PROTOCOL-ACTOR] HandleNewAnonymousSession: Creating session. ConnectId={ConnectId}, ExchangeType={ExchangeType}",
            command.ConnectId, command.ExchangeType);

        Result<(ProtocolSession Session, EcliptixSessionState State, byte[] HandshakeAck), EcliptixProtocolFailure>
            sessionResult = CreateSessionFromHandshake(command.ExchangeType, command.HandshakeInit, null, null);

        if (sessionResult.IsErr)
        {
            Sender.Tell(Result<DeriveSharedSecretResponse, EcliptixProtocolFailure>.Err(sessionResult.UnwrapErr()));
            return;
        }

        (ProtocolSession session, EcliptixSessionState newState, byte[] handshakeAck) = sessionResult.Unwrap();

        IActorRef? originalSender = Sender;
        PubKeyExchangeType exchangeType = command.ExchangeType;

        if (exchangeType == PubKeyExchangeType.DataCenterEphemeralConnect)
        {
            PersistNewEphemeralSession(exchangeType, session, newState, handshakeAck, originalSender);
        }
        else
        {
            HandleNewNonPersistentSession(exchangeType, session, handshakeAck, originalSender);
        }
    }

    private void PersistNewEphemeralSession(PubKeyExchangeType exchangeType, ProtocolSession session,
        EcliptixSessionState newState, byte[] handshakeAck, IActorRef originalSender)
    {
        Persist(newState, state =>
        {
            _state = state;
            ReplaceSession(exchangeType, session);
            _currentExchangeType = exchangeType;
            _cachedPreKeyBundle = null;

            Context.SetReceiveTimeout(IdleTimeout);

            originalSender.Tell(
                Result<DeriveSharedSecretResponse, EcliptixProtocolFailure>.Ok(new DeriveSharedSecretResponse(handshakeAck)));
            MaybeSaveSnapshot();
        });
    }

    private void HandleNewNonPersistentSession(PubKeyExchangeType exchangeType, ProtocolSession session,
        byte[] handshakeAck, IActorRef originalSender)
    {
        Context.GetLogger().Info(
            "[PROTOCOL-ACTOR] HandleNewNonPersistentSession: Creating non-persistent session. ConnectId={0}, ExchangeType={1}",
            connectId, exchangeType);

        ReplaceSession(exchangeType, session);
        _currentExchangeType = exchangeType;
        _cachedPreKeyBundle = null;

        Context.SetReceiveTimeout(null);

        Context.GetLogger().Info(
            "[PROTOCOL-ACTOR] HandleNewNonPersistentSession: Session created successfully. ConnectId={0}, ExchangeType={1}, AvailableSessions=[{2}]",
            connectId, exchangeType, string.Join(", ", _sessions.Keys));

        originalSender.Tell(
            Result<DeriveSharedSecretResponse, EcliptixProtocolFailure>.Ok(new DeriveSharedSecretResponse(handshakeAck)));
    }

    private void HandleInitialKeyExchange(DeriveSharedSecretCommand command)
    {
        Serilog.Log.Information(
            "[PROTOCOL-ACTOR] HandleInitialKeyExchange: ConnectId={ConnectId}, ExchangeType={ExchangeType}, ExistingSessions=[{Sessions}]",
            command.ConnectId, command.ExchangeType, string.Join(", ", _sessions.Keys));

        Context.GetLogger().Info(
            "[PROTOCOL-ACTOR] HandleInitialKeyExchange: Received handshake. ConnectId={0}, ExchangeType={1}, ExistingSessions=[{2}]",
            command.ConnectId, command.ExchangeType, string.Join(", ", _sessions.Keys));

        PubKeyExchangeType exchangeType = command.ExchangeType;

        if (ShouldResetStateForHandshake(exchangeType, command.HandshakeInit))
        {
            Context.GetLogger().Info(
                $"{LogTags.Session.FreshHandshake} Client handshake differs from recovered state for ConnectId {0}",
                command.ConnectId);
            ClearStatePreserveIdentity();
        }

        if (_sessions.TryGetValue(exchangeType, out ProtocolSession? existingSession))
        {
            if (IsAuthenticatedSession())
            {
                HandleAuthenticatedToAnonymousTransition();
            }
            else
            {
                existingSession.Dispose();
                _sessions.Remove(exchangeType);
            }
        }

        HandleNewAnonymousSession(command);
    }

    private void HandleNewAuthenticatedSession(InitializeAuthenticatedSessionCommand command)
    {
        Serilog.Log.Information(
            "[PROTOCOL-ACTOR] HandleNewAuthenticatedSession: Creating session. ConnectId={ConnectId}, ExchangeType={ExchangeType}",
            command.ConnectId, command.ExchangeType);

        Result<(ProtocolSession Session, EcliptixSessionState State, byte[] HandshakeAck), EcliptixProtocolFailure>
            sessionResult = CreateSessionFromHandshake(command.ExchangeType, command.HandshakeInit, command.MembershipId, command.AccountId);

        if (sessionResult.IsErr)
        {
            Sender.Tell(Result<InitializeAuthenticatedSessionResponse, EcliptixProtocolFailure>.Err(sessionResult.UnwrapErr()));
            return;
        }

        (ProtocolSession session, EcliptixSessionState newState, byte[] handshakeAck) = sessionResult.Unwrap();
        IActorRef originalSender = Sender;
        PubKeyExchangeType exchangeType = command.ExchangeType;

        if (exchangeType == PubKeyExchangeType.DataCenterEphemeralConnect)
        {
            PersistNewAuthenticatedEphemeralSession(exchangeType, session, newState, handshakeAck, originalSender);
        }
        else
        {
            HandleNewAuthenticatedNonPersistentSession(exchangeType, session, handshakeAck, originalSender);
        }
    }

    private void PersistNewAuthenticatedEphemeralSession(PubKeyExchangeType exchangeType, ProtocolSession session,
        EcliptixSessionState newState, byte[] handshakeAck, IActorRef originalSender)
    {
        Persist(newState, state =>
        {
            _state = state;
            ReplaceSession(exchangeType, session);
            _currentExchangeType = exchangeType;
            Context.SetReceiveTimeout(IdleTimeout);

            originalSender.Tell(
                Result<InitializeAuthenticatedSessionResponse, EcliptixProtocolFailure>.Ok(
                    new InitializeAuthenticatedSessionResponse(handshakeAck)));
            MaybeSaveSnapshot();
        });
    }

    private void HandleNewAuthenticatedNonPersistentSession(PubKeyExchangeType exchangeType, ProtocolSession session,
        byte[] handshakeAck, IActorRef originalSender)
    {
        ReplaceSession(exchangeType, session);
        _currentExchangeType = exchangeType;
        Context.SetReceiveTimeout(null);

        originalSender.Tell(
            Result<InitializeAuthenticatedSessionResponse, EcliptixProtocolFailure>.Ok(
                new InitializeAuthenticatedSessionResponse(handshakeAck)));
    }

    private void HandleAuthenticatedProtocolInitialization(InitializeAuthenticatedSessionCommand command)
    {
        PubKeyExchangeType exchangeType = command.ExchangeType;

        if (ShouldResetStateForHandshake(exchangeType, command.HandshakeInit))
        {
            Context.GetLogger().Info(
                $"{LogTags.Session.FreshHandshake} Client handshake differs from recovered state for ConnectId {0}",
                command.ConnectId);
            ClearStatePreserveIdentity();
        }

        if (_sessions.TryGetValue(exchangeType, out ProtocolSession? existingSession))
        {
            existingSession.Dispose();
            _sessions.Remove(exchangeType);
        }

        HandleNewAuthenticatedSession(command);
    }

    private void HandleEncrypt(EncryptPayloadCommand command)
    {
        Context.GetLogger().Debug(
            "[PROTOCOL-ACTOR] HandleEncrypt: ConnectId={0}, RequestedExchangeType={1}, AvailableSessions=[{2}], CurrentExchangeType={3}",
            connectId,
            command.PubKeyExchangeType,
            string.Join(", ", _sessions.Keys),
            _currentExchangeType?.ToString() ?? "null");

        if (!_sessions.TryGetValue(command.PubKeyExchangeType, out ProtocolSession? system))
        {
            Context.GetLogger().Warning(
                "[PROTOCOL-ACTOR] HandleEncrypt: Session not found for {0}, trying primary session. ConnectId={1}",
                command.PubKeyExchangeType, connectId);

            Option<ProtocolSession> primaryProtocolSystemOpt = GetPrimarySession();
            if (!primaryProtocolSystemOpt.IsSome || _state == null)
            {
                Context.GetLogger().Error(
                    "[PROTOCOL-ACTOR] HandleEncrypt: No session available! RequestedType={0}, HasState={1}, ConnectId={2}",
                    command.PubKeyExchangeType, _state != null, connectId);

                Sender.Tell(
                    Result<SecureEnvelope, EcliptixProtocolFailure>.Err(
                        EcliptixProtocolFailure.StateMismatch(
                            $"Protocol state desynchronized: no protocol system found for exchange type {command.PubKeyExchangeType}")));
                return;
            }

            system = primaryProtocolSystemOpt.Value!;
        }

        Result<byte[], EcliptixProtocolFailure> encryptResult = _protocolServer.Encrypt(
            system,
            command.Payload,
            command.EnvelopeType,
            command.EnvelopeId,
            command.CorrelationId);
        if (encryptResult.IsErr)
        {
            Sender.Tell(Result<SecureEnvelope, EcliptixProtocolFailure>.Err(encryptResult.UnwrapErr()));
            return;
        }

        SecureEnvelope envelope = SecureEnvelope.Parser.ParseFrom(encryptResult.Unwrap());
        Result<EcliptixSessionState, EcliptixProtocolFailure> newStateResult =
            ExportSessionState(system, _state, null, command.PubKeyExchangeType);
        if (newStateResult.IsErr)
        {
            Sender.Tell(Result<SecureEnvelope, EcliptixProtocolFailure>.Err(newStateResult.UnwrapErr()));
            return;
        }

        EcliptixSessionState newState = newStateResult.Unwrap();
        IActorRef? originalSender = Sender;

        if (command.PubKeyExchangeType == PubKeyExchangeType.DataCenterEphemeralConnect)
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
        Serilog.Log.Information(
            "[PROTOCOL-ACTOR] HandleDecrypt: Requested ExchangeType={ExchangeType}, AvailableSessions=[{Sessions}]",
            actorEvent.PubKeyExchangeType, string.Join(", ", _sessions.Keys));

        SecureEnvelope envelope = actorEvent.SecureEnvelope;
        Serilog.Log.Information(
            "[PROTOCOL-ACTOR] HandleDecrypt: ConnectId={ConnectId}, CurrentExchangeType={CurrentExchangeType}, Meta={Meta}, Payload={Payload}, HeaderNonce={HeaderNonce}, DhPublicKey={DhPublicKey}, KyberCiphertext={KyberCiphertext}, RatchetEpoch={RatchetEpoch}",
            connectId,
            _currentExchangeType?.ToString() ?? "null",
            envelope.EncryptedMetadata.Length,
            envelope.EncryptedPayload.Length,
            envelope.HeaderNonce.Length,
            envelope.DhPublicKey.Length,
            envelope.KyberCiphertext.Length,
            envelope.RatchetEpoch.ToString());

        if (!_sessions.TryGetValue(actorEvent.PubKeyExchangeType, out ProtocolSession? session))
        {
            Serilog.Log.Warning(
                "[PROTOCOL-ACTOR] HandleDecrypt: Session NOT FOUND for {ExchangeType}, falling back to primary session",
                actorEvent.PubKeyExchangeType);

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
            _protocolServer.ValidateEnvelope(envelopeBytes);
        if (validate.IsErr)
        {
            HandleDecryptionError(validate.UnwrapErr(), connectId);
            return;
        }

        Result<ProtocolDecryptResult, EcliptixProtocolFailure> result = _protocolServer.Decrypt(session, envelopeBytes);
        if (result.IsErr)
        {
            HandleDecryptionError(result.UnwrapErr(), connectId);
            return;
        }

        IActorRef? originalSender = Sender;
        Result<EcliptixSessionState, EcliptixProtocolFailure> newStateResult =
            ExportSessionState(session, _state, null, actorEvent.PubKeyExchangeType);
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
                originalSender.Tell(Result<byte[], EcliptixProtocolFailure>.Ok(result.Unwrap().Plaintext));
                MaybeSaveSnapshot();
            });
        }
        else
        {
            _state = newStateResult.Unwrap();
            originalSender.Tell(Result<byte[], EcliptixProtocolFailure>.Ok(result.Unwrap().Plaintext));
        }
    }

    private void HandleCleanupProtocolForType(CleanupProtocolForTypeCommand command)
    {
        if (_sessions.TryGetValue(command.ExchangeType, out ProtocolSession? system))
        {
            system?.Dispose();
            _sessions.Remove(command.ExchangeType);

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
        if (_hasSnapshotTime && now - _lastSnapshotTime < MinSnapshotInterval)
        {
            return;
        }

        _lastSnapshotTime = now;
        _hasSnapshotTime = true;
        SaveSnapshot(_state);
        Context.GetLogger().Debug(
            $"{LogTags.Persistence.SnapshotSave} Snapshot saved. ConnectId: {0}, SeqNr: {1}, Sending: {2}, Receiving: {3}",
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
        _cachedPreKeyBundle = null;

        if (_identitySeed != null)
        {
            CryptographicOperations.ZeroMemory(_identitySeed);
            _identitySeed = null;
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
                .Debug($"{LogTags.Recovery.General} Identity seed present but no handshake for ConnectId {0}. Skipping recreation.",
                    connectId);
            return;
        }

        if (_state.PeerHandshakeInit.IsEmpty)
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

        PubKeyExchangeType exchangeType = _state.ExchangeType;

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

        Result<ProtocolSession, EcliptixProtocolFailure> sessionResult = RecreateSessionFromState();

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
                    $"{LogTags.Recovery.General} State mismatch detected after restore for ConnectId {0}: {1}. Clearing state.",
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
        Context.GetLogger().Debug(
            "[PROTOCOL-ACTOR] ReplaceSession: Storing session. ConnectId={0}, ExchangeType={1}, ExistingSessionsBeforeReplace=[{2}]",
            connectId, exchangeType, string.Join(", ", _sessions.Keys));

        if (_sessions.TryGetValue(exchangeType, out ProtocolSession? existing))
        {
            Context.GetLogger().Debug("[PROTOCOL-ACTOR] ReplaceSession: Disposing existing session for {0}", exchangeType);
            existing.Dispose();
        }

        _sessions[exchangeType] = session;

        Context.GetLogger().Debug(
            "[PROTOCOL-ACTOR] ReplaceSession: Session stored. ConnectId={0}, ExchangeType={1}, AllSessions=[{2}]",
            connectId, exchangeType, string.Join(", ", _sessions.Keys));
    }

    private void HandleAuthenticatedToAnonymousTransition()
    {
        ClearStatePreserveIdentity();
    }

    private bool ShouldResetStateForHandshake(PubKeyExchangeType exchangeType, byte[] handshakeInit)
    {
        if (_state == null || _state.NativeState.IsEmpty)
        {
            return false;
        }

        if (_state.ExchangeType != exchangeType)
        {
            return false;
        }

        if (_state.PeerHandshakeInit.IsEmpty)
        {
            return false;
        }

        return !handshakeInit.AsSpan().SequenceEqual(_state.PeerHandshakeInit.Span);
    }

    private void ClearStatePreserveIdentity()
    {
        byte[]? seedToPreserve = _identitySeed ?? (_state?.IdentitySeed.IsEmpty == false
            ? _state.IdentitySeed.ToByteArray()
            : null);

        DisposeAllSessions();
        _state = null;
        _currentExchangeType = null;

        SaveSnapshot(new EcliptixSessionState
        {
            ConnectId = connectId,
            IdentitySeed = seedToPreserve != null ? ByteString.CopyFrom(seedToPreserve) : ByteString.Empty
        });
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

    private void HandleDecryptionError(EcliptixProtocolFailure error, uint actualConnectId)
    {
        Serilog.Log.Error(
            "[SERVER-DECRYPT-ERROR] Decryption failed. ActorConnectId={ActorConnectId}, RequestConnectId={RequestConnectId}, ErrorType={ErrorType}, Message={Message}",
            connectId, actualConnectId, error.FailureType, error.Message);

        bool isHeaderAuthFailure = error.FailureType == EcliptixProtocolFailureType.HeaderAuthenticationFailed;
        bool isIndexDesync = IsIndexDesyncError(error);
        bool clearSession = isHeaderAuthFailure ||
                            error.FailureType == EcliptixProtocolFailureType.SessionAuthenticationFailed ||
                            error.FailureType == EcliptixProtocolFailureType.StateMismatch ||
                            isIndexDesync;

        if (clearSession)
        {
            Serilog.Log.Warning(
                "[SERVER-DECRYPT-STATE-DESYNC] Header authentication failed for ConnectId={ConnectId} - protocol state desynchronized. Clearing state to force re-handshake.",
                connectId);

            ClearStatePreserveIdentity();

            Sender.Tell(Result<byte[], EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.StateMismatch(
                    "Protocol state desynchronized - re-handshake required")));
            return;
        }

        Sender.Tell(Result<byte[], EcliptixProtocolFailure>.Err(error));
    }

    private Result<uint, EcliptixProtocolFailure> ResolveChainLimit(PubKeyExchangeType exchangeType)
    {
        return exchangeType switch
        {
            PubKeyExchangeType.InitialHandshake => Result<uint, EcliptixProtocolFailure>.Ok(20),
            PubKeyExchangeType.DataCenterEphemeralConnect => Result<uint, EcliptixProtocolFailure>.Ok(20),
            PubKeyExchangeType.ServerStreaming => Result<uint, EcliptixProtocolFailure>.Ok(100),
            PubKeyExchangeType.DeviceToDevice => Result<uint, EcliptixProtocolFailure>.Ok(10),
            _ => Result<uint, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.InvalidInput($"Unsupported exchange type: {exchangeType}"))
        };
    }

    private Result<(ProtocolSession Session, EcliptixSessionState State, byte[] HandshakeAck), EcliptixProtocolFailure>
        CreateSessionFromHandshake(
            PubKeyExchangeType exchangeType,
            byte[] handshakeInit,
            Guid? membershipId,
            Guid? accountId)
    {
        if (handshakeInit.Length == 0)
        {
            return Result<(ProtocolSession, EcliptixSessionState, byte[]), EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.InvalidInput("Handshake init is empty"));
        }

        Result<ProtocolIdentity, EcliptixProtocolFailure> identityResult = EnsureIdentity();
        if (identityResult.IsErr)
        {
            return Result<(ProtocolSession, EcliptixSessionState, byte[]), EcliptixProtocolFailure>
                .Err(identityResult.UnwrapErr());
        }

        Result<uint, EcliptixProtocolFailure> chainLimitResult = ResolveChainLimit(exchangeType);
        if (chainLimitResult.IsErr)
        {
            return Result<(ProtocolSession, EcliptixSessionState, byte[]), EcliptixProtocolFailure>
                .Err(chainLimitResult.UnwrapErr());
        }

        byte[] preKeyBundle;
        if (_cachedPreKeyBundle != null)
        {
            preKeyBundle = _cachedPreKeyBundle;
            string bundleHash = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(preKeyBundle))[..16];
            string initHash = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(handshakeInit))[..16];
            Serilog.Log.Information(
                "[PROTOCOL-ACTOR] Using cached prekey bundle for handshake. ConnectId={ConnectId}, ExchangeType={ExchangeType}, BundleLength={Length}, BundleHash={BundleHash}, InitLength={InitLength}, InitHash={InitHash}",
                connectId, exchangeType, preKeyBundle.Length, bundleHash, handshakeInit.Length, initHash);
        }
        else
        {
            Serilog.Log.Warning(
                "[PROTOCOL-ACTOR] No cached prekey bundle found, creating new one. ConnectId={ConnectId}",
                connectId);
            Result<byte[], EcliptixProtocolFailure> bundleResult =
                _protocolServer.CreatePreKeyBundle(identityResult.Unwrap());
            if (bundleResult.IsErr)
            {
                return Result<(ProtocolSession, EcliptixSessionState, byte[]), EcliptixProtocolFailure>
                    .Err(bundleResult.UnwrapErr());
            }
            preKeyBundle = bundleResult.Unwrap();
        }

        Result<ProtocolHandshakeResponderStart, EcliptixProtocolFailure> responderStartResult =
            _protocolServer.StartHandshakeResponder(
                identityResult.Unwrap(),
                preKeyBundle,
                handshakeInit,
                chainLimitResult.Unwrap());
        if (responderStartResult.IsErr)
        {
            EcliptixProtocolFailure err = responderStartResult.UnwrapErr();
            Serilog.Log.Error(
                "[PROTOCOL-ACTOR] StartHandshakeResponder FAILED. ConnectId={ConnectId}, Error={Error}, FailureType={FailureType}",
                connectId, err.Message, err.FailureType);
            return Result<(ProtocolSession, EcliptixSessionState, byte[]), EcliptixProtocolFailure>
                .Err(err);
        }

        ProtocolHandshakeResponderStart responderStart = responderStartResult.Unwrap();
        Result<ProtocolSession, EcliptixProtocolFailure> sessionResult =
            _protocolServer.FinishHandshakeResponder(responderStart.Responder);
        if (sessionResult.IsErr)
        {
            responderStart.Responder.Dispose();
            return Result<(ProtocolSession, EcliptixSessionState, byte[]), EcliptixProtocolFailure>
                .Err(sessionResult.UnwrapErr());
        }

        ProtocolSession session = sessionResult.Unwrap();
        Result<EcliptixSessionState, EcliptixProtocolFailure> stateToPersistResult =
            ExportSessionState(session, _state, handshakeInit, exchangeType, membershipId, accountId);
        if (stateToPersistResult.IsErr)
        {
            session.Dispose();
            return Result<(ProtocolSession, EcliptixSessionState, byte[]), EcliptixProtocolFailure>
                .Err(stateToPersistResult.UnwrapErr());
        }

        return Result<(ProtocolSession, EcliptixSessionState, byte[]), EcliptixProtocolFailure>
            .Ok((session, stateToPersistResult.Unwrap(), responderStart.HandshakeAck));
    }

    private Result<ProtocolIdentity, EcliptixProtocolFailure> EnsureIdentity()
    {
        if (_identity != null)
        {
            Serilog.Log.Information(
                "[PROTOCOL-ACTOR] EnsureIdentity: Reusing existing identity for ConnectId={ConnectId}, IdentityObjectId={ObjectId}",
                connectId, _identity.GetHashCode());
            return Result<ProtocolIdentity, EcliptixProtocolFailure>.Ok(_identity);
        }

        // Clear cached prekey bundle when creating a new identity
        _cachedPreKeyBundle = null;

        if (_identitySeed == null || _identitySeed.Length == 0)
        {
            _identitySeed = new byte[32];
            RandomNumberGenerator.Fill(_identitySeed);
            Context.GetLogger().Info($"{LogTags.Identity.Ensure} Generated new identity seed for ConnectId {0}",
                connectId);
        }
        else
        {
            Context.GetLogger().Info($"{LogTags.Identity.Ensure} Using existing identity seed for ConnectId {0}",
                connectId);
        }

        Context.GetLogger().Info($"{LogTags.Identity.Ensure} Creating identity for ConnectId {0}",
            connectId);

        Result<ProtocolIdentity, EcliptixProtocolFailure> createResult = _protocolServer.CreateIdentity(_identitySeed);

        if (createResult.IsOk)
        {
            _identity = createResult.Unwrap();
            Serilog.Log.Information(
                "[PROTOCOL-ACTOR] EnsureIdentity: Created NEW identity for ConnectId={ConnectId}, IdentityObjectId={ObjectId}",
                connectId, _identity.GetHashCode());
        }
        else
        {
            Context.GetLogger().Warning($"{LogTags.Identity.Ensure} Failed to create identity for ConnectId {0}: {1}",
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

    private static bool IsIdentitySeedOnlyState(EcliptixSessionState state)
    {
        if (state.IdentitySeed.IsEmpty)
        {
            return false;
        }

        bool hasHandshake = !state.PeerHandshakeInit.IsEmpty;
        return !hasHandshake && state.NativeState.IsEmpty;
    }

    private Result<EcliptixSessionState, EcliptixProtocolFailure> ExportSessionState(
        ProtocolSession session,
        EcliptixSessionState? current,
        byte[]? peerHandshakeInit,
        PubKeyExchangeType? exchangeType = null,
        Guid? membershipId = null,
        Guid? accountId = null)
    {
        Result<byte[], EcliptixProtocolFailure> exportResult = _protocolServer.ExportState(session);
        if (exportResult.IsErr)
        {
            return Result<EcliptixSessionState, EcliptixProtocolFailure>.Err(exportResult.UnwrapErr());
        }

        ProtocolState protocolState;
        try
        {
            protocolState = ProtocolState.Parser.ParseFrom(exportResult.Unwrap());
        }
        catch (Exception ex)
        {
            return Result<EcliptixSessionState, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.Decode($"Failed to parse protocol state: {ex.Message}"));
        }

        ulong sendIndex = protocolState.SendChain?.MessageIndex ?? 0;
        ulong recvIndex = protocolState.RecvChain?.MessageIndex ?? 0;
        if (sendIndex > uint.MaxValue || recvIndex > uint.MaxValue)
        {
            return Result<EcliptixSessionState, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.StateMismatch("Chain index exceeds supported range"));
        }

        ByteString handshakeInit = peerHandshakeInit != null
            ? ByteString.CopyFrom(peerHandshakeInit)
            : current?.PeerHandshakeInit ?? ByteString.Empty;

        PubKeyExchangeType resolvedExchangeType = exchangeType ?? current?.ExchangeType ?? PubKeyExchangeType.InitialHandshake;

        return Result<EcliptixSessionState, EcliptixProtocolFailure>.Ok(new EcliptixSessionState
        {
            ConnectId = connectId,
            MembershipId = membershipId.HasValue
                ? Helpers.GuidToByteString(membershipId.Value)
                : current?.MembershipId ?? ByteString.Empty,
            AccountId = accountId.HasValue
                ? Helpers.GuidToByteString(accountId.Value)
                : current?.AccountId ?? ByteString.Empty,
            PeerHandshakeInit = handshakeInit,
            NativeState = ByteString.CopyFrom(exportResult.Unwrap()),
            IdentitySeed = ByteString.CopyFrom(_identitySeed ?? Array.Empty<byte>()),
            SendingChainIndex = (uint)sendIndex,
            ReceivingChainIndex = (uint)recvIndex,
            ExchangeType = resolvedExchangeType
        });
    }

    private Result<ProtocolSession, EcliptixProtocolFailure> RecreateSessionFromState()
    {
        if (_state == null || _state.NativeState.IsEmpty)
        {
            return Result<ProtocolSession, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.StateMismatch("Protocol state desynchronized: missing native state"));
        }

        Result<ProtocolSession, EcliptixProtocolFailure> importResult =
            _protocolServer.ImportState(_state.NativeState.ToByteArray());

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
        // Chain indices validation is no longer available in the native API
        // The session state is validated by the native library internally during deserialization
        return Result<Unit, EcliptixProtocolFailure>.Ok(Unit.Value);
    }

    private void OnProtocolStateChanged(uint _)
    {

    }

    public static Props Build(uint connectId) => Props.Create(() => new EcliptixProtocolConnectActor(connectId));
}
