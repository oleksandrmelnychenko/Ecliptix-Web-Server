using Akka.Actor;
using Akka.Event;
using Akka.Persistence;
using Ecliptix.Core.Domain.Events;
using Ecliptix.Core.Domain.ProtocolNative;
using Ecliptix.Domain.Memberships.ActorEvents.VerificationFlow;
using Ecliptix.Protobuf.Common;
using Ecliptix.Protobuf.Protocol;
using Ecliptix.Protobuf.ProtocolState;
using Ecliptix.Utilities;
using Google.Protobuf;
using System.Security.Cryptography;
using Unit = Ecliptix.Utilities.Unit;

namespace Ecliptix.Core.Domain.Actors;

public sealed class EcliptixProtocolConnectActor(uint connectId) : PersistentActor, IWithTimers
{
    private static readonly TimeSpan IdleTimeout = TimeSpan.FromMinutes(ActorConstants.Timeouts.IdleTimeoutMinutes);
    private const int MaxRecoveryRetries = ActorConstants.Recovery.MaxRetries;
    private const string RecoveryRetryTimerKey = ActorConstants.Recovery.RetryTimerKey;

    private EcliptixSessionState? _state;
    private readonly Dictionary<PubKeyExchangeType, NativeProtocolSession> _sessions = new();
    private readonly NativeProtocolSessionManager _sessionManager = new();
    private EcliptixIdentityKeysWrapper? _identityKeys;
    private byte[]? _identitySeed;
    private int _recoveryRetryCount;
    private bool _savingFinalSnapshot;
    private bool _pendingMessageDeletion;
    private bool _pendingSnapshotDeletion;
    private PubKeyExchangeType? _currentExchangeType;

    public ITimerScheduler Timers { get; set; } = null!;

    public override string PersistenceId { get; } = $"{ActorConstants.ActorNamePrefixes.Connect}{connectId}";

    protected override bool ReceiveRecover(object message)
    {
        switch (message)
        {
            case SnapshotOffer { Snapshot: EcliptixSessionState state }:
                _state = state;
                return true;
            case EcliptixSessionState state:
                _state = state;
                return true;
            case RecoveryCompleted:
                if (_state != null)
                {
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
            case InitializeProtocolWithMasterKeyActorEvent cmd:
                HandleAuthenticatedProtocolInitialization(cmd);
                return true;
            case DeriveSharedSecretActorEvent cmd:
                HandleInitialKeyExchange(cmd);
                return true;
            case EncryptPayloadActorEvent cmd:
                HandleEncrypt(cmd);
                return true;
            case DecryptSecureEnvelopeActorEvent cmd:
                HandleDecrypt(cmd);
                return true;
            case EncryptPayloadComponentsActorEvent cmd:
                HandleEncryptComponents(cmd);
                return true;
            case DecryptPayloadWithHeaderActorEvent cmd:
                HandleDecryptWithHeader(cmd);
                return true;
            case CleanupProtocolForTypeActorEvent cmd:
                HandleCleanupProtocolForType(cmd);
                return true;
            case ProtocolCleanupRequiredEvent evt:
                HandleProtocolCleanupRequired(evt);
                return true;
            case RestoreAppDeviceSecrecyChannelState:
                HandleRestoreSecrecyChannelState();
                return true;
            case GetProtocolStateActorEvent:
                HandleGetProtocolState();
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
        Context.System.EventStream.Subscribe(Self, typeof(ProtocolCleanupRequiredEvent));
    }

    protected override void PostStop()
    {
        Timers.CancelAll();
        DisposeAllSessions();
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

        Option<NativeProtocolSession> primarySessionOpt = GetPrimarySession();
        if (!primarySessionOpt.IsSome || _state == null || _state.NativeState.IsEmpty)
        {
            if (!primarySessionOpt.IsSome && _state != null)
            {
                Context.GetLogger().Warning(
                    "[SERVER-RESTORE] Inconsistent state detected (state exists but no DataCenter session). " +
                    "Clearing state for connectId: {0}", connectId);

                DisposeAllSessions();
                _state = null;
                _currentExchangeType = null;
                SaveSnapshot(new EcliptixSessionState());
            }

            Sender.Tell(
                Result<RestoreSecrecyChannelResponse, EcliptixProtocolFailure>.Ok(CreateSessionNotFoundResponse()));
            return;
        }

        NativeProtocolSession primarySession = primarySessionOpt.Value!;
        uint sendingIndex = _state?.SendingChainIndex ?? 0;
        uint receivingIndex = _state?.ReceivingChainIndex ?? 0;

        Result<(uint SendingIndex, uint ReceivingIndex), EcliptixProtocolFailure> chainResult =
            primarySession.GetChainIndices();
        if (chainResult.IsOk)
        {
            (uint newSendingIndex, uint newReceivingIndex) = chainResult.Unwrap();
            sendingIndex = newSendingIndex;
            receivingIndex = newReceivingIndex;
        }

        if (_state != null && chainResult.IsOk &&
            (_state.SendingChainIndex != sendingIndex || _state.ReceivingChainIndex != receivingIndex))
        {
            Result<EcliptixSessionState, EcliptixProtocolFailure> updatedStateResult =
                ExportSessionState(primarySession, _state, _state.PeerHandshakeMessage);
            if (updatedStateResult.IsOk)
            {
                Persist(updatedStateResult.Unwrap(), state =>
                {
                    _state = state;
                    MaybeSaveSnapshot();
                });
            }
            else
            {
                Context.GetLogger().Warning(
                    "[SERVER-RESTORE] Failed to refresh persisted state after restore. ConnectId: {0}, Error: {1}",
                    connectId,
                    updatedStateResult.UnwrapErr().Message);
            }
        }

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
            Sender.Tell(new GetProtocolStateReply(null));
            return;
        }

        GetProtocolStateReply reply = new(_state);
        Sender.Tell(reply);

        Context.GetLogger().Debug("[GET-PROTOCOL-STATE] Session state retrieved for ConnectId: {ConnectId}", connectId);
    }

    private void HandleNewAnonymousSession(DeriveSharedSecretActorEvent cmd)
    {
        Result<(NativeProtocolSession Session, EcliptixSessionState State, PubKeyExchange Reply), EcliptixProtocolFailure>
            sessionResult = CreateNewAnonymousSession(cmd.ConnectId, cmd.PubKeyExchange);

        if (sessionResult.IsErr)
        {
            Sender.Tell(Result<DeriveSharedSecretReply, EcliptixProtocolFailure>.Err(sessionResult.UnwrapErr()));
            return;
        }

        (NativeProtocolSession session, EcliptixSessionState newState, PubKeyExchange reply) = sessionResult.Unwrap();

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

    private void PersistNewEphemeralSession(PubKeyExchangeType exchangeType, NativeProtocolSession session,
        EcliptixSessionState newState, PubKeyExchange reply, IActorRef originalSender)
    {
        Persist(newState, state =>
        {
            _state = state;
            _sessions[exchangeType] = session;
            _currentExchangeType = exchangeType;

            Context.SetReceiveTimeout(IdleTimeout);

            originalSender.Tell(
                Result<DeriveSharedSecretReply, EcliptixProtocolFailure>.Ok(new DeriveSharedSecretReply(reply)));
            MaybeSaveSnapshot();
        });
    }

    private void HandleNewNonPersistentSession(PubKeyExchangeType exchangeType, NativeProtocolSession session,
        PubKeyExchange reply, IActorRef originalSender)
    {
        _sessions[exchangeType] = session;
        _currentExchangeType = exchangeType;

        Context.SetReceiveTimeout(null);

        originalSender.Tell(
            Result<DeriveSharedSecretReply, EcliptixProtocolFailure>.Ok(new DeriveSharedSecretReply(reply)));
    }

    private bool TryHandleExistingAnonymousSession(DeriveSharedSecretActorEvent cmd, NativeProtocolSession existingSession)
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

        PublicKeyBundle clientBundle = PublicKeyBundle.Parser.ParseFrom(cmd.PubKeyExchange.Payload);
        byte[] clientKyberPublicKey = clientBundle.KyberPublicKey.ToByteArray();

        Result<byte[], EcliptixProtocolFailure> handshakeResult =
            existingSession.BeginHandshakeWithPeerKyber(cmd.ConnectId, (byte)cmd.PubKeyExchange.OfType, clientKyberPublicKey);

        if (handshakeResult.IsErr)
        {

            existingSession.Dispose();
            _sessions.Remove(cmd.PubKeyExchange.OfType);
            Sender.Tell(Result<DeriveSharedSecretReply, EcliptixProtocolFailure>.Err(handshakeResult.UnwrapErr()));
            return true;
        }

        Result<Unit, EcliptixProtocolFailure> completeResult =
            existingSession.CompleteHandshakeAuto(cmd.PubKeyExchange.ToByteArray());
        if (completeResult.IsErr)
        {

            existingSession.Dispose();
            _sessions.Remove(cmd.PubKeyExchange.OfType);
            Sender.Tell(Result<DeriveSharedSecretReply, EcliptixProtocolFailure>.Err(completeResult.UnwrapErr()));
            return true;
        }

        if (cmd.PubKeyExchange.OfType == PubKeyExchangeType.DataCenterEphemeralConnect)
        {
            UpdateStateFromExistingSession(existingSession, handshakeResult.Unwrap());
        }

        ConfigureSessionTimeout(cmd.PubKeyExchange.OfType);

        PubKeyExchange pubKeyReply = PubKeyExchange.Parser.ParseFrom(handshakeResult.Unwrap());
        Sender.Tell(Result<DeriveSharedSecretReply, EcliptixProtocolFailure>.Ok(new DeriveSharedSecretReply(pubKeyReply)));

        return true;
    }

    private static bool IsSessionStale(NativeProtocolSession session)
    {
        try
        {
            Result<bool, EcliptixProtocolFailure> hasConn = session.HasConnection();
            return hasConn.IsErr || hasConn.Unwrap() == false;
        }
        catch (InvalidOperationException)
        {
            return true;
        }
    }

    private void UpdateStateFromExistingSession(NativeProtocolSession session, byte[] peerHandshake)
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

    private void HandleInitialKeyExchange(DeriveSharedSecretActorEvent cmd)
    {
        bool existingSessionFound = _sessions.TryGetValue(cmd.PubKeyExchange.OfType, out NativeProtocolSession? existingSession)
                                    && _state != null;

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

    private void ProcessAndReplyToExistingSession(InitializeProtocolWithMasterKeyActorEvent cmd, NativeProtocolSession existingSession)
    {
        PubKeyExchangeType exchangeType = cmd.ClientPubKeyExchange.OfType;

        PublicKeyBundle clientBundle = PublicKeyBundle.Parser.ParseFrom(cmd.ClientPubKeyExchange.Payload);
        byte[] clientKyberPublicKey = clientBundle.KyberPublicKey.ToByteArray();

        if (clientKyberPublicKey.Length == 0)
        {
            CryptographicOperations.ZeroMemory(cmd.RootKey);
            Context.GetLogger().Warning(
                "[AUTH-HANDSHAKE] Client did not provide Kyber public key for existing session. ConnectId: {0}",
                cmd.ConnectId);
            Sender.Tell(Result<InitializeProtocolWithMasterKeyReply, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.Decode(
                    "Client must provide Kyber public key for post-quantum hybrid authenticated handshake")));
            return;
        }

        Result<byte[], EcliptixProtocolFailure> handshakeResult =
            existingSession.BeginHandshakeWithPeerKyber(cmd.ConnectId, (byte)exchangeType, clientKyberPublicKey);
        if (handshakeResult.IsErr)
        {
            CryptographicOperations.ZeroMemory(cmd.RootKey);
            existingSession.Dispose();
            _sessions.Remove(exchangeType);
            Sender.Tell(Result<InitializeProtocolWithMasterKeyReply, EcliptixProtocolFailure>.Err(handshakeResult.UnwrapErr()));
            return;
        }

        Result<Unit, EcliptixProtocolFailure> completeResult =
            existingSession.CompleteHandshake(cmd.ClientPubKeyExchange.ToByteArray(), cmd.RootKey);
        CryptographicOperations.ZeroMemory(cmd.RootKey);

        if (completeResult.IsErr)
        {
            existingSession.Dispose();
            _sessions.Remove(exchangeType);
            Sender.Tell(Result<InitializeProtocolWithMasterKeyReply, EcliptixProtocolFailure>.Err(completeResult.UnwrapErr()));
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

    private void PersistExistingEphemeralSession(NativeProtocolSession existingSession, PubKeyExchange pubKeyReply, IActorRef sender, PubKeyExchangeType exchangeType)
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
                    Result<InitializeProtocolWithMasterKeyReply, EcliptixProtocolFailure>.Ok(
                        new InitializeProtocolWithMasterKeyReply(pubKeyReply)));
                MaybeSaveSnapshot();
            });
        }
        else
        {
            sender.Tell(Result<InitializeProtocolWithMasterKeyReply, EcliptixProtocolFailure>.Err(newStateResult.UnwrapErr()));
        }
    }

    private void HandleExistingNonPersistentSession(PubKeyExchange pubKeyReply, PubKeyExchangeType exchangeType, IActorRef sender)
    {
        _currentExchangeType = exchangeType;
        Context.SetReceiveTimeout(null);

        sender.Tell(
            Result<InitializeProtocolWithMasterKeyReply, EcliptixProtocolFailure>.Ok(
                new InitializeProtocolWithMasterKeyReply(pubKeyReply)));
    }
    private bool TryHandleExistingAuthenticatedSession(InitializeProtocolWithMasterKeyActorEvent cmd, NativeProtocolSession existingSession)
    {
        if (_state != null && !_state.IdentitySeed.IsEmpty)
        {
            ProcessAndReplyToExistingSession(cmd, existingSession);
            return true;
        }

        HandleKeyMismatch(cmd.ClientPubKeyExchange.OfType);
        return false;
    }

    private void HandleNewAuthenticatedSession(InitializeProtocolWithMasterKeyActorEvent cmd)
    {
        Result<(NativeProtocolSession Session, EcliptixSessionState State, PubKeyExchange Reply), EcliptixProtocolFailure>
            sessionResult = CreateNewAuthenticatedSession(cmd.ConnectId, cmd.AccountId, cmd.MembershipId,
                cmd.ClientPubKeyExchange, cmd.RootKey);

        if (sessionResult.IsErr)
        {
            Sender.Tell(Result<InitializeProtocolWithMasterKeyReply, EcliptixProtocolFailure>.Err(sessionResult.UnwrapErr()));
            return;
        }

        (NativeProtocolSession system, EcliptixSessionState newState, PubKeyExchange reply) = sessionResult.Unwrap();
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

    private void PersistNewAuthenticatedEphemeralSession(PubKeyExchangeType exchangeType, NativeProtocolSession session,
        EcliptixSessionState newState, PubKeyExchange reply, IActorRef originalSender)
    {
        Persist(newState, state =>
        {
            _state = state;
            _sessions[exchangeType] = session;
            _currentExchangeType = exchangeType;
            Context.SetReceiveTimeout(IdleTimeout);

            SaveSnapshot(_state);

            originalSender.Tell(
                Result<InitializeProtocolWithMasterKeyReply, EcliptixProtocolFailure>.Ok(
                    new InitializeProtocolWithMasterKeyReply(reply)));
        });
    }

    private void HandleNewAuthenticatedNonPersistentSession(PubKeyExchangeType exchangeType, NativeProtocolSession session,
        PubKeyExchange reply, IActorRef originalSender)
    {
        _sessions[exchangeType] = session;
        _currentExchangeType = exchangeType;
        Context.SetReceiveTimeout(null);

        originalSender.Tell(
            Result<InitializeProtocolWithMasterKeyReply, EcliptixProtocolFailure>.Ok(
                new InitializeProtocolWithMasterKeyReply(reply)));
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

    private void HandleAuthenticatedProtocolInitialization(InitializeProtocolWithMasterKeyActorEvent cmd)
    {
        PubKeyExchangeType exchangeType = cmd.ClientPubKeyExchange.OfType;

        if (_sessions.TryGetValue(exchangeType, out NativeProtocolSession? existingSystem)
            && _state != null
            && TryHandleExistingAuthenticatedSession(cmd, existingSystem))
        {
            return;
        }

        HandleNewAuthenticatedSession(cmd);
    }

    private void HandleEncrypt(EncryptPayloadActorEvent cmd)
    {
        if (!_sessions.TryGetValue(cmd.PubKeyExchangeType, out NativeProtocolSession? system))
        {
            Option<NativeProtocolSession> primaryProtocolSystemOpt = GetPrimarySession();
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

        Result<byte[], EcliptixProtocolFailure> sendResult = system.SendMessage(cmd.Payload);
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

    private void HandleDecrypt(DecryptSecureEnvelopeActorEvent actorEvent)
    {
        if (!_sessions.TryGetValue(actorEvent.PubKeyExchangeType, out NativeProtocolSession? session))
        {
            Option<NativeProtocolSession> primaryProtocolSystemOpt = GetPrimarySession();
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
            NativeProtocolSystem.ValidateEnvelopeHybridRequirements(envelopeBytes);
        if (validate.IsErr)
        {
            HandleDecryptionError(validate.UnwrapErr(), connectId);
            return;
        }

        Result<byte[], EcliptixProtocolFailure> result = session.ReceiveMessage(envelopeBytes);
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

    private void HandleCleanupProtocolForType(CleanupProtocolForTypeActorEvent cmd)
    {
        if (_sessions.TryGetValue(cmd.ExchangeType, out NativeProtocolSession? system))
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

        SaveSnapshot(_state);
        Context.GetLogger().Debug(
            "[SNAPSHOT-SAVE] Snapshot saved. ConnectId: {0}, SeqNr: {1}, Sending: {2}, Receiving: {3}",
            connectId, LastSequenceNr,
            _state.RatchetState?.SendingStep?.CurrentIndex ?? 0,
            _state.RatchetState?.ReceivingStep?.CurrentIndex ?? 0);
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
        foreach (NativeProtocolSession session in _sessions.Values)
        {
            session?.Dispose();
        }

        _sessions.Clear();
    }

    private void AttemptSystemRecreation()
    {
        if (_state == null)
        {
            Context.GetLogger()
                .Warning(ActorConstants.RecoveryLogMessages.NoStateAvailable, connectId);
            return;
        }

        if (_state.PeerHandshakeMessage == null)
        {
            Context.GetLogger()
                .Warning(ActorConstants.RecoveryLogMessages.PeerHandshakeMessageNull, connectId);
            _state = null;
            _currentExchangeType = null;
            SaveSnapshot(new EcliptixSessionState());
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

        Result<NativeProtocolSession, EcliptixProtocolFailure> sessionResult = RecreateNativeSessionFromState(exchangeType);

        if (sessionResult.IsOk)
        {
            _sessions[exchangeType] = sessionResult.Unwrap();
            _recoveryRetryCount = 0;
        }
        else
        {
            _recoveryRetryCount++;
            EcliptixProtocolFailure failure = sessionResult.UnwrapErr();

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

                DisposeAllSessions();
                _state = null;
                _currentExchangeType = null;

                SaveSnapshot(new EcliptixSessionState());
            }
        }
    }

    private bool IsAuthenticatedSession()
    {
        return _state != null &&
               _state.AccountId != null &&
               _state.AccountId.Length > 0;
    }

    private Option<NativeProtocolSession> GetPrimarySession()
    {
        return _sessions.TryGetValue(PubKeyExchangeType.DataCenterEphemeralConnect,
            out NativeProtocolSession? session)
            ? Option<NativeProtocolSession>.Some(session)
            : Option<NativeProtocolSession>.None;
    }

    private void HandleEncryptComponents(EncryptPayloadComponentsActorEvent cmd)
    {

        if (!_sessions.TryGetValue(cmd.ExchangeType, out NativeProtocolSession? session))
        {
            Option<NativeProtocolSession> primarySessionOpt = GetPrimarySession();
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

        Result<byte[], EcliptixProtocolFailure> sendResult = session.SendMessage(cmd.Payload);
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

    private void HandleDecryptWithHeader(DecryptPayloadWithHeaderActorEvent cmd)
    {
        if (!_sessions.TryGetValue(cmd.ExchangeType, out NativeProtocolSession? session))
        {
            Option<NativeProtocolSession> primaryProtocolSystemOpt = GetPrimarySession();
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
            NativeProtocolSystem.ValidateEnvelopeHybridRequirements(envelope.ToByteArray());
        if (validate.IsErr)
        {
            HandleDecryptionError(validate.UnwrapErr(), connectId);
            return;
        }

        Result<byte[], EcliptixProtocolFailure> result = session.ReceiveMessage(envelope.ToByteArray());
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
        _state = null;
        _identitySeed = null;
        _identityKeys?.Dispose();
        _identityKeys = null;
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
        bool clearSession = isHeaderAuthFailure ||
                            error.FailureType == EcliptixProtocolFailureType.SessionAuthenticationFailed ||
                            error.FailureType == EcliptixProtocolFailureType.StateMismatch;

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

    private Result<(NativeProtocolSession Session, EcliptixSessionState State, PubKeyExchange Reply),
            EcliptixProtocolFailure>
        CreateNewAuthenticatedSession(uint connectId, Guid accountId, Guid membershipId,
            PubKeyExchange clientPubKeyExchange, byte[] rootKey)
    {
        Result<EcliptixIdentityKeysWrapper, EcliptixProtocolFailure> identityResult = EnsureIdentity(accountId);
        if (identityResult.IsErr)
        {
            return Result<(NativeProtocolSession, EcliptixSessionState, PubKeyExchange), EcliptixProtocolFailure>
                .Err(identityResult.UnwrapErr());
        }

        Result<NativeProtocolSession, EcliptixProtocolFailure> sessionResult =
            _sessionManager.CreateOrReplace(connectId, identityResult.Unwrap(), OnProtocolStateChanged);
        if (sessionResult.IsErr)
        {
            CryptographicOperations.ZeroMemory(rootKey);
            return Result<(NativeProtocolSession, EcliptixSessionState, PubKeyExchange), EcliptixProtocolFailure>
                .Err(sessionResult.UnwrapErr());
        }

        NativeProtocolSession session = sessionResult.Unwrap();

        PublicKeyBundle clientBundle = PublicKeyBundle.Parser.ParseFrom(clientPubKeyExchange.Payload);
        byte[] clientKyberPublicKey = clientBundle.KyberPublicKey.ToByteArray();

        if (clientKyberPublicKey.Length == 0)
        {
            CryptographicOperations.ZeroMemory(rootKey);
            Context.GetLogger().Warning(
                "[AUTH-HANDSHAKE] Client did not provide Kyber public key for authenticated handshake. ConnectId: {0}, AccountId: {1}",
                connectId, accountId);
            return Result<(NativeProtocolSession, EcliptixSessionState, PubKeyExchange), EcliptixProtocolFailure>
                .Err(EcliptixProtocolFailure.Decode(
                    "Client must provide Kyber public key for post-quantum hybrid authenticated handshake"));
        }

        Result<byte[], EcliptixProtocolFailure> handshakeResult = session.BeginHandshakeWithPeerKyber(
            connectId, (byte)clientPubKeyExchange.OfType, clientKyberPublicKey);
        if (handshakeResult.IsErr)
        {
            CryptographicOperations.ZeroMemory(rootKey);
            return Result<(NativeProtocolSession, EcliptixSessionState, PubKeyExchange), EcliptixProtocolFailure>
                .Err(handshakeResult.UnwrapErr());
        }

        Result<Unit, EcliptixProtocolFailure> completeResult =
            session.CompleteHandshake(clientPubKeyExchange.ToByteArray(), rootKey);
        CryptographicOperations.ZeroMemory(rootKey);
        if (completeResult.IsErr)
        {
            return Result<(NativeProtocolSession, EcliptixSessionState, PubKeyExchange), EcliptixProtocolFailure>
                .Err(completeResult.UnwrapErr());
        }

        PubKeyExchange reply = PubKeyExchange.Parser.ParseFrom(handshakeResult.Unwrap());
        Result<EcliptixSessionState, EcliptixProtocolFailure> stateToPersistResult =
            ExportSessionState(session, _state, reply, membershipId, accountId);
        if (stateToPersistResult.IsErr)
        {
            return Result<(NativeProtocolSession, EcliptixSessionState, PubKeyExchange), EcliptixProtocolFailure>
                .Err(stateToPersistResult.UnwrapErr());
        }

        return Result<(NativeProtocolSession, EcliptixSessionState, PubKeyExchange), EcliptixProtocolFailure>
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

    private Result<(NativeProtocolSession Session, EcliptixSessionState State, PubKeyExchange Reply),
            EcliptixProtocolFailure>
        CreateNewAnonymousSession(uint connectId, PubKeyExchange pubKeyExchange)
    {
        Result<EcliptixIdentityKeysWrapper, EcliptixProtocolFailure> identityResult = EnsureIdentity();
        if (identityResult.IsErr)
        {
            return Result<(NativeProtocolSession, EcliptixSessionState, PubKeyExchange), EcliptixProtocolFailure>
                .Err(identityResult.UnwrapErr());
        }

        Result<NativeProtocolSession, EcliptixProtocolFailure> sessionResult =
            _sessionManager.CreateOrReplace(connectId, identityResult.Unwrap(), OnProtocolStateChanged);
        if (sessionResult.IsErr)
        {
            return Result<(NativeProtocolSession, EcliptixSessionState, PubKeyExchange), EcliptixProtocolFailure>
                .Err(sessionResult.UnwrapErr());
        }

        NativeProtocolSession session = sessionResult.Unwrap();

        PublicKeyBundle clientBundle = PublicKeyBundle.Parser.ParseFrom(pubKeyExchange.Payload);
        byte[] clientKyberPublicKey = clientBundle.KyberPublicKey.ToByteArray();

        Result<byte[], EcliptixProtocolFailure> replyResult = session.BeginHandshakeWithPeerKyber(
            connectId, (byte)pubKeyExchange.OfType, clientKyberPublicKey);
        if (replyResult.IsErr)
        {
            return Result<(NativeProtocolSession, EcliptixSessionState, PubKeyExchange), EcliptixProtocolFailure>
                .Err(replyResult.UnwrapErr());
        }

        Result<Unit, EcliptixProtocolFailure> completeResult =
            session.CompleteHandshakeAuto(pubKeyExchange.ToByteArray());
        if (completeResult.IsErr)
        {
            return Result<(NativeProtocolSession, EcliptixSessionState, PubKeyExchange), EcliptixProtocolFailure>
                .Err(completeResult.UnwrapErr());
        }

        PubKeyExchange reply = PubKeyExchange.Parser.ParseFrom(replyResult.Unwrap());
        Result<EcliptixSessionState, EcliptixProtocolFailure> stateToPersistResult =
            ExportSessionState(session, _state, reply);
        if (stateToPersistResult.IsErr)
        {
            return Result<(NativeProtocolSession, EcliptixSessionState, PubKeyExchange), EcliptixProtocolFailure>
                .Err(stateToPersistResult.UnwrapErr());
        }

        return Result<(NativeProtocolSession, EcliptixSessionState, PubKeyExchange), EcliptixProtocolFailure>
            .Ok((session, stateToPersistResult.Unwrap(), reply));
    }

    private Result<EcliptixIdentityKeysWrapper, EcliptixProtocolFailure> EnsureIdentity(Guid? accountId = null)
    {
        if (_identityKeys != null)
        {
            return Result<EcliptixIdentityKeysWrapper, EcliptixProtocolFailure>.Ok(_identityKeys);
        }

        if (_identitySeed == null || _identitySeed.Length == 0)
        {
            _identitySeed = new byte[32];
            RandomNumberGenerator.Fill(_identitySeed);
        }

        Result<EcliptixIdentityKeysWrapper, EcliptixProtocolFailure> createResult = accountId.HasValue
            ? NativeProtocolSystem.CreateIdentityFromSeed(_identitySeed, accountId.Value.ToString())
            : NativeProtocolSystem.CreateIdentityFromSeed(_identitySeed);

        if (createResult.IsOk)
        {
            _identityKeys = createResult.Unwrap();
        }

        return createResult;
    }

    private Result<EcliptixSessionState, EcliptixProtocolFailure> ExportSessionState(
        NativeProtocolSession session,
        EcliptixSessionState? current,
        IMessage? peerHandshake,
        Guid? membershipId = null,
        Guid? accountId = null)
    {
        Result<byte[], EcliptixProtocolFailure> exportResult = session.ExportState();
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
        Result<(uint SendingIndex, uint ReceivingIndex), EcliptixProtocolFailure> chainResult =
            session.GetChainIndices();
        if (chainResult.IsOk)
        {
            (uint newSendingIndex, uint newReceivingIndex) = chainResult.Unwrap();
            sendingIndex = newSendingIndex;
            receivingIndex = newReceivingIndex;
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

    private Result<NativeProtocolSession, EcliptixProtocolFailure> RecreateNativeSessionFromState(
        PubKeyExchangeType exchangeType)
    {
        if (_state == null || _state.NativeState.IsEmpty || _state.IdentitySeed.IsEmpty)
        {
            return Result<NativeProtocolSession, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.StateMismatch("Protocol state desynchronized: missing native state or identity seed"));
        }

        _identitySeed = _state.IdentitySeed.ToByteArray();
        Result<EcliptixIdentityKeysWrapper, EcliptixProtocolFailure> identityResult =
            EnsureIdentity(_state.AccountId.IsEmpty ? null : Helpers.FromByteStringToGuid(_state.AccountId));
        if (identityResult.IsErr)
        {
            return Result<NativeProtocolSession, EcliptixProtocolFailure>.Err(identityResult.UnwrapErr());
        }

        return _sessionManager.CreateOrReplaceFromState(
            connectId,
            identityResult.Unwrap(),
            _state.NativeState.ToByteArray(),
            OnProtocolStateChanged);
    }

    private void OnProtocolStateChanged(uint _)
    {

    }

    public static Props Build(uint connectId) => Props.Create(() => new EcliptixProtocolConnectActor(connectId));
}
