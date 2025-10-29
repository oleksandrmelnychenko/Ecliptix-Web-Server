using Akka.Actor;
using Akka.Event;
using Akka.Persistence;
using Ecliptix.Core.Domain.Events;
using Ecliptix.Core.Domain.Protocol;
using Ecliptix.Core.Domain.Protocol.Handlers;
using Ecliptix.Domain.Memberships.WorkerActors.VerificationFlow;
using Ecliptix.Protobuf.Common;
using Ecliptix.Protobuf.Protocol;
using Ecliptix.Protobuf.ProtocolState;
using Ecliptix.Utilities;
using Unit = Ecliptix.Utilities.Unit;

namespace Ecliptix.Core.Domain.Actors;

public sealed class EcliptixProtocolConnectActor(uint connectId) : PersistentActor, IWithTimers
{
    private static readonly TimeSpan IdleTimeout = TimeSpan.FromMinutes(ActorConstants.Timeouts.IdleTimeoutMinutes);
    private const int MaxRecoveryRetries = ActorConstants.Recovery.MaxRetries;
    private const string RecoveryRetryTimerKey = ActorConstants.Recovery.RetryTimerKey;

    private EcliptixSessionState? _state;
    private readonly Dictionary<PubKeyExchangeType, EcliptixProtocolSystem> _protocolSystems = new();
    private int _recoveryRetryCount;
    private bool _savingFinalSnapshot;
    private bool _pendingMessageDeletion;
    private bool _pendingSnapshotDeletion;
    private PubKeyExchangeType? _currentExchangeType;
    private readonly DecryptionHandler _decryptionHandler = new();

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
        DisposeAllSystems();
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

        Option<EcliptixProtocolSystem> primaryProtocolSystemOpt = GetPrimaryProtocolSystem();
        if (!primaryProtocolSystemOpt.IsSome || _state == null)
        {
            if (!primaryProtocolSystemOpt.IsSome && _state != null)
            {
                Context.GetLogger().Warning(
                    "[SERVER-RESTORE] Inconsistent state detected (state exists but no DataCenter protocol). " +
                    "Clearing state for connectId: {0}", connectId);

                DisposeAllSystems();
                _state = null;
                _currentExchangeType = null;
                SaveSnapshot(new EcliptixSessionState());
            }

            Sender.Tell(
                Result<RestoreSecrecyChannelResponse, EcliptixProtocolFailure>.Ok(CreateSessionNotFoundResponse()));
            return;
        }

        EcliptixProtocolSystem primaryProtocolSystem = primaryProtocolSystemOpt.Value!;

        Result<Unit, EcliptixProtocolFailure> stateValidation = StateValidationHandler.ValidateRecoveredState(_state);
        if (stateValidation.IsErr)
        {
            Context.GetLogger().Warning(ActorConstants.LogMessages.StateIntegrityValidationFailed,
                stateValidation.UnwrapErr().Message);

            Sender.Tell(
                Result<RestoreSecrecyChannelResponse, EcliptixProtocolFailure>.Ok(CreateSessionNotFoundResponse()));

            DisposeAllSystems();
            _state = null;
            SaveSnapshot(new EcliptixSessionState());
            return;
        }

        try
        {
            primaryProtocolSystem.GetConnection();
        }
        catch (InvalidOperationException)
        {
            Context.GetLogger()
                .Warning("[SERVER-RESTORE] Fresh handshake required. ConnectId: {0}, Reason: InvalidConnection",
                    connectId);

            Sender.Tell(
                Result<RestoreSecrecyChannelResponse, EcliptixProtocolFailure>.Ok(CreateSessionNotFoundResponse()));

            DisposeAllSystems();
            _state = null;
            SaveSnapshot(new EcliptixSessionState());
            return;
        }

        DateTime lastPersistTime = GetLastPersistenceTime();

        RestoreSecrecyChannelResponse reply = new()
        {
            ReceivingChainLength = _state.RatchetState.ReceivingStep.CurrentIndex,
            SendingChainLength = _state.RatchetState.SendingStep.CurrentIndex,
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

    private DateTime GetLastPersistenceTime()
    {
        return DateTime.UtcNow.AddMinutes(-((SnapshotSequenceNr % ActorConstants.Constants.SnapshotModulus) *
                                            ActorConstants.Constants.SnapshotMinuteMultiplier));
    }

    private void HandleInitialKeyExchange(DeriveSharedSecretActorEvent cmd)
    {
        PubKeyExchangeType exchangeType = cmd.PubKeyExchange.OfType;
        if (_protocolSystems.TryGetValue(exchangeType, out EcliptixProtocolSystem? existingSystem) && _state != null)
        {
            if (IsAuthenticatedSession())
            {
                HandleAuthenticatedToAnonymousTransition(cmd.ConnectId);
            }
            else
            {
                Context.GetLogger()
                    .Info(ActorConstants.LogMessages.UsingExistingSession, cmd.ConnectId, exchangeType);
                Result<PubKeyExchange, EcliptixProtocolFailure> existingReplyResult =
                    existingSystem.ProcessAndRespondToPubKeyExchange(cmd.ConnectId, cmd.PubKeyExchange);

                bool sessionStillValid = true;
                try
                {
                    existingSystem.GetConnection();
                }
                catch (InvalidOperationException)
                {
                    Context.GetLogger()
                        .Info(ActorConstants.LogMessages.SystemDetectedFreshHandshake);
                    DisposeAllSystems();
                    _state = null;
                    sessionStillValid = false;
                    SaveSnapshot(new EcliptixSessionState());
                }

                if (sessionStillValid)
                {
                    if (existingReplyResult.IsOk)
                    {
                        if (exchangeType == PubKeyExchangeType.DataCenterEphemeralConnect)
                        {
                            Result<EcliptixSessionState, EcliptixProtocolFailure> newStateResult =
                                EcliptixProtocol.CreateStateFromSystem(_state!, existingSystem!);
                            if (newStateResult.IsOk)
                            {
                                _state = newStateResult.Unwrap();
                                Persist(_state, _ => { });
                            }
                        }

                        ConfigureSessionTimeout(exchangeType, cmd.ConnectId);

                        PubKeyExchange pubKeyReply = existingReplyResult.Unwrap();
                        Sender.Tell(
                            Result<DeriveSharedSecretReply, EcliptixProtocolFailure>.Ok(
                                new DeriveSharedSecretReply(pubKeyReply)));
                    }
                    else
                    {
                        Sender.Tell(
                            Result<DeriveSharedSecretReply, EcliptixProtocolFailure>.Err(
                                existingReplyResult.UnwrapErr()));
                    }

                    return;
                }
            }
        }

        Result<(EcliptixProtocolSystem System, EcliptixSessionState State, PubKeyExchange Reply),
                EcliptixProtocolFailure>
            sessionResult = CreateNewAnonymousSession(cmd.ConnectId, cmd.PubKeyExchange);

        if (sessionResult.IsErr)
        {
            Sender.Tell(Result<DeriveSharedSecretReply, EcliptixProtocolFailure>.Err(sessionResult.UnwrapErr()));
            return;
        }

        (EcliptixProtocolSystem system, EcliptixSessionState newState, PubKeyExchange reply) = sessionResult.Unwrap();
        IActorRef? originalSender = Sender;

        if (exchangeType == PubKeyExchangeType.DataCenterEphemeralConnect)
        {
            Persist(newState, state =>
            {
                _state = state;
                _protocolSystems[exchangeType] = system;
                _currentExchangeType = exchangeType;

                Context.SetReceiveTimeout(IdleTimeout);

                originalSender.Tell(
                    Result<DeriveSharedSecretReply, EcliptixProtocolFailure>.Ok(new DeriveSharedSecretReply(reply)));
                MaybeSaveSnapshot();
            });
        }
        else
        {
            _protocolSystems[exchangeType] = system;
            _currentExchangeType = exchangeType;

            Context.SetReceiveTimeout(null);

            originalSender.Tell(
                Result<DeriveSharedSecretReply, EcliptixProtocolFailure>.Ok(new DeriveSharedSecretReply(reply)));
        }
    }

    private void HandleAuthenticatedProtocolInitialization(InitializeProtocolWithMasterKeyActorEvent cmd)
    {
        PubKeyExchangeType exchangeType = cmd.ClientPubKeyExchange.OfType;

        if (_protocolSystems.TryGetValue(exchangeType, out EcliptixProtocolSystem? existingSystem) && _state != null)
        {
            EcliptixSystemIdentityKeys existingKeys = existingSystem.GetIdentityKeys();
            bool keysMatch = AreIdentityKeysEqual(existingKeys, cmd.IdentityKeys);

            if (keysMatch)
            {
                Result<PubKeyExchange, EcliptixProtocolFailure> existingReplyResult =
                    existingSystem.ProcessAuthenticatedPubKeyExchange(cmd.ConnectId, cmd.ClientPubKeyExchange,
                        cmd.RootKey);

                if (existingReplyResult.IsOk)
                {
                    if (exchangeType == PubKeyExchangeType.DataCenterEphemeralConnect)
                    {
                        Result<EcliptixSessionState, EcliptixProtocolFailure> newStateResult =
                            EcliptixProtocol.CreateStateFromSystem(_state, existingSystem);
                        if (newStateResult.IsOk)
                        {
                            EcliptixSessionState authState = newStateResult.Unwrap();
                            IActorRef authSender = Sender;
                            PubKeyExchange pubKeyReply = existingReplyResult.Unwrap();

                            Persist(authState, state =>
                            {
                                _state = state;
                                _currentExchangeType = exchangeType;
                                Context.SetReceiveTimeout(IdleTimeout);
                                authSender.Tell(
                                    Result<InitializeProtocolWithMasterKeyReply, EcliptixProtocolFailure>.Ok(
                                        new InitializeProtocolWithMasterKeyReply(pubKeyReply)));
                                MaybeSaveSnapshot();
                            });
                        }
                        else
                        {
                            Sender.Tell(
                                Result<InitializeProtocolWithMasterKeyReply, EcliptixProtocolFailure>.Err(
                                    newStateResult.UnwrapErr()));
                        }
                    }
                    else
                    {
                        _currentExchangeType = exchangeType;
                        Context.SetReceiveTimeout(null);

                        PubKeyExchange pubKeyReply = existingReplyResult.Unwrap();
                        Sender.Tell(
                            Result<InitializeProtocolWithMasterKeyReply, EcliptixProtocolFailure>.Ok(
                                new InitializeProtocolWithMasterKeyReply(pubKeyReply)));
                    }
                }
                else
                {
                    Sender.Tell(
                        Result<InitializeProtocolWithMasterKeyReply, EcliptixProtocolFailure>.Err(existingReplyResult
                            .UnwrapErr()));
                }

                cmd.IdentityKeys.Dispose();
                return;
            }

            Context.GetLogger().Warning(
                "[PROTOCOL] Identity key mismatch detected for ConnectId {0}, ExchangeType {1} - disposing old system and creating new authenticated session",
                cmd.ConnectId, exchangeType);

            existingSystem.Dispose();
            _protocolSystems.Remove(exchangeType);
            _state = null;
            _currentExchangeType = null;

            SaveSnapshot(new EcliptixSessionState());
        }

        Result<(EcliptixProtocolSystem System, EcliptixSessionState State, PubKeyExchange Reply),
                EcliptixProtocolFailure>
            sessionResult = CreateNewAuthenticatedSession(cmd.ConnectId, cmd.MembershipId, cmd.ClientPubKeyExchange,
                cmd.RootKey, cmd.IdentityKeys);

        if (sessionResult.IsErr)
        {
            Sender.Tell(
                Result<InitializeProtocolWithMasterKeyReply, EcliptixProtocolFailure>.Err(sessionResult.UnwrapErr()));
            return;
        }

        (EcliptixProtocolSystem system, EcliptixSessionState newState, PubKeyExchange reply) = sessionResult.Unwrap();
        IActorRef? originalSender = Sender;

        if (exchangeType == PubKeyExchangeType.DataCenterEphemeralConnect)
        {
            Persist(newState, state =>
            {
                _state = state;
                _protocolSystems[exchangeType] = system;
                _currentExchangeType = exchangeType;

                Context.SetReceiveTimeout(IdleTimeout);

                SaveSnapshot(_state);

                originalSender.Tell(
                    Result<InitializeProtocolWithMasterKeyReply, EcliptixProtocolFailure>.Ok(
                        new InitializeProtocolWithMasterKeyReply(reply)));
            });
        }
        else
        {
            _protocolSystems[exchangeType] = system;
            _currentExchangeType = exchangeType;

            Context.SetReceiveTimeout(null);

            originalSender.Tell(
                Result<InitializeProtocolWithMasterKeyReply, EcliptixProtocolFailure>.Ok(
                    new InitializeProtocolWithMasterKeyReply(reply)));
        }
    }

    private static bool AreIdentityKeysEqual(EcliptixSystemIdentityKeys keys1, EcliptixSystemIdentityKeys keys2)
    {
        try
        {
            byte[] publicKey1 = keys1.IdentityX25519PublicKey;
            byte[] publicKey2 = keys2.IdentityX25519PublicKey;

            return publicKey1.SequenceEqual(publicKey2);
        }
        catch (Exception ex)
        {
            Context.GetLogger().Warning(
                "[PROTOCOL] Failed to compare identity keys: {0} - treating as different keys",
                ex.Message);
            return false;
        }
    }

    private void HandleEncrypt(EncryptPayloadActorEvent cmd)
    {
        if (!_protocolSystems.TryGetValue(cmd.PubKeyExchangeType, out EcliptixProtocolSystem? system))
        {
            Option<EcliptixProtocolSystem> primaryProtocolSystemOpt = GetPrimaryProtocolSystem();
            if (!primaryProtocolSystemOpt.IsSome || _state == null)
            {
                Sender.Tell(
                    Result<SecureEnvelope, EcliptixProtocolFailure>.Err(
                        EcliptixProtocolFailure.Generic(
                            $"No protocol system found for exchange type {cmd.PubKeyExchangeType}")));
                return;
            }

            system = primaryProtocolSystemOpt.Value!;
        }

        Result<EncryptionResult, EcliptixProtocolFailure> result =
            EncryptionHandler.EncryptPayload(system, _state, cmd.Payload, cmd.PubKeyExchangeType);

        if (result.IsErr)
        {
            Sender.Tell(Result<SecureEnvelope, EcliptixProtocolFailure>.Err(result.UnwrapErr()));
            return;
        }

        EncryptionResult encryptionResult = result.Unwrap();
        IActorRef? originalSender = Sender;

        if (encryptionResult.ShouldPersist)
        {
            Persist(encryptionResult.NewState, state =>
            {
                _state = state;
                originalSender.Tell(Result<SecureEnvelope, EcliptixProtocolFailure>.Ok(encryptionResult.Envelope));
                MaybeSaveSnapshot();
            });
        }
        else
        {
            originalSender.Tell(Result<SecureEnvelope, EcliptixProtocolFailure>.Ok(encryptionResult.Envelope));
        }
    }

    private void HandleDecrypt(DecryptSecureEnvelopeActorEvent actorEvent)
    {
        if (!_protocolSystems.TryGetValue(actorEvent.PubKeyExchangeType, out EcliptixProtocolSystem? system))
        {
            Option<EcliptixProtocolSystem> primaryProtocolSystemOpt = GetPrimaryProtocolSystem();
            if (!primaryProtocolSystemOpt.IsSome || _state == null)
            {
                Sender.Tell(
                    Result<byte[], EcliptixProtocolFailure>.Err(
                        EcliptixProtocolFailure.Generic(
                            $"No protocol system found for exchange type {actorEvent.PubKeyExchangeType}")));
                return;
            }

            system = primaryProtocolSystemOpt.Value!;
        }

        Result<DecryptionResult, EcliptixProtocolFailure> result =
            _decryptionHandler.DecryptEnvelope(system, _state, actorEvent.SecureEnvelope,
                actorEvent.PubKeyExchangeType);

        if (result.IsErr)
        {
            HandleDecryptionError(result.UnwrapErr(), connectId);
            return;
        }

        DecryptionResult decryptionResult = result.Unwrap();

        if (decryptionResult.RequiresSessionClear)
        {
            Context.GetLogger()
                .Warning(
                    "AD compatibility strategies exhausted - this indicates client-server cryptographic context mismatch. Clearing session to force fresh handshake.");
            DisposeAllSystems();
            _state = null;
            _currentExchangeType = null;

            SaveSnapshot(new EcliptixSessionState());
            Sender.Tell(Result<byte[], EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.SessionAuthFailed("Session authentication failed")));
            return;
        }

        IActorRef? originalSender = Sender;

        if (decryptionResult.ShouldPersist)
        {
            Persist(decryptionResult.NewState, state =>
            {
                _state = state;
                originalSender.Tell(Result<byte[], EcliptixProtocolFailure>.Ok(decryptionResult.Plaintext));
                MaybeSaveSnapshot();
            });
        }
        else
        {
            originalSender.Tell(Result<byte[], EcliptixProtocolFailure>.Ok(decryptionResult.Plaintext));
        }
    }

    private void HandleCleanupProtocolForType(CleanupProtocolForTypeActorEvent cmd)
    {
        if (_protocolSystems.TryGetValue(cmd.ExchangeType, out EcliptixProtocolSystem? system))
        {
            system?.Dispose();
            _protocolSystems.Remove(cmd.ExchangeType);

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

        DisposeAllSystems();
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

    private void DisposeAllSystems()
    {
        foreach (EcliptixProtocolSystem system in _protocolSystems.Values)
        {
            system?.Dispose();
        }

        _protocolSystems.Clear();
    }

    private void AttemptSystemRecreation()
    {
        if (_state == null)
        {
            Context.GetLogger()
                .Warning($"[Recovery] No state available for system recreation for connectId {connectId}");
            return;
        }

        if (_state.PeerHandshakeMessage == null)
        {
            Context.GetLogger()
                .Warning(
                    $"[Recovery] State exists but PeerHandshakeMessage is null - clearing state for connectId {connectId}");
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
                    "[Recovery] Attempting system recreation (attempt {0}/{1}) for connectId {2}",
                    attempt,
                    MaxRecoveryRetries,
                    connectId);
        }

        Result<EcliptixProtocolSystem, EcliptixProtocolFailure> systemResult =
            EcliptixProtocol.RecreateSystemFromState(_state);

        if (systemResult.IsOk)
        {
            EcliptixProtocolSystem system = systemResult.Unwrap();
            _protocolSystems[exchangeType] = system;
            _recoveryRetryCount = 0;
        }
        else
        {
            _recoveryRetryCount++;
            EcliptixProtocolFailure failure = systemResult.UnwrapErr();

            Context.GetLogger()
                .Warning(
                    $"[Recovery] Failed to recreate protocol system for connectId {connectId} (attempt {_recoveryRetryCount}/{MaxRecoveryRetries}): {failure.Message}");

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
                    .Error(
                        $"[Recovery] Max recovery retries exceeded for connectId {connectId}. Clearing corrupted state to allow fresh handshake.");

                DisposeAllSystems();
                _state = null;
                _currentExchangeType = null;

                SaveSnapshot(new EcliptixSessionState());
            }
        }
    }

    private bool IsAuthenticatedSession()
    {
        return _state != null &&
               _state.MembershipId != null &&
               _state.MembershipId.Length > 0;
    }

    private Option<EcliptixProtocolSystem> GetPrimaryProtocolSystem()
    {
        return _protocolSystems.TryGetValue(PubKeyExchangeType.DataCenterEphemeralConnect,
            out EcliptixProtocolSystem? system)
            ? Option<EcliptixProtocolSystem>.Some(system)
            : Option<EcliptixProtocolSystem>.None;
    }

    private void HandleEncryptComponents(EncryptPayloadComponentsActorEvent cmd)
    {
        if (!_protocolSystems.TryGetValue(cmd.ExchangeType, out EcliptixProtocolSystem? system))
        {
            Option<EcliptixProtocolSystem> primaryProtocolSystemOpt = GetPrimaryProtocolSystem();
            if (!primaryProtocolSystemOpt.IsSome || _state == null)
            {
                Sender.Tell(
                    Result<(EnvelopeMetadata Header, byte[] EncryptedPayload), EcliptixProtocolFailure>.Err(
                        EcliptixProtocolFailure.Generic(
                            $"No protocol system found for exchange type {cmd.ExchangeType}")));
                return;
            }

            system = primaryProtocolSystemOpt.Value!;
        }

        Result<EncryptionMaterialsResult, EcliptixProtocolFailure> result =
            EncryptionHandler.EncryptPayloadMaterials(system, _state, cmd.Payload, cmd.ExchangeType);

        if (result.IsErr)
        {
            Sender.Tell(
                Result<(EnvelopeMetadata Header, byte[] EncryptedPayload), EcliptixProtocolFailure>.Err(
                    result.UnwrapErr()));
            return;
        }

        EncryptionMaterialsResult encryptionResult = result.Unwrap();
        IActorRef? originalSender = Sender;

        if (encryptionResult.ShouldPersist)
        {
            Persist(encryptionResult.NewState, state =>
            {
                _state = state;
                originalSender.Tell(
                    Result<(EnvelopeMetadata Header, byte[] EncryptedPayload), EcliptixProtocolFailure>.Ok(
                        (encryptionResult.Header, encryptionResult.EncryptedPayload)));
                MaybeSaveSnapshot();
            });
        }
        else
        {
            originalSender.Tell(Result<(EnvelopeMetadata Header, byte[] EncryptedPayload), EcliptixProtocolFailure>.Ok(
                (encryptionResult.Header, encryptionResult.EncryptedPayload)));
        }
    }

    private void HandleDecryptWithHeader(DecryptPayloadWithHeaderActorEvent cmd)
    {
        if (!_protocolSystems.TryGetValue(cmd.ExchangeType, out EcliptixProtocolSystem? system))
        {
            Option<EcliptixProtocolSystem> primaryProtocolSystemOpt = GetPrimaryProtocolSystem();
            if (!primaryProtocolSystemOpt.IsSome || _state == null)
            {
                Sender.Tell(
                    Result<byte[], EcliptixProtocolFailure>.Err(
                        EcliptixProtocolFailure.Generic(
                            $"No protocol system found for exchange type {cmd.ExchangeType}")));
                return;
            }

            system = primaryProtocolSystemOpt.Value!;
        }

        Result<DecryptionResult, EcliptixProtocolFailure> result =
            _decryptionHandler.DecryptWithHeader(system, _state, cmd.Metadata, cmd.EncryptedPayload, cmd.ExchangeType);

        if (result.IsErr)
        {
            EcliptixProtocolFailure error = result.UnwrapErr();

            if (DecryptionHandler.ShouldClearSession(error))
            {
                Context.GetLogger()
                    .Warning(
                        "AD compatibility strategies exhausted - this indicates client-server cryptographic context mismatch. Clearing session to force fresh handshake.");
                DisposeAllSystems();
                _state = null;
                _currentExchangeType = null;

                SaveSnapshot(new EcliptixSessionState());
            }

            Sender.Tell(Result<byte[], EcliptixProtocolFailure>.Err(error));
            return;
        }

        DecryptionResult decryptionResult = result.Unwrap();

        if (decryptionResult.RequiresSessionClear)
        {
            Context.GetLogger()
                .Warning(
                    "AD compatibility strategies exhausted - this indicates client-server cryptographic context mismatch. Clearing session to force fresh handshake.");
            DisposeAllSystems();
            _state = null;
            _currentExchangeType = null;

            SaveSnapshot(new EcliptixSessionState());
            Sender.Tell(Result<byte[], EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.SessionAuthFailed("Session authentication failed")));
            return;
        }

        IActorRef? originalSender = Sender;

        if (decryptionResult.ShouldPersist)
        {
            Persist(decryptionResult.NewState, state =>
            {
                _state = state;
                originalSender.Tell(Result<byte[], EcliptixProtocolFailure>.Ok(decryptionResult.Plaintext));
                MaybeSaveSnapshot();
            });
        }
        else
        {
            originalSender.Tell(Result<byte[], EcliptixProtocolFailure>.Ok(decryptionResult.Plaintext));
        }
    }

    private void HandleAuthenticatedToAnonymousTransition(uint connectId)
    {
        DisposeAllSystems();
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

    private void HandleDecryptionError(EcliptixProtocolFailure error, uint connectId)
    {
        Context.GetLogger().Error(
            "[SERVER-DECRYPT-ERROR] Decryption failed. ConnectId: {0}, ErrorType: {1}, Message: {2}",
            connectId, error.FailureType, error.Message);

        bool isHeaderAuthFailure = error.FailureType == EcliptixProtocolFailureType.HeaderAuthenticationFailed;

        if (isHeaderAuthFailure || DecryptionHandler.ShouldClearSession(error))
        {
            Context.GetLogger()
                .Warning(
                    "[SERVER-STATE-DESYNC] Header authentication failed for ConnectId {0} - protocol state desynchronized. Clearing state to force re-handshake.",
                    connectId);
            DisposeAllSystems();
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

    private static Result<(EcliptixProtocolSystem System, EcliptixSessionState State, PubKeyExchange Reply),
            EcliptixProtocolFailure>
        CreateNewAuthenticatedSession(uint connectId, Guid membershipId, PubKeyExchange clientPubKeyExchange,
            byte[] rootKey, EcliptixSystemIdentityKeys identityKeys)
    {
        EcliptixProtocolSystem system = new(identityKeys);

        Result<PubKeyExchange, EcliptixProtocolFailure> replyResult =
            system.ProcessAuthenticatedPubKeyExchange(connectId, clientPubKeyExchange, rootKey);

        if (replyResult.IsErr)
        {
            system.Dispose();
            return Result<(EcliptixProtocolSystem, EcliptixSessionState, PubKeyExchange), EcliptixProtocolFailure>
                .Err(replyResult.UnwrapErr());
        }

        Result<EcliptixSessionState, EcliptixProtocolFailure> stateToPersistResult =
            EcliptixProtocol.CreateInitialState(connectId, clientPubKeyExchange, system);
        if (stateToPersistResult.IsErr)
        {
            system.Dispose();
            return Result<(EcliptixProtocolSystem, EcliptixSessionState, PubKeyExchange), EcliptixProtocolFailure>
                .Err(stateToPersistResult.UnwrapErr());
        }

        EcliptixSessionState newState = stateToPersistResult.Unwrap();
        newState.MembershipId = Helpers.GuidToByteString(membershipId);

        PubKeyExchange reply = replyResult.Unwrap();

        return Result<(EcliptixProtocolSystem, EcliptixSessionState, PubKeyExchange), EcliptixProtocolFailure>
            .Ok((system, newState, reply));
    }

    private void ConfigureSessionTimeout(PubKeyExchangeType exchangeType, uint connectId)
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

    private static Result<(EcliptixProtocolSystem System, EcliptixSessionState State, PubKeyExchange Reply),
            EcliptixProtocolFailure>
        CreateNewAnonymousSession(uint connectId, PubKeyExchange pubKeyExchange)
    {
        EcliptixSystemIdentityKeys identityKeys =
            EcliptixSystemIdentityKeys.Create(ActorConstants.Constants.IdentityKeySize).Unwrap();

        EcliptixProtocolSystem system = new(identityKeys);

        Result<PubKeyExchange, EcliptixProtocolFailure> replyResult =
            system.ProcessAndRespondToPubKeyExchange(connectId, pubKeyExchange);

        if (replyResult.IsErr)
        {
            system.Dispose();
            return Result<(EcliptixProtocolSystem, EcliptixSessionState, PubKeyExchange), EcliptixProtocolFailure>
                .Err(replyResult.UnwrapErr());
        }

        Result<EcliptixSessionState, EcliptixProtocolFailure> stateToPersistResult =
            EcliptixProtocol.CreateInitialState(connectId, pubKeyExchange, system);
        if (stateToPersistResult.IsErr)
        {
            system.Dispose();
            return Result<(EcliptixProtocolSystem, EcliptixSessionState, PubKeyExchange), EcliptixProtocolFailure>
                .Err(stateToPersistResult.UnwrapErr());
        }

        EcliptixSessionState newState = stateToPersistResult.Unwrap();
        PubKeyExchange reply = replyResult.Unwrap();

        return Result<(EcliptixProtocolSystem, EcliptixSessionState, PubKeyExchange), EcliptixProtocolFailure>
            .Ok((system, newState, reply));
    }

    public static Props Build(uint connectId) => Props.Create(() => new EcliptixProtocolConnectActor(connectId));
}
