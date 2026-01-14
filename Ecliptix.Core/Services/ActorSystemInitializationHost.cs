using Akka;
using Akka.Actor;
using Ecliptix.Core.Configuration;
using Ecliptix.DeviceProvisioning.Infrastructure.Persistors;
using Ecliptix.IdentityAccess.Domain;
using Ecliptix.IdentityAccess.Domain.Actors.AccountProfile;
using Ecliptix.IdentityAccess.Domain.Actors.Membership;
using Ecliptix.IdentityAccess.Domain.Actors.VerificationFlow;
using Ecliptix.IdentityAccess.Domain.Persistors;
using Ecliptix.IdentityAccess.Domain.Providers.Twilio;
using Ecliptix.IdentityAccess.Domain.Schema;
using Ecliptix.IdentityAccess.Domain.Services;
using Ecliptix.SharedKernel;
using Ecliptix.SharedKernel.Actors;
using Ecliptix.SharedKernel.Configuration;
using Ecliptix.SecureProtocol.Infrastructure.Actors;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Ecliptix.Security.Opaque.Contracts;
using Serilog;

namespace Ecliptix.Core.Services;

public sealed class ActorSystemInitializationHost(
    ActorSystem actorSystem,
    IEcliptixActorRegistry registry,
    IDbContextFactory<EcliptixSchemaContext> dbContextFactory,
    IOpaqueProtocolService opaqueProtocolService,
    ILocalizationService localizationService,
    IMasterKeyService masterKeyService,
    ISmsProvider smsProvider,
    IOptionsMonitor<SecurityConfiguration> securityConfig) : IHostedService
{
    public Task StartAsync(CancellationToken cancellationToken)
    {
        IActorRef protocolSystemActor = actorSystem.ActorOf(
            Props.Create(() => new EcliptixProtocolSystemActor()),
            ApplicationConstants.ActorNames.ProtocolSystem);

        IActorRef appDevicePersistor = actorSystem.ActorOf(
            AppDevicePersistorActor.Build(dbContextFactory),
            ApplicationConstants.ActorNames.AppDevicePersistor);

        IActorRef membershipPersistorActor = actorSystem.ActorOf(
            MembershipPersistorActor.Build(dbContextFactory, securityConfig),
            ApplicationConstants.ActorNames.MembershipPersistorActor);

        IActorRef accountPersistorActor = actorSystem.ActorOf(
            AccountPersistorActor.Build(dbContextFactory),
            ApplicationConstants.ActorNames.AccountPersistorActor);

        IActorRef passwordRecoveryPersistorActor = actorSystem.ActorOf(
            PasswordRecoveryPersistorActor.Build(dbContextFactory, securityConfig),
            ApplicationConstants.ActorNames.PasswordRecoveryPersistorActor);

        IActorRef masterKeySharePersistorActor = actorSystem.ActorOf(
            MasterKeySharePersistorActor.Build(dbContextFactory),
            ApplicationConstants.ActorNames.MasterKeySharePersistorActor);

        IActorRef logoutAuditPersistorActor = actorSystem.ActorOf(
            LogoutAuditPersistorActor.Build(dbContextFactory),
            ApplicationConstants.ActorNames.LogoutAuditPersistorActor);

        IActorRef accountProfilePersistorActor = actorSystem.ActorOf(
            AccountProfilePersistorActor.Build(dbContextFactory),
            ApplicationConstants.ActorNames.AccountProfilePersistorActor);

        IActorRef membershipActor = actorSystem.ActorOf(
            MembershipActor.Build(
                membershipPersistorActor,
                accountPersistorActor,
                passwordRecoveryPersistorActor,
                opaqueProtocolService,
                localizationService,
                masterKeyService,
                securityConfig),
            ApplicationConstants.ActorNames.MembershipActor);

        IActorRef verificationFlowPersistorActor = actorSystem.ActorOf(
            VerificationFlowPersistorActor.Build(dbContextFactory, securityConfig, Option<IActorRef>.Some(membershipPersistorActor)),
            ApplicationConstants.ActorNames.VerificationFlowPersistorActor);

        IActorRef verificationFlowManagerActor = actorSystem.ActorOf(
            VerificationFlowManagerActor.Build(
                verificationFlowPersistorActor,
                membershipActor,
                smsProvider,
                localizationService,
                securityConfig),
            ApplicationConstants.ActorNames.VerificationFlowManagerActor);

        IActorRef accountProfileActor = actorSystem.ActorOf(
            AccountProfileActor.Build(accountProfilePersistorActor),
            ApplicationConstants.ActorNames.AccountProfileActor);

        registry.Register(ActorIds.EcliptixProtocolSystemActor, protocolSystemActor);
        registry.Register(ActorIds.AppDevicePersistorActor, appDevicePersistor);
        registry.Register(ActorIds.VerificationFlowPersistorActor, verificationFlowPersistorActor);
        registry.Register(ActorIds.VerificationFlowManagerActor, verificationFlowManagerActor);
        registry.Register(ActorIds.MembershipPersistorActor, membershipPersistorActor);
        registry.Register(ActorIds.MembershipActor, membershipActor);
        registry.Register(ActorIds.MasterKeySharePersistorActor, masterKeySharePersistorActor);
        registry.Register(ActorIds.LogoutAuditPersistorActor, logoutAuditPersistorActor);
        registry.Register(ActorIds.AccountPersistorActor, accountPersistorActor);
        registry.Register(ActorIds.PasswordRecoveryPersistorActor, passwordRecoveryPersistorActor);
        registry.Register(ActorIds.AccountProfilePersistorActor, accountProfilePersistorActor);
        registry.Register(ActorIds.AccountProfileActor, accountProfileActor);

        RegisterShutdownHooks();

        return Task.CompletedTask;
    }

    private void RegisterShutdownHooks()
    {
        CoordinatedShutdown coordinatedShutdown = CoordinatedShutdown.Get(actorSystem);

        coordinatedShutdown.AddTask(CoordinatedShutdown.PhaseBeforeServiceUnbind,
            "stop-accepting-new-connections",
            () => Task.FromResult(Done.Instance));

        coordinatedShutdown.AddTask(CoordinatedShutdown.PhaseServiceRequestsDone,
            "drain-active-requests", async () =>
            {
                await Task.Delay(TimeSpan.FromSeconds(5));
                return Done.Instance;
            });

        coordinatedShutdown.AddTask(CoordinatedShutdown.PhaseBeforeActorSystemTerminate,
            "cleanup-resources",
            () => Task.FromResult(Done.Instance));
    }

    public async Task StopAsync(CancellationToken cancellationToken)
    {
        try
        {
            using CancellationTokenSource timeoutCts =
                CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeoutCts.CancelAfter(TimeSpan.FromSeconds(30));

            CoordinatedShutdown coordinatedShutdown = CoordinatedShutdown.Get(actorSystem);
            await coordinatedShutdown.Run(CoordinatedShutdown.ClrExitReason.Instance);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            Log.Debug("Actor system shutdown cancelled, forcing termination");
            await actorSystem.Terminate();
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Error during actor system shutdown, forcing termination");
            await actorSystem.Terminate();
        }
    }
}
