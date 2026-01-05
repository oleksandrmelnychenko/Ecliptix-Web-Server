using Akka.Actor;
using Ecliptix.Core.Configuration;
using Ecliptix.DeviceProvisioning.Infrastructure.Persistors;
using Ecliptix.IdentityAccess.Domain;
using Ecliptix.IdentityAccess.Domain.Memberships.WorkerActors.AccountProfileActor;
using Ecliptix.IdentityAccess.Domain.Memberships.WorkerActors.Membership;
using Ecliptix.IdentityAccess.Domain.Memberships.WorkerActors.VerificationFlow;
using Ecliptix.IdentityAccess.Domain.Memberships.Persistors;
using Ecliptix.IdentityAccess.Domain.Providers.Twilio;
using Ecliptix.IdentityAccess.Domain.Schema;
using Ecliptix.SharedKernel;
using Ecliptix.SharedKernel.Actors;
using Ecliptix.SharedKernel.Configuration;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Ecliptix.Security.Opaque.Contracts;
using Ecliptix.IdentityAccess.Domain.Services.Security;

namespace Ecliptix.Core.Services;

/// <summary>
/// Bootstraps the core actor system and registers all actor refs in the shared registry.
/// </summary>
public sealed class ActorSystemInitializationHost(
    ActorSystem actorSystem,
    IEcliptixActorRegistry registry,
    IDbContextFactory<EcliptixSchemaContext> dbContextFactory,
    IOpaqueProtocolService opaqueProtocolService,
    ILocalizationProvider localizationProvider,
    IMasterKeyService masterKeyService,
    ISmsProvider smsProvider,
    IOptionsMonitor<SecurityConfiguration> securityConfig) : IHostedService
{
    public Task StartAsync(CancellationToken cancellationToken)
    {
        IActorRef protocolSystemActor = actorSystem.ActorOf(
            Props.Create(() => new Domain.Actors.EcliptixProtocolSystemActor()),
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
                localizationProvider,
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
                localizationProvider,
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

        return Task.CompletedTask;
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
