using Akka.Actor;
using Ecliptix.Core.Configuration;
using Ecliptix.Core.Domain.Actors;
using Ecliptix.Domain;
using Ecliptix.Domain.AppDevices.Persistors;
using Ecliptix.Domain.Memberships.Persistors;
using Ecliptix.Domain.Memberships.WorkerActors.Membership;
using Ecliptix.Domain.Memberships.WorkerActors.VerificationFlow;
using Ecliptix.Domain.Providers.Twilio;
using Ecliptix.Domain.Schema;
using Ecliptix.Domain.Services.Security;
using Ecliptix.Security.Opaque.Contracts;
using Ecliptix.Utilities;
using Ecliptix.Utilities.Configuration;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace Ecliptix.Core.Services;

public sealed class ActorSystemInitializationHost(
    ActorSystem actorSystem,
    IEcliptixActorRegistry registry,
    IServiceProvider serviceProvider)
    : IHostedService
{
    public Task StartAsync(CancellationToken cancellationToken)
    {
        IDbContextFactory<EcliptixSchemaContext> dbContextFactory =
            serviceProvider.GetRequiredService<IDbContextFactory<EcliptixSchemaContext>>();
        IOpaqueProtocolService opaqueProtocolService = serviceProvider.GetRequiredService<IOpaqueProtocolService>();
        ISmsProvider smsProvider = serviceProvider.GetRequiredService<ISmsProvider>();
        ILocalizationProvider localizationProvider = serviceProvider.GetRequiredService<ILocalizationProvider>();
        IMasterKeyService masterKeyService = serviceProvider.GetRequiredService<IMasterKeyService>();
        IOptionsMonitor<SecurityConfiguration> securityConfig =
            serviceProvider.GetRequiredService<IOptionsMonitor<SecurityConfiguration>>();

        IActorRef protocolSystemActor = actorSystem.ActorOf(
            EcliptixProtocolSystemActor.Build(),
            ApplicationConstants.ActorNames.ProtocolSystem);

        IActorRef appDevicePersistor = actorSystem.ActorOf(
            AppDevicePersistorActor.Build(dbContextFactory),
            ApplicationConstants.ActorNames.AppDevicePersistor);

        IActorRef membershipPersistorActor = actorSystem.ActorOf(
            MembershipPersistorActor.Build(dbContextFactory, securityConfig),
            ApplicationConstants.ActorNames.MembershipPersistorActor);

        IActorRef verificationFlowPersistorActor = actorSystem.ActorOf(
            VerificationFlowPersistorActor.Build(dbContextFactory, securityConfig,
                Option<IActorRef>.Some(membershipPersistorActor)),
            ApplicationConstants.ActorNames.VerificationFlowPersistorActor);

        IActorRef masterKeySharePersistorActor = actorSystem.ActorOf(
            MasterKeySharePersistorActor.Build(dbContextFactory),
            ApplicationConstants.ActorNames.MasterKeySharePersistorActor);

        IActorRef logoutAuditPersistorActor = actorSystem.ActorOf(
            LogoutAuditPersistorActor.Build(dbContextFactory),
            ApplicationConstants.ActorNames.LogoutAuditPersistorActor);

        IActorRef accountPersistorActor = actorSystem.ActorOf(
            AccountPersistorActor.Build(dbContextFactory),
            ApplicationConstants.ActorNames.AccountPersistorActor);

        IActorRef passwordRecoveryPersistorActor = actorSystem.ActorOf(
            PasswordRecoveryPersistorActor.Build(dbContextFactory, securityConfig),
            ApplicationConstants.ActorNames.PasswordRecoveryPersistorActor);

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

        IActorRef verificationFlowManagerActor = actorSystem.ActorOf(
            VerificationFlowManagerActor.Build(
                verificationFlowPersistorActor,
                membershipActor,
                smsProvider,
                localizationProvider,
                securityConfig),
            ApplicationConstants.ActorNames.VerificationFlowManagerActor);

        registry.Register(ActorIds.EcliptixProtocolSystemActor, protocolSystemActor);
        registry.Register(ActorIds.AppDevicePersistorActor, appDevicePersistor);
        registry.Register(ActorIds.VerificationFlowPersistorActor, verificationFlowPersistorActor);
        registry.Register(ActorIds.VerificationFlowManagerActor, verificationFlowManagerActor);
        registry.Register(ActorIds.MembershipPersistorActor, membershipPersistorActor);
        registry.Register(ActorIds.MasterKeySharePersistorActor, masterKeySharePersistorActor);
        registry.Register(ActorIds.LogoutAuditPersistorActor, logoutAuditPersistorActor);
        registry.Register(ActorIds.AccountPersistorActor, accountPersistorActor);
        registry.Register(ActorIds.PasswordRecoveryPersistorActor, passwordRecoveryPersistorActor);
        registry.Register(ActorIds.MembershipActor, membershipActor);

        return Task.CompletedTask;
    }

    public Task StopAsync(CancellationToken cancellationToken)
    {
        return Task.CompletedTask;
    }
}
