using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Akka.Actor;
using Ecliptix.Core.Domain.Actors;
using Ecliptix.Domain.Abstractions;
using Ecliptix.Domain.AppDevices.Persistors;
using Ecliptix.Domain.Memberships.Persistors;
using Ecliptix.Domain.Memberships.WorkerActors;
using Ecliptix.Security.Opaque.Models;
using Ecliptix.Security.Opaque.Contracts;
using Ecliptix.Domain.Memberships.PhoneNumberValidation;
using Ecliptix.Domain.Providers.Twilio;
using Ecliptix.Domain.DbConnectionFactory;
using Ecliptix.Domain;
using Ecliptix.Core.Services;
using Ecliptix.Core.Configuration;

namespace Ecliptix.Core.Services;

public sealed class ActorSystemInitializationHost(
    ActorSystem actorSystem,
    IEcliptixActorRegistry registry,
    IServiceProvider serviceProvider)
    : IHostedService
{
    public Task StartAsync(CancellationToken cancellationToken)
    {
        IDbConnectionFactory dbConnectionFactory = serviceProvider.GetRequiredService<IDbConnectionFactory>();
        IOpaqueProtocolService opaqueProtocolService = serviceProvider.GetRequiredService<IOpaqueProtocolService>();
        ISessionKeyService sessionKeyService = serviceProvider.GetRequiredService<ISessionKeyService>();
        ISmsProvider smsProvider = serviceProvider.GetRequiredService<ISmsProvider>();
        ILocalizationProvider localizationProvider = serviceProvider.GetRequiredService<ILocalizationProvider>();

        IActorRef protocolSystemActor = actorSystem.ActorOf(
            EcliptixProtocolSystemActor.Build(),
            ApplicationConstants.ActorNames.ProtocolSystem);

        IActorRef appDevicePersistor = actorSystem.ActorOf(
            AppDevicePersistorActor.Build(dbConnectionFactory),
            ApplicationConstants.ActorNames.AppDevicePersistor);

        IActorRef verificationFlowPersistorActor = actorSystem.ActorOf(
            VerificationFlowPersistorActor.Build(dbConnectionFactory),
            ApplicationConstants.ActorNames.VerificationFlowPersistorActor);

        IActorRef membershipPersistorActor = actorSystem.ActorOf(
            MembershipPersistorActor.Build(dbConnectionFactory),
            ApplicationConstants.ActorNames.MembershipPersistorActor);

        IActorRef authContextPersistorActor = actorSystem.ActorOf(
            AuthContextPersistorActor.Build(dbConnectionFactory),
            ApplicationConstants.ActorNames.AuthContextPersistorActor);

        IActorRef authenticationStateManager = actorSystem.ActorOf(
            AuthenticationStateManager.Build(),
            ApplicationConstants.ActorNames.AuthenticationStateManager);

        IActorRef membershipActor = actorSystem.ActorOf(
            MembershipActor.Build(
                membershipPersistorActor,
                authContextPersistorActor,
                opaqueProtocolService,
                localizationProvider,
                authenticationStateManager,
                sessionKeyService),
            ApplicationConstants.ActorNames.MembershipActor);

        IActorRef verificationFlowManagerActor = actorSystem.ActorOf(
            VerificationFlowManagerActor.Build(
                verificationFlowPersistorActor,
                membershipActor,
                smsProvider,
                localizationProvider),
            ApplicationConstants.ActorNames.VerificationFlowManagerActor);

        registry.Register(ActorIds.EcliptixProtocolSystemActor, protocolSystemActor);
        registry.Register(ActorIds.AppDevicePersistorActor, appDevicePersistor);
        registry.Register(ActorIds.VerificationFlowPersistorActor, verificationFlowPersistorActor);
        registry.Register(ActorIds.VerificationFlowManagerActor, verificationFlowManagerActor);
        registry.Register(ActorIds.MembershipPersistorActor, membershipPersistorActor);
        registry.Register(ActorIds.MembershipActor, membershipActor);

        return Task.CompletedTask;
    }

    public Task StopAsync(CancellationToken cancellationToken)
    {
        return Task.CompletedTask;
    }
}