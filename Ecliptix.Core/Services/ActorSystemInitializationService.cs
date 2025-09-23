using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Akka.Actor;
using Ecliptix.Core.Domain.Actors;
using Ecliptix.Domain.Abstractions;
using Ecliptix.Domain.AppDevices.Persistors;
using Ecliptix.Domain.Memberships.Persistors;
using Ecliptix.Domain.Memberships.WorkerActors;
using Ecliptix.Domain.Memberships.OPAQUE;
using Ecliptix.Domain.Memberships.PhoneNumberValidation;
using Ecliptix.Domain.Providers.Twilio;
using Ecliptix.Domain.DbConnectionFactory;
using Ecliptix.Domain;
using Ecliptix.Core.Services;
using Ecliptix.Core.Configuration;

namespace Ecliptix.Core.Services;

public sealed class ActorSystemInitializationService : IHostedService
{
    private readonly ActorSystem _actorSystem;
    private readonly IEcliptixActorRegistry _registry;
    private readonly IServiceProvider _serviceProvider;
    private readonly ILogger<ActorSystemInitializationService> _logger;

    public ActorSystemInitializationService(
        ActorSystem actorSystem,
        IEcliptixActorRegistry registry,
        IServiceProvider serviceProvider,
        ILogger<ActorSystemInitializationService> logger)
    {
        _actorSystem = actorSystem;
        _registry = registry;
        _serviceProvider = serviceProvider;
        _logger = logger;
    }

    public Task StartAsync(CancellationToken cancellationToken)
    {
        _logger.LogInformation("Initializing actor system");

        IDbConnectionFactory dbConnectionFactory = _serviceProvider.GetRequiredService<IDbConnectionFactory>();
        IOpaqueProtocolService opaqueProtocolService = _serviceProvider.GetRequiredService<IOpaqueProtocolService>();
        ISessionKeyService sessionKeyService = _serviceProvider.GetRequiredService<ISessionKeyService>();
        ISmsProvider smsProvider = _serviceProvider.GetRequiredService<ISmsProvider>();
        ILocalizationProvider localizationProvider = _serviceProvider.GetRequiredService<ILocalizationProvider>();

        IActorRef protocolSystemActor = _actorSystem.ActorOf(
            EcliptixProtocolSystemActor.Build(),
            ApplicationConstants.ActorNames.ProtocolSystem);

        IActorRef appDevicePersistor = _actorSystem.ActorOf(
            AppDevicePersistorActor.Build(dbConnectionFactory, opaqueProtocolService),
            ApplicationConstants.ActorNames.AppDevicePersistor);

        IActorRef verificationFlowPersistorActor = _actorSystem.ActorOf(
            VerificationFlowPersistorActor.Build(dbConnectionFactory),
            ApplicationConstants.ActorNames.VerificationFlowPersistorActor);

        IActorRef membershipPersistorActor = _actorSystem.ActorOf(
            MembershipPersistorActor.Build(dbConnectionFactory),
            ApplicationConstants.ActorNames.MembershipPersistorActor);

        IActorRef authContextPersistorActor = _actorSystem.ActorOf(
            AuthContextPersistorActor.Build(dbConnectionFactory),
            ApplicationConstants.ActorNames.AuthContextPersistorActor);

        IActorRef authenticationStateManager = _actorSystem.ActorOf(
            AuthenticationStateManager.Build(),
            ApplicationConstants.ActorNames.AuthenticationStateManager);

        IActorRef membershipActor = _actorSystem.ActorOf(
            MembershipActor.Build(
                membershipPersistorActor,
                authContextPersistorActor,
                opaqueProtocolService,
                localizationProvider,
                authenticationStateManager,
                sessionKeyService),
            ApplicationConstants.ActorNames.MembershipActor);

        IActorRef verificationFlowManagerActor = _actorSystem.ActorOf(
            VerificationFlowManagerActor.Build(
                verificationFlowPersistorActor,
                membershipActor,
                smsProvider,
                localizationProvider),
            ApplicationConstants.ActorNames.VerificationFlowManagerActor);

        _registry.Register(ActorIds.EcliptixProtocolSystemActor, protocolSystemActor);
        _registry.Register(ActorIds.AppDevicePersistorActor, appDevicePersistor);
        _registry.Register(ActorIds.VerificationFlowPersistorActor, verificationFlowPersistorActor);
        _registry.Register(ActorIds.VerificationFlowManagerActor, verificationFlowManagerActor);
        _registry.Register(ActorIds.MembershipPersistorActor, membershipPersistorActor);
        _registry.Register(ActorIds.MembershipActor, membershipActor);

        _logger.LogInformation("Actor system initialized with {ActorCount} actors", 6);

        return Task.CompletedTask;
    }

    public Task StopAsync(CancellationToken cancellationToken)
    {
        _logger.LogInformation("Shutting down actor system");
        return Task.CompletedTask;
    }
}