using Akka.Cluster.Hosting;
using Akka.Discovery.Config.Hosting;
using Akka.Discovery.KubernetesApi;
using Akka.Hosting;
using Akka.Management;
using Akka.Management.Cluster.Bootstrap;
using Akka.Persistence.Hosting;
using Akka.Persistence.Sql.Hosting;
using Akka.Remote.Hosting;
using Ecliptix.Core.Configuration.Settings;
using Ecliptix.Core.Services;
using Ecliptix.IdentityAccess.Domain.Schema;
using Ecliptix.SharedKernel.Configuration;
using LinqToDB;

namespace Ecliptix.Core.Configuration;

internal static class AkkaConfiguration
{
    public static void ConfigureAkka(WebApplicationBuilder builder)
    {
        AkkaSettings akkaSettings = new();
        builder.Configuration.GetSection(nameof(AkkaSettings)).Bind(akkaSettings);
        builder.Services.AddSingleton(akkaSettings);

        string? connectionString = builder.Configuration.GetConnectionString("EcliptixMemberships");
        bool usePostgreSQL = builder.Configuration.GetValue<bool>("UsePostgreSQL", false);

        string hostname = Environment.GetEnvironmentVariable(EnvironmentVariableNames.PodIp) ?? akkaSettings.Remoting.Hostname;
        int port = int.Parse(Environment.GetEnvironmentVariable(EnvironmentVariableNames.AkkaPort) ?? akkaSettings.Remoting.Port.ToString());

        const string systemActorName = ApplicationConstants.ActorSystem.SystemName;

        builder.Services.AddAkka(systemActorName, configurationBuilder =>
        {
            configurationBuilder
                .ConfigureLoggers(setup =>
                {
                    setup.LogLevel = Akka.Event.LogLevel.InfoLevel;
                    setup.DeadLetterOptions = new DeadLetterOptions { LogCount = 10, LogDuringShutdown = false, };
                })
                .WithSqlPersistence(
                    connectionString: connectionString!,
                    providerName: usePostgreSQL ? ProviderName.PostgreSQL : ProviderName.SqlServer2022,
                    databaseMapping: usePostgreSQL ? DatabaseMapping.PostgreSql : DatabaseMapping.SqlServer,
                    mode: PersistenceMode.Both,
                    autoInitialize: true,
                    schemaName: usePostgreSQL ? DatabaseConstants.SchemaNames.PostgreSql : DatabaseConstants.SchemaNames.SqlServer,
                    journalBuilder: journalBuilder =>
                    {
                        journalBuilder
                            .WithHealthCheck(name: "Akka.Persistence.Sql.Journal[default]")
                            .WithConnectivityCheck();
                    },
                    snapshotBuilder: snapshotBuilder =>
                    {
                        snapshotBuilder
                            .WithHealthCheck(name: "Akka.Persistence.Sql.SnapshotStore[default]")
                            .WithConnectivityCheck();
                    }
                );

            if (!akkaSettings.ClusterMode.Equals("None", StringComparison.OrdinalIgnoreCase))
            {
                configurationBuilder
                    .WithRemoting(hostname, port)
                    .WithClustering(new ClusterOptions
                    {
                        Roles = akkaSettings.Cluster.Roles,
                        SeedNodes = akkaSettings.ClusterMode.Equals("Config", StringComparison.OrdinalIgnoreCase)
                            ? akkaSettings.Cluster.SeedNodes
                            : []
                    })
                    .WithAkkaManagement(setup =>
                    {
                        setup.Http.HostName = akkaSettings.AkkaManagement.HostName;
                        setup.Http.Port = akkaSettings.AkkaManagement.Port;
                        setup.Http.BindHostName = akkaSettings.AkkaManagement.BindHostName;
                        setup.Http.BindPort = akkaSettings.AkkaManagement.BindPort;
                    });

                if (akkaSettings.ClusterMode.Equals("Kubernetes", StringComparison.OrdinalIgnoreCase))
                {
                    configurationBuilder
                        .WithClusterBootstrap(setup =>
                        {
                            setup.ContactPointDiscovery.ServiceName = akkaSettings.ClusterBootstrap.ServiceName;
                            setup.ContactPointDiscovery.PortName = akkaSettings.ClusterBootstrap.PortName;
                            setup.ContactPointDiscovery.RequiredContactPointsNr =
                                akkaSettings.ClusterBootstrap.RequiredContactPointsNr;
                        }, autoStart: akkaSettings.ClusterBootstrap.AutoStart)
                        .WithKubernetesDiscovery(setup =>
                        {
                            setup.PodLabelSelector = akkaSettings.KubernetesDiscovery.PodLabelSelector;
                        });
                }
                else if (akkaSettings.ClusterMode.Equals("Config", StringComparison.OrdinalIgnoreCase))
                {
                    configurationBuilder
                        .WithConfigDiscovery(_ => { });
                }
            }

            configurationBuilder
                // Actor wiring is handled by ActorSystemInitializationHost; no extra registrations here.
                .WithActors((_, _) => { })
                .AddHocon($@"
                    akka {{
                        akka.actor.ask-timeout = {TimeoutConfiguration.FormatForAkka(TimeoutConfiguration.Actor.AskTimeout)}
                        akka.persistence.sql-store.journal.call-timeout = {TimeoutConfiguration.FormatForAkka(TimeoutConfiguration.Database.CommandTimeout)}
                        akka.persistence.sql-store.snapshot.call-timeout = {TimeoutConfiguration.FormatForAkka(TimeoutConfiguration.Database.CommandTimeout)}

                         stdout-loglevel = INFO

                        persistence {{
                            journal {{
                                # Max batch size for batched writes - set to 1 to prevent sequence collisions
                                # This ensures events are written one at a time to avoid unique constraint violations
                                max-batch-size = 1
                                # Disable parallelism to enforce sequential writes
                                parallelism = 1
                            }}
                            sql-store {{
                                journal.circuit-breaker {{
                                    max-failures = 5
                                    call-timeout = 10s
                                    reset-timeout = 30s
                                }}
                                snapshot.circuit-breaker {{
                                    max-failures = 5
                                    call-timeout = 10s
                                    reset-timeout = 30s
                                }}
                            }}
                            recovery {{
                                replay-filter {{
                                    # Changed from 'repair-by-discard-old' to 'warn' to prevent silent event discarding
                                    # 'warn' mode will log warnings about potential issues but recover all events
                                    # This prevents the issue where event #11 was silently discarded during recovery
                                    mode = warn
                                    window-size = 100
                                    max-old-writers = 10
                                    # Enable debug to see detailed recovery information
                                    debug = true
                                }}
                            }}
                        }}

                        actor {{
                            default-dispatcher {{
                                type = Dispatcher
                                executor = fork-join-executor
                                fork-join-executor {{
                                    parallelism-min = 2
                                    parallelism-max = 8
                                    parallelism-factor = 2.0
                                }}
                                throughput = 5
                            }}
                            database-dispatcher {{
                                type = Dispatcher
                                executor = thread-pool-executor
                                thread-pool-executor {{
                                    fixed-pool-size = 4
                                    task-queue-size = -1
                                }}
                                throughput = 1
                            }}
                            serializers {{
                                protobuf = ""Ecliptix.Core.Infrastructure.Serialization.Base64SessionStateSerializer, Ecliptix.Core""
                            }}
                            serialization-bindings {{
                                ""Ecliptix.Protobuf.ProtocolState.EcliptixSessionState, Ecliptix.Protobufs"" = protobuf
                                ""Ecliptix.Protobuf.ProtocolState.IdentityKeysState, Ecliptix.Protobufs"" = protobuf
                                ""Ecliptix.Protobuf.ProtocolState.RatchetState, Ecliptix.Protobufs"" = protobuf
                                ""Ecliptix.Protobuf.ProtocolState.OneTimePreKeySecret, Ecliptix.Protobufs"" = protobuf
                                ""Ecliptix.Protobuf.ProtocolState.ChainStepState, Ecliptix.Protobufs"" = protobuf
                                ""Ecliptix.Protobuf.ProtocolState.CachedMessageKey, Ecliptix.Protobufs"" = protobuf
                            }}
                        }}
                    }}
                ", HoconAddMode.Prepend);
        });

    }
}
