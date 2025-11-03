using Akka.Hosting;
using Akka.Persistence.Hosting;
using Akka.Persistence.Sql.Hosting;
using Ecliptix.Core.Configuration.Settings;
using Ecliptix.Utilities.Configuration;
using LinqToDB;

namespace Ecliptix.Core.Configuration;

internal static class AkkaConfiguration
{
    public static void ConfigureAkka(WebApplicationBuilder builder)
    {
        AkkaSettings akkaSettings = BindAkkaSettings(builder.Services, builder.Configuration);
        string? connectionString = builder.Configuration.GetConnectionString("EcliptixMemberships");
        if (connectionString == null)
            throw new Exception("No EcliptixMemberships connection string configured");
        
        builder.Services.AddAkka(ApplicationConstants.ActorSystem.SystemName, akkaConfigurationBuilder =>
        {
            akkaConfigurationBuilder
                .ConfigureLoggers(setup =>
                {
                    setup.LogLevel = Akka.Event.LogLevel.InfoLevel;
                    setup.DeadLetterOptions = new DeadLetterOptions
                    {
                        LogCount = 10,
                        LogDuringShutdown = false,
                    };
                })
                .WithSqlPersistence(
                    connectionString: connectionString,
                    providerName: ProviderName.SqlServer2022,
                    databaseMapping: DatabaseMapping.SqlServer,
                    mode: PersistenceMode.Both,
                    autoInitialize: true,
                    schemaName: "dbo",
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
                )
                .AddHocon($@"
                    akka.actor.ask-timeout = {TimeoutConfiguration.FormatForAkka(TimeoutConfiguration.Actor.AskTimeout)}
                    akka.persistence.sql-store.journal.call-timeout = {TimeoutConfiguration.FormatForAkka(TimeoutConfiguration.Database.CommandTimeout)}
                    akka.persistence.sql-store.snapshot.call-timeout = {TimeoutConfiguration.FormatForAkka(TimeoutConfiguration.Database.CommandTimeout)}

                    akka {{
                        stdout-loglevel = INFO
                        
                        persistence {{
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
                                    mode = repair-by-discard-old
                                    window-size = 100
                                    max-old-writers = 10
                                    debug = false
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
        
        builder.Services.AddHostedService<ActorSystemHostedService>();
    }

    private static AkkaSettings BindAkkaSettings(IServiceCollection services, IConfiguration configuration)
    {
        AkkaSettings akkaSettings = new();
        configuration.GetSection(nameof(AkkaSettings)).Bind(akkaSettings);
        services.AddSingleton(akkaSettings);

        return akkaSettings;
    }
}