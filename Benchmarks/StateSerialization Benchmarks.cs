using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Engines;
using Ecliptix.Core.Protocol;
using Ecliptix.Protobuf.ProtocolState;
using Microsoft.Extensions.Logging;
using Moq;

namespace Benchmarks;

[MemoryDiagnoser]
[RPlotExporter]
[MinColumn, MaxColumn, MeanColumn, MedianColumn]
[SimpleJob(RunStrategy.Throughput, launchCount: 1, warmupCount: 3, iterationCount: 10)]
public class StateSerializationBenchmarks
{
    private EcliptixSystemIdentityKeys _identityKeys = null!;
    private EcliptixProtocolSystem _protocolSystem = null!;
    private uint _sessionId;
    private ILogger<EcliptixProtocolSystem> _logger = null!;

    [GlobalSetup]
    public void GlobalSetup()
    {
        Mock<ILogger<EcliptixProtocolSystem>> loggerMock = new Mock<ILogger<EcliptixProtocolSystem>>();
        _logger = loggerMock.Object;

        Result<EcliptixSystemIdentityKeys, EcliptixProtocolFailure> identityKeysResult = EcliptixSystemIdentityKeys.Create(1);
        if (identityKeysResult.IsErr)
            throw new InvalidOperationException($"Failed to create identity keys: {identityKeysResult.UnwrapErr().Message}");

        _identityKeys = identityKeysResult.Unwrap();
        _protocolSystem = new EcliptixProtocolSystem(_identityKeys, null, _logger);

        _sessionId = 1;
        Result<(uint, EcliptixProtocolSystem, Ecliptix.Protobuf.PubKeyExchange.PubKeyExchange), EcliptixProtocolFailure> sessionResult = _protocolSystem.BeginDataCenterPubKeyExchange(_sessionId, Ecliptix.Protobuf.PubKeyExchange.PubKeyExchangeType.DataCenterEphemeralConnect);
        if (sessionResult.IsErr)
            throw new InvalidOperationException($"Failed to setup session: {sessionResult.UnwrapErr().Message}");

        (uint _, EcliptixProtocolSystem updatedSystem, Ecliptix.Protobuf.PubKeyExchange.PubKeyExchange _) = sessionResult.Unwrap();
        _protocolSystem = updatedSystem;
    }

    [Benchmark(Description = "Identity Keys ToProtoState (with caching)")]
    public IdentityKeysState IdentityKeysToProtoState()
    {
        Result<IdentityKeysState, EcliptixProtocolFailure> result = _identityKeys.ToProtoState();
        if (result.IsErr)
            throw new InvalidOperationException($"ToProtoState failed: {result.UnwrapErr().Message}");
        return result.Unwrap();
    }

    [Benchmark(Description = "Identity Keys ToProtoState Repeated (tests cache hit)")]
    public IdentityKeysState IdentityKeysToProtoStateRepeated()
    {
        Result<IdentityKeysState, EcliptixProtocolFailure> result1 = _identityKeys.ToProtoState();
        Result<IdentityKeysState, EcliptixProtocolFailure> result2 = _identityKeys.ToProtoState();
        Result<IdentityKeysState, EcliptixProtocolFailure> result3 = _identityKeys.ToProtoState();

        if (result3.IsErr)
            throw new InvalidOperationException($"ToProtoState failed: {result3.UnwrapErr().Message}");
        return result3.Unwrap();
    }

    [Benchmark(Description = "Full Session State Creation")]
    public Ecliptix.Protobuf.ProtocolState.EcliptixSessionState FullSessionStateCreation()
    {
        Ecliptix.Protobuf.ProtocolState.EcliptixSessionState dummyOldState = new Ecliptix.Protobuf.ProtocolState.EcliptixSessionState
        {
            ConnectId = _sessionId
        };

        Result<Ecliptix.Protobuf.ProtocolState.EcliptixSessionState, EcliptixProtocolFailure> result = EcliptixProtocol.CreateStateFromSystem(dummyOldState, _protocolSystem);
        if (result.IsErr)
            throw new InvalidOperationException($"CreateStateFromSystem failed: {result.UnwrapErr().Message}");
        return result.Unwrap();
    }

    [Benchmark(Description = "Memory Allocation Pressure Test")]
    public void MemoryAllocationPressureTest()
    {
        for (int i = 0; i < 100; i++)
        {
            Result<IdentityKeysState, EcliptixProtocolFailure> result = _identityKeys.ToProtoState();
            if (result.IsOk)
            {
                result.Unwrap();
            }
        }
    }

    [GlobalCleanup]
    public void GlobalCleanup()
    {
        _protocolSystem?.Dispose();
        _identityKeys?.Dispose();
    }
}