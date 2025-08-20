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
        // Mock logger
        var loggerMock = new Mock<ILogger<EcliptixProtocolSystem>>();
        _logger = loggerMock.Object;

        // Create identity keys for benchmarking
        var identityKeysResult = EcliptixSystemIdentityKeys.Create(1);
        if (identityKeysResult.IsErr)
            throw new InvalidOperationException($"Failed to create identity keys: {identityKeysResult.UnwrapErr().Message}");

        _identityKeys = identityKeysResult.Unwrap();
        _protocolSystem = new EcliptixProtocolSystem(_identityKeys, null, _logger);
        
        // Setup a session for state creation benchmarks
        _sessionId = 1;
        var sessionResult = _protocolSystem.BeginDataCenterPubKeyExchange(_sessionId, Ecliptix.Protobuf.PubKeyExchange.PubKeyExchangeType.DataCenterEphemeralConnect);
        if (sessionResult.IsErr)
            throw new InvalidOperationException($"Failed to setup session: {sessionResult.UnwrapErr().Message}");
        
        var (_, updatedSystem, _) = sessionResult.Unwrap();
        _protocolSystem = updatedSystem;
    }

    [Benchmark(Description = "Identity Keys ToProtoState (with caching)")]
    public IdentityKeysState IdentityKeysToProtoState()
    {
        var result = _identityKeys.ToProtoState();
        if (result.IsErr)
            throw new InvalidOperationException($"ToProtoState failed: {result.UnwrapErr().Message}");
        return result.Unwrap();
    }

    [Benchmark(Description = "Identity Keys ToProtoState Repeated (tests cache hit)")]
    public IdentityKeysState IdentityKeysToProtoStateRepeated()
    {
        // Call multiple times to test caching effectiveness
        var result1 = _identityKeys.ToProtoState();
        var result2 = _identityKeys.ToProtoState();
        var result3 = _identityKeys.ToProtoState();
        
        if (result3.IsErr)
            throw new InvalidOperationException($"ToProtoState failed: {result3.UnwrapErr().Message}");
        return result3.Unwrap();
    }

    [Benchmark(Description = "Full Session State Creation")]
    public Ecliptix.Protobuf.ProtocolState.EcliptixSessionState FullSessionStateCreation()
    {
        // This tests the full state serialization path including all optimizations
        var dummyOldState = new Ecliptix.Protobuf.ProtocolState.EcliptixSessionState
        {
            ConnectId = _sessionId
        };
        
        var result = EcliptixProtocol.CreateStateFromSystem(dummyOldState, _protocolSystem);
        if (result.IsErr)
            throw new InvalidOperationException($"CreateStateFromSystem failed: {result.UnwrapErr().Message}");
        return result.Unwrap();
    }

    [Benchmark(Description = "Memory Allocation Pressure Test")]
    public void MemoryAllocationPressureTest()
    {
        // Test repeated state serialization to measure GC pressure
        for (int i = 0; i < 100; i++)
        {
            var result = _identityKeys.ToProtoState();
            if (result.IsOk)
            {
                // Dispose to simulate realistic usage
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