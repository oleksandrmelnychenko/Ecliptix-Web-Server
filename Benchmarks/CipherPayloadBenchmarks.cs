using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Engines;
using Ecliptix.Core.Protocol;
using Ecliptix.Protobuf.CipherPayload;
using Ecliptix.Protobuf.PubKeyExchange;
using Microsoft.Extensions.Logging;
using Moq;
using System.Text;

namespace Benchmarks;

[MemoryDiagnoser]
[RPlotExporter]
[MinColumn, MaxColumn, MeanColumn, MedianColumn]
[SimpleJob(RunStrategy.Throughput, launchCount: 1, warmupCount: 3, iterationCount: 20)]
public class CipherPayloadBenchmarks
{
    private EcliptixProtocolSystem _aliceSystem = null!;
    private EcliptixProtocolSystem _bobSystem = null!;
    private uint _sessionId;
    private byte[] _sampleMessage = null!;
    private CipherPayload _sampleCipherPayload = null!;
    private ILogger<EcliptixProtocolSystem> _logger = null!;
    private const PubKeyExchangeType ExchangeType = PubKeyExchangeType.DataCenterEphemeralConnect;

    [Params(64, 512, 2048)] // Test different message sizes to measure scaling
    public int MessageSize { get; set; }

    [GlobalSetup]
    public void GlobalSetup()
    {
        // Mock logger
        var loggerMock = new Mock<ILogger<EcliptixProtocolSystem>>();
        _logger = loggerMock.Object;

        // Setup Alice and Bob systems
        var aliceMaterial = EcliptixSystemIdentityKeys.Create(1).Unwrap();
        var bobMaterial = EcliptixSystemIdentityKeys.Create(2).Unwrap();
        
        _aliceSystem = new EcliptixProtocolSystem(aliceMaterial, null, _logger);
        _bobSystem = new EcliptixProtocolSystem(bobMaterial, null, _logger);

        _sessionId = 1;

        // Perform handshake
        var aliceHandshake = _aliceSystem.BeginDataCenterPubKeyExchange(_sessionId, ExchangeType);
        var (_, updatedAlice, aliceMsg) = aliceHandshake.Unwrap();
        _aliceSystem = updatedAlice;

        var bobHandshake = _bobSystem.ProcessAndRespondToPubKeyExchange(_sessionId, aliceMsg);
        var (_, updatedBob, bobMsg) = bobHandshake.Unwrap();
        _bobSystem = updatedBob;

        var aliceComplete = _aliceSystem.CompleteDataCenterPubKeyExchange(_sessionId, ExchangeType, bobMsg);
        _aliceSystem = aliceComplete.Unwrap().Item1;

        // Prepare test message
        _sampleMessage = Encoding.UTF8.GetBytes(new string('A', MessageSize));
        
        // Create a sample cipher payload for decryption benchmarks
        var encryptResult = _aliceSystem.ProduceOutboundMessage(_sessionId, ExchangeType, _sampleMessage);
        var (cipherPayload, updatedSystem, _) = encryptResult.Unwrap();
        _aliceSystem = updatedSystem;
        _sampleCipherPayload = cipherPayload;
    }

    [Benchmark(Description = "CipherPayload Creation (Optimized)")]
    public CipherPayload CipherPayloadCreation()
    {
        var result = _aliceSystem.ProduceOutboundMessage(_sessionId, ExchangeType, _sampleMessage);
        if (result.IsErr)
            throw new InvalidOperationException($"Message encryption failed: {result.UnwrapErr().Message}");
        
        var (cipherPayload, updatedSystem, _) = result.Unwrap();
        _aliceSystem = updatedSystem;
        return cipherPayload;
    }

    [Benchmark(Description = "CipherPayload Processing (Zero-Copy Optimized)")]
    public byte[] CipherPayloadProcessing()
    {
        var result = _bobSystem.ProcessInboundMessage(_sessionId, ExchangeType, _sampleCipherPayload);
        if (result.IsErr)
            throw new InvalidOperationException($"Message decryption failed: {result.UnwrapErr().Message}");
        
        var (plaintext, updatedSystem, _) = result.Unwrap();
        _bobSystem = updatedSystem;
        return plaintext;
    }

    [Benchmark(Description = "Full Message Round-Trip")]
    public byte[] FullMessageRoundTrip()
    {
        // Encrypt
        var encryptResult = _aliceSystem.ProduceOutboundMessage(_sessionId, ExchangeType, _sampleMessage);
        var (cipherPayload, updatedAlice, _) = encryptResult.Unwrap();
        _aliceSystem = updatedAlice;

        // Decrypt
        var decryptResult = _bobSystem.ProcessInboundMessage(_sessionId, ExchangeType, cipherPayload);
        var (plaintext, updatedBob, _) = decryptResult.Unwrap();
        _bobSystem = updatedBob;
        
        return plaintext;
    }

    [Benchmark(Description = "High Throughput Simulation")]
    public void HighThroughputSimulation()
    {
        // Simulate processing many messages to test GC pressure
        for (int i = 0; i < 50; i++)
        {
            var encryptResult = _aliceSystem.ProduceOutboundMessage(_sessionId, ExchangeType, _sampleMessage);
            if (encryptResult.IsOk)
            {
                var (cipherPayload, updatedAlice, _) = encryptResult.Unwrap();
                _aliceSystem = updatedAlice;
                
                var decryptResult = _bobSystem.ProcessInboundMessage(_sessionId, ExchangeType, cipherPayload);
                if (decryptResult.IsOk)
                {
                    var (_, updatedBob, _) = decryptResult.Unwrap();
                    _bobSystem = updatedBob;
                }
            }
        }
    }

    [GlobalCleanup]
    public void GlobalCleanup()
    {
        _aliceSystem?.Dispose();
        _bobSystem?.Dispose();
    }
}