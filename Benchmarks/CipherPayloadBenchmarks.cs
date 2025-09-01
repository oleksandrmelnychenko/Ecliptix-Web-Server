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

    [Params(64, 512, 2048)]
    public int MessageSize { get; set; }

    [GlobalSetup]
    public void GlobalSetup()
    {
        Mock<ILogger<EcliptixProtocolSystem>> loggerMock = new Mock<ILogger<EcliptixProtocolSystem>>();
        _logger = loggerMock.Object;

        EcliptixSystemIdentityKeys aliceMaterial = EcliptixSystemIdentityKeys.Create(1).Unwrap();
        EcliptixSystemIdentityKeys bobMaterial = EcliptixSystemIdentityKeys.Create(2).Unwrap();

        _aliceSystem = new EcliptixProtocolSystem(aliceMaterial, null, _logger);
        _bobSystem = new EcliptixProtocolSystem(bobMaterial, null, _logger);

        _sessionId = 1;

        Result<(uint, EcliptixProtocolSystem, PubKeyExchange), EcliptixProtocolFailure> aliceHandshake = _aliceSystem.BeginDataCenterPubKeyExchange(_sessionId, ExchangeType);
        (uint _, EcliptixProtocolSystem updatedAlice, PubKeyExchange aliceMsg) = aliceHandshake.Unwrap();
        _aliceSystem = updatedAlice;

        Result<(uint, EcliptixProtocolSystem, PubKeyExchange), EcliptixProtocolFailure> bobHandshake = _bobSystem.ProcessAndRespondToPubKeyExchange(_sessionId, aliceMsg);
        (uint _, EcliptixProtocolSystem updatedBob, PubKeyExchange bobMsg) = bobHandshake.Unwrap();
        _bobSystem = updatedBob;

        Result<(EcliptixProtocolSystem, Unit), EcliptixProtocolFailure> aliceComplete = _aliceSystem.CompleteDataCenterPubKeyExchange(_sessionId, ExchangeType, bobMsg);
        _aliceSystem = aliceComplete.Unwrap().Item1;

        _sampleMessage = Encoding.UTF8.GetBytes(new string('A', MessageSize));

        Result<(CipherPayload, EcliptixProtocolSystem, Unit), EcliptixProtocolFailure> encryptResult = _aliceSystem.ProduceOutboundMessage(_sessionId, ExchangeType, _sampleMessage);
        (CipherPayload cipherPayload, EcliptixProtocolSystem updatedSystem, Unit _) = encryptResult.Unwrap();
        _aliceSystem = updatedSystem;
        _sampleCipherPayload = cipherPayload;
    }

    [Benchmark(Description = "CipherPayload Creation (Optimized)")]
    public CipherPayload CipherPayloadCreation()
    {
        Result<(CipherPayload, EcliptixProtocolSystem, Unit), EcliptixProtocolFailure> result = _aliceSystem.ProduceOutboundMessage(_sessionId, ExchangeType, _sampleMessage);
        if (result.IsErr)
            throw new InvalidOperationException($"Message encryption failed: {result.UnwrapErr().Message}");

        (CipherPayload cipherPayload, EcliptixProtocolSystem updatedSystem, Unit _) = result.Unwrap();
        _aliceSystem = updatedSystem;
        return cipherPayload;
    }

    [Benchmark(Description = "CipherPayload Processing (Zero-Copy Optimized)")]
    public byte[] CipherPayloadProcessing()
    {
        Result<(byte[], EcliptixProtocolSystem, Unit), EcliptixProtocolFailure> result = _bobSystem.ProcessInboundMessage(_sessionId, ExchangeType, _sampleCipherPayload);
        if (result.IsErr)
            throw new InvalidOperationException($"Message decryption failed: {result.UnwrapErr().Message}");

        (byte[] plaintext, EcliptixProtocolSystem updatedSystem, Unit _) = result.Unwrap();
        _bobSystem = updatedSystem;
        return plaintext;
    }

    [Benchmark(Description = "Full Message Round-Trip")]
    public byte[] FullMessageRoundTrip()
    {
        Result<(CipherPayload, EcliptixProtocolSystem, Unit), EcliptixProtocolFailure> encryptResult = _aliceSystem.ProduceOutboundMessage(_sessionId, ExchangeType, _sampleMessage);
        (CipherPayload cipherPayload, EcliptixProtocolSystem updatedAlice, Unit _) = encryptResult.Unwrap();
        _aliceSystem = updatedAlice;

        Result<(byte[], EcliptixProtocolSystem, Unit), EcliptixProtocolFailure> decryptResult = _bobSystem.ProcessInboundMessage(_sessionId, ExchangeType, cipherPayload);
        (byte[] plaintext, EcliptixProtocolSystem updatedBob, Unit _) = decryptResult.Unwrap();
        _bobSystem = updatedBob;

        return plaintext;
    }

    [Benchmark(Description = "High Throughput Simulation")]
    public void HighThroughputSimulation()
    {
        for (int i = 0; i < 50; i++)
        {
            Result<(CipherPayload, EcliptixProtocolSystem, Unit), EcliptixProtocolFailure> encryptResult = _aliceSystem.ProduceOutboundMessage(_sessionId, ExchangeType, _sampleMessage);
            if (encryptResult.IsOk)
            {
                (CipherPayload cipherPayload, EcliptixProtocolSystem updatedAlice, Unit _) = encryptResult.Unwrap();
                _aliceSystem = updatedAlice;

                Result<(byte[], EcliptixProtocolSystem, Unit), EcliptixProtocolFailure> decryptResult = _bobSystem.ProcessInboundMessage(_sessionId, ExchangeType, cipherPayload);
                if (decryptResult.IsOk)
                {
                    (byte[] _, EcliptixProtocolSystem updatedBob, Unit _) = decryptResult.Unwrap();
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