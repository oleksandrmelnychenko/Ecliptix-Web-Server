/*using System.Text;
using Akka.Event;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Engines;
using Ecliptix.Core.Protocol;
using Ecliptix.Core.Protocol.Utilities;
using Ecliptix.Protobuf.CipherPayload;
using Ecliptix.Protobuf.PubKeyExchange;
using Microsoft.Extensions.Logging;
using LogLevel = Microsoft.Extensions.Logging.LogLevel;

namespace Benchmarks;

[MemoryDiagnoser]
[RPlotExporter]
[MinColumn, MaxColumn, MeanColumn, MedianColumn]
[SimpleJob(RunStrategy.Throughput, launchCount: 3, warmupCount: 5, iterationCount: 10)]
public class MinimalProtocolBenchmarks
{
    private EcliptixProtocolSystem _aliceProtocolSystem;
    private EcliptixProtocolSystemNonPooled _aliceProtocolSystemNonPooled;
    private uint _sessionId;
    private byte[] _sampleMessage;
    private ILogger<EcliptixProtocolSystem> _logger;
    private readonly PubKeyExchangeType _exchangeType = PubKeyExchangeType.AppDeviceEphemeralConnect;

    [Params(64, 1024)] // Test small and large messages
    public int MessageSize { get; set; }

    [Params(100, 1000)] // Test different message counts
    public int MessageCount { get; set; }

    [GlobalSetup]
    public void GlobalSetup()
    {
        // Mock logger
        var loggerMock = new Mock<ILogger<EcliptixProtocolSystem>>();
        _logger = loggerMock.Object;

        // Initialize key material
        var aliceMaterialResult = EcliptixSystemIdentityKeys.Create(1);
        if (aliceMaterialResult.IsErr)
            throw new InvalidOperationException(
                $"Failed to create key material: {aliceMaterialResult.UnwrapErr().Message}");

        var aliceMaterial = aliceMaterialResult.Unwrap();
        _aliceProtocolSystem = new EcliptixProtocolSystem(aliceMaterial, null, _logger);
        _aliceProtocolSystemNonPooled = new EcliptixProtocolSystemNonPooled(aliceMaterial);

        // Setup session
        _sessionId = 1;
        var result = _aliceProtocolSystem.BeginDataCenterPubKeyExchange(_sessionId, _exchangeType);
        if (result.IsErr)
            throw new InvalidOperationException($"Session setup failed: {result.UnwrapErr().Message}");

        var (_, updatedSystem, _) = result.Unwrap();
        _aliceProtocolSystem = updatedSystem;

        // Initialize sample message
        _sampleMessage = Encoding.UTF8.GetBytes(new string('A', MessageSize));
    }

    [Benchmark(Description = "X3DH Handshake")]
    public void X3DH_Handshake()
    {
        var material = EcliptixSystemIdentityKeys.Create(2).Unwrap();
        var system = new EcliptixProtocolSystem(material, null, _logger);
        var result = system.BeginDataCenterPubKeyExchange(2, _exchangeType);
        if (result.IsOk)
        {
            var (_, updatedSystem, _) = result.Unwrap();
            updatedSystem.RemoveSession(2); // Cleanup
        }
    }

    [Benchmark(Description = "Message Encryption with ArrayPool")]
    public void Message_Encryption_With_ArrayPool()
    {
        var result = _aliceProtocolSystem.ProduceOutboundMessage(_sessionId, _exchangeType, _sampleMessage);
        if (result.IsOk)
        {
            var (_, updatedSystem, _) = result.Unwrap();
            _aliceProtocolSystem = updatedSystem;
        }
    }

    [Benchmark(Description = "Message Encryption without ArrayPool")]
    public void Message_Encryption_Without_ArrayPool()
    {
        var result = _aliceProtocolSystemNonPooled.ProduceOutboundMessage(_sessionId, _exchangeType, _sampleMessage);
        if (result.IsOk)
        {
            var (_, updatedSystem, _) = result.Unwrap();
            _aliceProtocolSystemNonPooled = (EcliptixProtocolSystemNonPooled)updatedSystem;
        }
    }

    [Benchmark(Description = "Message Decryption")]
    public void Message_Decryption()
    {
        var cipherResult = _aliceProtocolSystem.ProduceOutboundMessage(_sessionId, _exchangeType, _sampleMessage);
        if (cipherResult.IsOk)
        {
            var (cipher, updatedSystem, _) = cipherResult.Unwrap();
            _aliceProtocolSystem = updatedSystem;
            var decryptResult = _aliceProtocolSystem.ProcessInboundMessage(_sessionId, _exchangeType, cipher);
            if (decryptResult.IsOk)
            {
                var (_, finalSystem, _) = decryptResult.Unwrap();
                _aliceProtocolSystem = finalSystem;
            }
        }
    }

    [Benchmark(Description = "Session Creation and Removal")]
    public void Session_Creation_And_Removal()
    {
        var result = _aliceProtocolSystem.BeginDataCenterPubKeyExchange(3, _exchangeType);
        if (result.IsOk)
        {
            var (_, updatedSystem, _) = result.Unwrap();
            var removeResult = updatedSystem.RemoveSession(3);
            if (removeResult.IsOk)
            {
                var (finalSystem, _) = removeResult.Unwrap();
                _aliceProtocolSystem = finalSystem;
            }
        }
    }

    [Benchmark(Description = "Single Session Throughput")]
    public void Single_Session_Throughput()
    {
        for (int i = 0; i < MessageCount; i++)
        {
            var cipherResult = _aliceProtocolSystem.ProduceOutboundMessage(_sessionId, _exchangeType, _sampleMessage);
            if (cipherResult.IsOk)
            {
                var (cipher, updatedSystem, _) = cipherResult.Unwrap();
                _aliceProtocolSystem = updatedSystem;
                var decryptResult = _aliceProtocolSystem.ProcessInboundMessage(_sessionId, _exchangeType, cipher);
                if (decryptResult.IsOk)
                {
                    var (_, finalSystem, _) = decryptResult.Unwrap();
                    _aliceProtocolSystem = finalSystem;
                }
            }
        }
    }
}*/