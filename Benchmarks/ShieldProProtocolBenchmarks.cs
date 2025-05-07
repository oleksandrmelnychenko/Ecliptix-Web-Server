using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Engines;
using Ecliptix.Core.Protocol;
using Ecliptix.Protobuf.CipherPayload;
using Ecliptix.Protobuf.PubKeyExchange;
using System;
using System.Text;
using System.Threading.Tasks;

namespace Benchmarks;

[MemoryDiagnoser]
[RPlotExporter]
[MinColumn, MaxColumn, MeanColumn, MedianColumn]
[SimpleJob(RunStrategy.Throughput, launchCount: 1, warmupCount: 5, iterationCount: 20)]
public class ShieldProProtocolBenchmarks
{
    private EcliptixProtocolSystem _aliceEcliptixProtocolSystem;
    private EcliptixProtocolSystem _bobEcliptixProtocolSystem;
    private uint _aliceSessionId;
    private uint _bobSessionId;
    private readonly PubKeyExchangeType _exchangeType = PubKeyExchangeType.AppDeviceEphemeralConnect;
    private byte[] _sampleMessage;
    private const int MessageSize = 64;
    private const int MessageCount = 10;
    private const int ParallelSessionCount = 10;
    private const int MessagesPerSession = 10;

    [GlobalSetup]
    public void GlobalSetup()
    {
        var aliceMaterialResult = EcliptixSystemIdentityKeys.Create(1);
        var bobMaterialResult = EcliptixSystemIdentityKeys.Create(2);
        if (aliceMaterialResult.IsErr || bobMaterialResult.IsErr)
            throw new InvalidOperationException("Failed to create key materials.");

        var aliceMaterial = aliceMaterialResult.Unwrap();
        var bobMaterial = bobMaterialResult.Unwrap();

        uint sessionId = 2;

        _aliceEcliptixProtocolSystem = new EcliptixProtocolSystem(aliceMaterial);
        _bobEcliptixProtocolSystem = new EcliptixProtocolSystem(bobMaterial);

        PubKeyExchange aliceResult =
            _aliceEcliptixProtocolSystem.BeginDataCenterPubKeyExchange(sessionId, _exchangeType);

        PubKeyExchange bobResult =
            _bobEcliptixProtocolSystem.ProcessAndRespondToPubKeyExchange(sessionId, aliceResult);

        _aliceEcliptixProtocolSystem.CompleteDataCenterPubKeyExchange(_aliceSessionId, _exchangeType,
            bobResult);

        _sampleMessage = Encoding.UTF8.GetBytes(new string('A', MessageSize));
    }

    [Benchmark(Description = "X3DH Handshake")]
    public void X3DH_Handshake()
    {
        var aliceMaterial = EcliptixSystemIdentityKeys.Create(3).Unwrap();
        var bobMaterial = EcliptixSystemIdentityKeys.Create(4).Unwrap();
        var alice = new EcliptixProtocolSystem(aliceMaterial);
        var bob = new EcliptixProtocolSystem(bobMaterial);
        uint sessionId = 2;
        var aliceMsg = alice.BeginDataCenterPubKeyExchange(sessionId, _exchangeType);
        var bobMsg = bob.ProcessAndRespondToPubKeyExchange(sessionId, aliceMsg);
        alice.CompleteDataCenterPubKeyExchange(sessionId, _exchangeType, bobMsg);
    }

    [Benchmark(Description = "Symmetric Ratchet")]
    public void Symmetric_Ratchet()
    {
        var aliceMaterial = EcliptixSystemIdentityKeys.Create(5).Unwrap();
        var bobMaterial = EcliptixSystemIdentityKeys.Create(6).Unwrap();
        var alice = new EcliptixProtocolSystem(aliceMaterial);
        var bob = new EcliptixProtocolSystem(bobMaterial);
        uint sessionId = 2;
        var aliceMsg = alice.BeginDataCenterPubKeyExchange(sessionId, _exchangeType);
        var bobMsg = bob.ProcessAndRespondToPubKeyExchange(sessionId, aliceMsg);
        alice.CompleteDataCenterPubKeyExchange(sessionId, _exchangeType, bobMsg);

        for (int i = 0; i < 10; i++)
        {
            alice.ProduceOutboundMessage(sessionId, _exchangeType, _sampleMessage);
        }
    }

    [Benchmark(Description = "DH Ratchet")]
    public void DH_Ratchet()
    {
        int sessionId = 2;
        for (int i = 0; i < 10; i++)
        {
            var cipher =
                _aliceEcliptixProtocolSystem.ProduceOutboundMessage(_aliceSessionId, _exchangeType,
                    _sampleMessage);
            _bobEcliptixProtocolSystem.ProcessInboundMessage(_bobSessionId, _exchangeType, cipher);
        }
    }

    [Benchmark(Description = "Message Encryption")]
    public void Message_Encryption()
    {
        _aliceEcliptixProtocolSystem.ProduceOutboundMessage(_aliceSessionId, _exchangeType, _sampleMessage);
    }

    [Benchmark(Description = "Message Decryption")]
    public void Message_Decryption()
    {
        var cipher =
            _aliceEcliptixProtocolSystem.ProduceOutboundMessage(_aliceSessionId, _exchangeType,
                _sampleMessage);
        _bobEcliptixProtocolSystem.ProcessInboundMessage(_bobSessionId, _exchangeType, cipher);
    }

    [Benchmark(Description = "Single Session Throughput")]
    public void Single_Session_Throughput()
    {
        for (int i = 0; i < MessageCount; i++)
        {
            var cipher =
                _aliceEcliptixProtocolSystem.ProduceOutboundMessage(_aliceSessionId, _exchangeType,
                    _sampleMessage);
            _bobEcliptixProtocolSystem.ProcessInboundMessage(_bobSessionId, _exchangeType, cipher);
            var reply = _bobEcliptixProtocolSystem.ProduceOutboundMessage(_bobSessionId, _exchangeType,
                _sampleMessage);
            _aliceEcliptixProtocolSystem.ProcessInboundMessage(_aliceSessionId, _exchangeType, reply);
        }
    }

    [Benchmark(Description = "Multiple Sessions Throughput")]
    public async Task Multiple_Sessions_Throughput()
    {
        Task[] tasks = new Task[ParallelSessionCount];
        for (int s = 0; s < ParallelSessionCount; s++)
        {
            int sessionId = s;
            tasks[s] = Task.Run(() =>
            {
                EcliptixSystemIdentityKeys aliceMaterial =
                    EcliptixSystemIdentityKeys.Create((uint)(sessionId * 2 + 7)).Unwrap();
                EcliptixSystemIdentityKeys bobMaterial =
                    EcliptixSystemIdentityKeys.Create((uint)(sessionId * 2 + 8)).Unwrap();
                EcliptixProtocolSystem alice = new EcliptixProtocolSystem(aliceMaterial);
                EcliptixProtocolSystem bob = new EcliptixProtocolSystem(bobMaterial);

                uint connectId = 2;
                PubKeyExchange aliceMsg = alice.BeginDataCenterPubKeyExchange(connectId, _exchangeType);
                PubKeyExchange bobMsg = bob.ProcessAndRespondToPubKeyExchange(connectId, aliceMsg);
                alice.CompleteDataCenterPubKeyExchange(connectId, _exchangeType, bobMsg);

                for (int i = 0; i < MessagesPerSession; i++)
                {
                    CipherPayload cipher =
                        alice.ProduceOutboundMessage(connectId, _exchangeType, _sampleMessage);
                    bob.ProcessInboundMessage(connectId, _exchangeType, cipher);
                }
            });
        }

        await Task.WhenAll(tasks);
    }
}