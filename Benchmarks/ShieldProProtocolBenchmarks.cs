using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Engines;
using Ecliptix.Core.Protocol;
using Ecliptix.Core.Protocol.Utilities;
using Ecliptix.Protobuf.CipherPayload;
using Ecliptix.Protobuf.PubKeyExchange;
using System;
using System.Text;
using System.Threading.Tasks;

namespace Benchmarks;

[MemoryDiagnoser]
[RPlotExporter]
[MinColumn, MaxColumn, MeanColumn, MedianColumn]
[SimpleJob(RunStrategy.Throughput, launchCount: 3, warmupCount: 5, iterationCount: 10)]
public class ShieldProProtocolBenchmarks
{
    private EcliptixProtocolSystem _aliceEcliptixProtocolSystem;
    private EcliptixProtocolSystem _bobEcliptixProtocolSystem;
    private uint _aliceSessionId;
    private uint _bobSessionId;
    private readonly PubKeyExchangeType _exchangeType = PubKeyExchangeType.AppDeviceEphemeralConnect;
    private byte[] _sampleMessage;
    private const int MessageSize = 64;
    private const int MessageCount = 1000;
    private const int ParallelSessionCount = 10;
    private const int MessagesPerSession = 100;

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
            _aliceEcliptixProtocolSystem.BeginDataCenterPubKeyExchangeAsync(sessionId, _exchangeType);

        PubKeyExchange bobResult =
            _bobEcliptixProtocolSystem.ProcessAndRespondToPubKeyExchangeAsync(sessionId, aliceResult);

        _aliceEcliptixProtocolSystem.CompleteDataCenterPubKeyExchangeAsync(_aliceSessionId, _exchangeType,
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
        var aliceMsg = alice.BeginDataCenterPubKeyExchangeAsync(sessionId, _exchangeType);
        var bobMsg = bob.ProcessAndRespondToPubKeyExchangeAsync(sessionId, aliceMsg);
        alice.CompleteDataCenterPubKeyExchangeAsync(sessionId, _exchangeType, bobMsg);
    }

    [Benchmark(Description = "Symmetric Ratchet")]
    public void Symmetric_Ratchet()
    {
        var aliceMaterial = EcliptixSystemIdentityKeys.Create(5).Unwrap();
        var bobMaterial = EcliptixSystemIdentityKeys.Create(6).Unwrap();
        var alice = new EcliptixProtocolSystem(aliceMaterial);
        var bob = new EcliptixProtocolSystem(bobMaterial);
        uint sessionId = 2;
        var aliceMsg = alice.BeginDataCenterPubKeyExchangeAsync(sessionId, _exchangeType);
        var bobMsg = bob.ProcessAndRespondToPubKeyExchangeAsync(sessionId, aliceMsg);
        alice.CompleteDataCenterPubKeyExchangeAsync(sessionId, _exchangeType, bobMsg);

        for (int i = 0; i < 100; i++)
        {
            alice.ProduceOutboundMessageAsync(sessionId, _exchangeType, _sampleMessage);
        }
    }

    [Benchmark(Description = "DH Ratchet")]
    public void DH_Ratchet()
    {
        int sessionId = 2;
        for (int i = 0; i < 10; i++)
        {
            var cipher =
                _aliceEcliptixProtocolSystem.ProduceOutboundMessageAsync(_aliceSessionId, _exchangeType,
                    _sampleMessage);
            _bobEcliptixProtocolSystem.ProcessInboundMessageAsync(_bobSessionId, _exchangeType, cipher);
        }
    }

    [Benchmark(Description = "Message Encryption")]
    public async Task Message_Encryption()
    {
        _aliceEcliptixProtocolSystem.ProduceOutboundMessageAsync(_aliceSessionId, _exchangeType, _sampleMessage);
    }

    [Benchmark(Description = "Message Decryption")]
    public async Task Message_Decryption()
    {
        var cipher =
            _aliceEcliptixProtocolSystem.ProduceOutboundMessageAsync(_aliceSessionId, _exchangeType,
                _sampleMessage);
        _bobEcliptixProtocolSystem.ProcessInboundMessageAsync(_bobSessionId, _exchangeType, cipher);
    }

    [Benchmark(Description = "Single Session Throughput")]
    public async Task Single_Session_Throughput()
    {
        for (int i = 0; i < MessageCount; i++)
        {
            var cipher =
                _aliceEcliptixProtocolSystem.ProduceOutboundMessageAsync(_aliceSessionId, _exchangeType,
                    _sampleMessage);
            _bobEcliptixProtocolSystem.ProcessInboundMessageAsync(_bobSessionId, _exchangeType, cipher);
            var reply = _bobEcliptixProtocolSystem.ProduceOutboundMessageAsync(_bobSessionId, _exchangeType,
                _sampleMessage);
            _aliceEcliptixProtocolSystem.ProcessInboundMessageAsync(_aliceSessionId, _exchangeType, reply);
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
                PubKeyExchange aliceMsg = alice.BeginDataCenterPubKeyExchangeAsync(connectId, _exchangeType);
                PubKeyExchange bobMsg = bob.ProcessAndRespondToPubKeyExchangeAsync(connectId, aliceMsg);
                alice.CompleteDataCenterPubKeyExchangeAsync(connectId, _exchangeType, bobMsg);

                for (int i = 0; i < MessagesPerSession; i++)
                {
                    CipherPayload cipher =
                        alice.ProduceOutboundMessageAsync(connectId, _exchangeType, _sampleMessage);
                    bob.ProcessInboundMessageAsync(connectId, _exchangeType, cipher);
                }
            });
        }

        await Task.WhenAll(tasks);
    }
}