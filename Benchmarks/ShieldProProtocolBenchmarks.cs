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
    private readonly PubKeyExchangeType _exchangeType = PubKeyExchangeType.DataCenterEphemeralConnect;
    private byte[] _sampleMessage;
    private const int MessageSize = 64;
    private const int MessageCount = 10;
    private const int ParallelSessionCount = 10;
    private const int MessagesPerSession = 10;

    [GlobalSetup]
    public void GlobalSetup()
    {
        Result<EcliptixSystemIdentityKeys, EcliptixProtocolFailure> aliceMaterialResult = EcliptixSystemIdentityKeys.Create(1);
        Result<EcliptixSystemIdentityKeys, EcliptixProtocolFailure> bobMaterialResult = EcliptixSystemIdentityKeys.Create(2);
        if (aliceMaterialResult.IsErr || bobMaterialResult.IsErr)
            throw new InvalidOperationException("Failed to create key materials.");

        EcliptixSystemIdentityKeys aliceMaterial = aliceMaterialResult.Unwrap();
        EcliptixSystemIdentityKeys bobMaterial = bobMaterialResult.Unwrap();

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
        EcliptixSystemIdentityKeys aliceMaterial = EcliptixSystemIdentityKeys.Create(3).Unwrap();
        EcliptixSystemIdentityKeys bobMaterial = EcliptixSystemIdentityKeys.Create(4).Unwrap();
        EcliptixProtocolSystem alice = new EcliptixProtocolSystem(aliceMaterial);
        EcliptixProtocolSystem bob = new EcliptixProtocolSystem(bobMaterial);
        uint sessionId = 2;
        PubKeyExchange aliceMsg = alice.BeginDataCenterPubKeyExchange(sessionId, _exchangeType).Unwrap();
        PubKeyExchange bobMsg = bob.ProcessAndRespondToPubKeyExchange(sessionId, aliceMsg).Unwrap();
        alice.CompleteDataCenterPubKeyExchange(sessionId, _exchangeType, bobMsg);
    }

    [Benchmark(Description = "Symmetric Ratchet")]
    public void Symmetric_Ratchet()
    {
        EcliptixSystemIdentityKeys aliceMaterial = EcliptixSystemIdentityKeys.Create(5).Unwrap();
        EcliptixSystemIdentityKeys bobMaterial = EcliptixSystemIdentityKeys.Create(6).Unwrap();
        EcliptixProtocolSystem alice = new EcliptixProtocolSystem(aliceMaterial);
        EcliptixProtocolSystem bob = new EcliptixProtocolSystem(bobMaterial);
        uint sessionId = 2;
        PubKeyExchange aliceMsg = alice.BeginDataCenterPubKeyExchange(sessionId, _exchangeType).Unwrap();
        PubKeyExchange bobMsg = bob.ProcessAndRespondToPubKeyExchange(sessionId, aliceMsg).Unwrap();
        alice.CompleteDataCenterPubKeyExchange(sessionId, _exchangeType, bobMsg);

        for (int i = 0; i < 10; i++)
        {
            alice.ProduceOutboundMessage(_exchangeType, _sampleMessage);
        }
    }

    [Benchmark(Description = "DH Ratchet")]
    public void DH_Ratchet()
    {
        int sessionId = 2;
        for (int i = 0; i < 10; i++)
        {
            CipherPayload cipher =
                _aliceEcliptixProtocolSystem.ProduceOutboundMessage(_exchangeType,
                    _sampleMessage).Unwrap();
            _bobEcliptixProtocolSystem.ProcessInboundMessage(_exchangeType, cipher);
        }
    }

    [Benchmark(Description = "Message Encryption")]
    public void Message_Encryption()
    {
        _aliceEcliptixProtocolSystem.ProduceOutboundMessage(_exchangeType, _sampleMessage);
    }

    [Benchmark(Description = "Message Decryption")]
    public void Message_Decryption()
    {
        CipherPayload cipher =
            _aliceEcliptixProtocolSystem.ProduceOutboundMessage(_exchangeType,
                _sampleMessage).Unwrap();
        _bobEcliptixProtocolSystem.ProcessInboundMessage(_exchangeType, cipher);
    }

    [Benchmark(Description = "Single Session Throughput")]
    public void Single_Session_Throughput()
    {
        for (int i = 0; i < MessageCount; i++)
        {
            CipherPayload cipher =
                _aliceEcliptixProtocolSystem.ProduceOutboundMessage(_exchangeType,
                    _sampleMessage).Unwrap();
            _bobEcliptixProtocolSystem.ProcessInboundMessage(_exchangeType, cipher);
            CipherPayload reply = _bobEcliptixProtocolSystem.ProduceOutboundMessage(_exchangeType,
                _sampleMessage).Unwrap();
            _aliceEcliptixProtocolSystem.ProcessInboundMessage(_exchangeType, reply);
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
                        alice.ProduceOutboundMessage(_exchangeType, _sampleMessage);
                    bob.ProcessInboundMessage(_exchangeType, cipher);
                }
            });
        }

        await Task.WhenAll(tasks);
    }
}