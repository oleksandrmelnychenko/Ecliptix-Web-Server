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
    private ShieldPro _aliceShieldPro;
    private ShieldPro _bobShieldPro;
    private uint _aliceSessionId;
    private uint _bobSessionId;
    private readonly PubKeyExchangeType _exchangeType = PubKeyExchangeType.AppDeviceEphemeralConnect;
    private byte[] _sampleMessage;
    private const int MessageSize = 64;
    private const int MessageCount = 1000;
    private const int ParallelSessionCount = 10;
    private const int MessagesPerSession = 100;

    [GlobalSetup]
    public async Task GlobalSetup()
    {
        var aliceMaterialResult = EcliptixSystemIdentityKeys.Create(1);
        var bobMaterialResult = EcliptixSystemIdentityKeys.Create(2);
        if (aliceMaterialResult.IsErr || bobMaterialResult.IsErr)
            throw new InvalidOperationException("Failed to create key materials.");

        var aliceMaterial = aliceMaterialResult.Unwrap();
        var bobMaterial = bobMaterialResult.Unwrap();

        _aliceShieldPro = new ShieldPro(aliceMaterial);
        _bobShieldPro = new ShieldPro(bobMaterial);

        (uint SessionId, PubKeyExchange InitialMessage) aliceResult = await _aliceShieldPro.BeginDataCenterPubKeyExchangeAsync(_exchangeType);
        _aliceSessionId = aliceResult.SessionId;

        (uint SessionId, PubKeyExchange ResponseMessage) bobResult = await _bobShieldPro.ProcessAndRespondToPubKeyExchangeAsync(aliceResult.InitialMessage);
        _bobSessionId = bobResult.SessionId;

        await _aliceShieldPro.CompleteDataCenterPubKeyExchangeAsync(_aliceSessionId, _exchangeType,
            bobResult.ResponseMessage);

        _sampleMessage = Encoding.UTF8.GetBytes(new string('A', MessageSize));
    }

    [Benchmark(Description = "X3DH Handshake")]
    public async Task X3DH_Handshake()
    {
        var aliceMaterial = EcliptixSystemIdentityKeys.Create(3).Unwrap();
        var bobMaterial = EcliptixSystemIdentityKeys.Create(4).Unwrap();
        var alice = new ShieldPro(aliceMaterial);
        var bob = new ShieldPro(bobMaterial);

        try
        {
            var (aliceId, aliceMsg) = await alice.BeginDataCenterPubKeyExchangeAsync(_exchangeType);
            var (bobId, bobMsg) = await bob.ProcessAndRespondToPubKeyExchangeAsync(aliceMsg);
            await alice.CompleteDataCenterPubKeyExchangeAsync(aliceId, _exchangeType, bobMsg);
        }
        finally
        {
            await alice.DisposeAsync();
            await bob.DisposeAsync();
        }
    }

    [Benchmark(Description = "Symmetric Ratchet")]
    public async Task Symmetric_Ratchet()
    {
        var aliceMaterial = EcliptixSystemIdentityKeys.Create(5).Unwrap();
        var bobMaterial = EcliptixSystemIdentityKeys.Create(6).Unwrap();
        var alice = new ShieldPro(aliceMaterial);
        var bob = new ShieldPro(bobMaterial);

        try
        {
            var (aliceId, aliceMsg) = await alice.BeginDataCenterPubKeyExchangeAsync(_exchangeType);
            var (bobId, bobMsg) = await bob.ProcessAndRespondToPubKeyExchangeAsync(aliceMsg);
            await alice.CompleteDataCenterPubKeyExchangeAsync(aliceId, _exchangeType, bobMsg);

            for (int i = 0; i < 100; i++)
            {
                await alice.ProduceOutboundMessageAsync(aliceId, _exchangeType, _sampleMessage);
            }
        }
        finally
        {
            await alice.DisposeAsync();
            await bob.DisposeAsync();
        }
    }

    [Benchmark(Description = "DH Ratchet")]
    public async Task DH_Ratchet()
    {
        for (int i = 0; i < 10; i++)
        {
            var cipher =
                await _aliceShieldPro.ProduceOutboundMessageAsync(_aliceSessionId, _exchangeType, _sampleMessage);
            await _bobShieldPro.ProcessInboundMessageAsync(_bobSessionId, _exchangeType, cipher);
        }
    }

    [Benchmark(Description = "Message Encryption")]
    public async Task Message_Encryption()
    {
        await _aliceShieldPro.ProduceOutboundMessageAsync(_aliceSessionId, _exchangeType, _sampleMessage);
    }

    [Benchmark(Description = "Message Decryption")]
    public async Task Message_Decryption()
    {
        var cipher = await _aliceShieldPro.ProduceOutboundMessageAsync(_aliceSessionId, _exchangeType, _sampleMessage);
        await _bobShieldPro.ProcessInboundMessageAsync(_bobSessionId, _exchangeType, cipher);
    }

    [Benchmark(Description = "Single Session Throughput")]
    public async Task Single_Session_Throughput()
    {
        for (int i = 0; i < MessageCount; i++)
        {
            var cipher =
                await _aliceShieldPro.ProduceOutboundMessageAsync(_aliceSessionId, _exchangeType, _sampleMessage);
            await _bobShieldPro.ProcessInboundMessageAsync(_bobSessionId, _exchangeType, cipher);
            var reply = await _bobShieldPro.ProduceOutboundMessageAsync(_bobSessionId, _exchangeType, _sampleMessage);
            await _aliceShieldPro.ProcessInboundMessageAsync(_aliceSessionId, _exchangeType, reply);
        }
    }

    [Benchmark(Description = "Multiple Sessions Throughput")]
    public async Task Multiple_Sessions_Throughput()
    {
        var tasks = new Task[ParallelSessionCount];
        for (int s = 0; s < ParallelSessionCount; s++)
        {
            var sessionId = s;
            tasks[s] = Task.Run(async () =>
            {
                var aliceMaterial = EcliptixSystemIdentityKeys.Create((uint)(sessionId * 2 + 7)).Unwrap();
                var bobMaterial = EcliptixSystemIdentityKeys.Create((uint)(sessionId * 2 + 8)).Unwrap();
                var alice = new ShieldPro(aliceMaterial);
                var bob = new ShieldPro(bobMaterial);

                try
                {
                    var (aliceId, aliceMsg) = await alice.BeginDataCenterPubKeyExchangeAsync(_exchangeType);
                    var (bobId, bobMsg) = await bob.ProcessAndRespondToPubKeyExchangeAsync(aliceMsg);
                    await alice.CompleteDataCenterPubKeyExchangeAsync(aliceId, _exchangeType, bobMsg);

                    for (int i = 0; i < MessagesPerSession; i++)
                    {
                        var cipher = await alice.ProduceOutboundMessageAsync(aliceId, _exchangeType, _sampleMessage);
                        await bob.ProcessInboundMessageAsync(bobId, _exchangeType, cipher);
                    }
                }
                finally
                {
                    await alice.DisposeAsync();
                    await bob.DisposeAsync();
                }
            });
        }

        await Task.WhenAll(tasks);
    }

    [GlobalCleanup]
    public async Task GlobalCleanup()
    {
        if (_aliceShieldPro != null)
            await _aliceShieldPro.DisposeAsync();
        if (_bobShieldPro != null)
            await _bobShieldPro.DisposeAsync();
    }
}