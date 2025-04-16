using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Running;
using Ecliptix.Core.Protocol;

namespace Benchmarks;

[MemoryDiagnoser]
public class SodiumSecureMemoryHandleBenchmarks
{
    private SodiumSecureMemoryHandle _handle;
    private byte[] _sampleData;

    [GlobalSetup]
    public void Setup()
    {
        // Allocate a secure memory handle of 1024 bytes.
        var result = SodiumSecureMemoryHandle.Allocate(1024);
        if (result.IsErr)
            throw new Exception("Failed to allocate secure memory handle for benchmarks.");
        _handle = result.Unwrap();

        // Create sample data for writing.
        _sampleData = new byte[64];
        new Random().NextBytes(_sampleData);
    }

    [Benchmark]
    public void SingleThreadedWrite()
    {
        // Single-threaded write
        _handle.Write(_sampleData);
    }

    [Benchmark]
    public void ConcurrentWrite()
    {
        // Simulate concurrent writes using Parallel.For.
        Parallel.For(0, 1000, i =>
        {
            _handle.Write(_sampleData);
        });
    }

    [GlobalCleanup]
    public void Cleanup()
    {
        // Dispose the handle; the SafeHandle will automatically free the unmanaged resources.
        _handle.Dispose();
    }
}

public class Program
{
    public static void Main(string[] args)
    {
        var summary = BenchmarkRunner.Run<SodiumSecureMemoryHandleBenchmarks>();
    }
}