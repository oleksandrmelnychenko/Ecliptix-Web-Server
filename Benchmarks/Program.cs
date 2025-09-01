

using BenchmarkDotNet.Running;
using Benchmarks;

BenchmarkDotNet.Reports.Summary summary = BenchmarkRunner.Run<ShieldProProtocolBenchmarks>();
Console.WriteLine("Hello, World!");