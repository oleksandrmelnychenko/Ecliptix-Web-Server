```

BenchmarkDotNet v0.14.0, macOS Sequoia 15.3.2 (24D81) [Darwin 24.3.0]
Apple M1 Pro, 1 CPU, 10 logical and 10 physical cores
.NET SDK 9.0.101
  [Host]     : .NET 9.0.0 (9.0.24.52809), Arm64 RyuJIT AdvSIMD
  Job-KRILQQ : .NET 9.0.0 (9.0.24.52809), Arm64 RyuJIT AdvSIMD

IterationCount=10  LaunchCount=3  RunStrategy=Throughput  
WarmupCount=5  

```
| Method                         | Mean          | Error        | StdDev       | Min           | Max           | Median        | Gen0       | Gen1     | Allocated   |
|------------------------------- |--------------:|-------------:|-------------:|--------------:|--------------:|--------------:|-----------:|---------:|------------:|
| &#39;X3DH Handshake&#39;               |   1,017.09 μs |    59.170 μs |    86.731 μs |     958.00 μs |   1,368.99 μs |     981.93 μs |    15.6250 |   3.9063 |    96.74 KB |
| &#39;Symmetric Ratchet&#39;            |   6,722.09 μs |   151.094 μs |   221.471 μs |   6,360.21 μs |   7,098.59 μs |   6,705.02 μs |   328.1250 |  31.2500 |  2085.75 KB |
| &#39;DH Ratchet&#39;                   |   1,042.31 μs |    37.281 μs |    54.646 μs |     974.41 μs |   1,142.88 μs |   1,021.82 μs |    62.5000 |   1.9531 |    385.4 KB |
| &#39;Message Encryption&#39;           |      65.88 μs |     2.391 μs |     3.352 μs |      62.25 μs |      76.51 μs |      65.11 μs |     3.1738 |   0.2441 |     19.9 KB |
| &#39;Message Decryption&#39;           |     111.39 μs |     1.579 μs |     2.214 μs |     107.68 μs |     116.09 μs |     111.01 μs |     6.1035 |   0.2441 |     38.7 KB |
| &#39;Single Session Throughput&#39;    | 170,750.47 μs | 4,888.872 μs | 7,011.474 μs | 158,035.50 μs | 184,128.06 μs | 170,640.62 μs | 10000.0000 | 500.0000 | 61065.13 KB |
| &#39;Multiple Sessions Throughput&#39; | 109,189.44 μs | 2,162.471 μs | 2,960.015 μs | 103,656.99 μs | 114,177.98 μs | 109,203.72 μs |  6600.0000 | 200.0000 | 40038.78 KB |
