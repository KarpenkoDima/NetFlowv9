# Graph Report - C:\Users\Dima\Desktop\NetFlowv9  (2026-06-09)

## Corpus Check
- cluster-only mode — file stats not available

## Summary
- 183 nodes · 259 edges · 17 communities (14 shown, 3 thin omitted)
- Extraction: 100% EXTRACTED · 0% INFERRED · 0% AMBIGUOUS · INFERRED: 1 edges (avg confidence: 0.9)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `05a48f3d`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- [[_COMMUNITY_Community 0|Community 0]]
- [[_COMMUNITY_Community 1|Community 1]]
- [[_COMMUNITY_Community 2|Community 2]]
- [[_COMMUNITY_Community 3|Community 3]]
- [[_COMMUNITY_Community 4|Community 4]]
- [[_COMMUNITY_Community 5|Community 5]]
- [[_COMMUNITY_Community 6|Community 6]]
- [[_COMMUNITY_Community 7|Community 7]]
- [[_COMMUNITY_Community 8|Community 8]]
- [[_COMMUNITY_Community 9|Community 9]]
- [[_COMMUNITY_Community 10|Community 10]]
- [[_COMMUNITY_Community 11|Community 11]]
- [[_COMMUNITY_Community 12|Community 12]]
- [[_COMMUNITY_Community 13|Community 13]]

## God Nodes (most connected - your core abstractions)
1. `NetFlowJsonExporter` - 14 edges
2. `NetFlowV9Parser` - 11 edges
3. `createCharts()` - 7 edges
4. `NetFlowPcapReader` - 7 edges
5. `NetFlowPcapReader` - 6 edges
6. `ByteUtils` - 6 edges
7. `processNetFlowData()` - 6 edges
8. `ReadOnlySpan` - 5 edges
9. `TemplateRecord` - 5 edges
10. `TemplateCache` - 5 edges

## Surprising Connections (you probably didn't know these)
- `NetFlow Dashboard` --references--> `NetFlowJsonExporter`  [INFERRED]
  NetFlowAnalizer/view/index.html → NetFlowAnalizer.Infrastructure/Export/NetFlowJsonExporter.cs
- `NetFlowPcapReader` --calls--> `PacketDotNet`  [EXTRACTED]
  NetFlowAnalizer.Infrastructure/Readers/NetFlowPcapReader.cs → README.md
- `NetFlowPcapReader` --calls--> `SharpPcap`  [EXTRACTED]
  NetFlowAnalizer.Infrastructure/Readers/NetFlowPcapReader.cs → README.md
- `CLI Application` --calls--> `NetFlowV9Parser`  [EXTRACTED]
  NetFlowAnalizer.Console/Program.cs → NetFlowAnalizer.Infrastructure/Parsers/NetFlowV9Parser.cs
- `NetFlowV9Parser` --references--> `Result<T>`  [EXTRACTED]
  NetFlowAnalizer.Infrastructure/Parsers/NetFlowV9Parser.cs → NetFlowAnalizer.Core/Common/Result.cs

## Import Cycles
- None detected.

## Communities (17 total, 3 thin omitted)

### Community 0 - "Community 0"
Cohesion: 0.11
Nodes (19): BinaryReader, INetFlowParser, CapturedPacket, CaptureSummary, Dictionary, List, Task, DataRecord (+11 more)

### Community 1 - "Community 1"
Cohesion: 0.13
Nodes (15): Result<T>, DataRecord, INetFlowRecord, NetFlowV9Parser, MethodImpl, INetFlowRecord, FromBytes(), ReadOnlySpan (+7 more)

### Community 2 - "Community 2"
Cohesion: 0.16
Nodes (16): allFlowRecords, charts, createCharts(), createIPChart(), createPortChart(), createProtocolChart(), createTimeChart(), displayTemplates() (+8 more)

### Community 3 - "Community 3"
Cohesion: 0.12
Nodes (15): net8.0, Microsoft.NET.Sdk, net8.0, Microsoft.NET.Sdk, net8.0, SharpPcap (6.3.1), Microsoft.NET.Sdk, net8.0 (+7 more)

### Community 4 - "Community 4"
Cohesion: 0.15
Nodes (10): bool, FileStream, IDisposable, NetFlowJsonExporter, ILogger, int, ITemplateCache, NetFlowPacket (+2 more)

### Community 5 - "Community 5"
Cohesion: 0.20
Nodes (6): ITemplateCache, Dictionary, TemplateRecord, Dictionary, TemplateRecord, object

### Community 6 - "Community 6"
Cohesion: 0.18
Nodes (10): Action, CLI Application, PacketDotNet, SharpPcap, NetFlowPcapReader, CancellationToken, ILogger, INetFlowParser (+2 more)

### Community 7 - "Community 7"
Cohesion: 0.24
Nodes (9): 256, 257, Fields, TemplateId, exportTime, packets, templates, 0 (+1 more)

### Community 8 - "Community 8"
Cohesion: 0.39
Nodes (6): INetFlowRepository, DateTime, IEnumerable, CancellationToken, INetFlowRecord, Task

### Community 10 - "Community 10"
Cohesion: 0.60
Nodes (4): Failure(), Success(), Result, T

### Community 12 - "Community 12"
Cohesion: 0.67
Nodes (3): NetFlow v9 Protocol, RFC 3954, NetFlow Analyzer v9

## Knowledge Gaps
- **52 isolated node(s):** `net8.0`, `Microsoft.Extensions.DependencyInjection (9.0.8)`, `Microsoft.Extensions.Hosting (9.0.8)`, `Microsoft.IdentityModel.Logging (8.14.0)`, `Microsoft.NET.Sdk` (+47 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **3 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `NetFlowV9Parser` connect `Community 1` to `Community 0`, `Community 6`?**
  _High betweenness centrality (0.191) - this node is a cross-community bridge._
- **Why does `CLI Application` connect `Community 6` to `Community 1`?**
  _High betweenness centrality (0.121) - this node is a cross-community bridge._
- **What connects `net8.0`, `Microsoft.Extensions.DependencyInjection (9.0.8)`, `Microsoft.Extensions.Hosting (9.0.8)` to the rest of the system?**
  _52 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `Community 0` be split into smaller, more focused modules?**
  _Cohesion score 0.10634920634920635 - nodes in this community are weakly interconnected._
- **Should `Community 1` be split into smaller, more focused modules?**
  _Cohesion score 0.12987012987012986 - nodes in this community are weakly interconnected._
- **Should `Community 3` be split into smaller, more focused modules?**
  _Cohesion score 0.12280701754385964 - nodes in this community are weakly interconnected._