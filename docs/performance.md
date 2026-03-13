# Performance Benchmarks

This document describes the expected performance characteristics of env-check
and provides guidance on optimizing performance in various scenarios.

## Overview

env-check is designed for fast, deterministic execution in CI/CD environments.
The tool prioritizes:

1. **Fast startup**: Minimal initialization time
2. **Efficient parsing**: Zero-copy parsing where possible
3. **Parallel probing**: Concurrent tool version checks
4. **Deterministic output**: Stable execution time for the same inputs

## Performance Targets

### Execution Time

| Scenario | Target | Typical |
|----------|--------|---------|
| Empty project (no sources) | < 50ms | ~10ms |
| Small project (1-3 sources, 2-5 tools) | < 500ms | ~100ms |
| Medium project (3-5 sources, 5-15 tools) | < 2s | ~500ms |
| Large project (5+ sources, 15+ tools) | < 5s | ~1-2s |

### Memory Usage

| Scenario | Target | Typical |
|----------|--------|---------|
| All scenarios | < 50MB | ~10-20MB |

### Binary Size

| Build Type | Size (approx) |
|------------|---------------|
| Release (default features) | ~5-8MB |
| Release (minimal features) | ~3-5MB |
| Release (all features) | ~8-12MB |

## Performance by Component

### Source Discovery

Source discovery scans the working directory for known source files.

| Operation | Time (typical) |
|-----------|----------------|
| Directory scan (small project) | < 5ms |
| Directory scan (medium project) | < 20ms |
| Directory scan (large monorepo) | < 100ms |

**Factors affecting performance:**
- Number of directories to scan
- Filesystem speed (SSD vs HDD)
- Operating system file I/O performance

### Parsing

Parsing is generally the fastest component. All parsers are designed for
zero-copy or minimal-allocation parsing.

| Parser | Time per file (typical) |
|--------|------------------------|
| `.tool-versions` | < 1ms |
| `.mise.toml` | < 2ms |
| `.node-version` / `.nvmrc` | < 0.5ms |
| `package.json` | < 2ms |
| `.python-version` | < 0.5ms |
| `pyproject.toml` | < 3ms |
| `go.mod` | < 2ms |
| `rust-toolchain.toml` | < 2ms |
| Hash manifests | < 5ms |

**Factors affecting performance:**
- File size (larger files take longer)
- Number of tools declared
- Complexity of version constraints

### Runtime Probing

Runtime probing is typically the slowest component because it involves
spawning external processes.

| Probe Type | Time per tool (typical) |
|------------|------------------------|
| Tool not found | < 10ms |
| Tool found, version check | 20-100ms |
| Tool found, hash check | 50-200ms |

**Factors affecting performance:**
- Number of tools to probe
- Tool startup time (Node.js is slower than Go)
- Whether tools are in disk cache
- PATH length and complexity

### Evaluation

Domain evaluation is very fast, typically completing in microseconds.

| Operation | Time (typical) |
|-----------|----------------|
| Version constraint matching | < 10µs |
| Full evaluation (10 tools) | < 1ms |

### Rendering

Output rendering is fast for typical finding counts.

| Finding Count | Time (typical) |
|---------------|----------------|
| 0-10 findings | < 5ms |
| 10-50 findings | < 20ms |
| 50-100 findings | < 50ms |
| 100+ findings | < 100ms |

## Benchmarking env-check

### Using the Built-in Timing

Run env-check with debug logging to see timing information:

```bash
env-check --debug
```

The debug output includes timing for each phase:
- Source discovery
- Parsing
- Probing
- Evaluation
- Rendering

### Manual Benchmarking

Use `time` to measure overall execution:

```bash
# Linux/macOS
time env-check

# Windows PowerShell
Measure-Command { env-check }

# Windows CMD
powershell -Command "Measure-Command { env-check }"
```

### Hyperfine for Accurate Benchmarks

For more accurate benchmarking, use [hyperfine](https://github.com/sharkdp/hyperfine):

```bash
hyperfine --warmup 3 'env-check'
```

## Performance Optimization

### General Tips

1. **Use source filtering**: If you only need to check specific sources,
   use the `--sources` flag to skip others:

   ```bash
   env-check --sources tool-versions,node-version
   ```

2. **Reduce PATH complexity**: A shorter PATH with fewer directories
   speeds up tool lookups.

3. **Use SSD storage**: Faster disk I/O improves all file operations.

4. **Pin tool versions**: Using exact versions instead of ranges can
   slightly speed up evaluation.

### CI/CD Optimization

1. **Cache tool installations**: Use tool caching in CI to ensure tools
   are in the disk cache.

2. **Run in parallel with other jobs**: env-check is fast enough to run
   concurrently with linting, testing, etc.

3. **Use appropriate profile**: The `oss` profile is fastest for open-source
   projects where missing tools are acceptable.

4. **Skip unnecessary checks**: Use `--sources` to only check relevant
   source files for your project.

### Configuration Optimization

1. **Disable unused parsers**: In `env-check.toml`, disable parsers you
   don't need:

   ```toml
   [parsers]
   go = false
   python = false
   ```

2. **Limit hash verification**: Hash verification is expensive. Only enable
   it when security is critical.

## Performance Troubleshooting

### Slow Execution

If env-check is running slowly:

1. **Check debug output**: Run with `--debug` to identify which phase is slow.

2. **Count your tools**: More tools mean more probe commands.

3. **Check tool startup time**: Some tools (like Node.js) have slower startup.

4. **Check filesystem**: Network filesystems or slow disks impact performance.

5. **Check PATH**: Very long PATH environment variables slow down tool lookups.

### High Memory Usage

If env-check is using more memory than expected:

1. **Check file sizes**: Very large source files increase memory usage.

2. **Check finding count**: Thousands of findings require more memory.

3. **Report a bug**: Memory usage should be bounded; high usage may indicate
   a bug.

## Performance Regressions

We monitor performance to prevent regressions:

- Benchmarks run in CI for significant changes
- Performance tests compare against baseline measurements
- Significant regressions (>20% slowdown) require investigation

### Running Performance Tests

```bash
# Run criterion benchmarks
cargo bench

# Run with specific benchmark
cargo bench --bench parsing
```

## Performance by Platform

Performance varies by platform due to differences in process spawning and
filesystem performance:

| Platform | Relative Performance |
|----------|---------------------|
| Linux (x86_64) | Baseline (fastest) |
| macOS (x86_64) | ~10-20% slower |
| macOS (ARM64) | ~5-15% slower |
| Windows (x86_64) | ~20-40% slower |

**Windows-specific notes:**
- Process spawning is slower on Windows
- `where` command is slower than Unix `which`
- Consider using WSL for best performance

## Scaling Characteristics

### Source Files

Performance scales linearly with the number of source files:

- 1 source file: baseline
- 5 source files: ~3x baseline
- 10 source files: ~5x baseline

### Tools

Performance scales linearly with the number of unique tools:

- 1 tool: baseline
- 10 tools: ~8x baseline
- 50 tools: ~35x baseline

### Project Size

Performance scales sub-linearly with project directory size due to efficient
directory traversal:

- Small project (< 100 files): baseline
- Medium project (100-1000 files): ~1.2x baseline
- Large project (1000+ files): ~1.5x baseline

## Future Performance Improvements

Planned performance improvements:

1. **Parallel probing**: Spawn probe commands concurrently (planned)
2. **Caching**: Cache probe results between runs (planned)
3. **Incremental mode**: Only re-check changed sources (planned)
4. **Native Windows support**: Improve Windows-specific performance (ongoing)

---

For troubleshooting performance issues, see [troubleshooting.md](troubleshooting.md).
