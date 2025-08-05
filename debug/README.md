# Debug (tvault-core)

## Description

The `debug` package provides comprehensive profiling and debugging capabilities for Go applications. 
It allows developers to collect detailed performance metrics and trace information at runtime, which can be invaluable for troubleshooting performance issues and understanding application behavior.

## Profile Types

The package supports the following profile types:

- `ProfileCPU`: CPU usage profile
- `ProfileMemory`: Heap memory allocation profile
- `ProfileTrace`: Execution trace output
- `ProfileBlock`: Goroutine blocking profile
- `ProfileMutex`: Mutex contention profile
- `ProfileGoroutine`: Goroutine state snapshot

## Output Files

All profile data is saved to files in the configured profile directory (default: `./debug/profiles`). 
Files are named using the pattern `<profile_type>_<timestamp>.<extension>`, where:

- `<profile_type>` is one of: cpu, mem, trace, block, mutex, goroutine
- `<timestamp>` is formatted as "YYYYMMDD_HHMMSS"
- `<extension>` is either `.prof` or `.out` (for trace files)

## CPU profile analysis

```go tool pprof -http=:8080 ./debug/profiles/cpu_20240125_120000.prof```

## Memory profile analysis

```go tool pprof -http=:8080 ./debug/profiles/mem_20240125_120000.prof```

## Trace analysis

```go tool trace ./debug/profiles/trace_20240125_120000.out```

