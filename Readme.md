# perftrace

This is a tiny Python library which compiles a C helper that lets it use the `perf_event_open` syscall to use hardware breakpoints to trace a small set of addresses in any program and capture their registers when the breakpoints are hit.

```python
child = StoppedChild(lambda: os.execv("./cache", ["./cache"]))
bp = Breakpoint(child.pid, 0x402720, ["SI", "DI"], one_time=False)
bp2 = Breakpoint(child.pid, 0x402ff0, ["SI", "DI"], one_time=True)
child.resume()
# Process is running at this time...
child.wait()
events = sorted(itertools.chain(bp.results(), bp2.results()), key=lambda x: x.time)
for sample in events:
    print(sample)
```
