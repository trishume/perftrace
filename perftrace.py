from ctypes import *
from dataclasses import dataclass
import itertools
import os

class _Breakpoint(Structure):
    _fields_ = [("fd", c_int),
                ("mmap_size", c_size_t),
                ("mmap_addr", c_void_p),]

class _Sample(Structure):
    _fields_ = [("ip", c_uint64),
                ("pid", c_uint32),
                ("tid", c_uint32),
                ("time", c_uint64),
                ("abi", c_uint64),
                ("regs", c_uint64 * 23)]

REGS = [
"AX","BX","CX","DX","SI","DI","BP","SP","IP","FLAGS","CS","SS","DS","ES","FS","GS","R8","R9","R10","R11","R12","R13","R14","R15",
]
DEFAULT_REGS = ["AX", "DI", "SP", "R14", "SI", "R10", "BP", "R11"]

def check_recompile():
    """Check if perftrace.so is older than perftrace.c and recompile if so"""
    if not os.path.exists("./perftrace.so"):
        return True
    so_time = os.path.getmtime("./perftrace.so")
    c_time = os.path.getmtime("./perftrace.c")
    return c_time > so_time

if check_recompile():
    os.system("gcc -shared -fPIC -o perftrace.so perftrace.c")    

SO = CDLL("./perftrace.so")
SO.breakpoint_next.argtypes = [POINTER(_Breakpoint), POINTER(_Sample)]
SO.breakpoint_next.restype = c_int
SO.breakpoint_create.argtypes = [c_int, c_ulong, c_ulong, c_bool]
SO.breakpoint_create.restype = POINTER(_Breakpoint)

class StoppedChild:
    """
    Utilities to start a process in a stopped state so you can attach
    perf breakpoints to it
    """
    def __init__(self, launch_fn):
        pid = os.fork()
        if pid == 0:
            SO.ptrace_traceme()
            launch_fn()
            return
        
        # Wait for ptrace stop
        os.waitpid(pid, 0)
        self.pid = pid
    
    def resume(self):
        SO.ptrace_detach(self.pid)

    def wait(self):
        os.waitpid(self.pid, 0)

@dataclass
class Sample:
    ip: int
    pid: int
    tid: int
    time: int
    regs: dict

    def __repr__(self):
        hex_regs = {r: hex(v) for r,v in self.regs.items()}
        return f"Sample(ip={hex(self.ip)}, pid={self.pid}, tid={self.tid}, time={self.time}, regs={hex_regs})"

class Breakpoint:
    def __init__(self, pid, addr, regs=DEFAULT_REGS, one_time=False):
        self.orig_regs = regs
        # The C code always expects 8 registers so do some shenanigans
        extra_regs = list(set(DEFAULT_REGS) - set(regs))[:len(DEFAULT_REGS) - len(regs)]
        self.regs = sorted(regs + extra_regs, key=lambda x: REGS.index(x))
        reg_flag = sum(1 << REGS.index(r) for r in self.regs)
        self.bp = SO.breakpoint_create(pid, addr, reg_flag, one_time)

    def next_hit(self):
        sample = _Sample()
        res = SO.breakpoint_next(self.bp, byref(sample))
        if res == 0:
            return None
        regs = {r: v for r,v in zip(self.regs, sample.regs) if r in self.orig_regs}
        return Sample(sample.ip, sample.pid, sample.tid, sample.time, regs)
    
    def results(self):
        while True:
            sample = self.next_hit()
            if sample is None:
                break
            yield sample
    

if __name__ == "__main__":
    child = StoppedChild(lambda: os.execv("./cache", ["./cache"]))
    bp = Breakpoint(child.pid, 0x402720, ["SI", "DI"], one_time=False)
    bp2 = Breakpoint(child.pid, 0x402ff0, ["SI", "DI"], one_time=True)
    child.resume()
    # Process is running at this time...
    child.wait()
    events = sorted(itertools.chain(bp.results(), bp2.results()), key=lambda x: x.time)
    for sample in events:
        print(sample)

