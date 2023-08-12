#include <sys/ptrace.h>

#include <assert.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>

#include <signal.h>
#include <unistd.h>

#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/prctl.h>

#include <asm/perf_regs.h>
#include <linux/hw_breakpoint.h>
#include <linux/perf_event.h>

static int sys_perf_event_open(struct perf_event_attr *attr, pid_t pid, int cpu,
                               int group_fd, unsigned long flags) {
  return syscall(SYS_perf_event_open, attr, pid, cpu, group_fd, flags);
}

int ptrace_traceme() {
  prctl( PR_SET_PDEATHSIG, SIGKILL );
  return ptrace(PTRACE_TRACEME, 0, NULL, NULL);
}

void ptrace_detach(int pid) {
  ptrace(PTRACE_DETACH, pid, NULL, NULL);
}

#define rmb() asm volatile("" ::: "memory")

struct breakpoint_state {
  int fd;
  size_t mmap_size;
  volatile struct perf_event_mmap_page *mmap;
};

void destroy_breakpoint_state(struct breakpoint_state *s) {
  if (s->mmap && s->mmap != MAP_FAILED)
    munmap((void *)s->mmap, s->mmap_size);
  if (s->fd > 0)
    close(s->fd);
  free(s);
}

struct breakpoint_state *breakpoint_create(int pid, uint64_t addr, uint64_t regs, bool single_hit) {
  struct perf_event_attr attr;

  memset(&attr, 0, sizeof(attr));
  attr.size = sizeof(attr);
  attr.type = PERF_TYPE_BREAKPOINT;
  attr.bp_type = HW_BREAKPOINT_X;
  attr.bp_addr = addr;
  attr.bp_len = sizeof(long);
  attr.sample_period = 1;
  attr.sample_type = PERF_SAMPLE_TIME | PERF_SAMPLE_IP | PERF_SAMPLE_REGS_USER |
                     PERF_SAMPLE_TID;
  attr.exclude_hv = 1;
  attr.exclude_kernel = 1;
  attr.disabled = single_hit;
  attr.wakeup_events = 1;
  attr.precise_ip = 2;
  // sample all the registers
//   int max = 12;
//   printf("Register count: %d\n", max);
  assert(__builtin_popcount(regs) == 8);
  attr.sample_regs_user = regs;
  // calloc returns zeroed memory so we don't try to free garbage in error cases
  struct breakpoint_state *s = calloc(1, sizeof(*s));

  s->fd = sys_perf_event_open(&attr, pid, -1, -1, PERF_FLAG_FD_CLOEXEC);

  if (s->fd < 0)
    goto failed;

  s->mmap_size = sysconf(_SC_PAGESIZE) * (1 + 16);
  // The PROT_READ and PROT_WRITE is how we tell perf we'll be updating
  // data_tail
  s->mmap =
      mmap(NULL, s->mmap_size, PROT_READ | PROT_WRITE, MAP_SHARED, s->fd, 0);
  if (s->mmap == MAP_FAILED)
    goto failed;

  // Makes it so the breakpoint only triggers once before being disabled
  if (single_hit) {
    if (ioctl(s->fd, PERF_EVENT_IOC_REFRESH, 1) < 0)
      goto failed;
  }

  return s;
failed:
  destroy_breakpoint_state(s);
  assert(errno > 0);
  return NULL;
}

static uint64_t
perf_time_of_tsc(volatile struct perf_event_mmap_page *perf_mmap,
                 uint64_t tsc) {
  uint64_t quot = tsc >> perf_mmap->time_shift;
  uint64_t rem = tsc & (((uint64_t)1 << perf_mmap->time_shift) - 1);
  return perf_mmap->time_zero + quot * perf_mmap->time_mult +
         ((rem * perf_mmap->time_mult) >> perf_mmap->time_shift);
}

struct my_sample {
  uint64_t ip;
  uint32_t pid, tid;
  uint64_t time;
  uint64_t abi;
  uint64_t regs[8];
};

struct my_full_sample {
  struct perf_event_header header;
  struct my_sample contents;
};

int breakpoint_next(struct breakpoint_state *s, struct my_sample *out) {
  char *cur = (char *)s->mmap + s->mmap->data_offset +
              (s->mmap->data_tail % s->mmap->data_size);
  char *events_end = (char *)s->mmap + s->mmap->data_offset +
                     (s->mmap->data_head % s->mmap->data_size);
  rmb();

  while (cur < events_end) {
    struct perf_event_header *ev = (struct perf_event_header *)cur;
    if (ev->type == PERF_RECORD_SAMPLE) {
      struct my_full_sample *samp = (struct my_full_sample *)ev;
    //   printf("ip: %lx\n", samp->contents.ip);
      memcpy(out, &samp->contents, sizeof(*out));
      // Needs to be updated after we read the sample because the kernel uses
      // this value to not overwrite data until we've read it.
      s->mmap->data_tail += ev->size;
      return 1;
    } else {
      s->mmap->data_tail += ev->size;
    }
    cur += ev->size;
  }
  return 0;
}