#ifndef UTILS_H
#define UTILS_H

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdint.h>
#include <time.h>

#if defined(__aarch64__) && defined(__ARM_FEATURE_MEMORY_TAGGING)
#include <sys/prctl.h>
#include <unistd.h>
#include <sys/mman.h>

#ifndef PR_SET_TAGGED_ADDR_CTRL
#define PR_SET_TAGGED_ADDR_CTRL 55
#endif

#ifndef PR_TAGGED_ADDR_ENABLE
#define PR_TAGGED_ADDR_ENABLE (1UL << 0)
#endif

#ifndef PR_MTE_TCF_SHIFT
#define PR_MTE_TCF_SHIFT 1
#endif

#ifndef PR_MTE_TCF_SYNC
#define PR_MTE_TCF_SYNC (1UL << PR_MTE_TCF_SHIFT)
#endif

#ifndef PR_MTE_TCF_ASYNC
#define PR_MTE_TCF_ASYNC (2UL << PR_MTE_TCF_SHIFT)
#endif

#ifndef PR_MTE_TAG_SHIFT
#define PR_MTE_TAG_SHIFT 3
#endif

#ifndef PROT_MTE
#define PROT_MTE 0x20
#endif

__attribute__((constructor(101), used)) static void arm64_init_tagged_addr(void) {
  // Aktywacja Tagged Address ABI oraz MTE w kernelu Linuksa dla ARM64 (TBI / MTE)
  // Włączamy obsługę trybów SYNC oraz ASYNC
  unsigned long ctrl = PR_TAGGED_ADDR_ENABLE | PR_MTE_TCF_SYNC | PR_MTE_TCF_ASYNC | (0xfffeUL << PR_MTE_TAG_SHIFT);
  int res = prctl(PR_SET_TAGGED_ADDR_CTRL, ctrl, 0L, 0L, 0L);
  if (res == 0) {
    // Jeżeli kernel i CPU wspierają MTE, upewnijmy się, że strony stosu mają uprawnienie PROT_MTE
    void* sp = NULL;
    __asm__ volatile("mov %0, sp" : "=r"(sp));
    long page_size = sysconf(_SC_PAGESIZE);
    if (page_size > 0 && sp != NULL) {
      uintptr_t page_start = ((uintptr_t)sp) & ~(page_size - 1);
      mprotect((void*)(page_start - 128 * 1024), 256 * 1024, PROT_READ | PROT_WRITE | PROT_MTE);
    }
  }
}
#endif

#ifdef __cplusplus
extern "C" {
#endif

static inline uint64_t get_time_ns(void) {
#if defined(__aarch64__)
  uint64_t cnt, freq;
  __asm__ volatile("mrs %0, cntvct_el0" : "=r"(cnt));
  __asm__ volatile("mrs %0, cntfrq_el0" : "=r"(freq));
  if (freq == 0) freq = 62500000;
  // Używamy unsigned __int128, aby zapobiec przepełnieniu 64-bitowemu mnożenia cnt * 1e9
  return (uint64_t)(((unsigned __int128)cnt * 1000000000ULL) / freq);
#else
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
#endif
}

#ifdef __cplusplus
}
#endif

#endif // UTILS_H