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
#include <unistd.h>
#include <string.h>
#include <errno.h>

#if defined(__aarch64__) && defined(__linux__)
#include <sys/prctl.h>
#include <sys/mman.h>

#ifndef PR_SET_TAGGED_ADDR_CTRL
#define PR_SET_TAGGED_ADDR_CTRL 55
#define PR_GET_TAGGED_ADDR_CTRL 56
#define PR_TAGGED_ADDR_ENABLE (1UL << 0)
#define PR_MTE_TCF_SHIFT 1
#define PR_MTE_TCF_NONE  (0UL << PR_MTE_TCF_SHIFT)
#define PR_MTE_TCF_SYNC  (1UL << PR_MTE_TCF_SHIFT)
#define PR_MTE_TCF_ASYNC (2UL << PR_MTE_TCF_SHIFT)
#define PR_MTE_TAG_SHIFT 3
#endif

#ifndef PR_MTE_TCF_MASK
#define PR_MTE_TCF_MASK (3UL << PR_MTE_TCF_SHIFT)
#endif
#ifndef PR_MTE_TAG_MASK
#define PR_MTE_TAG_MASK (0xffffUL << PR_MTE_TAG_SHIFT)
#endif

#ifndef PROT_MTE
#define PROT_MTE 0x20
#endif

#ifndef PROT_BTI
#define PROT_BTI 0x10
#endif
#endif

static inline void thesis_safe_write(const char *msg) {
    if (msg) {
        ssize_t ret = write(STDERR_FILENO, msg, strlen(msg));
        (void)ret;
    }
}

static inline void thesis_safe_write_int(const char *prefix, int val) {
    thesis_safe_write(prefix);
    char buf[16];
    int i = 14;
    buf[15] = '\n';
    int is_neg = 0;
    if (val < 0) {
        is_neg = 1;
        val = -val;
    } else if (val == 0) {
        buf[i--] = '0';
    }
    while (val > 0 && i >= 0) {
        buf[i--] = '0' + (val % 10);
        val /= 10;
    }
    if (is_neg && i >= 0) {
        buf[i--] = '-';
    }
    ssize_t ret = write(STDERR_FILENO, &buf[i + 1], 15 - i);
    (void)ret;
}

static inline void thesis_safe_write_hex(const char *prefix, unsigned long long val) {
    thesis_safe_write(prefix);
    char buf[19];
    buf[0] = '0';
    buf[1] = 'x';
    int i = 17;
    for (int j = 0; j < 16; ++j) {
        int nibble = val & 0xF;
        buf[i--] = (nibble < 10) ? ('0' + nibble) : ('a' + (nibble - 10));
        val >>= 4;
    }
    buf[18] = '\n';
    ssize_t ret = write(STDERR_FILENO, buf, 19);
    (void)ret;
}

/* Exit code 78 identifies a configuration failure, not an attack outcome. */
__attribute__((noreturn)) static inline void thesis_security_init_error(const char *message) {
    thesis_safe_write("[SECURITY_INIT_ERROR] ");
    thesis_safe_write(message);
    thesis_safe_write("\n");
    _exit(78);
}

static inline void thesis_log_exploit_success(const char *exploit_name) {
    thesis_safe_write("[EXPLOIT_SUCCESS] ");
    thesis_safe_write(exploit_name);
    thesis_safe_write("\n");
}

/* Start marker only: completion and detection are separate observations. */
static inline void thesis_log_attack_trigger(const char *scenario) {
    thesis_safe_write("[ATTACK_TRIGGER] ");
    thesis_safe_write(scenario);
    thesis_safe_write("\n");
}

/* ============================================================================
 * INICJALIZACJA SPRZĘTOWEGO MTE (MEMORY TAGGING EXTENSION) NA LINUKSIE
 * ============================================================================
 */
#if (defined(FORCE_MTE_SYNC) || defined(FORCE_MTE_ASYNC)) && defined(__aarch64__) && defined(__linux__)
__attribute__((constructor(101), used)) static void init_mte_mode(void) {
#if defined(FORCE_MTE_SYNC)
    const unsigned long ctrl = PR_TAGGED_ADDR_ENABLE | PR_MTE_TCF_SYNC | (0xfffeUL << PR_MTE_TAG_SHIFT);
    const char *mode_str = "MTE Synchronous Mode";
#elif defined(FORCE_MTE_ASYNC)
    const unsigned long ctrl = PR_TAGGED_ADDR_ENABLE | PR_MTE_TCF_ASYNC | (0xfffeUL << PR_MTE_TAG_SHIFT);
    const char *mode_str = "MTE Asynchronous Mode";
#endif

    if (prctl(PR_SET_TAGGED_ADDR_CTRL, ctrl, 0L, 0L, 0L) != 0) {
        thesis_security_init_error("prctl(PR_SET_TAGGED_ADDR_CTRL): cannot enable requested MTE mode");
    }

    const int active_ctrl = prctl(PR_GET_TAGGED_ADDR_CTRL, 0L, 0L, 0L, 0L);
    if (active_ctrl < 0) {
        thesis_security_init_error("prctl(PR_GET_TAGGED_ADDR_CTRL): cannot verify MTE mode");
    }
    const unsigned long verify_mask = PR_TAGGED_ADDR_ENABLE | PR_MTE_TCF_MASK | PR_MTE_TAG_MASK;
    if (((unsigned long)active_ctrl & verify_mask) != (ctrl & verify_mask)) {
        thesis_security_init_error("MTE readback differs from requested tagged ABI, fault mode or tag mask");
    }

    /* This preparation covers 17 pages around the current SP in these small,
       single-threaded workloads. It is not a general runtime for all stack
       growth or stacks of additional threads. */
    void *sp = NULL;
    __asm__ volatile("mov %0, sp" : "=r"(sp));
    const long page_size = sysconf(_SC_PAGESIZE);
    if (page_size <= 0 || sp == NULL ||
        (((unsigned long)page_size & ((unsigned long)page_size - 1UL)) != 0)) {
        thesis_security_init_error("invalid page size or stack pointer while preparing MTE stack pages");
    }
    const uintptr_t page_start = (uintptr_t)sp & ~((uintptr_t)page_size - 1);
    if (page_start < 16 * (uintptr_t)page_size) {
        thesis_security_init_error("MTE stack preparation address underflow");
    }
    volatile char *touch = (volatile char *)page_start;
    for (long i = 1; i <= 16; ++i) {
        touch[-i * page_size] = 0;
    }
    if (mprotect((void *)(page_start - 16 * (uintptr_t)page_size),
                 17 * (size_t)page_size,
                 PROT_READ | PROT_WRITE | PROT_MTE) != 0) {
        thesis_security_init_error("mprotect(PROT_MTE): cannot prepare the tested stack range");
    }

    /* Announce success only after both mode readback and page setup succeeded. */
    thesis_safe_write("[SECURITY_INIT] ");
    thesis_safe_write(mode_str);
    thesis_safe_write("; tested stack range prepared with PROT_MTE\n");
}
#elif defined(USE_SCUDO) && !defined(FORCE_MTE_SYNC) && !defined(FORCE_MTE_ASYNC) && defined(__aarch64__) && defined(__linux__)
__attribute__((constructor(101), used)) static void init_scudo_standalone(void) {
    /* Scudo hardened heap allocator configuration on AArch64.
       Enables tagged addressing and synchronous heap tag checking with standard Scudo tag mask,
       without instrumenting the stack (no memtag-stack or PROT_MTE on stack pages). */
    const unsigned long ctrl = PR_TAGGED_ADDR_ENABLE | PR_MTE_TCF_SYNC | (0xfffeUL << PR_MTE_TAG_SHIFT);
    if (prctl(PR_SET_TAGGED_ADDR_CTRL, ctrl, 0L, 0L, 0L) != 0) {
        thesis_security_init_error("Scudo: prctl(PR_SET_TAGGED_ADDR_CTRL) failed");
    }
    const int active_ctrl = prctl(PR_GET_TAGGED_ADDR_CTRL, 0L, 0L, 0L, 0L);
    const unsigned long verify_mask = PR_TAGGED_ADDR_ENABLE | PR_MTE_TCF_MASK | PR_MTE_TAG_MASK;
    if (active_ctrl < 0 || ((unsigned long)active_ctrl & verify_mask) != ctrl) {
        thesis_security_init_error("Scudo: tagged ABI or requested MTE mode was not confirmed");
    }
    thesis_safe_write("[SECURITY_INIT] Aktywowano alokator Scudo (ochrona sterty MTE, stos bez tagowania)\n");
}
#endif

/* ============================================================================
 * HANDLER SYGNAŁÓW BEZPIECZEŃSTWA (DLA CFI, PAC, BTI, MTE)
 * ============================================================================
 */
#if !defined(__SANITIZE_ADDRESS__) && !defined(__SANITIZE_HWADDRESS__)
#if defined(__has_feature)
  #if __has_feature(address_sanitizer) || __has_feature(hwaddress_sanitizer)
    #define HAS_SANITIZER 1
  #endif
#endif
#endif

#ifndef HAS_SANITIZER
#include <signal.h>
#include <ucontext.h>

#ifdef __linux__
#ifdef __cplusplus
extern "C" char __executable_start;
#else
extern char __executable_start;
#endif
#endif

#ifndef SEGV_MTEAERR
#define SEGV_MTEAERR 8
#endif
#ifndef SEGV_MTESERR
#define SEGV_MTESERR 9
#endif

static void thesis_fault_handler(int sig, siginfo_t *si, void *vcontext) {
    ucontext_t *context = (ucontext_t *)vcontext;
    unsigned long long pc = 0;
#ifdef __aarch64__
    if (context) pc = context->uc_mcontext.pc;
#elif defined(__x86_64__) && defined(REG_RIP)
    if (context) pc = context->uc_mcontext.gregs[REG_RIP];
#endif

    thesis_safe_write("[!] Przechwycono sygnal naruszenia bezpieczenstwa.\n");

    if (sig == SIGSEGV) {
        thesis_safe_write("[!] Sygnal: SIGSEGV (11)\n");
        if (si && si->si_code == SEGV_MTESERR) {
            thesis_safe_write("[SECURITY_TRAP] Kod bledu (si_code): SEGV_MTESERR (9) [MTE Synchronous Tag Check Fault]\n");
        } else if (si && si->si_code == SEGV_MTEAERR) {
            thesis_safe_write("[SECURITY_TRAP] Kod bledu (si_code): SEGV_MTEAERR (8) [MTE Asynchronous Tag Check Fault]\n");
        } else if (si && si->si_code == 1) {
#if defined(__ARM_FEATURE_PAC_DEFAULT)
            thesis_safe_write("[SECURITY_TRAP] mechanism=PAC Kod bledu (si_code): SEGV_MAPERR (1) [Address not mapped / Invalid PAC pointer]\n");
#else
            thesis_safe_write("[SECURITY_TRAP] Kod bledu (si_code): SEGV_MAPERR (1) [Address not mapped]\n");
#endif
        } else if (si && si->si_code == 2) {
#if defined(__ARM_FEATURE_PAC_DEFAULT)
            thesis_safe_write("[SECURITY_TRAP] mechanism=PAC Kod bledu (si_code): SEGV_ACCERR (2) [Invalid permissions / Invalid PAC pointer]\n");
#else
            thesis_safe_write("[SECURITY_TRAP] Kod bledu (si_code): SEGV_ACCERR (2) [Invalid permissions]\n");
#endif
        } else if (si) {
            thesis_safe_write_int("[SECURITY_TRAP] Kod bledu (si_code): ", si->si_code);
        }
    } else if (sig == SIGILL) {
#if defined(__ARM_FEATURE_BTI_DEFAULT)
        thesis_safe_write("[SECURITY_TRAP] mechanism=BTI Sygnal: SIGILL (4) [BTI Branch Fault]\n");
#elif defined(__ARM_FEATURE_PAC_DEFAULT)
        thesis_safe_write("[SECURITY_TRAP] mechanism=PAC Sygnal: SIGILL (4) [PAC FPAC Trap]\n");
#elif defined(FLAG_CFI_ACTIVE) || (defined(__has_feature) && __has_feature(cfi))
        thesis_safe_write("[SECURITY_TRAP] mechanism=CFI Sygnal: SIGILL (4) [CFI Compiler Trap]\n");
#else
        thesis_safe_write("[SECURITY_TRAP] Sygnal: SIGILL (4) [Illegal opcode]\n");
#endif
        if (si) thesis_safe_write_int("[!] Kod bledu (si_code): ", si->si_code);
    } else if (sig == SIGTRAP) {
#if defined(FLAG_CFI_ACTIVE) || (defined(__has_feature) && __has_feature(cfi))
        thesis_safe_write("[SECURITY_TRAP] mechanism=CFI Sygnal: SIGTRAP (5) [Breakpoint / CFI Compiler Trap]\n");
#else
        thesis_safe_write("[SECURITY_TRAP] Sygnal: SIGTRAP (5) [Breakpoint Trap]\n");
#endif
        if (si) thesis_safe_write_int("[!] Kod bledu (si_code): ", si->si_code);
    } else if (sig == SIGBUS) {
#if defined(__ARM_FEATURE_PAC_DEFAULT)
        thesis_safe_write("[SECURITY_TRAP] mechanism=PAC Sygnal: SIGBUS (7) [Bus Error / PAC Pointer Auth Fault]\n");
#else
        thesis_safe_write("[SECURITY_TRAP] Sygnal: SIGBUS (7) [Bus Error]\n");
#endif
        if (si) thesis_safe_write_int("[!] Kod bledu (si_code): ", si->si_code);
    } else {
        thesis_safe_write_int("[!] Sygnal nieznany: ", sig);
        if (si) thesis_safe_write_int("[!] Kod bledu (si_code): ", si->si_code);
    }

    if (si) {
        thesis_safe_write_hex("[!] Adres bledu: ", (unsigned long long)si->si_addr);
    }
    thesis_safe_write_hex("[!] PC: ", pc);
#ifdef __linux__
    /* ELF-relative offset supports exact-binary disassembly review with ASLR. */
    if (pc >= (unsigned long long)(uintptr_t)&__executable_start) {
        thesis_safe_write_hex("[!] PC_OFFSET: ",
                              pc - (unsigned long long)(uintptr_t)&__executable_start);
    }
#endif

    _exit(128 + sig);
}

__attribute__((constructor(102), used)) static void init_thesis_fault_handler(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_flags = SA_SIGINFO;
    sa.sa_sigaction = thesis_fault_handler;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGILL, &sa, NULL);
    sigaction(SIGTRAP, &sa, NULL);
    sigaction(SIGBUS, &sa, NULL);
}
#endif

#ifdef __cplusplus
extern "C" {
#endif

static inline uint64_t get_time_ns(void) {
#if defined(__aarch64__)
    uint64_t cnt, freq;
    __asm__ volatile("isb; mrs %0, cntvct_el0" : "=r"(cnt) :: "memory");
    __asm__ volatile("mrs %0, cntfrq_el0" : "=r"(freq));
    if (freq == 0) freq = 62500000;
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
