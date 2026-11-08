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

static inline void thesis_log_exploit_success(const char *exploit_name) {
    thesis_safe_write("[EXPLOIT_SUCCESS] ");
    thesis_safe_write(exploit_name);
    thesis_safe_write("\n");
}

/* ============================================================================
 * INICJALIZACJA SPRZĘTOWEGO MTE (MEMORY TAGGING EXTENSION) NA LINUKSIE
 * ============================================================================
 */
#if (defined(FORCE_MTE_SYNC) || defined(FORCE_MTE_ASYNC)) && defined(__aarch64__) && defined(__linux__)
__attribute__((constructor(101), used)) static void init_mte_mode(void) {
#if defined(FORCE_MTE_SYNC)
    unsigned long ctrl = PR_TAGGED_ADDR_ENABLE | PR_MTE_TCF_SYNC | (0xfffeUL << PR_MTE_TAG_SHIFT);
    const char *mode_str = "MTE Sync (SEGV_MTESERR)";
#elif defined(FORCE_MTE_ASYNC)
    unsigned long ctrl = PR_TAGGED_ADDR_ENABLE | PR_MTE_TCF_ASYNC | (0xfffeUL << PR_MTE_TAG_SHIFT);
    const char *mode_str = "MTE Async (SEGV_MTEAERR)";
#endif

    int res = prctl(PR_SET_TAGGED_ADDR_CTRL, ctrl, 0L, 0L, 0L);
    if (res != 0) {
        thesis_safe_write("[!] OSTRZEŻENIE: prctl(PR_SET_TAGGED_ADDR_CTRL) nie powiodło się! Kod błędu: ");
        thesis_safe_write_int("", errno);
        return;
    }

    // Weryfikacja aktywacji trybu MTE przez jądro
    int active_ctrl = prctl(PR_GET_TAGGED_ADDR_CTRL, 0L, 0L, 0L, 0L);
    if (active_ctrl < 0 || !(active_ctrl & PR_TAGGED_ADDR_ENABLE)) {
        thesis_safe_write("[!] OSTRZEŻENIE: Tryb MTE nie został włączony przez jądro!\n");
        return;
    }

    thesis_safe_write("[SECURITY_INIT] Pomyślnie aktywowano tryb sprzętowy: ");
    thesis_safe_write(mode_str);
    thesis_safe_write("\n");

    // Włączenie PROT_MTE na zaalokowanym obszarze stosu (dla -fsanitize=memtag-stack):
    void* sp = NULL;
    __asm__ volatile("mov %0, sp" : "=r"(sp));
    long page_size = sysconf(_SC_PAGESIZE);
    if (page_size > 0 && sp != NULL) {
        uintptr_t page_start = ((uintptr_t)sp) & ~((uintptr_t)page_size - 1);
        volatile char *touch = (volatile char *)page_start;
        for (long i = 1; i <= 16; ++i) {
            touch[-i * page_size] = 0;
        }
        int mprot_res = mprotect((void*)(page_start - 16 * (uintptr_t)page_size),
                                 17 * (size_t)page_size,
                                 PROT_READ | PROT_WRITE | PROT_MTE);
        if (mprot_res != 0) {
            thesis_safe_write("[!] OSTRZEŻENIE: mprotect(PROT_MTE) dla stosu zwróciło błąd: ");
            thesis_safe_write_int("", errno);
        }
    }
}
#elif defined(USE_SCUDO) && !defined(FORCE_MTE_SYNC) && !defined(FORCE_MTE_ASYNC) && defined(__aarch64__) && defined(__linux__)
__attribute__((constructor(101), used)) static void init_scudo_standalone(void) {
    // Alokator Scudo na ARM64 – włączamy TBI i maskę tagów zgodną z runtime Scudo,
    // eliminując błędy corrupted chunk header w środowiskach glibc/QEMU:
    unsigned long ctrl = PR_TAGGED_ADDR_ENABLE | PR_MTE_TCF_SYNC | (0xfffeUL << PR_MTE_TAG_SHIFT);
    int res = prctl(PR_SET_TAGGED_ADDR_CTRL, ctrl, 0L, 0L, 0L);
    if (res != 0) {
        thesis_safe_write("[!] OSTRZEŻENIE: prctl(PR_SET_TAGGED_ADDR_CTRL) dla Scudo zwróciło błąd: ");
        thesis_safe_write_int("", errno);
    }
    thesis_safe_write("[SECURITY_INIT] Aktywowano alokator Scudo (ochrona sterty)\n");
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
            thesis_safe_write("[SECURITY_TRAP] Kod bledu (si_code): SEGV_MAPERR (1) [Address not mapped / Invalid PAC pointer]\n");
        } else if (si && si->si_code == 2) {
            thesis_safe_write("[SECURITY_TRAP] Kod bledu (si_code): SEGV_ACCERR (2) [Invalid permissions / Invalid PAC pointer]\n");
        } else if (si) {
            thesis_safe_write_int("[SECURITY_TRAP] Kod bledu (si_code): ", si->si_code);
        }
    } else if (sig == SIGILL) {
        thesis_safe_write("[SECURITY_TRAP] Sygnal: SIGILL (4) [Illegal opcode / BTI Branch Fault / PAC FPAC Trap]\n");
        if (si) thesis_safe_write_int("[!] Kod bledu (si_code): ", si->si_code);
    } else if (sig == SIGTRAP) {
        thesis_safe_write("[SECURITY_TRAP] Sygnal: SIGTRAP (5) [Breakpoint / CFI Compiler Trap]\n");
        if (si) thesis_safe_write_int("[!] Kod bledu (si_code): ", si->si_code);
    } else if (sig == SIGBUS) {
        thesis_safe_write("[SECURITY_TRAP] Sygnal: SIGBUS (7) [Bus Error / PAC Pointer Auth Fault]\n");
        if (si) thesis_safe_write_int("[!] Kod bledu (si_code): ", si->si_code);
    } else {
        thesis_safe_write_int("[!] Sygnal nieznany: ", sig);
        if (si) thesis_safe_write_int("[!] Kod bledu (si_code): ", si->si_code);
    }

    if (si) {
        thesis_safe_write_hex("[!] Adres bledu: ", (unsigned long long)si->si_addr);
    }
    thesis_safe_write_hex("[!] PC: ", pc);

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
