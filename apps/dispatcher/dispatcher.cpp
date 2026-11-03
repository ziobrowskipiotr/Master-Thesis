#include "utils.h"
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <signal.h>
#include <sys/mman.h>
#include <ucontext.h>
#include <unistd.h>

#ifndef PROT_BTI
#define PROT_BTI 0x10
#endif

using CallbackFn = void (*)();

__attribute__((noinline)) void valid_callback() {
  [[maybe_unused]] volatile int a = 1;
}

__attribute__((noinline)) void malicious_callback_diff_type(int x, double y) {
  [[maybe_unused]] volatile int b = 2 + x + (int)y;
}

__attribute__((noinline)) void malicious_callback_same_type() {
  [[maybe_unused]] volatile int b = 666;
}

class EventHandler {
public:
  virtual void handle() { [[maybe_unused]] volatile int c = 3; }
  virtual ~EventHandler() = default;
};

[[maybe_unused]] static class UnrelatedMalicious {
public:
  virtual void __attribute__((noinline)) fake_handle() {
    [[maybe_unused]] volatile int d = 4;
  }
} malicious_instance;

void safe_print_hex(const char *prefix, unsigned long long val) {
  write(STDERR_FILENO, prefix, strlen(prefix));
  char buf[18];
  buf[0] = '0';
  buf[1] = 'x';
  int i = 17;
  for (int j = 0; j < 16; ++j) {
    int nibble = val & 0xF;
    buf[i--] = (nibble < 10) ? ('0' + nibble) : ('a' + (nibble - 10));
    val >>= 4;
  }
  write(STDERR_FILENO, buf, 18);
  write(STDERR_FILENO, "\n", 1);
}

void fault_handler(int sig, siginfo_t *si, void *vcontext) {
  ucontext_t *context = (ucontext_t *)vcontext;
  unsigned long long pc = 0;
#ifdef __aarch64__
  pc = context->uc_mcontext.pc;
#elif defined(__x86_64__)
  pc = context->uc_mcontext.gregs[REG_RIP];
#endif

  const char *msg = "[!] Przechwycono sygnal naruszenia bezpieczenstwa.\n";
  write(STDERR_FILENO, msg, strlen(msg));
  safe_print_hex("[!] Adres bledu: ", (unsigned long long)si->si_addr);
  safe_print_hex("[!] PC: ", pc);

  _exit(128 + sig);
}

__attribute__((noinline)) void dummy_leaf() { asm volatile("" ::: "memory"); }

__attribute__((noinline)) void vulnerable_stack_func() {
  char buffer[16];
  dummy_leaf(); // Wymusza zapisanie rejestru powrotu x30 (LR) i x29 na stosie
#ifdef BUG_D1
  void *dst = buffer;
  size_t len = 64;
  asm volatile("" : "+r"(dst), "+r"(len) :: "memory");
  std::memset(dst, 0xAA, len);
#else
  buffer[0] = 1;
#endif
}

// Deklaracja wyprzedzająca – potrzebna do obliczenia zakresu stron kodu w
// mprotect
void run_dispatcher(int iterations);

static void activate_bti_protection(void) {
#if defined(__aarch64__) && defined(__ARM_FEATURE_BTI_DEFAULT)
  uintptr_t start_addr = (uintptr_t)valid_callback;
  uintptr_t end_addr = (uintptr_t)run_dispatcher;
  if (end_addr < start_addr) {
    uintptr_t tmp = start_addr;
    start_addr = end_addr;
    end_addr = tmp;
  }
  long page_size = sysconf(_SC_PAGESIZE);
  if (page_size > 0) {
    uintptr_t page_start = start_addr & ~(page_size - 1);
    size_t len = ((end_addr + page_size) & ~(page_size - 1)) - page_start;
    mprotect((void *)page_start, len, PROT_READ | PROT_EXEC | PROT_BTI);
  }
#endif
}

static void deactivate_bti_protection(void) {
#if defined(__aarch64__) && defined(__ARM_FEATURE_BTI_DEFAULT)
  uintptr_t start_addr = (uintptr_t)valid_callback;
  uintptr_t end_addr = (uintptr_t)run_dispatcher;
  if (end_addr < start_addr) {
    uintptr_t tmp = start_addr;
    start_addr = end_addr;
    end_addr = tmp;
  }
  long page_size = sysconf(_SC_PAGESIZE);
  if (page_size > 0) {
    uintptr_t page_start = start_addr & ~(page_size - 1);
    size_t len = ((end_addr + page_size) & ~(page_size - 1)) - page_start;
    mprotect((void *)page_start, len, PROT_READ | PROT_EXEC);
  }
#endif
}

void run_dispatcher(int iterations) {
  CallbackFn cb = valid_callback;
  EventHandler *handler = new EventHandler();

#ifdef BUG_D2
  void *malicious_addr = (void *)malicious_callback_diff_type;
  std::memcpy(&cb, &malicious_addr, sizeof(void *));
#endif

#ifdef BUG_D2_BYPASS
  void *malicious_addr = (void *)malicious_callback_same_type;
  std::memcpy(&cb, &malicious_addr, sizeof(void *));
#endif

#ifdef BUG_D3
  void **obj_ptr = reinterpret_cast<void **>(handler);
  void **malicious_ptr = reinterpret_cast<void **>(&malicious_instance);
  *obj_ptr = *malicious_ptr;
#endif

#ifdef BUG_D4
  void *invalid_bti_target = (char *)valid_callback + 4;
  std::memcpy(&cb, &invalid_bti_target, sizeof(void *));
#endif

  asm volatile("" : "+r"(cb));
  asm volatile("" : "+r"(handler));

  activate_bti_protection();

  uint64_t start_time = get_time_ns();
  for (int i = 0; i < iterations; ++i) {
    cb();
    handler->handle();
    vulnerable_stack_func();
  }
  uint64_t end_time = get_time_ns();

  deactivate_bti_protection();

  std::cout << "Czas_wykonania_ns:" << (end_time - start_time) << "\n";
  delete handler;
}

int main(int argc, char **argv) {
  struct sigaction sa = {};
  sa.sa_flags = SA_SIGINFO;
  sa.sa_sigaction = fault_handler;
  sigemptyset(&sa.sa_mask);
  sigaction(SIGSEGV, &sa, NULL);
  sigaction(SIGILL, &sa, NULL);
  sigaction(SIGTRAP, &sa, NULL);
  sigaction(SIGABRT, &sa, NULL);
  sigaction(SIGBUS, &sa, NULL);

  int iter = (argc > 1) ? std::atoi(argv[1]) : 1;
  run_dispatcher(iter);
  return 0;
}