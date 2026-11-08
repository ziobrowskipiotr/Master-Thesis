#include "utils.h"
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <signal.h>
#include <sys/mman.h>
#include <ucontext.h>
#include <unistd.h>

using CallbackFn = void (*)();

[[maybe_unused]] static int g_bti_active = 0;

__attribute__((noinline)) void unauthorized_target_func() {
  thesis_log_exploit_success("D1_stack_smash (Przejęcie adresu powrotu LR i wykonanie unauthorized_target_func)");
  _exit(0);
}

__attribute__((noinline)) void valid_callback() {
  [[maybe_unused]] volatile int a = 1;
}

__attribute__((noinline)) void malicious_callback_diff_type(int x, double y) {
  thesis_log_exploit_success("D2_indirect_call_hijack (Wykonanie nieautoryzowanej funkcji o niezgodnej sygnaturze)");
  [[maybe_unused]] volatile int b = 2 + x + (int)y;
}

__attribute__((noinline)) void malicious_callback_same_type() {
  thesis_log_exploit_success("D2_bypass_cfi (Obejsice CFI: wykonanie funkcji o zgodnej sygnaturze typu)");
  [[maybe_unused]] volatile int b = 666;
}

class EventHandler {
public:
  virtual void handle() { [[maybe_unused]] volatile int c = 3; }
  virtual ~EventHandler() = default;
};

class UnrelatedMalicious {
public:
  virtual void __attribute__((noinline)) fake_handle() {
    thesis_log_exploit_success("D3_vtable_hijack (Wykonanie fake_handle przez podmieniona tablice vtable)");
    [[maybe_unused]] volatile int d = 4;
  }
  virtual ~UnrelatedMalicious() = default;
};

[[maybe_unused]] static UnrelatedMalicious malicious_instance;

__attribute__((noinline)) void dummy_leaf() { asm volatile("" ::: "memory"); }

__attribute__((noinline)) void vulnerable_stack_func() {
  char buffer[16];
  dummy_leaf(); // Wymusza zapisanie rejestru powrotu x30 (LR) i x29 na stosie

#ifdef BUG_D1
  // Nadpisanie stosu: bufor 16B, za nim na ARM64 zapisane x29 i x30 (LR).
  // W wariancie bez ochrony nadpisujemy x30 adresem unauthorized_target_func.
  // - Stack Canary (-fstack-protector-all) wykrywa naruszenie kanarka przed ret (__stack_chk_fail).
  // - ARM PAC (-mbranch-protection=pac-ret) weryfikuje podpis w autiasp i zgłasza błąd autoryzacji.
  uintptr_t target = reinterpret_cast<uintptr_t>(unauthorized_target_func);
  void *dst = buffer;
  size_t len = 64;
  asm volatile("" : "+r"(dst), "+r"(len), "+r"(target) :: "memory");

  uintptr_t *words = reinterpret_cast<uintptr_t *>(buffer);
  for (size_t i = 0; i < len / sizeof(uintptr_t); ++i) {
    words[i] = target;
  }
#else
  buffer[0] = 1;
#endif
}

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
    int mres = mprotect((void *)page_start, len, PROT_READ | PROT_EXEC | PROT_BTI);
    if (mres == 0) {
      g_bti_active = 1;
      thesis_safe_write("[SECURITY_INIT] Pomyślnie nadano uprawnienie PROT_BTI dla stron kodu\n");
    } else {
      thesis_safe_write("[!] OSTRZEŻENIE: mprotect(PROT_BTI) zwróciło błąd: ");
      thesis_safe_write_int("", errno);
    }
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

#ifdef BUG_D4
  if (g_bti_active == 0) {
    thesis_log_exploit_success("D4_bti_landing (Skok pod valid_callback+4 wykonany bez ladowiska BTI)");
  }
#endif

  deactivate_bti_protection();

  std::cout << "Czas_wykonania_ns:" << (end_time - start_time) << "\n";
  delete handler;
}

int main(int argc, char **argv) {
  int iter = (argc > 1) ? std::atoi(argv[1]) : 1;
  run_dispatcher(iter);
  return 0;
}
