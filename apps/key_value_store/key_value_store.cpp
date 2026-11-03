#include "utils.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <stdint.h>

struct Record {
  uint32_t key;
  char *data;
};

#ifdef BUG_M3
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wreturn-stack-address"
__attribute__((noinline)) static char *get_scope_stack_ptr() {
  char tmp[32] = {0};
  char *p = tmp;
  asm volatile("" : "+r"(p) :: "memory");
  return p;
}
#pragma GCC diagnostic pop
#endif

void process_kv_workload(int num_records, int access_iterations) {

  Record **store = (Record **)std::malloc(num_records * sizeof(Record *));

  uint64_t t0 = get_time_ns();
  for (int i = 0; i < num_records; ++i) {
    Record *r = (Record *)std::malloc(sizeof(Record));
    r->key = static_cast<uint32_t>(i);
    r->data = (char *)std::malloc(64);
    std::strcpy(r->data, "Some valid data");
    store[i] = r;
  }
  uint64_t t1 = get_time_ns();

  volatile char dummy = 0;
  for (int iter = 0; iter < access_iterations; ++iter) {
    for (int i = 0; i < num_records; ++i) {
      dummy = store[i]->data[0];
      store[i]->data[0] = dummy + 1;
    }
  }
  uint64_t t2 = get_time_ns();

  Record *target = store[num_records / 2];
  std::free(target->data);

#if !defined(BUG_M1) && !defined(BUG_M2)
  target->data = nullptr;
#endif

#ifdef BUG_M1
  std::strcpy(target->data, "Malicious write");
#endif

#ifdef BUG_M2
  std::free(target->data);
#endif

#ifdef BUG_M3
  // Atak M3: Stack Use-After-Scope / Return (temporalny błąd stosu).
  // Wskaźnik wskazuje na tablicę wewnątrz zakończonego zakresu (ramki funkcji),
  // do której następuje zapis po powrocie.
  // Canary, PAC, Scudo nie wykrywają błędu (0%).
  // MTE-stack (-fsanitize=memtag-stack), HWASan i ASan wykrywają naruszenie w 100%.
  char *stack_uaf_ptr = get_scope_stack_ptr();
  stack_uaf_ptr[0] = 'X';
  asm volatile("" : "+m"(stack_uaf_ptr[0]) :: "memory");
#endif

  uint64_t t3 = get_time_ns();

  for (int i = 0; i < num_records; ++i) {
    Record *r = store[i];
    if (r->data != nullptr && r != target) {
      std::free(r->data);
    }
    std::free(r);
  }
  std::free(store);
  uint64_t t4 = get_time_ns();

  std::printf("Czas_Alokacji_ns:%llu\n", (unsigned long long)(t1 - t0));
  std::printf("Czas_Przetwarzania_ns:%llu\n", (unsigned long long)(t2 - t1));
  std::printf("Czas_Sprzatania_ns:%llu\n", (unsigned long long)(t4 - t3));
}

int main(int argc, char **argv) {
  int records = (argc > 1) ? std::atoi(argv[1]) : 50000;
  int iters = (argc > 2) ? std::atoi(argv[2]) : 1000;

  process_kv_workload(records, iters);
  return 0;
}