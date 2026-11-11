#include "utils.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <stdint.h>

struct Record {
  uint32_t key;
  char *data;
};

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
  thesis_log_attack_trigger("M1_use_after_free");
  std::strcpy(target->data, "Malicious write");
  asm volatile("" : "+m"(*target->data) :: "memory");
  (void)getpid();
  thesis_log_exploit_success("M1_use_after_free (Zapis do zwolnionej pamięci sterty wykonany bez wykrycia)");
#endif

#ifdef BUG_M2
  thesis_log_attack_trigger("M2_double_free");
  std::free(target->data);
  (void)getpid();
  thesis_log_exploit_success("M2_double_free (Podwójne zwolnienie pamięci sterty wykonane bez wykrycia)");
#endif

#ifdef BUG_M3
  // Prawdziwy Stack Use-After-Scope wewnątrz funkcji:
  // Wyjście z pierwszego bloku emituje @llvm.lifetime.end (ASan zatruwa slot wartością 0xf8,
  // a MTE/HWASan zmienia tag przy alokacji zmiennej w kolejnym zasięgu).
  char *stack_uaf_ptr = nullptr;
  {
    char scope_buf[32] = {0};
    stack_uaf_ptr = scope_buf;
    asm volatile("" : "+r"(stack_uaf_ptr), "+m"(scope_buf) :: "memory");
  }
  {
    char reused_scope_buf[32] = {1};
    char *reused_ptr = reused_scope_buf;
    asm volatile("" : "+r"(reused_ptr), "+m"(reused_scope_buf) :: "memory");
    thesis_log_attack_trigger("M3_stack_use_after_scope");
    stack_uaf_ptr[0] = 'X';
    asm volatile("" : "+m"(stack_uaf_ptr[0]), "+m"(reused_scope_buf) :: "memory");
  }
  (void)getpid(); // Punkt synchronizacji jądra dla MTE_ASYNC (TFSRE0_EL1)
  thesis_log_exploit_success("M3_stack_use_after_scope (Zapis do zmiennej stosowej poza zakresem wykonany bez wykrycia)");
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

  (void)getpid(); // Punkt synchronizacji jądra dla MTE_ASYNC (TFSRE0_EL1)
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
