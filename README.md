# Ocena wpływu mechanizmów bezpieczeństwa pamięci na wydajność w ARM64

Środowisko badawcze i autorska metodyka oceny kompromisu między poziomem bezpieczeństwa a narzutem wydajnościowym i chmurowym dla aplikacji niskopoziomowych w architekturze **AArch64 (ARMv8.5-A+)**.

---

## 1. Architektura i badane mechanizmy

Projekt bada **13 wariantów zabezpieczeń** w trzech domenach ochrony (przestrzenna, temporalna, integralność przepływu sterowania):

| Mechanizm | Flagi kompilatora / linkera | Domena ochrony |
| :--- | :--- | :--- |
| **base** | `-O3 -march=armv8.5-a` | Brak ochrony (baseline) |
| **canary** | `-fstack-protector-all` | Stos (Stack Canary) |
| **pac** | `-mbranch-protection=pac-ret` | Adres powrotu x30 / LR |
| **bti** | `-mbranch-protection=bti -Wl,-z,now` | Lądowiska skoków pośrednich (`BTI C/J`) |
| **pac_bti** | `-mbranch-protection=pac-ret+bti -Wl,-z,now` | ROP + JOP / COP |
| **cfi** | `-flto=thin -fvisibility=hidden -fsanitize=cfi` | Sygnatury wywołań pośrednich i vtables |
| **cfi_pac_bti** | CFI + PAC + BTI | Pełna integralność sterowania (Forward + Backward) |
| **scudo** | `-march=armv8.5-a+memtag -fsanitize=scudo` | Alokator sterty (ochrona przed UAF / Double-Free) |
| **mte_async** | `-march=armv8.5-a+memtag -fsanitize=memtag-stack -fsanitize-memtag-mode=async` | Sprzętowe tagowanie MTE (tryb asynchroniczny) |
| **mte_sync** | `-march=armv8.5-a+memtag -fsanitize=memtag-stack -fsanitize-memtag-mode=sync` | Sprzętowe tagowanie MTE (tryb synchroniczny) |
| **cfi_pac_bti_mte** | CFI + PAC + BTI + MTE-Sync + Scudo | Synergia sprzętowo-kompilatorowa (Production Hardened) |
| **cfi_pac_bti_mte_fortify_bounds** | Synergy + `-D_FORTIFY_SOURCE=3 -fsanitize=bounds` | Pełna obrona w głąb (Defense-in-Depth) |
| **hwasan** | `-fsanitize=hwaddress -mllvm -hwasan-globals=1` | Programowe tagowanie pamięci (ARM TBI) |
| **asan** | `-fsanitize=address` | Klasyczny AddressSanitizer (Shadow Memory 1/8) |

---

## 2. Struktura repozytorium

```
.
├── apps/
│   ├── parser/                 # Parser binarny TLV (błędy przestrzenne P1..P6)
│   ├── key_value_store/        # Składnica klucz-wartość (błędy temporalne M1..M3)
│   └── dispatcher/             # Pętla zdarzeń i wirtualne metody (ataki na sterowanie D1..D4)
├── common/
│   └── utils.h                 # Precyzyjny licznik czasu ARM64 (cntvct_el0) oraz obsługa MTE/BTI
├── data/                       # Deterministyczne zbiory wejściowe (SHA-256)
├── scripts/
│   ├── generate_datasets.py    # Deterministyczny generator datasetów
│   ├── run_benchmarks.py       # Główny runner benchmarków, metryk i wykresów
│   └── vm/                     # Skrypty konfiguracji i uruchomienia maszyny QEMU ARM64
├── CMakeLists.txt              # Definicje 143 celów binarnych Clang / LLD
└── README.md
```

---

## 3. Scenariusze ataków (13 wektorów testowych)

1. **Pamięć przestrzenna (Spatial):**
   - `P1_heap_overflow`: Przepełnienie bufora sterty (`malloc(16)` -> zapis 24B).
   - `P2_stack_overflow`: Przepełnienie bufora stosu (zapis 64B do bufora 16B).
   - `P3_global_overflow`: Przepełnienie bufora w sekcji globalnej `.bss/.data`.
   - `P4_heap_oob_read`: Odczyt poza zaalokowany zakres bufora wejściowego.
   - `P5_subgranule_overflow`: Przepełnienie wewnątrz 16-bajtowego kafelka MTE (8B alloc -> 12B copy).
   - `P6_stack_dop`: Data-Oriented Programming (nadpisanie flagi `is_admin` bez modyfikacji ramki stosu).
2. **Pamięć temporalna (Temporal):**
   - `M1_use_after_free`: Zapis do zwolnionego obszaru pamięci na stercie.
   - `M2_double_free`: Ponowne zwolnienie tego samego wskaźnika sterty.
   - `M3_stack_use_after_scope`: Dostęp do zmiennej stosowej po wyjściu z bloku leksykalnego (`@llvm.lifetime.end`).
3. **Integralność przepływu sterowania (Control Flow):**
   - `D1_stack_smash`: Nadpisanie rejestru powrotu `x30` (LR) na stosie.
   - `D2_indirect_call_hijack`: Podmiana wskaźnika funkcji na cel o **niezgodnej sygnaturze** (CFI Forward-Edge).
   - `D2_bypass_cfi`: Podmiana wskaźnika funkcji na cel o **zgodnej sygnaturze** (teoretyczna granica CFI).
   - `D3_vtable_hijack`: Podmiana wskaźnika tabeli wirtualnej `vptr` (Type Confusion / Vtable Hijack).
   - `D4_bti_landing`: Skok pośredni na instrukcję bez lądowiska `BTI` (skok pod `fn + 4`).

---

## 4. Instrukcja uruchomienia

### Krok 1: Uruchomienie maszyny wirtualnej ARM64 (QEMU)
```bash
# Na maszynie hosta:
./scripts/vm/start_vm.sh

# W osobnym terminalu:
./scripts/vm/connect_vm.sh
```

### Krok 2: Generowanie powtarzalnych danych wejściowych
```bash
python3 scripts/generate_datasets.py --verify
```

### Krok 3: Wykonanie testów w maszynie VM

- **Szybka weryfikacja poprawności (Smoke Test, ~1 min):**
  ```bash
  python3 scripts/run_benchmarks.py --profile smoke
  ```

- **Oficjalne pomiary do pracy magisterskiej (50 powtórzeń, losowa permutacja kolejności):**
  ```bash
  python3 scripts/run_benchmarks.py --profile thesis --shuffle
  ```

---

## 5. Wyniki i artefakty analityczne

Skrypt generuje kompletny zestaw tabel CSV oraz 22 wykresy PNG w rozdzielczości 300 DPI:
- `benchmark_methodology_scores.csv` & `benchmark_cost_efficiency.csv`: Wskaźniki FTS (Fuzzing & Testing Score), PPS (Production Protection Score) oraz narzut chmurowy $C_{cloud}$.
- `benchmark_efficacy_matrix.csv` & `benchmark_efficacy_heatmap.png`: Macierz skuteczności detekcji z precyzyjnym rozróżnieniem domenowym `N/A`.
- `benchmark_efficacy_per_mechanism.csv` & `benchmark_efficacy_per_mechanism.png`: Rzeczywista skuteczność empiryczna wraz z **95% przedziałem ufności Wilsona**.
- `benchmark_pareto_cloud.png`: Przestrzeń kompromisu Pareto między narzutem chmurowym ($C_{cloud}$) a pełnosystemową skutecznością produkcyjną ($S_{sys\_prod}$).
- `benchmark_fts_vs_pps.png`: Porównanie opłacalności wdrożenia w środowisku deweloperskim/CI a środowisku produkcyjnym.
