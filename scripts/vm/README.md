# Środowisko QEMU ARM64 (AArch64) z MTE, PAC i BTI

To środowisko uruchamia pełną maszynę wirtualną **ARM64** na Twojej Fedorze za pomocą emulatora QEMU, ze sprzętową emulacją:
- **ARM MTE (Memory Tagging Extension)** (`-machine virt,mte=on`)
- **ARM PAC (Pointer Authentication)** (`-cpu max`)
- **ARM BTI (Branch Target Identification)** (`-cpu max`)

---

## 🚀 Instrukcja krok po kroku

### Krok 1: Instalacja zależności na Fedorze (jednorazowo)
W terminalu na swoim laptopie uruchom:
```bash
./scripts/vm/setup_host.sh
```
Zainstaluje to: `qemu-system-aarch64`, `edk2-aarch64`, `genisoimage` itp.

---

### Krok 2: Przygotowanie dysku i obrazu Ubuntu ARM64 (jednorazowo)
W terminalu na swoim laptopie uruchom:
```bash
./scripts/vm/init_vm.sh
```
Skrypt automatycznie:
- Pobierze oficjalny minimalny obraz **Ubuntu 24.04 LTS (Noble) ARM64** (~650 MB).
- Skonfiguruje użytkownika `piotr` (hasło: `thesis`, sudo bez hasła).
- Przygotuje automatyczną instalację `clang`, `cmake`, `python3-pandas`, itp.
- Skonfiguruje automatyczne montowanie Twojego repozytorium pod `/home/piotr/Master-Thesis`.

---

### Krok 3: Uruchomienie maszyny wirtualnej
W terminalu na laptopie:
```bash
./scripts/vm/start_vm.sh
```
* **Pierwsze uruchomienie:** Może potrwać 2–3 minuty, ponieważ `cloud-init` w tle instaluje pakiety (`clang`, `cmake`).
* **Wyjście z konsoli QEMU:** Wciśnij skrót `Ctrl + A`, a następnie klawisz `X`.

---

### Krok 4: Połączenie przez SSH (opcjonalne, najwygodniejsze)
Możesz zostawić maszynę działającą w jednym oknie terminala, a w drugim oknie połączyć się przez SSH:
```bash
./scripts/vm/connect_vm.sh
```
(lub ręcznie: `ssh -p 2222 piotr@localhost`, hasło: `thesis`).

---

### Krok 5: Kompilacja i testy wewnątrz maszyny ARM64
Gdy jesteś zalogowany w maszynie wirtualnej:
```bash
cd ~/Master-Thesis
mkdir -p build && cd build
CC=clang CXX=clang++ cmake ..
make -j4
```

A następnie uruchomienie benchmarków:
```bash
python3 ../scripts/run_benchmarks.py
```
Pliki wynikowe zapiszą się bezpośrednio w Twoim projekcie na laptopie!
