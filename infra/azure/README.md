# Azure ARM64 (Microsoft Cobalt 100) — Środowisko Badawcze

Ten moduł Terraforma uruchamia maszynę wirtualną **ARM64** w chmurze Microsoft Azure z procesorem **Microsoft Cobalt 100** (architektura **ARMv9-A / Neoverse-N2**).

## 🚀 Uruchomienie krok po kroku

### 1. Logowanie do konta Azure (jednorazowo przed pracą)
```bash
az login
```

### 2. Inicjalizacja i uruchomienie maszyny
Przejdź do tego katalogu:
```bash
cd infra/azure
terraform init
terraform apply -auto-approve
```

Terraform w około 60-90 sekund:
1. Utworzy bezpieczną grupę zasobów i sieć.
2. Wygeneruje lokalny klucz SSH `id_cobalt_rsa`.
3. Uruchomi maszynę **`Standard_D2ps_v6`** (Cobalt 100, 2 vCPU, 8 GB RAM) w regionie `swedencentral`.
4. Przekaże skrypt `cloud-init`, który sam zainstaluje `clang`, `cmake`, `lld` i sklonuje Twoje repozytorium do `/home/piotr/Master-Thesis`.

### 3. Weryfikacja flag procesora (MTE / PAC / BTI)
Po zakończeniu `terraform apply` wyświetli się gotowe polecenie do weryfikacji flag CPU. Możesz je uruchomić od razu:
```bash
ssh -i id_cobalt_rsa -o StrictHostKeyChecking=no piotr@<PUBLIC_IP> "lscpu && grep -E '(mte|paca|pacg|bti)' /proc/cpuinfo"
```

### 4. Połączenie przez SSH i uruchomienie pomiarów
```bash
ssh -i id_cobalt_rsa -o StrictHostKeyChecking=no piotr@<PUBLIC_IP>
```
Wewnątrz maszyny:
```bash
cd ~/Master-Thesis
# Uruchomienie badań (dane zapiszą się w results/azure_cobalt100):
python3 scripts/run_benchmarks.py --profile thesis --output-dir results/azure_cobalt100
```

### 5. Pobranie wyników na laptopa
Z poziomu Twojego laptopa:
```bash
scp -i infra/azure/id_cobalt_rsa -r piotr@<PUBLIC_IP>:/home/piotr/Master-Thesis/results/azure_cobalt100 ./results/
```

### 6. Zgaszenie maszyny (Kluczowy krok finansowy!)
Gdy skończysz testy i pobierzesz pliki z wynikami:
```bash
terraform destroy -auto-approve
```
To jedno polecenie całkowicie usuwa maszynę, dysk i adres IP.

