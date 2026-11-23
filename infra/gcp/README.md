# Google Cloud ARM64 (Google Axion C4A) — Środowisko Badawcze

Ten moduł Terraforma uruchamia najnowocześniejszą maszynę wirtualną **ARMv9-A** w chmurze Google Cloud Platform (GCP) opartą na procesorze **Google Axion** (architektura **ARMv9.2-A / Neoverse-V2**).

Posiada ona sprzętowe wsparcie dla mechanizmów bezpieczeństwa ARMv9: **PAC, BTI oraz MTE** (odpowiednik Azure Cobalt 100).

---

## 🚀 Uruchomienie krok po kroku

### 1. Inicjalizacja i uruchomienie maszyny
Przejdź do tego katalogu:
```bash
cd infra/gcp
terraform apply -auto-approve
```

Terraform w około 60-90 sekund:
1. Skonfiguruje dedykowaną sieć i firewall (SSH).
2. Wygeneruje bezpieczny klucz SSH `id_gcp_rsa`.
3. Uruchomi instancję **Google Axion `c4a-standard-4`** (4 vCPU, 16 GB DDR5 RAM, Hyperdisk Balanced) w strefie `europe-west4-b` (Holandia).
4. Przekaże skrypt `cloud-init`, który zainstaluje `clang`, `lld`, `cmake` i sklonuje Twoje repozytorium do `/home/piotr/Master-Thesis`.

### 2. Weryfikacja flag procesora (MTE / PAC / BTI)
Po zakończeniu wdrożenia Terraform wyświetli gotowe polecenie:
```bash
ssh -i id_gcp_rsa -o StrictHostKeyChecking=no piotr@<PUBLIC_IP> "lscpu && grep -E '(mte|paca|pacg|bti)' /proc/cpuinfo"
```

### 3. Połączenie przez SSH i uruchomienie pomiarów
```bash
ssh -i id_gcp_rsa -o StrictHostKeyChecking=no piotr@<PUBLIC_IP>
```
Wewnątrz maszyny:
```bash
cd ~/Master-Thesis
python3 scripts/run_benchmarks.py --profile thesis --output-dir results/gcp_axion_c4a
```

### 4. Pobranie wyników na laptopa
Z poziomu Twojego laptopa:
```bash
scp -i infra/gcp/id_gcp_rsa -r piotr@<PUBLIC_IP>:/home/piotr/Master-Thesis/results/gcp_axion_c4a ./results/
```

### 5. Zgaszenie maszyny (Koszty!)
```bash
terraform destroy -auto-approve
```
