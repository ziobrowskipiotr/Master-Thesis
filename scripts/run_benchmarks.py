#!/usr/bin/env python3
"""
Benchmark mechanizmów bezpieczeństwa pamięci ARM64 i autorska metodyka oceny opłacalności.
Wersja zoptymalizowana, w pełni spójna z CMakeLists.txt i rygorystyczna metodologicznie.
"""

import subprocess
import re
import sys
import argparse
import os
import platform
import time
import json
import warnings
import numpy as np

# Wymuszenie natychmiastowego buforowania liniowego (brak opóźnień w terminalu)
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(line_buffering=True)
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(line_buffering=True)

# Filtrujemy ostrzeżenia matplotlib/seaborn
warnings.filterwarnings("ignore", message=".*Tight layout not applied.*")
warnings.filterwarnings("ignore", category=UserWarning)

# Bezpieczne opcje dla alokatora Scudo na Linuksie (glibc / QEMU)
os.environ['SCUDO_OPTIONS'] = 'delete_size_mismatch=false:dealloc_type_mismatch=false:quarantine_size_kb=0:thread_local_quarantine_size_kb=0'
os.environ['LIBC_FATAL_STDERR_'] = '1'
os.environ['ASAN_OPTIONS'] = 'detect_stack_use_after_return=1'


def extract_mechanism(variant):
    """
    Jednoznacznie wyodrębnia nazwę mechanizmu z nazwy wariantu lub binarki.
    Sprawdza najdłuższe nazwy w pierwszej kolejności, zapobiegając błędnemu przypisaniu
    'pac_bti' lub 'cfi_pac_bti' do krótkiego 'bti', a także precyzyjnie obsługuje 'bypass_*'.
    """
    var_str = str(variant)

    if 'bypass_cfi' in var_str:
        return 'cfi'
    if 'bypass_lto' in var_str:
        return 'lto'
    if 'bypass_base' in var_str:
        return 'base'

    ordered_mechs = [
        'cfi_pac_bti_mte_fortify_bounds',
        'cfi_pac_bti_mte',
        'cfi_pac_bti',
        'pac_bti',
        'mte_async',
        'mte_sync',
        'scudo',
        'canary',
        'hwasan',
        'asan',
        'cfi',
        'pac',
        'bti',
        'lto',
        'base',
    ]

    for m in ordered_mechs:
        if var_str == m or var_str.endswith('_' + m):
            return m

    parts = var_str.split('_')
    if len(parts) >= 3:
        return '_'.join(parts[2:])
    return 'base'


def variant_sort_key(var_name):
    """Sortuje warianty logicznie do tabel i wykresów: base -> kompilatorowe -> sprzętowe -> sanitizery."""
    order_map = {
        'base': 0,
        'bypass_base': 1,
        'lto': 10,
        'bypass_lto': 11,
        'canary': 12,
        'cfi': 14,
        'bypass_cfi': 15,
        'pac': 20,
        'bti': 21,
        'pac_bti': 22,
        'cfi_pac_bti': 24,
        'mte_async': 26,
        'mte_sync': 27,
        'cfi_pac_bti_mte': 28,
        'cfi_pac_bti_mte_fortify_bounds': 29,
        'scudo': 30,
        'hwasan': 31,
        'asan': 32,
    }
    mech = extract_mechanism(var_name)
    if mech in order_map:
        return (order_map[mech], var_name)
    for k, v in sorted(order_map.items(), key=lambda x: len(x[0]), reverse=True):
        if str(var_name).endswith('_' + k) or var_name == k:
            return (v, var_name)
    return (99, var_name)


def wilson_score_interval(successes, total, confidence=0.95):
    """
    Oblicza 95% dwustronny przedział ufności Wilsona dla proporcji dwumianowej.
    Dla małych prób (np. 5/5) i testów probabilistycznych (MTE 15/16) daje rzetelne oszacowanie.
    """
    if total <= 0:
        return 0.0, 0.0
    z = 1.95996  # 95% poziom ufności
    p = float(successes) / float(total)
    denominator = 1.0 + (z**2) / total
    center = (p + (z**2) / (2.0 * total)) / denominator
    factor = (p * (1.0 - p) / total) + ((z**2) / (4.0 * (total**2)))
    spread = (z * np.sqrt(max(0.0, factor))) / denominator
    lower = max(0.0, center - spread)
    upper = min(1.0, center + spread)
    return round(lower * 100.0, 1), round(upper * 100.0, 1)


def get_binary_metrics(executable):
    """Zwraca (rozmiar_sekcji_.text_B, rozmiar_calkowity_binarki_B)."""
    bin_path = f'./build/{executable}'
    text_size = None
    total_size = None

    try:
        total_size = os.path.getsize(bin_path)
    except OSError:
        pass

    try:
        result = subprocess.run(['readelf', '-WS', bin_path], capture_output=True, text=True, check=True)
        for line in result.stdout.splitlines():
            if '.text' in line:
                parts = line.split()
                try:
                    idx = parts.index('.text')
                    text_size = int(parts[idx + 4], 16)
                    break
                except (ValueError, IndexError):
                    pass
    except Exception:
        pass

    return text_size, total_size


def run_performance_test(executable, dataset_or_iters, args=[]):
    """Wykonuje pojedynczy pomiar wydajności (czas wewnętrzny, czas przetwarzania, Peak RSS)."""
    cmd = ['/usr/bin/time', '-v', f'./build/{executable}']
    if isinstance(dataset_or_iters, str):
        cmd.append(dataset_or_iters)
    elif isinstance(dataset_or_iters, int):
        cmd.append(str(dataset_or_iters))
    cmd.extend(args)

    env = os.environ.copy()
    env['SCUDO_OPTIONS'] = 'delete_size_mismatch=false:dealloc_type_mismatch=false:quarantine_size_kb=0:thread_local_quarantine_size_kb=0'

    result = subprocess.run(cmd, capture_output=True, text=True, env=env)

    if result.returncode != 0:
        return {'Wariant': executable, 'ReturnCode': result.returncode, 'Error': True, 'Stderr': result.stderr}

    internal_time_ns = 0
    alloc_time_ns = 0
    proc_time_ns = 0
    clean_time_ns = 0
    for line in result.stdout.splitlines():
        if "Czas_" in line and "_ns:" in line:
            match = re.search(r'(\d+)$', line)
            if match:
                val = int(match.group(1))
                internal_time_ns += val
                if "Czas_Alokacji_ns" in line:
                    alloc_time_ns = val
                elif "Czas_Przetwarzania_ns" in line:
                    proc_time_ns = val
                elif "Czas_Sprzatania_ns" in line:
                    clean_time_ns = val

    rss_match = re.search(r'Maximum resident set size \(kbytes\): (\d+)', result.stderr)
    rss_kb = int(rss_match.group(1)) if rss_match else 0

    return {
        'Wariant': executable,
        'ReturnCode': result.returncode,
        'Czas Wewnętrzny (s)': internal_time_ns / 1_000_000_000.0,
        'Czas Przetwarzania (s)': (proc_time_ns if proc_time_ns > 0 else internal_time_ns) / 1_000_000_000.0,
        'Czas Alokacji (s)': alloc_time_ns / 1_000_000_000.0,
        'Czas Sprzatania (s)': clean_time_ns / 1_000_000_000.0,
        'RAM (KB)': rss_kb,
        'Error': False
    }


def evaluate_single_run(executable, dataset_or_iters, args=[]):
    """
    Rygorystyczna ocena pojedynczej próby ataku.
    Rozróżnia:
      1. Błąd środowiska uruchomieniowego (inicjalizacja HWASan/MTE/glibc) -> TEST NIEWAŻNY
      2. Wykonanie ładunku ataku ([EXPLOIT_SUCCESS]):
         - ret == 0: Pełny sukces ataku (OMINIĘTO)
         - ret != 0: Ładunek wykonany, po czym nastąpiła opóźniona detekcja / awaria
      3. Zablokowanie przez mechanizmy ochronne (ASan, HWASan, Stack Canary, Fortify, Scudo, MTE, CFI, BTI, PAC)
      4. Zakończenie z kodem 0 bez ładunku (OMINIĘTO)
      5. Niepotwierdzona awaria (CRASH/AWARIA bez jednoznacznej sygnatury zabezpieczenia)
    """
    cmd = [f'./build/{executable}']
    if isinstance(dataset_or_iters, str):
        cmd.append(dataset_or_iters)
    elif isinstance(dataset_or_iters, int):
        cmd.append(str(dataset_or_iters))
    cmd.extend(args)

    env = os.environ.copy()
    env['SCUDO_OPTIONS'] = 'delete_size_mismatch=false:dealloc_type_mismatch=false:quarantine_size_kb=0:thread_local_quarantine_size_kb=0'
    env['LIBC_FATAL_STDERR_'] = '1'
    env['ASAN_OPTIONS'] = 'detect_stack_use_after_return=1'

    result = subprocess.run(cmd, capture_output=True, text=True, env=env)
    stdout = result.stdout
    stderr = result.stderr
    ret = result.returncode

    sig = None
    if ret < 0:
        sig = -ret
    elif ret in [4, 5, 6, 7, 11]:
        sig = ret
    elif ret in [132, 133, 134, 135, 139]:
        sig = ret - 128

    sig_map = {4: "SIGILL", 5: "SIGTRAP", 6: "SIGABRT", 7: "SIGBUS", 11: "SIGSEGV"}
    sig_name = sig_map.get(sig, f"SIG({sig})" if sig else "Brak")

    exploit_success = ("[EXPLOIT_SUCCESS]" in stdout or "[EXPLOIT_SUCCESS]" in stderr)

    # 1. Kontrola błędów środowiska (nieudana aktywacja środowiska / runtime)
    if ret == 1 and ("HWAddressSanitizer: failed to" in stderr or "failed to allocate shadow" in stderr):
        return False, "BŁĄD ŚRODOWISKA (HWASan: błąd inicjalizacji pamięci cienia)", "Błąd środowiska", sig_name, ret

    if "[!] OSTRZEŻENIE: prctl(PR_SET_TAGGED_ADDR_CTRL) nie powiodło się" in stderr:
        return False, "BŁĄD ŚRODOWISKA (Błąd aktywacji MTE w prctl)", "Błąd środowiska", sig_name, ret

    if ret == 127:
        return False, "BŁĄD ŚRODOWISKA (Brak pliku wykonywalnego lub biblioteki, kod 127)", "Błąd środowiska", sig_name, ret

    # 2. Wykrycie wykonania ładunku ataku ([EXPLOIT_SUCCESS])
    if exploit_success:
        if ret == 0:
            return False, "OMINIĘTO (Atak powiódł się - wykonano ładunek)", "Brak", sig_name, ret
        else:
            # Ładunek zdołał się wykonać (brak prewencji), ale nastąpiła opóźniona detekcja / crash (np. MTE async)
            return False, f"OMINIĘTO (Wykonano ładunek, po czym nastąpiła awaria {sig_name}, kod {ret})", "Opóźniona detekcja", sig_name, ret

    # 3. Raport sanitizera ASan / HWASan (wyłącznie gdy proces zakończył się błędem)
    sanitizer_error = "Brak"
    for line in stderr.splitlines():
        san_match = re.search(
            r'(AddressSanitizer|HWAddressSanitizer):\s+'
            r'(heap-buffer-overflow|stack-buffer-overflow|global-buffer-overflow'
            r'|heap-use-after-free|stack-use-after-scope|stack-use-after-return|double-free'
            r'|attempting free on address|SEGV on unknown address|tag-mismatch)',
            line
        )
        if san_match:
            sanitizer_error = f"{san_match.group(1)}: {san_match.group(2)}"
            break

    if sanitizer_error != "Brak" and ret != 0:
        return True, f"ZABLOKOWANO ({sanitizer_error})", sanitizer_error, sig_name, ret

    if (("ERROR: AddressSanitizer:" in stderr or "ERROR: HWAddressSanitizer:" in stderr) or (ret == 99 and 'hwasan' in executable)) and ret != 0:
        return True, "ZABLOKOWANO (Sanitizer report)", "Sanitizer Report", sig_name, ret

    # 4. Stack smashing detected (Stack Canary)
    if ("stack smashing detected" in stderr or "__stack_chk_fail" in stderr) and ret != 0:
        return True, "ZABLOKOWANO (Stack Canary: naruszenie stosu)", "Canary __stack_chk_fail", sig_name, ret

    # 5. Fortify Source: wykrycie przepełnienia bufora
    if "buffer overflow detected" in stderr and ret != 0:
        return True, "ZABLOKOWANO (Fortify Source: naruszenie bufora)", "Fortify Source", sig_name, ret

    # 6. Scudo Memory Allocator
    if ("Scudo ERROR:" in stderr or "Scudo error:" in stderr) and ret != 0:
        return True, "ZABLOKOWANO (Scudo: naruszenie spójności sterty)", "Scudo Abort", sig_name, ret

    # 7. Sprzętowe MTE (SEGV_MTESERR / SEGV_MTEAERR)
    # Wykrywamy rzeczywisty trap błędu tagu zgłoszony przez procesor / kernel fault handler,
    # a NIE tekst powitalny konstruktora [SECURITY_INIT]!
    is_mte_sync_trap = (
        (ret in [139, 11, -11]) and (
            ("[SECURITY_TRAP]" in stderr and "SEGV_MTESERR" in stderr) or
            ("si_code): 9" in stderr) or
            ("si_code): SEGV_MTESERR" in stderr) or
            ("SEGV_MTESERR" in stderr and "[SECURITY_INIT]" not in stderr)
        )
    )
    is_mte_async_trap = (
        (ret in [139, 11, -11]) and (
            ("[SECURITY_TRAP]" in stderr and "SEGV_MTEAERR" in stderr) or
            ("si_code): 8" in stderr) or
            ("si_code): SEGV_MTEAERR" in stderr) or
            ("SEGV_MTEAERR" in stderr and "[SECURITY_INIT]" not in stderr)
        )
    )

    if is_mte_sync_trap:
        if '_base' in executable or '_lto' in executable:
            return False, f"CRASH (Awaria niechroniona: {sig_name}, kod {ret})", "Brak", sig_name, ret
        return True, "ZABLOKOWANO (MTE: synchroniczny błąd tagu SEGV_MTESERR)", "MTE Sync Tag Fault", sig_name, ret

    if is_mte_async_trap:
        if '_base' in executable or '_lto' in executable:
            return False, f"CRASH (Awaria niechroniona: {sig_name}, kod {ret})", "Brak", sig_name, ret
        return True, "ZABLOKOWANO (MTE: asynchroniczny błąd tagu SEGV_MTEAERR)", "MTE Async Tag Fault", sig_name, ret

    # 8. Sygnały przechwycone przez nasz fault handler ze znacznikiem [SECURITY_TRAP]
    # lub bezpośrednie sygnały sprzętowe architektury AArch64 (SIGILL=4/132, SIGTRAP=5/133, SIGBUS=7/135)
    is_sec_trap = ("[SECURITY_TRAP]" in stderr) or (sig in [4, 5, 7]) or (ret in [132, 133, 135])
    if is_sec_trap and ret != 0:
        if '_base' in executable or '_lto' in executable:
            return False, f"CRASH (Awaria niechroniona: {sig_name}, kod {ret})", "Brak", sig_name, ret

        if any(k in executable for k in ['cfi', 'cfi_pac_bti', 'cfi_pac_bti_mte', 'cfi_pac_bti_mte_fortify_bounds']) and any(k in executable for k in ['_D2_', '_D3_', '_D4_']) and (sig in [4, 5] or ret in [132, 133]):
            return True, f"ZABLOKOWANO (CFI: pułapka kompilatora / nielegalny skok {sig_name})", "CFI Trap", sig_name, ret

        if any(k in executable for k in ['bti', 'pac_bti', 'cfi_pac_bti', 'cfi_pac_bti_mte', 'cfi_pac_bti_mte_fortify_bounds']) and '_D4_' in executable and (sig in [4, 5] or ret in [132, 133]):
            return True, f"ZABLOKOWANO (BTI: skok bez instrukcji lądowiska {sig_name})", "BTI Branch Fault", sig_name, ret

        if any(k in executable for k in ['pac', 'pac_bti', 'cfi_pac_bti', 'cfi_pac_bti_mte', 'cfi_pac_bti_mte_fortify_bounds']) and '_D1_' in executable and (sig in [4, 7, 11] or ret in [132, 135, 139]):
            return True, f"ZABLOKOWANO (PAC: błąd autoryzacji adresu {sig_name})", "PAC Auth Fault", sig_name, ret

    # 9. Czyste wyjście z kodem 0 (brak ładunku i brak błędu)
    if ret == 0:
        return False, "OMINIĘTO (Zakończono poprawnie bez wykrycia, kod 0)", "Brak", "Brak", 0

    # 10. Niepotwierdzona awaria (Crash bez jednoznacznego sygnału ochrony)
    return False, f"AWARIA (Crash niepotwierdzony: {sig_name}, kod {ret})", "Brak", sig_name, ret


def run_efficacy_test(executable, dataset_or_iters, trials=5, args=[]):
    blocked_count = 0
    statuses = []
    last_sanitizer = "Brak"
    last_sig = "Brak"
    last_ret = 0

    log_file = "benchmark_trials_log.csv"
    log_exists = os.path.exists(log_file)
    with open(log_file, "a", encoding="utf-8") as f_log:
        if not log_exists:
            f_log.write("timestamp,executable,trial_idx,blocked,status,sanitizer,signal,returncode\n")

        for trial_idx in range(trials):
            blocked, status, san, sig, ret = evaluate_single_run(executable, dataset_or_iters, args)
            if blocked:
                blocked_count += 1
            statuses.append(status)
            if san != "Brak":
                last_sanitizer = san
            last_sig = sig
            last_ret = ret

            ts = time.strftime("%Y-%m-%d %H:%M:%S")
            clean_status = status.replace('"', '""')
            f_log.write(f'"{ts}","{executable}",{trial_idx + 1},{int(blocked)},"{clean_status}","{san}","{sig}",{ret}\n')

    eff_percent = (blocked_count / trials) * 100.0
    common_status = max(set(statuses), key=statuses.count)
    summary_status = f"{common_status} ({blocked_count}/{trials})"

    return {
        'Wariant': executable,
        'Status': summary_status,
        'Zablokowano': 1 if blocked_count == trials else (0 if blocked_count == 0 else 0.5),
        'Skutecznosc_Procent': eff_percent,
        'Zablokowane_Proby': blocked_count,
        'Liczba_Prob': trials,
        'Sanitizer': last_sanitizer,
        'Sygnal': last_sig,
        'PC': "Brak",
        'ReturnCode': last_ret
    }


def gather_environment_metadata():
    """Zbiera pełne metadane środowiska uruchomieniowego i narzędzi."""
    meta = {
        'timestamp': time.strftime("%Y-%m-%d %H:%M:%S"),
        'host_architecture': platform.machine(),
        'platform': platform.platform(),
        'processor': platform.processor(),
        'python_version': platform.python_version(),
    }
    try:
        with open('/proc/cpuinfo', 'r') as f:
            cpuinfo = f.read()
            meta['cpuinfo_features'] = [l.strip() for l in cpuinfo.splitlines() if 'Features' in l or 'Hardware' in l][:3]
    except Exception:
        meta['cpuinfo_features'] = []

    try:
        clang_out = subprocess.run(['clang', '--version'], capture_output=True, text=True).stdout.splitlines()[0]
        meta['clang_version'] = clang_out
    except Exception:
        meta['clang_version'] = 'Unknown'

    meta['emulation_note'] = (
        "Środowisko badawcze: QEMU AArch64 System Emulation z włączonym MTE (mte=on) oraz PAC/BTI (-cpu max). "
        "W przypadku hosta x86_64 emulator działa w trybie TCG (Tiny Code Generator), co oznacza programową emulację "
        "instrukcji ARM64. Pomiary czasu odzwierciedlają narzut emulacji w TCG."
    )
    return meta


# ============================================================================
# GŁÓWNA LOGIKA
# ============================================================================

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Benchmark mechanizmów bezpieczeństwa pamięci ARM64 i autorska ocena opłacalności chmurowej."
    )
    parser.add_argument(
        '--profile', '-P',
        choices=['smoke', 'quick', 'standard', 'full', 'thesis'],
        default='standard',
        help="Profil testu: 'smoke' (1 powtórzenie, weryfikacja poprawności), 'quick' (5 powtórzeń), 'standard' (30 powtórzeń), 'thesis' (50 powtórzeń)."
    )
    parser.add_argument(
        '--runs', '-n',
        type=int,
        default=None,
        help="Ujednolicona liczba powtórzeń (ustawia iteracje wydajności i próby ataków)."
    )
    parser.add_argument(
        '--iterations', '-i',
        type=int,
        default=None,
        help="Liczba powtórzeń testów wydajnościowych."
    )
    parser.add_argument(
        '--trials', '-t',
        type=int,
        default=None,
        help="Liczba prób w testach ataków."
    )
    parser.add_argument(
        '--warmup', '-w',
        type=int,
        default=None,
        help="Liczba przebiegów rozgrzewkowych (domyślnie 3)."
    )
    parser.add_argument(
        '--dataset', '-d',
        choices=['small', 'medium', 'large'],
        default='small',
        help="Zbiór danych dla parsera (domyślnie 'small')."
    )
    parser.add_argument(
        '--shuffle',
        action='store_true',
        help="Losowa kolejność wykonywania wariantów (eliminuje dryf obciążenia hosta)."
    )
    parser.add_argument(
        '--plots-only', '-p',
        action='store_true',
        help="Generuje tylko wykresy i tabele z istniejących plików CSV."
    )
    parser.add_argument(
        '--efficacy-only', '-e',
        action='store_true',
        help="Uruchamia wyłącznie testy skuteczności ataków."
    )
    parser.add_argument(
        '--perf-only',
        action='store_true',
        help="Uruchamia wyłącznie testy wydajnościowe."
    )
    args = parser.parse_args()

    # Domyślne mapowanie parametrów
    profile_defaults = {
        'smoke':    {'runs': 1,  'warmup': 0, 'dataset': 'small'},
        'quick':    {'runs': 5,  'warmup': 1, 'dataset': 'small'},
        'standard': {'runs': 30, 'warmup': 3, 'dataset': 'small'},
        'full':     {'runs': 30, 'warmup': 3, 'dataset': 'large'},
        'thesis':   {'runs': 50, 'warmup': 3, 'dataset': 'large'},
    }
    prof = profile_defaults[args.profile]
    runs = args.runs or prof['runs']
    runs_count = args.iterations or runs
    trials_count = args.trials or runs
    warmup_count = args.warmup if args.warmup is not None else prof['warmup']
    dataset_name = args.dataset if args.dataset != 'small' else prof['dataset']
    plots_only = args.plots_only

    dataset_perf = f"data/dataset_{dataset_name}.bin"
    dataset_p1 = "data/dataset_p1_malicious.bin"
    dataset_p2 = "data/dataset_p2_malicious.bin"
    dataset_p3 = "data/dataset_p3_malicious.bin"
    dataset_p4 = "data/dataset_p4_malicious.bin"
    dataset_p5 = "data/dataset_p5_malicious.bin"
    dataset_p6 = "data/dataset_p6_malicious.bin"

    print("=" * 75)
    print("   BENCHMARK MECHANIZMÓW BEZPIECZEŃSTWA PAMIĘCI W ARM64")
    print(f"   Profil: {args.profile} | Powtórzenia wydajności: {runs_count} | Próby ataków: {trials_count}")
    print(f"   Dataset: {dataset_perf} | Rozgrzewka: {warmup_count} | Shuffle: {args.shuffle}")
    print("=" * 75)

    # Zapis metadanych środowiska (wyłącznie przy rzeczywistym wykonaniu testów)
    if not plots_only:
        env_meta = gather_environment_metadata()
        env_meta['profile'] = args.profile
        env_meta['runs_count'] = runs_count
        env_meta['trials_count'] = trials_count
        with open("benchmark_environment.json", "w") as f:
            json.dump(env_meta, f, indent=2)
    else:
        if os.path.exists("benchmark_environment.json"):
            print("  [INFO] Tryb --plots-only: zachowano oryginalny plik benchmark_environment.json.")
            try:
                with open("benchmark_environment.json", "r") as f:
                    old_meta = json.load(f)
                    print(f"  [INFO] Pochodzenie danych z benchmark_environment.json: platforma={old_meta.get('platform')}, timestamp={old_meta.get('timestamp')}")
            except Exception:
                pass

    perf_apps = {
        'Parser': ([
            'parser_P0_base', 'parser_P0_canary', 'parser_P0_scudo',
            'parser_P0_mte_async', 'parser_P0_mte_sync',
            'parser_P0_cfi_pac_bti_mte', 'parser_P0_cfi_pac_bti_mte_fortify_bounds',
            'parser_P0_hwasan', 'parser_P0_asan'
        ], dataset_perf),
        'KV_Store': ([
            'kv_M0_base', 'kv_M0_canary', 'kv_M0_mte_async', 'kv_M0_mte_sync',
            'kv_M0_scudo', 'kv_M0_cfi_pac_bti_mte', 'kv_M0_cfi_pac_bti_mte_fortify_bounds',
            'kv_M0_hwasan', 'kv_M0_asan'
        ], 10000),
        'Dispatcher': ([
            'disp_D0_base', 'disp_D0_canary', 'disp_D0_lto', 'disp_D0_cfi',
            'disp_D0_pac', 'disp_D0_bti', 'disp_D0_pac_bti',
            'disp_D0_cfi_pac_bti', 'disp_D0_cfi_pac_bti_mte',
            'disp_D0_cfi_pac_bti_mte_fortify_bounds', 'disp_D0_asan'
        ], 500000)
    }

    efficacy_apps = {
        # --- PARSER: błędy pamięci przestrzenne (spatial) ---
        'P1_heap_overflow': ([
            'parser_P1_base', 'parser_P1_asan', 'parser_P1_hwasan',
            'parser_P1_mte_sync', 'parser_P1_mte_async',
            'parser_P1_canary', 'parser_P1_scudo',
            'parser_P1_cfi_pac_bti_mte', 'parser_P1_cfi_pac_bti_mte_fortify_bounds'
        ], dataset_p1),
        'P2_stack_overflow': ([
            'parser_P2_base', 'parser_P2_asan', 'parser_P2_hwasan',
            'parser_P2_mte_sync', 'parser_P2_mte_async',
            'parser_P2_canary',
            'parser_P2_cfi_pac_bti_mte', 'parser_P2_cfi_pac_bti_mte_fortify_bounds'
        ], dataset_p2),
        'P3_global_overflow': ([
            'parser_P3_base', 'parser_P3_asan', 'parser_P3_hwasan',
            'parser_P3_mte_sync', 'parser_P3_mte_async',
            'parser_P3_canary', 'parser_P3_scudo',
            'parser_P3_cfi_pac_bti_mte', 'parser_P3_cfi_pac_bti_mte_fortify_bounds'
        ], dataset_p3),
        'P4_heap_oob_read': ([
            'parser_P4_base', 'parser_P4_asan', 'parser_P4_hwasan',
            'parser_P4_mte_sync', 'parser_P4_mte_async',
            'parser_P4_canary', 'parser_P4_scudo',
            'parser_P4_cfi_pac_bti_mte', 'parser_P4_cfi_pac_bti_mte_fortify_bounds'
        ], dataset_p4),
        'P5_subgranule_overflow': ([
            'parser_P5_base', 'parser_P5_asan', 'parser_P5_hwasan',
            'parser_P5_mte_sync', 'parser_P5_mte_async',
            'parser_P5_canary', 'parser_P5_scudo',
            'parser_P5_cfi_pac_bti_mte', 'parser_P5_cfi_pac_bti_mte_fortify_bounds'
        ], dataset_p5),
        'P6_stack_dop': ([
            'parser_P6_base', 'parser_P6_asan', 'parser_P6_hwasan',
            'parser_P6_mte_sync', 'parser_P6_mte_async',
            'parser_P6_canary',
            'parser_P6_cfi_pac_bti_mte', 'parser_P6_cfi_pac_bti_mte_fortify_bounds'
        ], dataset_p6),

        # --- KV STORE: błędy pamięci temporalne (temporal) ---
        'M1_use_after_free': ([
            'kv_M1_base', 'kv_M1_asan', 'kv_M1_hwasan',
            'kv_M1_mte_sync', 'kv_M1_mte_async',
            'kv_M1_scudo', 'kv_M1_canary',
            'kv_M1_cfi_pac_bti_mte', 'kv_M1_cfi_pac_bti_mte_fortify_bounds'
        ], 500),
        'M2_double_free': ([
            'kv_M2_base', 'kv_M2_asan', 'kv_M2_hwasan',
            'kv_M2_scudo', 'kv_M2_mte_sync', 'kv_M2_mte_async',
            'kv_M2_canary',
            'kv_M2_cfi_pac_bti_mte', 'kv_M2_cfi_pac_bti_mte_fortify_bounds'
        ], 500),
        'M3_stack_use_after_scope': ([
            'kv_M3_base', 'kv_M3_asan', 'kv_M3_hwasan',
            'kv_M3_scudo', 'kv_M3_mte_sync', 'kv_M3_mte_async',
            'kv_M3_canary',
            'kv_M3_cfi_pac_bti_mte', 'kv_M3_cfi_pac_bti_mte_fortify_bounds'
        ], 500),

        # --- DISPATCHER: ataki na przepływ sterowania (control flow) ---
        'D1_stack_smash': ([
            'disp_D1_base', 'disp_D1_pac', 'disp_D1_bti', 'disp_D1_pac_bti',
            'disp_D1_canary', 'disp_D1_cfi_pac_bti',
            'disp_D1_cfi_pac_bti_mte', 'disp_D1_cfi_pac_bti_mte_fortify_bounds',
            'disp_D1_asan'
        ], 1),
        'D2_indirect_call_hijack': ([
            'disp_D2_base', 'disp_D2_lto', 'disp_D2_cfi',
            'disp_D2_bti', 'disp_D2_pac_bti',
            'disp_D2_cfi_pac_bti', 'disp_D2_cfi_pac_bti_mte',
            'disp_D2_cfi_pac_bti_mte_fortify_bounds'
        ], 1),
        'D2_bypass_cfi': ([
            'disp_D2_bypass_base', 'disp_D2_bypass_lto', 'disp_D2_bypass_cfi'
        ], 1),
        'D3_vtable_hijack': ([
            'disp_D3_base', 'disp_D3_lto', 'disp_D3_cfi',
            'disp_D3_cfi_pac_bti', 'disp_D3_cfi_pac_bti_mte',
            'disp_D3_cfi_pac_bti_mte_fortify_bounds'
        ], 1),
        'D4_bti_landing': ([
            'disp_D4_base', 'disp_D4_pac', 'disp_D4_bti', 'disp_D4_pac_bti',
            'disp_D4_cfi', 'disp_D4_lto',
            'disp_D4_cfi_pac_bti', 'disp_D4_cfi_pac_bti_mte',
            'disp_D4_cfi_pac_bti_mte_fortify_bounds'
        ], 1),
    }

    ATTACK_CLASSES = {
        'P1_heap_overflow': 'Spatial (pamięć)',
        'P2_stack_overflow': 'Spatial (pamięć)',
        'P3_global_overflow': 'Spatial (pamięć)',
        'P4_heap_oob_read': 'Spatial (pamięć)',
        'P5_subgranule_overflow': 'Spatial (pamięć)',
        'P6_stack_dop': 'Spatial (pamięć)',
        'M1_use_after_free': 'Temporal (pamięć)',
        'M2_double_free': 'Temporal (pamięć)',
        'M3_stack_use_after_scope': 'Temporal (pamięć)',
        'D1_stack_smash': 'Control Flow',
        'D2_indirect_call_hijack': 'Control Flow',
        'D2_bypass_cfi': 'Control Flow (CFI Bypass)',
        'D3_vtable_hijack': 'Control Flow',
        'D4_bti_landing': 'Control Flow',
    }

    # ==================================================================
    # KOMPILACJA BINAREK
    # ==================================================================
    if not plots_only:
        print("\n[+] Weryfikacja i kompilacja celów projektu...")
        import shutil

        # Sprawdzamy czy w cache nie ma konfliktu generatora (np. Unix Makefiles vs Ninja)
        cache_file = "build/CMakeCache.txt"
        if os.path.exists(cache_file):
            try:
                with open(cache_file, "r") as f:
                    ccontent = f.read()
                    if "CMAKE_GENERATOR:INTERNAL=Unix Makefiles" in ccontent:
                        print("  [INFO] Wykryto starszy generator 'Unix Makefiles'. Czyszczenie cache dla 'Ninja'...")
                        os.remove(cache_file)
                        if os.path.exists("build/CMakeFiles"):
                            shutil.rmtree("build/CMakeFiles")
            except Exception:
                pass

        build_success = False
        try:
            if not os.path.exists("build/build.ninja"):
                subprocess.run(["cmake", "-B", "build", "-G", "Ninja"], check=True)
            subprocess.run(["ninja", "-C", "build", "-j4"], check=True)
            build_success = True
            print("  -> Kompilacja Ninja zakończona sukcesem.\n")
        except Exception as e:
            print(f"  [WARN] Pierwsza próba kompilacji Ninja nie powiodła się: {e}")
            print("  [RETRY] Czyszczenie cache i ponowna próba...")
            try:
                if os.path.exists("build/CMakeCache.txt"):
                    os.remove("build/CMakeCache.txt")
                if os.path.exists("build/CMakeFiles"):
                    shutil.rmtree("build/CMakeFiles")
                subprocess.run(["cmake", "-B", "build", "-G", "Ninja"], check=True)
                subprocess.run(["ninja", "-C", "build", "-j4"], check=True)
                build_success = True
                print("  -> Kompilacja Ninja zakończona sukcesem po wyczyszczeniu cache.\n")
            except Exception as e2:
                print(f"  [WARN] Ninja niedostępny lub błąd: {e2}. Próba z klasycznym 'make'...")
                try:
                    if os.path.exists("build/CMakeCache.txt"):
                        os.remove("build/CMakeCache.txt")
                    if os.path.exists("build/CMakeFiles"):
                        shutil.rmtree("build/CMakeFiles")
                    subprocess.run(["cmake", "-B", "build"], check=True)
                    subprocess.run(["make", "-C", "build", "-j4"], check=True)
                    build_success = True
                    print("  -> Kompilacja Make zakończona sukcesem.\n")
                except Exception as e3:
                    print(f"\n  [KRYTYCZNY BŁĄD KOMPILACJI]: {e3}")
                    sys.exit(1)

    # Sprawdzenie obecności pandasa do przetwarzania
    try:
        import pandas as pd
        import matplotlib.pyplot as plt
        import seaborn as sns
        has_plotting = True
    except ImportError:
        print("[!] Brak bibliotek pandas/matplotlib/seaborn w środowisku. Pomiary zostaną zapisane w CSV za pomocą modułu csv.")
        has_plotting = False

    # ==================================================================
    # FAZA 1: METRYKI STATYCZNE (ROZMIAR KODU .TEXT / BINARKI)
    # ==================================================================
    print("=" * 70)
    print("   FAZA 1: METRYKI STATYCZNE (rozmiar binarki / sekcji .text)")
    print("=" * 70)

    binary_metrics = []
    if (plots_only or args.efficacy_only) and os.path.exists("benchmark_binary_size.csv") and has_plotting:
        df_bin = pd.read_csv("benchmark_binary_size.csv")
        binary_metrics = df_bin.to_dict('records')
        print(f"  [CACHE] Załadowano {len(binary_metrics)} wpisów z benchmark_binary_size.csv")
    else:
        all_executables = set()
        for _, (exes, _) in list(perf_apps.items()) + list(efficacy_apps.items()):
            all_executables.update(exes)

        for exe in sorted(all_executables, key=variant_sort_key):
            text_size, total_size = get_binary_metrics(exe)
            if text_size is not None:
                binary_metrics.append({
                    'Wariant': exe,
                    'Rozmiar .text (B)': text_size,
                    'Rozmiar binarki (B)': total_size,
                })
        if binary_metrics and has_plotting:
            df_bin = pd.DataFrame(binary_metrics)
            df_bin.to_csv("benchmark_binary_size.csv", index=False)
            print(f"  -> Zapisano {len(binary_metrics)} wpisów do benchmark_binary_size.csv")

            # Wykresy rozmiaru sekcji .text dla każdej grupy
            for app_group, (executables, _) in perf_apps.items():
                group_data = df_bin[df_bin['Wariant'].isin(executables)].copy()
                if group_data.empty:
                    continue
                group_data['sort_key'] = group_data['Wariant'].apply(variant_sort_key)
                group_data = group_data.sort_values('sort_key', ascending=True)
                kb_values = group_data['Rozmiar .text (B)'] / 1024.0

                fig, ax = plt.subplots(figsize=(12, 5.5))
                colors = sns.color_palette("Set2", len(group_data))
                bars = ax.bar(group_data['Wariant'], kb_values, color=colors, edgecolor='black', linewidth=0.5)
                ax.set_title(f'Rozmiar sekcji kodu (.text) – {app_group}', fontsize=12, fontweight='bold', pad=10)
                ax.set_ylabel('Rozmiar sekcji .text (KB)', fontsize=10, fontweight='bold')
                plt.xticks(rotation=25, ha='right', fontsize=9.5)
                max_h = float(kb_values.max()) if not kb_values.empty else 10.0
                ax.set_ylim(0, max_h * 1.15)
                for bar, val in zip(bars, kb_values):
                    ax.annotate(f'{val:.1f} KB',
                                xy=(bar.get_x() + bar.get_width() / 2, val),
                                xytext=(0, 3), textcoords="offset points",
                                ha='center', va='bottom', fontsize=8.5, fontweight='bold')
                fig.tight_layout()
                fig.savefig(f"benchmark_text_size_{app_group}.png", dpi=300)
                plt.close(fig)

    # ==================================================================
    # FAZA 2: TESTY WYDAJNOŚCI (PERFORMANCE)
    # ==================================================================
    print(f"\n{'=' * 70}")
    print(f"   FAZA 2: TESTY WYDAJNOŚCI (PERFORMANCE)")
    print(f"{'=' * 70}")

    perf_results = []
    if (plots_only or args.efficacy_only) and os.path.exists("benchmark_performance_data.csv") and has_plotting:
        df_raw = pd.read_csv("benchmark_performance_data.csv")
        perf_results = df_raw.to_dict('records')
        print(f"  [CACHE] Załadowano dane wydajnościowe z benchmark_performance_data.csv")
    elif not args.efficacy_only:
        for app_group, (executables, arg) in perf_apps.items():
            print(f"\n[+] Testowanie grupy: {app_group}")
            exec_list = list(executables)

            # Rozgrzewka (Warmup) dla każdego wariantu
            print(f"  Faza rozgrzewki ({warmup_count} przebiegów)...")
            for exe in exec_list:
                for _ in range(warmup_count):
                    run_performance_test(exe, arg)

            # Pomiar z losowaniem blokowym (Randomized Complete Block Design - RCBD)
            print(f"  Faza pomiarowa ({runs_count} iteracji, Randomized Block Design: {args.shuffle})...")
            for iter_idx in range(runs_count):
                block_execs = list(exec_list)
                if args.shuffle:
                    np.random.shuffle(block_execs)

                for exe in block_execs:
                    res = run_performance_test(exe, arg)
                    if res.get('Error'):
                        print(f"    [BŁĄD] Wariant {exe} zakończył się błędem: {res.get('Stderr')}")
                        continue
                    res['Grupa'] = app_group
                    res['Iteracja'] = iter_idx + 1
                    perf_results.append(res)

        if perf_results and has_plotting:
            df_raw = pd.DataFrame(perf_results)
            df_raw.to_csv("benchmark_performance_data.csv", index=False)

    # Przetwarzanie podsumowania wydajności
    if perf_results and has_plotting:
        df_raw = pd.DataFrame(perf_results)
        summary_rows = []
        for app_group in df_raw['Grupa'].unique():
            grp_data = df_raw[df_raw['Grupa'] == app_group]
            base_run = grp_data[grp_data['Wariant'].str.endswith('_base')]
            lto_run = grp_data[grp_data['Wariant'].str.endswith('_lto')]
            base_time = base_run['Czas Wewnętrzny (s)'].median() if not base_run.empty else 1.0
            base_proc = base_run['Czas Przetwarzania (s)'].median() if not base_run.empty else 1.0
            base_ram = base_run['RAM (KB)'].median() if not base_run.empty else 1.0
            lto_time = lto_run['Czas Wewnętrzny (s)'].median() if not lto_run.empty else None

            for var in grp_data['Wariant'].unique():
                var_data = grp_data[grp_data['Wariant'] == var]
                med_time = var_data['Czas Wewnętrzny (s)'].median()
                med_proc = var_data['Czas Przetwarzania (s)'].median()
                med_alloc = var_data['Czas Alokacji (s)'].median()
                med_clean = var_data['Czas Sprzatania (s)'].median()
                mean_time = var_data['Czas Wewnętrzny (s)'].mean()
                std_time = var_data['Czas Wewnętrzny (s)'].std() if len(var_data) > 1 else 0.0
                if len(var_data) > 1:
                    q75, q25 = np.percentile(var_data['Czas Wewnętrzny (s)'], [75, 25])
                    iqr_time = q75 - q25
                else:
                    iqr_time = 0.0
                time_overhead_pct = ((med_time - base_time) / base_time) * 100.0 if base_time else 0.0
                proc_overhead_pct = ((med_proc - base_proc) / base_proc) * 100.0 if base_proc else 0.0

                # Obliczenie narzutu względem LTO (dla precyzyjnego wyizolowania kosztu CFI):
                if lto_time is not None and lto_time > 0 and any(k in var for k in ['cfi', 'lto']):
                    lto_overhead_pct = round(((med_time - lto_time) / lto_time) * 100.0, 2)
                else:
                    lto_overhead_pct = 'N/A'

                med_ram = var_data['RAM (KB)'].median()
                ram_overhead_pct = ((med_ram - base_ram) / base_ram) * 100.0 if base_ram else 0.0

                text_size, bin_size = get_binary_metrics(var)
                base_text = 1.0
                if not base_run.empty:
                    b_text, _ = get_binary_metrics(base_run['Wariant'].iloc[0])
                    base_text = b_text if b_text else 1.0
                text_overhead_pct = (((text_size - base_text) / base_text) * 100.0) if text_size and base_text else 0.0

                summary_rows.append({
                    'Grupa': app_group,
                    'Wariant': var,
                    'Mediana czasu (s)': round(med_time, 6),
                    'Mediana przetwarzania (s)': round(med_proc, 6),
                    'Narzut przetwarzania (%)': round(proc_overhead_pct, 2),
                    'Mediana alokacji (s)': round(med_alloc, 6),
                    'Mediana sprzątania (s)': round(med_clean, 6),
                    'Średnia czasu (s)': round(mean_time, 6),
                    'Odch. std. czasu (s)': round(std_time, 6),
                    'IQR czasu (s)': round(iqr_time, 6),
                    'Narzut czasowy (%)': round(time_overhead_pct, 2),
                    'Narzut vs LTO (%)': lto_overhead_pct,
                    'Mediana RAM (KB)': int(med_ram),
                    'Narzut RAM (%)': round(ram_overhead_pct, 2),
                    'Rozmiar .text (B)': text_size or 0,
                    'Rozmiar binarki (B)': bin_size or 0,
                    'Narzut .text (%)': round(text_overhead_pct, 2),
                })

        df_summary = pd.DataFrame(summary_rows)
        df_summary.to_csv("benchmark_summary.csv", index=False)
        print("  -> Zapisano podsumowanie statystyczne do benchmark_summary.csv")

        # 1. Wykresy czasu wykonania (boxplots)
        for app_group in df_raw['Grupa'].unique():
            group_df = df_raw[df_raw['Grupa'] == app_group].copy()
            unique_vars = sorted(group_df['Wariant'].unique(), key=variant_sort_key)
            med_times = group_df.groupby('Wariant')['Czas Wewnętrzny (s)'].median()
            time_ratio = med_times.max() / max(med_times.min(), 0.0001)

            if time_ratio > 8:
                fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(16, 6))
                sns.boxplot(x='Wariant', y='Czas Wewnętrzny (s)', data=group_df,
                            order=unique_vars, hue='Wariant', palette="Set2", legend=False, ax=ax1)
                ax1.set_title(f'Czas wykonania (skala liniowa) – {app_group}', fontsize=12, fontweight='bold')
                ax1.set_ylabel('Czas Wewnętrzny (s)', fontsize=11, fontweight='bold')
                ax1.tick_params(axis='x', rotation=25)

                sns.boxplot(x='Wariant', y='Czas Wewnętrzny (s)', data=group_df,
                            order=unique_vars, hue='Wariant', palette="Set2", legend=False, ax=ax2)
                ax2.set_yscale('log')
                ax2.set_title(f'Czas wykonania (skala logarytmiczna) – {app_group}', fontsize=12, fontweight='bold')
                ax2.set_ylabel('Czas Wewnętrzny (s, skala log)', fontsize=11, fontweight='bold')
                ax2.tick_params(axis='x', rotation=25)

                fig.tight_layout()
                fig.savefig(f"benchmark_time_{app_group}.png", dpi=300)
                plt.close(fig)
            else:
                fig, ax = plt.subplots(figsize=(12, 6))
                sns.boxplot(x='Wariant', y='Czas Wewnętrzny (s)', data=group_df,
                            order=unique_vars, hue='Wariant', palette="Set2", legend=False, ax=ax)
                ax.set_title(f'Czas wykonania – {app_group} ({runs_count} iteracji)', fontsize=13, fontweight='bold')
                ax.set_ylabel('Czas Wewnętrzny (s)', fontsize=11, fontweight='bold')
                plt.xticks(rotation=25, ha='right')
                fig.tight_layout()
                fig.savefig(f"benchmark_time_{app_group}.png", dpi=300)
                plt.close(fig)

        # 2. Wykresy zużycia pamięci RAM (Peak RSS)
        for app_group in df_raw['Grupa'].unique():
            group_df = df_raw[df_raw['Grupa'] == app_group]
            unique_vars = sorted(group_df['Wariant'].unique(), key=variant_sort_key)
            fig, ax = plt.subplots(figsize=(12, 6))
            sns.boxplot(x='Wariant', y='RAM (KB)', data=group_df,
                        order=unique_vars, hue='Wariant', palette="Set2", legend=False, ax=ax)
            ax.set_title(f'Zużycie pamięci RAM (Peak RSS) – {app_group}', fontsize=13, fontweight='bold')
            ax.set_ylabel('Peak RSS (KB)', fontsize=11, fontweight='bold')
            plt.xticks(rotation=25, ha='right')
            fig.tight_layout()
            fig.savefig(f"benchmark_ram_{app_group}.png", dpi=300)
            plt.close(fig)

        # 3. Wykresy słupkowe narzutu % (czas + RAM)
        for app_group in df_summary['Grupa'].unique():
            group_sum = df_summary[df_summary['Grupa'] == app_group].copy()
            group_sum['sort_key'] = group_sum['Wariant'].apply(variant_sort_key)
            group_sum = group_sum.sort_values('sort_key', ascending=False)

            fig, axes = plt.subplots(1, 2, figsize=(16, 6))

            def draw_horizontal_overhead(ax, values, y_labels, title, xlabel, threshold_yellow=5, threshold_red=50):
                colors = ['#2ecc71' if abs(x) <= threshold_yellow else '#f39c12' if abs(x) <= threshold_red else '#e74c3c'
                          for x in values]
                ax.barh(y_labels, values, color=colors, edgecolor='black', linewidth=0.5)
                ax.set_xlabel(xlabel, fontsize=11, fontweight='bold')
                ax.set_title(title, fontsize=12, fontweight='bold')
                ax.axvline(x=0, color='black', linewidth=0.7)

                min_v = min(0.0, float(values.min()))
                max_v = max(0.0, float(values.max()))
                span = max(max_v - min_v, 10.0)

                pad_right = span * 0.22
                pad_left = span * 0.15 if min_v < 0 else span * 0.05
                ax.set_xlim(min_v - pad_left, max_v + pad_right)

                offset = span * 0.025
                for i, val in enumerate(values):
                    txt_x = val + (offset if val >= 0 else -offset)
                    ha = 'left' if val >= 0 else 'right'
                    ax.text(txt_x, i, f'{val:+.1f}%', va='center', ha=ha, fontsize=9, fontweight='bold')

            draw_horizontal_overhead(axes[0], group_sum['Narzut czasowy (%)'], group_sum['Wariant'],
                                     f'Narzut czasu vs baseline – {app_group}', 'Narzut czasowy (%)',
                                     threshold_yellow=5, threshold_red=50)

            draw_horizontal_overhead(axes[1], group_sum['Narzut RAM (%)'], group_sum['Wariant'],
                                     f'Narzut pamięci vs baseline – {app_group}', 'Narzut RAM (%)',
                                     threshold_yellow=10, threshold_red=100)

            fig.subplots_adjust(left=0.22, right=0.96, top=0.90, bottom=0.10, wspace=0.45)
            fig.savefig(f"benchmark_overhead_{app_group}.png", dpi=300)
            plt.close(fig)

        # 4. Wykresy narzutu rozmiaru kodu .text
        for app_group in df_summary['Grupa'].unique():
            group_sum = df_summary[df_summary['Grupa'] == app_group]
            if 'Narzut .text (%)' not in group_sum.columns:
                continue
            valid = group_sum.dropna(subset=['Narzut .text (%)']).copy()
            if valid.empty:
                continue

            valid['sort_key'] = valid['Wariant'].apply(variant_sort_key)
            valid = valid.sort_values('sort_key', ascending=False)

            fig, ax = plt.subplots(figsize=(12, 5.5))
            colors_b = ['#2ecc71' if abs(x) <= 5 else '#f39c12' if abs(x) <= 50 else '#e74c3c'
                        for x in valid['Narzut .text (%)']]
            ax.barh(valid['Wariant'], valid['Narzut .text (%)'], color=colors_b, edgecolor='black', linewidth=0.5)
            ax.set_xlabel('Narzut rozmiaru sekcji .text (%)', fontsize=11, fontweight='bold')
            ax.set_title(f'Narzut rozmiaru kodu vs baseline – {app_group}', fontsize=12, fontweight='bold')
            ax.axvline(x=0, color='black', linewidth=0.7)

            min_v = min(0.0, float(valid['Narzut .text (%)'].min()))
            max_v = max(0.0, float(valid['Narzut .text (%)'].max()))
            span = max(max_v - min_v, 10.0)
            pad_right = span * 0.20
            pad_left = span * 0.12 if min_v < 0 else span * 0.05
            ax.set_xlim(min_v - pad_left, max_v + pad_right)

            offset = span * 0.02
            for i, val in enumerate(valid['Narzut .text (%)']):
                txt_x = val + (offset if val >= 0 else -offset)
                ha = 'left' if val >= 0 else 'right'
                ax.text(txt_x, i, f'{val:+.1f}%', va='center', ha=ha, fontsize=9, fontweight='bold')

            fig.tight_layout()
            fig.savefig(f"benchmark_text_overhead_{app_group}.png", dpi=300)
            plt.close(fig)

    # ==================================================================
    # FAZA 3: TESTY SKUTECZNOŚCI (EFFICACY)
    # ==================================================================
    print(f"\n{'=' * 70}")
    print(f"   FAZA 3: TESTY SKUTECZNOŚCI DETEKCJI ATAKÓW")
    print(f"{'=' * 70}")

    efficacy_results = []
    if plots_only and os.path.exists("benchmark_efficacy_data.csv") and has_plotting:
        df_eff = pd.read_csv("benchmark_efficacy_data.csv")
        efficacy_results = df_eff.to_dict('records')
        print("  [CACHE] Załadowano wyniki skuteczności z benchmark_efficacy_data.csv")
    elif not args.perf_only:
        for app_group, (executables, arg) in efficacy_apps.items():
            print(f"\n[+] Scenariusz ataku: {app_group}")
            for exe in executables:
                res = run_efficacy_test(exe, arg, trials=trials_count)
                if res:
                    if res['Zablokowane_Proby'] == res['Liczba_Prob']:
                        icon = "✓ ZABLOKOWANO"
                    elif res['Zablokowane_Proby'] == 0 and "OMINIĘTO" in res['Status']:
                        icon = "✗ OMINIĘTO"
                    elif res['Zablokowane_Proby'] == 0:
                        icon = "⚠ AWARIA"
                    else:
                        icon = "◐ CZĘŚCIOWO"
                    print(f"    [{exe:45s}] {icon:16s} {res['Status']:35s}")
                    res['Atak'] = app_group
                    res['Mechanizm'] = extract_mechanism(exe)
                    res['Klasa ataku'] = ATTACK_CLASSES.get(app_group, 'Inna')
                    efficacy_results.append(res)

        if efficacy_results and has_plotting:
            df_eff = pd.DataFrame(efficacy_results)
            df_eff.to_csv("benchmark_efficacy_data.csv", index=False)
            print("\n  -> Zapisano surowe wyniki skuteczności do benchmark_efficacy_data.csv")

    # Przetwarzanie macierzy i wykresów skuteczności
    if efficacy_results and has_plotting:
        df_eff = pd.DataFrame(efficacy_results)
        df_eff['Mechanizm'] = df_eff['Wariant'].apply(extract_mechanism)
        df_eff['Klasa ataku'] = df_eff['Atak'].map(ATTACK_CLASSES)

        # Filtrujemy warianty bazowe bez ochrony oraz bypassy z ogólnych wskaźników mechanizmów
        df_mechanisms_raw = df_eff[
            (~df_eff['Mechanizm'].isin(['base', 'lto', 'bypass_base', 'bypass_lto', 'bypass_cfi'])) &
            (df_eff['Atak'] != 'D2_bypass_cfi')
        ].copy()

        # ------------------------------------------------------------------
        # 1. RZETELNE PODSUMOWANIE SKUTECZNOŚCI PER MECHANIZM (EMPIRYCZNE)
        # ------------------------------------------------------------------
        # Liczymy wyłącznie na podstawie faktycznie przeprowadzonych testów (bez dopisywania zer)!
        mech_summary = df_mechanisms_raw.groupby('Mechanizm').agg(
            Scenariusze_Testowane=('Atak', 'nunique'),
            Proby_Rzeczywiste=('Liczba_Prob', 'sum'),
            Zablokowane_Proby=('Zablokowane_Proby', 'sum'),
        ).reset_index()
        mech_summary['Skutecznosc_Empiryczna (%)'] = (
            mech_summary['Zablokowane_Proby'] / mech_summary['Proby_Rzeczywiste'] * 100.0
        ).round(1)

        # Przedziały ufności Wilsona 95%
        cis = [
            wilson_score_interval(b, t)
            for b, t in zip(mech_summary['Zablokowane_Proby'], mech_summary['Proby_Rzeczywiste'])
        ]
        mech_summary['CI_95_Dolna (%)'] = [c[0] for c in cis]
        mech_summary['CI_95_Gorna (%)'] = [c[1] for c in cis]
        mech_summary['sort_key'] = mech_summary['Mechanizm'].apply(variant_sort_key)
        mech_summary = mech_summary.sort_values('sort_key').drop(columns=['sort_key'])
        mech_summary.to_csv("benchmark_efficacy_per_mechanism.csv", index=False)

        print("\n" + "=" * 75)
        print("   SKUTECZNOŚĆ EMPIRYCZNA PER MECHANIZM (RZECZYWISTE TESTY + 95% CI)")
        print("=" * 75)
        print(f"  {'Mechanizm':32s} {'Scenariusze':>11s} {'Próby':>7s} {'Zablokowane':>12s} {'Skuteczność':>12s} {'95% CI':>16s}")
        print("  " + "-" * 95)
        for _, row in mech_summary.iterrows():
            ci_str = f"[{row['CI_95_Dolna (%)']:.1f}% - {row['CI_95_Gorna (%)']:.1f}%]"
            print(f"  {row['Mechanizm']:32s} {int(row['Scenariusze_Testowane']):>11d} {int(row['Proby_Rzeczywiste']):>7d} "
                  f"{int(row['Zablokowane_Proby']):>12d} {row['Skutecznosc_Empiryczna (%)']:>11.1f}% {ci_str:>16s}")

        # ------------------------------------------------------------------
        # 2. MACIERZ SKUTECZNOŚCI (MECHANIZM × ATAK) Z OZNACZENIEM N/A
        # ------------------------------------------------------------------
        pivot = df_eff[~df_eff['Mechanizm'].isin(['base', 'lto', 'bypass_base', 'bypass_lto'])].pivot_table(
            index='Mechanizm',
            columns='Atak',
            values='Skutecznosc_Procent',
            aggfunc='mean'
        )
        pivot.to_csv("benchmark_efficacy_matrix.csv")

        # Rysowanie heatmapy z jawnym rozróżnieniem N/A (nie testowano / poza zakresem)
        fig, ax = plt.subplots(figsize=(17, 8.5))
        sns.set_theme(style="white")

        # Kolorujemy komórki z danymi
        cmap = sns.color_palette("RdYlGn", as_cmap=True)
        sns.heatmap(pivot, annot=True, fmt=".0f", cmap=cmap, vmin=0, vmax=100,
                    linewidths=1.0, linecolor="white", cbar_kws={'label': 'Skuteczność detekcji (%)'},
                    ax=ax, mask=pivot.isnull())

        # Komórki niezbadane (NaN / N/A) oznaczamy neutralnym kolorem szarym
        ax.patch.set_facecolor('#edf2f7')
        for i in range(len(pivot.index)):
            for j in range(len(pivot.columns)):
                if np.isnan(pivot.iloc[i, j]):
                    ax.text(j + 0.5, i + 0.5, "N/A", ha="center", va="center", color="#718096", fontsize=9, fontweight="bold")

        ax.set_title("Macierz skuteczności mechanizmów bezpieczeństwa ARM64 (% zablokowanych prób)\n"
                     "Komórki 'N/A' oznaczają scenariusze poza zakresem projektowym danego mechanizmu",
                     fontsize=13, fontweight='bold', pad=15)
        ax.set_xlabel("Scenariusz ataku", fontsize=11, fontweight='bold', labelpad=10)
        ax.set_ylabel("Badany mechanizm", fontsize=11, fontweight='bold', labelpad=10)
        plt.xticks(rotation=30, ha='right', fontsize=9.5)
        plt.yticks(rotation=0, fontsize=10)
        fig.tight_layout()
        fig.savefig("benchmark_efficacy_heatmap.png", dpi=300)
        plt.close(fig)

        # ------------------------------------------------------------------
        # 3. WYKRES SŁUPKOWY SKUTECZNOŚCI Z WĄSAMI PRZEDZIAŁU UFNOŚCI (95% CI)
        # ------------------------------------------------------------------
        fig, ax = plt.subplots(figsize=(13, 6.5))
        y_pos = np.arange(len(mech_summary))
        eff_vals = mech_summary['Skutecznosc_Empiryczna (%)'].values
        ci_low = mech_summary['CI_95_Dolna (%)'].values
        ci_high = mech_summary['CI_95_Gorna (%)'].values
        xerr = [eff_vals - ci_low, ci_high - eff_vals]

        colors = ['#e53e3e' if x < 40 else '#dd6b20' if x < 80 else '#38a169' for x in eff_vals]
        bars = ax.barh(y_pos, eff_vals, xerr=xerr, capsize=4, color=colors, edgecolor='black', linewidth=0.6, alpha=0.9)
        ax.set_yticks(y_pos)
        ax.set_yticklabels(mech_summary['Mechanizm'], fontsize=10)
        ax.set_xlabel("Empiryczna skuteczność detekcji w badanych scenariuszach (%) [95% Wilson CI]", fontsize=11, fontweight='bold')
        ax.set_title("Skuteczność mechanizmów bezpieczeństwa ARM64 w testowanych domenach\n(uwzględnia rzeczywiste próby i przedziały ufności)",
                     fontsize=12, fontweight='bold', pad=12)
        ax.set_xlim(0, 115)

        for bar, eff, bl, tot in zip(bars, eff_vals, mech_summary['Zablokowane_Proby'], mech_summary['Proby_Rzeczywiste']):
            ax.text(bar.get_width() + 4, bar.get_y() + bar.get_height()/2,
                    f"{eff:.1f}% ({int(bl)}/{int(tot)})", va='center', fontsize=9, fontweight='bold')

        ax.axvline(x=50, color='gray', linestyle='--', linewidth=0.8, alpha=0.6)
        fig.tight_layout()
        fig.savefig("benchmark_efficacy_per_mechanism.png", dpi=300)
        plt.close(fig)

        # ------------------------------------------------------------------
        # 4. SKUTECZNOŚĆ W PODZIALE NA KLASY BŁĘDÓW (SPATIAL, TEMPORAL, CF)
        # ------------------------------------------------------------------
        class_summary = df_mechanisms_raw.groupby(['Klasa ataku', 'Mechanizm']).agg(
            Testy=('Liczba_Prob', 'sum'),
            Zablokowane=('Zablokowane_Proby', 'sum')
        ).reset_index()
        class_summary['Skuteczność (%)'] = (class_summary['Zablokowane'] / class_summary['Testy'] * 100.0).round(1)
        class_summary.to_csv("benchmark_efficacy_per_class.csv", index=False)

        # ------------------------------------------------------------------
        # 5. DASHBOARD SKUTECZNOŚCI PER SCENARIUSZ ATAKU
        # ------------------------------------------------------------------
        attacks_order = [
            'D1_stack_smash', 'D2_indirect_call_hijack', 'D3_vtable_hijack', 'D4_bti_landing',
            'P1_heap_overflow', 'P2_stack_overflow', 'P3_global_overflow', 'P4_heap_oob_read',
            'P5_subgranule_overflow', 'P6_stack_dop',
            'M1_use_after_free', 'M2_double_free', 'M3_stack_use_after_scope'
        ]
        active_attacks = [a for a in attacks_order if a in df_mechanisms_raw['Atak'].unique()]

        n_attacks = len(active_attacks)
        n_cols = 2
        n_rows = (n_attacks + n_cols - 1) // n_cols

        fig, axes = plt.subplots(n_rows, n_cols, figsize=(16, 3.2 * n_rows), sharex=True)
        axes_flat = axes.flatten() if hasattr(axes, 'flatten') else [axes]

        for idx, attack in enumerate(active_attacks):
            ax = axes_flat[idx]
            subset = df_mechanisms_raw[df_mechanisms_raw['Atak'] == attack].copy()
            subset['sort_key'] = subset['Mechanizm'].apply(variant_sort_key)
            subset = subset.sort_values('sort_key', ascending=False)

            colors_att = ['#2ecc71' if p > 0 else '#e74c3c' for p in subset['Skutecznosc_Procent']]
            bars = ax.barh(subset['Mechanizm'], subset['Skutecznosc_Procent'], color=colors_att, edgecolor='white')

            cls_name = ATTACK_CLASSES.get(attack, '')
            ax.set_title(f'{attack}  [{cls_name}]', fontsize=11, fontweight='bold', pad=8)
            ax.set_xlim(0, 130)
            ax.axvline(x=100, color='gray', linestyle=':', alpha=0.5)

            for bar, pct, bl, tot in zip(bars, subset['Skutecznosc_Procent'], subset['Zablokowane_Proby'], subset['Liczba_Prob']):
                label_txt = f"{pct:.0f}% ({int(bl)}/{int(tot)})"
                ax.text(bar.get_width() + 2, bar.get_y() + bar.get_height() / 2,
                        label_txt, va='center', ha='left', fontsize=9, fontweight='bold',
                        color='#27ae60' if pct > 0 else '#c0392b')

        for j in range(len(active_attacks), len(axes_flat)):
            axes_flat[j].axis('off')

        fig.suptitle('Szczegółowa skuteczność mechanizmów w każdym scenariuszu ataku', fontsize=14, fontweight='bold', y=0.99)
        fig.tight_layout(rect=[0, 0, 1, 0.97])
        fig.savefig("benchmark_efficacy_per_attack.png", dpi=300)
        plt.close(fig)

        # ------------------------------------------------------------------
        # 6. WYKRES SKUTECZNOŚCI W PODZIALE NA KLASY ATAKÓW
        # ------------------------------------------------------------------
        classes = sorted(class_summary['Klasa ataku'].unique())
        n_classes = len(classes)
        fig, axes = plt.subplots(1, n_classes, figsize=(7.5 * n_classes, 7), sharey=False)
        if n_classes == 1:
            axes = [axes]

        for ax, cls in zip(axes, classes):
            cls_data = class_summary[class_summary['Klasa ataku'] == cls].sort_values('Skuteczność (%)', ascending=True)
            colors = ['#e74c3c' if x < 30 else '#f39c12' if x < 60 else '#2ecc71'
                      for x in cls_data['Skuteczność (%)']]
            ax.barh(cls_data['Mechanizm'], cls_data['Skuteczność (%)'], color=colors)
            ax.set_xlim(0, 120)
            ax.set_xlabel('Skuteczność (%)', fontsize=11, fontweight='bold')
            ax.set_title(f'{cls}', fontsize=13, fontweight='bold', pad=10)
            ax.axvline(x=50, color='gray', linewidth=0.5, linestyle='--', alpha=0.5)
            for i, (pct, bl, tot) in enumerate(zip(cls_data['Skuteczność (%)'],
                                                   cls_data['Zablokowane'],
                                                   cls_data['Testy'])):
                ax.text(pct + 2, i, f'{pct:.0f}% ({int(bl)}/{int(tot)})', va='center', fontsize=9, fontweight='bold')

        fig.suptitle('Skuteczność mechanizmów w podziale na klasy ataków', fontsize=15, fontweight='bold', y=0.98)
        fig.tight_layout(rect=[0, 0, 1, 0.95])
        fig.savefig("benchmark_efficacy_per_class.png", dpi=300)
        plt.close(fig)

        # ------------------------------------------------------------------
        # 7. STACKED BAR: ZABLOKOWANE VS OMINIĘTE PER MECHANIZM
        # ------------------------------------------------------------------
        mech_stacked = df_mechanisms_raw.groupby('Mechanizm').agg(
            Zablokowane=('Zablokowane_Proby', 'sum'),
            Testy=('Liczba_Prob', 'sum')
        ).reset_index()
        mech_stacked['Ominięte'] = mech_stacked['Testy'] - mech_stacked['Zablokowane']
        mech_stacked['sort_key'] = mech_stacked['Mechanizm'].apply(variant_sort_key)
        mech_stacked = mech_stacked.sort_values('sort_key', ascending=False)

        fig, ax = plt.subplots(figsize=(12, 6))
        ax.barh(mech_stacked['Mechanizm'], mech_stacked['Zablokowane'],
                color='#2ecc71', label='Zablokowane', edgecolor='white')
        ax.barh(mech_stacked['Mechanizm'], mech_stacked['Ominięte'],
                left=mech_stacked['Zablokowane'],
                color='#e74c3c', label='Ominięte / niezablokowane', edgecolor='white')
        ax.set_xlabel('Liczba prób ataku', fontsize=11, fontweight='bold')
        ax.set_title('Zablokowane vs ominięte próby ataków per mechanizm', fontsize=13, fontweight='bold')

        for i, row in mech_stacked.reset_index().iterrows():
            bl = int(row['Zablokowane'])
            om = int(row['Ominięte'])
            if bl > 0:
                ax.text(bl / 2, i, str(bl), va='center', ha='center', color='white', fontweight='bold', fontsize=9)
            if om > 0:
                ax.text(bl + om / 2, i, str(om), va='center', ha='center', color='white', fontweight='bold', fontsize=9)
            tot = bl + om
            ax.text(tot + 0.15, i, f'Razem: {tot}', va='center', ha='left', fontsize=8.5, color='#333333')

        ax.set_xlim(0, mech_stacked['Testy'].max() * 1.15 + 1)
        ax.legend(loc='lower right', frameon=True)
        fig.tight_layout()
        fig.savefig("benchmark_efficacy_stacked.png", dpi=300)
        plt.close(fig)

    # ==================================================================
    # FAZA 4: AUTORSKA METODYKA OCENY (FTS, PPS & KOSZT CHMUROWY)
    # ==================================================================
    print(f"\n{'=' * 70}")
    print(f"   FAZA 4: AUTORSKA METODYKA OCENY (MODEL PUNKTOWY I KOSZT)")
    print(f"{'=' * 70}")

    if os.path.exists("benchmark_summary.csv") and os.path.exists("benchmark_efficacy_data.csv") and has_plotting:
        df_sum_m = pd.read_csv("benchmark_summary.csv")
        df_eff_m = pd.read_csv("benchmark_efficacy_data.csv")
        df_sum_m['Mechanizm'] = df_sum_m['Wariant'].apply(extract_mechanism)
        df_eff_m['Mechanizm'] = df_eff_m['Wariant'].apply(extract_mechanism)

        # Współczynniki gotowości diagnostycznej i produkcyjnej: (tau_test, tau_prod)
        MECH_TAU = {
            'canary':                         (0.85, 0.70),
            'pac':                            (1.00, 1.00),
            'bti':                            (1.00, 1.00),
            'pac_bti':                        (1.00, 1.00),
            'cfi':                            (1.00, 1.00),
            'cfi_pac_bti':                    (1.00, 1.00),
            'scudo':                          (1.00, 1.00),
            'mte_async':                      (0.85, 0.10),
            'mte_sync':                       (1.00, 1.00),
            'cfi_pac_bti_mte':                (1.00, 1.00),
            'cfi_pac_bti_mte_fortify_bounds': (1.00, 1.00),
            'hwasan':                         (1.00, 1.00),
            'asan':                           (1.00, 1.00),
        }

        def get_attack_p_ent(mech, attack):
            """Wyznacza prawdopodobieństwo determinizmu lub sufit entropii tagów."""
            if mech == 'asan':
                return 1.0000
            if (attack.startswith('D2') or attack.startswith('D3')) and any(k in mech for k in ['cfi', 'cfi_pac_bti_mte']):
                return 1.0000
            if attack.startswith('D4') and any(k in mech for k in ['bti', 'cfi_pac_bti_mte']):
                return 1.0000
            if (attack.startswith('D1') or attack.startswith('P2')) and any(k in mech for k in ['canary', 'cfi_pac_bti_mte']):
                return 1.0000
            if attack.startswith('P3') and any(k in mech for k in ['fortify', 'cfi_pac_bti_mte_fortify_bounds']):
                return 1.0000

            if mech in ['pac', 'pac_bti', 'cfi_pac_bti']:
                return 0.9990
            if mech == 'canary':
                return 0.9990
            if mech == 'hwasan':
                return 0.9961
            if any(k in mech for k in ['mte_sync', 'mte_async', 'scudo', 'cfi_pac_bti_mte']):
                return 0.9375
            return 1.0000

        # Wyliczenie r_T, r_M, r_S oraz C_cloud
        cost_records = []
        for grp in df_sum_m['Grupa'].unique():
            grp_df = df_sum_m[df_sum_m['Grupa'] == grp]
            base_row = grp_df[grp_df['Mechanizm'] == 'base']
            if base_row.empty:
                continue
            t_base = float(base_row['Mediana czasu (s)'].iloc[0])
            m_base = float(base_row['Mediana RAM (KB)'].iloc[0])
            s_base = float(base_row['Rozmiar .text (B)'].iloc[0]) if 'Rozmiar .text (B)' in base_row.columns else 1.0

            for _, row in grp_df.iterrows():
                mech = row['Mechanizm']
                if mech in ['base', 'lto']:
                    continue
                r_t = max(1.0, float(row['Mediana czasu (s)']) / max(t_base, 1e-9))
                r_m = max(1.0, float(row['Mediana RAM (KB)']) / max(m_base, 1.0))
                r_s = max(1.0, float(row.get('Rozmiar .text (B)', s_base)) / max(s_base, 1.0))

                # Koszt infrastrukturalny oparty na rozliczeniu czasu CPU (vCPU) i iloczynu pamięci (GB-s):
                c_cloud = 0.75 * r_t + 0.25 * (r_t * r_m)
                cost_records.append({
                    'Grupa': grp,
                    'Mechanizm': mech,
                    'r_T': r_t,
                    'r_M': r_m,
                    'r_S': r_s,
                    'C_cloud': c_cloud,
                    'Omega_cloud_pct': (c_cloud - 1.0) * 100.0
                })

        df_costs = pd.DataFrame(cost_records)

        # Ujednolicone i symetryczne uśrednianie kosztu C_cloud:
        # Mechanizmy pamięciowe (asan, hwasan, scudo, mte_sync, mte_async)
        # porównujemy na aplikacjach obciążających stertę (Parser i KV_Store).
        mem_mechs = ['asan', 'hwasan', 'scudo', 'mte_sync', 'mte_async']
        df_costs_sym = df_costs[
            (~df_costs['Mechanizm'].isin(mem_mechs)) |
            (df_costs['Grupa'].isin(['Parser', 'KV_Store']))
        ].copy()

        avg_costs = df_costs_sym.groupby('Mechanizm').agg(
            r_T=('r_T', 'mean'),
            r_M=('r_M', 'mean'),
            r_S=('r_S', 'mean'),
            C_cloud=('C_cloud', 'mean'),
            Omega_cloud_pct=('Omega_cloud_pct', 'mean')
        ).reset_index()

        all_attacks = [a for a in ATTACK_CLASSES.keys() if a != 'D2_bypass_cfi']
        all_classes = ['Spatial (pamięć)', 'Temporal (pamięć)', 'Control Flow']
        eps = 0.05
        methodology_rows = []

        for mech in sorted(MECH_TAU.keys(), key=variant_sort_key):
            sub_raw = df_eff_m[df_eff_m['Mechanizm'] == mech]
            if sub_raw.empty:
                continue

            tau_test, tau_prod = MECH_TAU[mech]
            full_atk_rows = []
            for a in all_attacks:
                match_row = sub_raw[sub_raw['Atak'] == a]
                d_emp = (float(match_row['Skutecznosc_Procent'].mean()) / 100.0) if not match_row.empty else 0.0
                p_ent = get_attack_p_ent(mech, a)
                eff = min(d_emp, p_ent) if d_emp > 0.0 else 0.0
                full_atk_rows.append({
                    'Atak': a,
                    'Klasa ataku': ATTACK_CLASSES[a],
                    'Tested': not match_row.empty,
                    'E_test': eff * tau_test,
                    'E_prod': eff * tau_prod,
                })
            df_m_full = pd.DataFrame(full_atk_rows)

            tested_df = df_m_full[df_m_full['Tested']]
            if not tested_df.empty:
                cls_test = tested_df.groupby('Klasa ataku')['E_test'].mean().values
                cls_prod = tested_df.groupby('Klasa ataku')['E_prod'].mean().values
                s_dom_test = float(np.prod([eps + x for x in cls_test]) ** (1.0 / len(cls_test)) - eps)
                s_dom_prod = float(np.prod([eps + x for x in cls_prod]) ** (1.0 / len(cls_prod)) - eps)
            else:
                s_dom_test = s_dom_prod = 0.0

            sys_vec_test = [float(df_m_full[df_m_full['Klasa ataku'] == c]['E_test'].mean()) for c in all_classes]
            sys_vec_prod = [float(df_m_full[df_m_full['Klasa ataku'] == c]['E_prod'].mean()) for c in all_classes]
            s_sys_test = float(np.prod([eps + x for x in sys_vec_test]) ** (1.0 / 3.0) - eps)
            s_sys_prod = float(np.prod([eps + x for x in sys_vec_prod]) ** (1.0 / 3.0) - eps)

            cost_row = avg_costs[avg_costs['Mechanizm'] == mech]
            if cost_row.empty:
                c_cloud = np.nan
                omega_pct = np.nan
                fts_domain = pps_domain = fts_sys = pps_sys = np.nan
            else:
                c_cloud = float(cost_row['C_cloud'].iloc[0])
                omega_pct = float(cost_row['Omega_cloud_pct'].iloc[0])
                fts_domain = (s_dom_test / c_cloud) * 100.0
                pps_domain = ((s_dom_prod ** 2) / c_cloud) * 100.0
                fts_sys = (s_sys_test / c_cloud) * 100.0
                pps_sys = ((s_sys_prod ** 2) / c_cloud) * 100.0

            methodology_rows.append({
                'Mechanizm': mech,
                'C_cloud (mnoznik)': round(c_cloud, 3) if not np.isnan(c_cloud) else 'N/A',
                'Narzut_Chmurowy (%)': round(omega_pct, 1) if not np.isnan(omega_pct) else 'N/A',
                'S_dom_test (%)': round(s_dom_test * 100.0, 1),
                'S_dom_prod (%)': round(s_dom_prod * 100.0, 1),
                'S_sys_test (%)': round(s_sys_test * 100.0, 1),
                'S_sys_prod (%)': round(s_sys_prod * 100.0, 1),
                'FTS_Domena (pkt)': round(fts_domain, 1) if not np.isnan(fts_domain) else 'N/A',
                'PPS_Domena (pkt)': round(pps_domain, 1) if not np.isnan(pps_domain) else 'N/A',
                'FTS_System (pkt)': round(fts_sys, 1) if not np.isnan(fts_sys) else 'N/A',
                'PPS_System (pkt)': round(pps_sys, 1) if not np.isnan(pps_sys) else 'N/A',
            })

        df_meth = pd.DataFrame(methodology_rows)
        df_meth.to_csv("benchmark_methodology_scores.csv", index=False)
        df_meth.to_csv("benchmark_cost_efficiency.csv", index=False)
        print(df_meth.to_string(index=False))
        print("\n  -> Zapisano wyniki do benchmark_methodology_scores.csv i benchmark_cost_efficiency.csv")

        # ------------------------------------------------------------------
        # ANALIZA WRAŻLIWOŚCI (SENSITIVITY ANALYSIS)
        # ------------------------------------------------------------------
        sens_records = []
        weight_configs = [
            ("Zrównoważony (50/50)", 0.50, 0.50),
            ("Domyślny (75/25)",      0.75, 0.25),
            ("Dominacja CPU (90/10)",  0.90, 0.10)
        ]
        for cfg_name, w_t, w_m in weight_configs:
            for _, r in df_meth.iterrows():
                mech = r['Mechanizm']
                c_row = avg_costs[avg_costs['Mechanizm'] == mech]
                if c_row.empty:
                    continue
                rt = float(c_row['r_T'].iloc[0])
                rm = float(c_row['r_M'].iloc[0])
                c_custom = w_t * rt + w_m * (rt * rm)
                s_prod = float(r['S_sys_prod (%)']) / 100.0

                pps_lin = (s_prod / max(c_custom, 1e-6)) * 100.0
                pps_quad = ((s_prod ** 2) / max(c_custom, 1e-6)) * 100.0

                sens_records.append({
                    'Konfiguracja': cfg_name,
                    'Waga_CPU': w_t,
                    'Waga_RAM': w_m,
                    'Mechanizm': mech,
                    'C_cloud': round(c_custom, 3),
                    'PPS_Liniowy': round(pps_lin, 1),
                    'PPS_Kwadratowy': round(pps_quad, 1),
                })
        df_sens = pd.DataFrame(sens_records)
        df_sens.to_csv("benchmark_sensitivity_analysis.csv", index=False)
        print("\n  -> Zapisano analizę wrażliwości do benchmark_sensitivity_analysis.csv")

        # Generowanie wykresów FTS vs PPS oraz Frontu Pareto
        df_plot = df_meth[df_meth['C_cloud (mnoznik)'] != 'N/A'].copy()
        if not df_plot.empty:
            df_plot['FTS_System (pkt)'] = pd.to_numeric(df_plot['FTS_System (pkt)'])
            df_plot['PPS_System (pkt)'] = pd.to_numeric(df_plot['PPS_System (pkt)'])
            df_plot['C_cloud (mnoznik)'] = pd.to_numeric(df_plot['C_cloud (mnoznik)'])
            df_plot['S_sys_prod (%)'] = pd.to_numeric(df_plot['S_sys_prod (%)'])

            # Wykres 1: Porównanie wskaźników FTS vs PPS dla systemów
            fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(16, 6))
            df_plot_fts = df_plot.sort_values('FTS_System (pkt)', ascending=True)
            ax1.barh(df_plot_fts['Mechanizm'], df_plot_fts['FTS_System (pkt)'], color='#3498db')
            ax1.set_title('FTS_System (Fuzzing & Testing Score)\nOpłacalność w testach/CI (3 klasy ataków)', fontsize=11, fontweight='bold')
            ax1.set_xlabel('Wskaźnik FTS_System (pkt)', fontsize=10)
            for i, v in enumerate(df_plot_fts['FTS_System (pkt)']):
                ax1.text(v + 1, i, f"{v:.1f}", va='center', fontweight='bold', fontsize=9)
            ax1.set_xlim(0, max(df_plot_fts['FTS_System (pkt)'].max() * 1.18, 10))

            df_plot_pps = df_plot.sort_values('PPS_System (pkt)', ascending=True)
            ax2.barh(df_plot_pps['Mechanizm'], df_plot_pps['PPS_System (pkt)'], color='#2ecc71')
            ax2.set_title('PPS_System (Production Protection Score)\nEfektywność w profilu produkcyjnym (3 klasy ataków)', fontsize=11, fontweight='bold')
            ax2.set_xlabel('Wskaźnik PPS_System (pkt)', fontsize=10)
            for i, v in enumerate(df_plot_pps['PPS_System (pkt)']):
                ax2.text(v + 1, i, f"{v:.1f}", va='center', fontweight='bold', fontsize=9)
            ax2.set_xlim(0, max(df_plot_pps['PPS_System (pkt)'].max() * 1.18, 10))

            fig.tight_layout()
            fig.savefig("benchmark_fts_vs_pps.png", dpi=300)
            plt.close(fig)

            # Wykres 2: Front Pareto (Koszt Chmurowy C_cloud vs Pełnosystemowa Skuteczność Produkcyjna S_sys_prod)
            fig, ax = plt.subplots(figsize=(11, 7))
            x_vals = df_plot['C_cloud (mnoznik)']
            y_vals = df_plot['S_sys_prod (%)']
            ax.scatter(x_vals, y_vals, s=140, c='#e74c3c', edgecolors='black', zorder=4)
            for _, r in df_plot.iterrows():
                ax.annotate(r['Mechanizm'], (r['C_cloud (mnoznik)'], r['S_sys_prod (%)']),
                            xytext=(7, 5), textcoords='offset points', fontsize=10, fontweight='bold')
            ax.set_xscale('log')
            ax.set_xlabel('Mnożnik Kosztu Chmurowego C_cloud (skala log, 1.0 = baseline)', fontsize=11, fontweight='bold')
            ax.set_ylabel('Pełnosystemowa Skuteczność Produkcyjna S_sys_prod (%)', fontsize=11, fontweight='bold')
            ax.set_title('Przestrzeń kompromisu: Koszt Chmurowy (vCPU + RAM GB-s) vs Pełne Pokrycie (3 klasy)', fontsize=13, fontweight='bold')
            ax.set_ylim(-5, 110)
            ax.grid(True, which="both", linestyle='--', alpha=0.5)
            fig.tight_layout()
            fig.savefig("benchmark_pareto_cloud.png", dpi=300)
            plt.close(fig)

    # ==================================================================
    # PODSUMOWANIE KOŃCOWE
    # ==================================================================
    print(f"\n{'=' * 70}")
    print(f"   ZAKOŃCZONO WSZYSTKIE TESTY")
    print(f"{'=' * 70}")
    expected_files = [
        ("benchmark_environment.json",         "Metadane środowiska i kompilatora"),
        ("benchmark_binary_size.csv",          "Rozmiary binarek i sekcji .text"),
        ("benchmark_performance_data.csv",     "Surowe dane wydajnościowe (wszystkie iteracje)"),
        ("benchmark_summary.csv",              "Podsumowanie statystyczne wydajności (z narzutem vs LTO)"),
        ("benchmark_trials_log.csv",           "Audytowalny log każdej pojedynczej próby ataku"),
        ("benchmark_efficacy_data.csv",        "Zbiorcze wyniki prób skuteczności ataków"),
        ("benchmark_efficacy_matrix.csv",      "Macierz skuteczności (mechanizm × atak)"),
        ("benchmark_efficacy_per_mechanism.csv","Rzeczywista skuteczność per mechanizm z 95% CI"),
        ("benchmark_efficacy_per_class.csv",   "Skuteczność per klasa ataku"),
        ("benchmark_methodology_scores.csv",   "Punktacja i koszt heurystyczny (FTS, PPS, C_cloud)"),
        ("benchmark_cost_efficiency.csv",      "Ujednolicona efektywność kosztowa i ranking"),
        ("benchmark_sensitivity_analysis.csv", "Analiza wrażliwości wag modelu kosztu i metryk"),
    ]
    for fname, desc in expected_files:
        marker = "✓" if os.path.exists(fname) else "✗"
        print(f"    {marker} {fname:47s} {desc}")

    png_files = sorted([f for f in os.listdir('.') if f.endswith('.png') and f.startswith('benchmark_')])
    print(f"\n  Wygenerowane wykresy ({len(png_files)} plików):")
    for f in png_files:
        print(f"    ✓ {f:47s} Wykres PNG")
