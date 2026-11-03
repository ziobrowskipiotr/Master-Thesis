import subprocess
import re
import sys
import argparse
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import os
import numpy as np
import warnings

warnings.filterwarnings("ignore", message=".*Tight layout not applied.*")
warnings.filterwarnings("ignore", category=UserWarning)

# Bezpieczne opcje dla alokatora Scudo na Linuksie (glibc / QEMU)
os.environ['SCUDO_OPTIONS'] = 'delete_size_mismatch=false:dealloc_type_mismatch=false:quarantine_size_kb=0:thread_local_quarantine_size_kb=0'
os.environ['LIBC_FATAL_STDERR_'] = '1'
os.environ['ASAN_OPTIONS'] = 'detect_stack_use_after_return=1:detect_stack_use_after_scope=1'


def extract_mechanism(variant):
    """Wyodrębnia nazwę mechanizmu z nazwy wariantu (np. 'parser_P1_asan' -> 'asan')."""
    known_mechs = [
        'canary', 'lto', 'cfi', 'pac', 'bti', 'pac_bti', 'cfi_pac_bti',
        'mte_async', 'mte_sync', 'combined', 'hardened_prod', 'scudo', 'hwasan', 'asan'
    ]
    if variant in known_mechs:
        return variant
    parts = str(variant).split('_')
    if len(parts) >= 3:
        return '_'.join(parts[2:])
    return 'base'


def variant_sort_key(var_name):
    """Sortuje warianty logicznie do wykresów: base -> kompilatorowe -> sprzętowe -> sanitizery."""
    order_map = {
        'base': 0,
        'canary': 10,
        'lto': 11,
        'cfi': 12,
        'pac': 20,
        'bti': 21,
        'pac_bti': 22,
        'cfi_pac_bti': 23,
        'mte_async': 25,
        'mte_sync': 26,
        'combined': 28,
        'hardened_prod': 29,
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

# ============================================================================

def get_text_section_bounds(executable):
    """Zwraca (addr_start, addr_end) sekcji .text dla analizy PC po crashu."""
    try:
        result = subprocess.run(['readelf', '-WS', executable], capture_output=True, text=True, check=True)
        for line in result.stdout.splitlines():
            if '.text' in line:
                parts = line.split()
                try:
                    idx = parts.index('.text')
                    addr = int(parts[idx + 2], 16)
                    size = int(parts[idx + 3], 16)
                    return addr, addr + size
                except (ValueError, IndexError):
                    pass
    except Exception as e:
        print(f"  [WARN] Błąd odczytu sekcji .text dla {executable}: {e}")
    return None, None


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
                    text_size = int(parts[idx + 3], 16)
                except (ValueError, IndexError):
                    pass
    except Exception:
        pass

    return text_size, total_size


def run_performance_test(executable, dataset_or_iters, args=[]):
    bin_path = f'./build/{executable}'
    if not os.path.exists(bin_path):
        return None

    cmd = ['/usr/bin/time', '-v', bin_path]
    if dataset_or_iters:
        cmd.append(str(dataset_or_iters))
    cmd.extend(args)

    env = os.environ.copy()
    env['SCUDO_OPTIONS'] = 'delete_size_mismatch=false:dealloc_type_mismatch=false:quarantine_size_kb=0:thread_local_quarantine_size_kb=0'

    result = subprocess.run(cmd, capture_output=True, text=True, env=env)

    if result.returncode != 0:
        return {'Wariant': executable, 'ReturnCode': result.returncode, 'Error': True, 'Stderr': result.stderr}

    internal_time_ns = 0
    for line in result.stdout.splitlines():
        if "Czas_" in line and "_ns:" in line:
            match = re.search(r'(\d+)$', line)
            if match:
                internal_time_ns += int(match.group(1))

    rss_match = re.search(r'Maximum resident set size \(kbytes\): (\d+)', result.stderr)
    rss_kb = int(rss_match.group(1)) if rss_match else 0

    return {
        'Wariant': executable,
        'ReturnCode': result.returncode,
        'Czas Wewnętrzny (s)': internal_time_ns / 1_000_000_000.0,
        'RAM (KB)': rss_kb,
        'Error': False
    }


def evaluate_single_run(executable, dataset_or_iters, args=[]):
    bin_path = f'./build/{executable}'
    if not os.path.exists(bin_path):
        return False, "BRAK_PLIKU", "Brak", "Brak", -1

    cmd = [bin_path]
    if dataset_or_iters:
        cmd.append(str(dataset_or_iters))
    cmd.extend(args)

    env = os.environ.copy()
    env['SCUDO_OPTIONS'] = 'delete_size_mismatch=false:dealloc_type_mismatch=false:quarantine_size_kb=0:thread_local_quarantine_size_kb=0'
    env['LIBC_FATAL_STDERR_'] = '1'
    env['ASAN_OPTIONS'] = 'detect_stack_use_after_return=1:detect_stack_use_after_scope=1'

    result = subprocess.run(cmd, capture_output=True, text=True, env=env)

    sanitizer_error = "Brak"
    for line in result.stderr.splitlines():
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

    ret = result.returncode
    sig = None
    if ret < 0:
        sig = -ret
    elif ret in [4, 5, 6, 7, 11]:
        sig = ret
    elif ret in [132, 133, 134, 135, 139]:
        sig = ret - 128

    sig_name = "Brak"
    if sig:
        sig_map = {4: "SIGILL", 5: "SIGTRAP", 6: "SIGABRT", 7: "SIGBUS", 11: "SIGSEGV"}
        sig_name = sig_map.get(sig, f"SIG({sig})")

    # 1. Raport sanitizera ASan / HWASan
    if sanitizer_error != "Brak":
        return True, f"ZABLOKOWANO ({sanitizer_error})", sanitizer_error, sig_name, ret

    if "AddressSanitizer" in result.stderr or "HWAddressSanitizer" in result.stderr:
        return True, "ZABLOKOWANO (Sanitizer report)", "Sanitizer Report", sig_name, ret

    # 2. Kod wyjścia 99 HWASan
    if ret == 99 and 'hwasan' in executable:
        return True, "ZABLOKOWANO (HWASan: niezgodność tagu)", "HWASan tag-mismatch", sig_name, ret

    # 3. Stack smashing detected (Stack Canary)
    # Uwaga: sprawdzamy TYLKO komunikat __stack_chk_fail, nie sam sygnał SIGABRT.
    # glibc natywnie wykrywa np. double-free i heap corruption (SIGABRT)
    # — to NIE jest zasługa canary i nie powinno być jako takie liczone.
    if "stack smashing detected" in result.stderr or "__stack_chk_fail" in result.stderr:
        return True, "ZABLOKOWANO (Stack Canary: naruszenie stosu)", "Canary __stack_chk_fail", sig_name, ret

    # 3b. Fortify Source: wykrycie przepełnienia bufora w bibliotece C
    if "buffer overflow detected" in result.stderr:
        return True, "ZABLOKOWANO (Fortify Source: naruszenie bufora)", "Fortify Source", sig_name, ret

    # 4. Przechwycono sygnał w naszym handlerze (CFI, PAC, BTI)
    if "[!] Przechwycono sygnal naruszenia bezpieczenstwa" in result.stderr:
        if '_base' in executable or '_lto' in executable:
            return False, f"CRASH (Awaria niechroniona: {sig_name}, kod {ret})", "Brak", sig_name, ret
        # BTI nie chroni stosu (D1) – rozbicie stosu w D1 dla bti to awaria bez ochrony (SIGBUS)
        if '_D1_' in executable and 'bti' in executable and 'pac' not in executable and 'combined' not in executable and 'hardened' not in executable:
            return False, f"CRASH (BTI nie chroni stosu: {sig_name}, kod {ret})", "Brak", sig_name, ret
        # PAC nie chroni lądowisk skoków BTI (D4) – naruszenie etykiety w D4 dla pac bez bti to awaria niechroniona
        if '_D4_' in executable and 'pac' in executable and 'bti' not in executable and 'combined' not in executable and 'hardened' not in executable:
            return False, f"CRASH (PAC nie chroni lądowisk BTI: {sig_name}, kod {ret})", "Brak", sig_name, ret
        return True, f"ZABLOKOWANO (Sprzętowa ochrona ARM / CFI: {sig_name})", "Signal Handler Trap", sig_name, ret

    # 5. Sygnały sprzętowe i trap kompilatora dla konkretnych mechanizmów:
    if sig is not None:
        # Atak P5: Sub-granule Overflow (alokacja 8B, nadpisanie 4B wewnątrz kafelka 16B)
        # Żaden mechanizm 16-bajtowego tagowania (MTE sync/async, Scudo, Combined, Hardened)
        # nie wykrywa przepełnienia wewnątrz kafelka. Jedynie ASan i HWASan (short-granule) wykrywają to w 100%.
        if '_P5_' in executable:
            if 'asan' in executable or 'hwasan' in executable:
                return True, f"ZABLOKOWANO (Sanitizer wykrył sub-granule overflow: {sig_name})", "Sanitizer Trap", sig_name, ret
            return False, f"OMINIĘTO / AWARIA (MTE 16B nie wykrywa sub-granule: {sig_name}, kod {ret})", "Brak", sig_name, ret

        # Atak P6: Data-Oriented Programming (DOP) na stosie (nadpisanie is_admin)
        # Canary, PAC, BTI, CFI nie chronią danych wewnątrz ramki (brak modyfikacji x30 ani wskaźników).
        # MTE-stack (-fsanitize=memtag-stack), HWASan i ASan tagują/izolują sloty zmiennych na stosie.
        if '_P6_' in executable:
            if any(k in executable for k in ['mte', 'combined', 'hardened', 'asan', 'hwasan']):
                return True, f"ZABLOKOWANO (Ochrona stosu MTE/Sanitizer: {sig_name})", "Stack Memory Tagging", sig_name, ret
            return False, f"OMINIĘTO (Atak DOP omija Canary/PAC/BTI/CFI, kod {ret})", "Brak", sig_name, ret

        # Atak M3: Stack Use-After-Scope (temporalny błąd stosu)
        # Canary, PAC, Scudo nie chronią zmiennych na stosie po wyjściu ze scope'a.
        # Jedynie memtag-stack (MTE sync/async, combined, hardened_prod), HWASan i ASan wykrywają naruszenie tagu.
        if '_M3_' in executable:
            if any(k in executable for k in ['mte', 'combined', 'hardened', 'asan', 'hwasan']):
                return True, f"ZABLOKOWANO (Ochrona stosu MTE/Sanitizer przed use-after-scope: {sig_name})", "Stack Use-After-Scope Trap", sig_name, ret
            return False, f"OMINIĘTO (Atak use-after-scope omija Canary/PAC/Scudo, kod {ret})", "Brak", sig_name, ret

        if 'scudo' in executable and sig in [6, 11]:
            # Scudo chroni wyłącznie stertę (heap) – nie chroni zmiennych globalnych (P3) ani stosu (P2/D1/P6/M3)
            if any(k in executable for k in ['_P3_', '_P2_', '_D1_', '_P6_', '_M3_']):
                return False, f"CRASH (Scudo nie chroni sekcji global/stack: {sig_name}, kod {ret})", "Brak", sig_name, ret
            return True, f"ZABLOKOWANO (Scudo: naruszenie spójności sterty {sig_name})", "Scudo Abort", sig_name, ret

        if 'cfi' in executable and sig in [4, 5, 11]:
            return True, f"ZABLOKOWANO (CFI: nielegalny skok pośredni {sig_name})", "CFI Trap", sig_name, ret

        if 'pac' in executable and sig in [4, 7, 11]:
            return True, f"ZABLOKOWANO (PAC: błąd autoryzacji adresu {sig_name})", "PAC Auth Fault", sig_name, ret

        if 'bti' in executable and sig in [4, 11]:
            return True, f"ZABLOKOWANO (BTI: skok bez instrukcji lądowiska {sig_name})", "BTI Branch Fault", sig_name, ret

        if 'mte' in executable and sig in [6, 11]:
            # MTE na Linuksie glibc nie chroni zmiennych globalnych (P3)
            if '_P3_' in executable:
                return False, f"CRASH (MTE nie chroni sekcji global na glibc: {sig_name}, kod {ret})", "Brak", sig_name, ret
            return True, f"ZABLOKOWANO (MTE: błąd tagu pamięci {sig_name})", "MTE Tag Fault", sig_name, ret

        # Profil połączony / synergiczny (combined / hardened_prod):
        # Zawiera PAC + BTI + CFI + MTE + Scudo (+ _FORTIFY_SOURCE=3 w hardened_prod).
        # Dowolny sygnał bezpieczeństwa (SIGILL 4, SIGTRAP 5, SIGABRT 6, SIGBUS 7, SIGSEGV 11)
        # jest legalnym przechwyceniem ataku przez odpowiedni podsystem.
        if ('combined' in executable or 'hardened' in executable) and sig in [4, 5, 6, 7, 11]:
            # Sekcja globalna (P3):
            # hardened_prod posiada _FORTIFY_SOURCE=3, więc chroni global_buffer!
            # combined NIE posiada _FORTIFY_SOURCE=3, więc na glibc nie chroni sekcji global.
            if '_P3_' in executable and 'hardened' not in executable:
                return False, f"CRASH (Brak ochrony sekcji global na glibc: {sig_name}, kod {ret})", "Brak", sig_name, ret
            if '_P3_' in executable and 'hardened' in executable:
                return True, "ZABLOKOWANO (Fortify Source / Hardened Prod: ochrona sekcji globalnej)", "Fortify Source", sig_name, ret
            return True, f"ZABLOKOWANO (Synergia ochronna: zablokowano przez sprzęt/kompilator {sig_name})", "Combined Trap", sig_name, ret

        if 'asan' in executable or 'hwasan' in executable:
            return True, f"ZABLOKOWANO (Sanitizer trap {sig_name})", "Sanitizer Trap", sig_name, ret

        # Jeśli to baseline ('base' lub 'lto'), program się po prostu rozbił bez ochrony
        return False, f"CRASH (Awaria niechroniona: {sig_name}, kod {ret})", "Brak", sig_name, ret

    # 6. Kod 0: program wykonał atak i nie został powstrzymany
    if ret == 0:
        return False, "OMINIĘTO (Atak powiódł się bez wykrycia, kod 0)", "Brak", "Brak", 0

    return False, f"CRASH (Nieznany kod wyjścia {ret})", "Brak", sig_name, ret


def run_efficacy_test(executable, dataset_or_iters, trials=5, args=[]):
    blocked_count = 0
    statuses = []
    last_sanitizer = "Brak"
    last_sig = "Brak"
    last_ret = 0

    for _ in range(trials):
        blocked, status_str, san_err, sig_name, ret = evaluate_single_run(executable, dataset_or_iters, args)
        if blocked:
            blocked_count += 1
        statuses.append(status_str)
        if san_err != "Brak":
            last_sanitizer = san_err
        if sig_name != "Brak":
            last_sig = sig_name
        last_ret = ret

    detection_rate_pct = (blocked_count / trials) * 100.0

    if any("BRAK_PLIKU" in s for s in statuses):
        status = f"BŁĄD (Brak pliku ./build/{executable})"
    elif blocked_count == trials:
        status = f"ZABLOKOWANO ({blocked_count}/{trials}, 100%)"
    elif blocked_count > 0:
        status = f"CZĘŚCIOWO ({blocked_count}/{trials}, {detection_rate_pct:.0f}%)"
    elif any("CRASH" in s for s in statuses):
        status = f"CRASH (Awaria bez ochrony, 0/{trials})"
    else:
        status = f"OMINIĘTO (Atak niewykryty, 0/{trials})"

    return {
        'Wariant': executable,
        'Status': status,
        'Zablokowano': 1 if detection_rate_pct >= 50.0 else 0,
        'Skutecznosc_Procent': round(detection_rate_pct, 1),
        'Zablokowane_Proby': blocked_count,
        'Liczba_Prob': trials,
        'Sanitizer': last_sanitizer,
        'Sygnal': last_sig,
        'PC': "Brak",
        'ReturnCode': last_ret
    }


# ============================================================================
# GŁÓWNA LOGIKA
# ============================================================================

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Benchmark mechanizmów bezpieczeństwa pamięci ARM64 i autorska ocena opłacalności chmurowej."
    )
    parser.add_argument(
        '--profile', '-P',
        choices=['quick', 'standard', 'full', 'thesis'],
        default='standard',
        help="Profil testu: 'quick' (5 powtórzeń), 'standard' (30 powtórzeń, large), 'full' (30 powtórzeń, large), 'thesis' (50 powtórzeń, large)."
    )
    parser.add_argument(
        '--runs', '-n',
        type=int,
        default=None,
        help="Ujednolicona liczba powtórzeń (ustawia jednocześnie taką samą liczbę iteracji wydajności i prób ataków, np. 30)."
    )
    parser.add_argument(
        '--iterations', '-i',
        type=int,
        default=None,
        help="Liczba powtórzeń testów wydajnościowych (domyślnie równa próbom ataków)."
    )
    parser.add_argument(
        '--trials', '-t',
        type=int,
        default=None,
        help="Liczba prób w testach ataków (domyślnie równa iteracjom wydajnościowym)."
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
        help="Zbiór danych dla parsera (domyślnie 'small': ~668KB)."
    )
    parser.add_argument(
        '--plots-only', '-p',
        action='store_true',
        help="Generuje tylko wykresy i tabele z istniejących plików CSV (bez ponownego uruchamiania binarek)."
    )
    parser.add_argument(
        '--efficacy-only', '-e',
        action='store_true',
        help="Uruchamia wyłącznie testy skuteczności ataków (szybkie sprawdzenie MTE/ASan z dużą liczbą prób)."
    )
    parser.add_argument(
        '--perf-only',
        action='store_true',
        help="Uruchamia wyłącznie testy wydajnościowe (czas wykonania i zużycie RAM)."
    )
    args = parser.parse_args()

    # Mapowanie profili na domyślne parametry (iteracje == triale):
    profile_configs = {
        'quick':    {'runs': 5,  'warmup': 1, 'dataset': 'small'},
        'standard': {'runs': 5,  'warmup': 1, 'dataset': 'small'},
        'full':     {'runs': 10, 'warmup': 2, 'dataset': 'small'},
        'thesis':   {'runs': 30, 'warmup': 3, 'dataset': 'small'},
    }
    cfg = profile_configs.get(args.profile, profile_configs['standard'])

    # Ujednolicenie: iteracje i triale są domyślnie równe
    base_runs = args.runs if args.runs is not None else cfg['runs']
    if args.iterations is not None and args.trials is not None:
        iterations = args.iterations
        trials_count = args.trials
    elif args.iterations is not None:
        iterations = args.iterations
        trials_count = args.iterations
    elif args.trials is not None:
        trials_count = args.trials
        iterations = args.trials
    else:
        iterations = base_runs
        trials_count = base_runs

    warmup_runs = args.warmup if args.warmup is not None else cfg['warmup']
    dataset_choice = args.dataset if args.dataset is not None else cfg['dataset']

    dataset_map = {
        'small': "data/dataset_small.bin",
        'medium': "data/dataset_medium.bin",
        'large': "data/dataset_large.bin",
    }
    dataset_perf = dataset_map.get(dataset_choice, "data/dataset_small.bin")
    dataset_malicious = "data/dataset_p4_malicious.bin"
    dataset_p1 = "data/dataset_p1_malicious.bin" if os.path.exists("data/dataset_p1_malicious.bin") else dataset_malicious
    dataset_p2 = "data/dataset_p2_malicious.bin" if os.path.exists("data/dataset_p2_malicious.bin") else dataset_malicious
    dataset_p3 = "data/dataset_p3_malicious.bin" if os.path.exists("data/dataset_p3_malicious.bin") else dataset_malicious
    dataset_p5 = "data/dataset_p5_malicious.bin" if os.path.exists("data/dataset_p5_malicious.bin") else dataset_malicious
    dataset_p6 = "data/dataset_p6_malicious.bin" if os.path.exists("data/dataset_p6_malicious.bin") else dataset_malicious

    perf_apps = {
        'Parser': (['parser_P0_base', 'parser_P0_canary', 'parser_P0_scudo', 'parser_P0_mte_async', 'parser_P0_mte_sync', 'parser_P0_combined', 'parser_P0_hardened_prod', 'parser_P0_hwasan', 'parser_P0_asan'], dataset_perf),
        'KV_Store': (['kv_M0_base', 'kv_M0_canary', 'kv_M0_mte_async', 'kv_M0_mte_sync', 'kv_M0_scudo', 'kv_M0_combined', 'kv_M0_hardened_prod', 'kv_M0_hwasan', 'kv_M0_asan'], 10000),
        'Dispatcher': (['disp_D0_base', 'disp_D0_canary', 'disp_D0_lto', 'disp_D0_cfi', 'disp_D0_pac', 'disp_D0_bti', 'disp_D0_pac_bti', 'disp_D0_cfi_pac_bti', 'disp_D0_combined', 'disp_D0_hardened_prod', 'disp_D0_asan'], 500000)
    }

    efficacy_apps = {
        # --- PARSER: błędy pamięci przestrzenne (spatial) ---
        # Każdy atak używa pojedynczego złośliwego pakietu (single-shot exploit),
        # aby rzetelnie mierzyć prawdopodobieństwo detekcji sprzętowej (np. kolizję 1/16 w MTE).
        'P1_heap_overflow': (
            ['parser_P1_base', 'parser_P1_asan', 'parser_P1_hwasan',
             'parser_P1_mte_sync', 'parser_P1_mte_async',
             'parser_P1_canary', 'parser_P1_scudo', 'parser_P1_combined', 'parser_P1_hardened_prod'], dataset_p1),
        'P2_stack_overflow': (
            ['parser_P2_base', 'parser_P2_asan', 'parser_P2_hwasan',
             'parser_P2_mte_sync', 'parser_P2_mte_async',
             'parser_P2_canary', 'parser_P2_combined', 'parser_P2_hardened_prod'], dataset_p2),
        'P3_global_overflow': (
            ['parser_P3_base', 'parser_P3_asan', 'parser_P3_hwasan',
             'parser_P3_mte_sync', 'parser_P3_mte_async',
             'parser_P3_canary', 'parser_P3_scudo', 'parser_P3_combined', 'parser_P3_hardened_prod'], dataset_p3),
        'P4_heap_oob_read': (
            ['parser_P4_base', 'parser_P4_asan', 'parser_P4_hwasan',
             'parser_P4_mte_sync', 'parser_P4_mte_async',
             'parser_P4_canary', 'parser_P4_scudo', 'parser_P4_combined', 'parser_P4_hardened_prod'], dataset_malicious),
        'P5_subgranule_overflow': (
            ['parser_P5_base', 'parser_P5_asan', 'parser_P5_hwasan',
             'parser_P5_mte_sync', 'parser_P5_mte_async',
             'parser_P5_canary', 'parser_P5_scudo', 'parser_P5_combined', 'parser_P5_hardened_prod'], dataset_p5),
        'P6_stack_dop': (
            ['parser_P6_base', 'parser_P6_asan', 'parser_P6_hwasan',
             'parser_P6_mte_sync', 'parser_P6_mte_async',
             'parser_P6_canary', 'parser_P6_combined', 'parser_P6_hardened_prod'], dataset_p6),
        # --- KV STORE: błędy pamięci temporalne (temporal) ---
        'M1_use_after_free': (
            ['kv_M1_base', 'kv_M1_asan', 'kv_M1_hwasan',
             'kv_M1_mte_sync', 'kv_M1_mte_async',
             'kv_M1_scudo', 'kv_M1_canary', 'kv_M1_combined', 'kv_M1_hardened_prod'], 500),
        'M2_double_free': (
            ['kv_M2_base', 'kv_M2_asan', 'kv_M2_hwasan',
             'kv_M2_scudo', 'kv_M2_mte_sync', 'kv_M2_mte_async',
             'kv_M2_canary', 'kv_M2_combined', 'kv_M2_hardened_prod'], 500),
        'M3_stack_use_after_scope': (
            ['kv_M3_base', 'kv_M3_asan', 'kv_M3_hwasan',
             'kv_M3_scudo', 'kv_M3_mte_sync', 'kv_M3_mte_async',
             'kv_M3_canary', 'kv_M3_combined', 'kv_M3_hardened_prod'], 500),
        # --- DISPATCHER: ataki na przepływ sterowania (control flow) ---
        'D1_stack_smash': (
            ['disp_D1_base', 'disp_D1_pac', 'disp_D1_bti', 'disp_D1_pac_bti',
             'disp_D1_canary', 'disp_D1_cfi_pac_bti', 'disp_D1_combined', 'disp_D1_hardened_prod', 'disp_D1_asan'], 1),
        'D2_indirect_call_hijack': (
            ['disp_D2_lto', 'disp_D2_cfi',
             'disp_D2_bti', 'disp_D2_pac_bti',
             'disp_D2_bypass_lto', 'disp_D2_bypass_cfi',
             'disp_D2_cfi_pac_bti', 'disp_D2_combined', 'disp_D2_hardened_prod'], 1),
        'D3_vtable_hijack': (
            ['disp_D3_lto', 'disp_D3_cfi',
             'disp_D3_cfi_pac_bti', 'disp_D3_combined', 'disp_D3_hardened_prod'], 1),
        'D4_bti_landing': (
            ['disp_D4_base', 'disp_D4_pac', 'disp_D4_bti', 'disp_D4_pac_bti',
             'disp_D4_cfi', 'disp_D4_lto',
             'disp_D4_cfi_pac_bti', 'disp_D4_combined', 'disp_D4_hardened_prod'], 1),
    }

    # Mapowanie ataków na klasy (do grupowania na wykresach)
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
        'D3_vtable_hijack': 'Control Flow',
        'D4_bti_landing': 'Control Flow',
    }

    plots_only = args.plots_only
    print("=" * 70)
    print("   KONFIGURACJA BENCHMARKU BEZPIECZEŃSTWA ARM64")
    print("=" * 70)
    print(f"  • Profil:             {args.profile.upper()}")
    print(f"  • Zbiór danych:       {dataset_perf}")
    print(f"  • Iteracje wydajność: {iterations} (rozgrzewka: {warmup_runs})")
    print(f"  • Próby ataków:       {trials_count} per scenariusz (MTE tag-collision test)")
    if args.efficacy_only:
        print("  • Tryb:               TYLKO TESTY SKUTECZNOŚCI ATAKÓW (--efficacy-only)")
    elif args.perf_only:
        print("  • Tryb:               TYLKO TESTY WYDAJNOŚCIOWE (--perf-only)")
    elif plots_only:
        print("  • Tryb:               TYLKO GENEROWANIE WYKRESÓW (--plots-only)")
    else:
        print("  • Tryb:               PEŁNY TEST GENERALNY (Kompilacja + Wydajność + Ataki + Faza 4)")
    print("=" * 70 + "\n")

    if not plots_only:
        # ==================================================================
        # KOMPILACJA ZMIENIONYCH CELÓW (NINJA / CCACHE)
        # ==================================================================
        print("=" * 70)
        print("   AUTOMATYCZNA KOMPILACJA (NINJA / CCACHE)...")
        print("=" * 70)
        reconfig = False
        current_dir = os.path.abspath(".")
        if os.path.exists("build/CMakeCache.txt"):
            try:
                with open("build/CMakeCache.txt", "r") as f:
                    cache_content = f.read()
                if f"CMAKE_HOME_DIRECTORY:INTERNAL={current_dir}" not in cache_content:
                    reconfig = True
            except Exception:
                reconfig = True
        else:
            reconfig = True

        critical_bins = ['parser_P5_asan', 'parser_P6_asan', 'kv_M3_asan', 'disp_D2_bti']
        if any(not os.path.exists(f"build/{b}") for b in critical_bins):
            reconfig = True

        try:
            if reconfig:
                print("  [INFO] Wykryto zmianę ścieżek/brak konfiguracji. Rekonfiguracja CMake...")
                subprocess.run(["cmake", "-B", "build", "-G", "Ninja"], check=True)
            if os.path.exists("build/build.ninja"):
                subprocess.run(["ninja", "-C", "build", "-j4"], check=True)
            elif os.path.exists("build/Makefile"):
                subprocess.run(["make", "-C", "build", "-j4"], check=True)
            else:
                subprocess.run(["cmake", "-B", "build", "-G", "Ninja"], check=True)
                subprocess.run(["ninja", "-C", "build", "-j4"], check=True)
            print("  -> Kompilacja zakończona sukcesem.\n")
        except Exception as e:
            print(f"\n  [KRYTYCZNY BŁĄD KOMPILACJI]: {e}")
            print("  [!] Nie udało się skompilować celów. Przerwanie benchmarku, aby zapobiec fałszywym wynikom.")
            sys.exit(1)

    # ==================================================================
    # FAZA 1: METRYKI STATYCZNE (rozmiar binarki / sekcji .text)
    # ==================================================================
    print("=" * 70)
    print("   FAZA 1: METRYKI STATYCZNE (rozmiar binarki / sekcji .text)")
    print("=" * 70)

    binary_metrics = []
    if (plots_only or args.efficacy_only) and os.path.exists("benchmark_binary_size.csv"):
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
                print(f"  {exe:40s} .text: {text_size:>8d} B ({text_size/1024:.1f} KB)"
                      f"  total: {total_size:>10d} B ({total_size/1024:.1f} KB)")
                binary_metrics.append({
                    'Wariant': exe,
                    'Rozmiar .text (B)': text_size,
                    'Rozmiar binarki (B)': total_size,
                })

        if binary_metrics:
            df_bin = pd.DataFrame(binary_metrics)
            df_bin.to_csv("benchmark_binary_size.csv", index=False)
            print(f"\n  -> Zapisano {len(binary_metrics)} wpisów do benchmark_binary_size.csv")

    if binary_metrics:
        # Wykres rozmiaru .text per grupa wydajnosciowa
        sns.set_theme(style="whitegrid")
        for app_group, (executables, _) in perf_apps.items():
            group_data = df_bin[df_bin['Wariant'].isin(executables)].copy()
            if group_data.empty:
                continue
            group_data['sort_key'] = group_data['Wariant'].apply(variant_sort_key)
            group_data = group_data.sort_values('sort_key').drop(columns=['sort_key'])

            kb_values = group_data['Rozmiar .text (B)'] / 1024
            max_kb = float(kb_values.max())
            min_kb = float(kb_values.min())

            # Jeśli asan/hwasan dominuje (> 8x), rysujemy panel podwójny (liniowy + logarytmiczny)
            if max_kb / max(min_kb, 0.1) > 8:
                fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(15, 5))

                # Panel 1: Skala liniowa
                bars1 = ax1.bar(group_data['Wariant'], kb_values,
                                color=sns.color_palette("Set2", len(group_data)))
                ax1.set_ylabel('Rozmiar sekcji .text (KB)', fontsize=11, fontweight='bold')
                ax1.set_title(f'Rozmiar kodu – {app_group} (skala liniowa)', fontsize=12, fontweight='bold')
                ax1.tick_params(axis='x', rotation=20)
                ax1.set_ylim(0, max_kb * 1.15)
                for bar in bars1:
                    h = bar.get_height()
                    ax1.annotate(f'{h:.1f}',
                                xy=(bar.get_x() + bar.get_width() / 2, h),
                                xytext=(0, 3), textcoords="offset points",
                                ha='center', va='bottom', fontsize=8.5, fontweight='bold')

                # Panel 2: Skala logarytmiczna (pozwala porównać Base vs Canary vs MTE)
                bars2 = ax2.bar(group_data['Wariant'], kb_values,
                                color=sns.color_palette("Set2", len(group_data)), bottom=0.5)
                ax2.set_yscale('log')
                ax2.set_ylabel('Rozmiar sekcji .text (KB, skala log)', fontsize=11, fontweight='bold')
                ax2.set_title(f'Rozmiar kodu – {app_group} (skala logarytmiczna)', fontsize=12, fontweight='bold')
                ax2.tick_params(axis='x', rotation=20)
                ax2.set_ylim(bottom=1, top=max_kb * 2.2)
                for bar in bars2:
                    h = bar.get_height()
                    ax2.annotate(f'{h:.1f}',
                                xy=(bar.get_x() + bar.get_width() / 2, h),
                                xytext=(0, 3), textcoords="offset points",
                                ha='center', va='bottom', fontsize=8.5, fontweight='bold')

                fig.tight_layout()
                fig.savefig(f"benchmark_text_size_{app_group}.png", dpi=300)
                plt.close(fig)
            else:
                fig, ax = plt.subplots(figsize=(10, 5))
                bars = ax.bar(group_data['Wariant'], kb_values,
                              color=sns.color_palette("Set2", len(group_data)))
                ax.set_ylabel('Rozmiar sekcji .text (KB)', fontsize=11, fontweight='bold')
                ax.set_title(f'Rozmiar kodu wykonywalnego – {app_group}', fontsize=12, fontweight='bold')
                ax.tick_params(axis='x', rotation=15)
                ax.set_ylim(0, max_kb * 1.15)
                for bar in bars:
                    height = bar.get_height()
                    ax.annotate(f'{height:.1f}',
                                xy=(bar.get_x() + bar.get_width() / 2, height),
                                xytext=(0, 3), textcoords="offset points",
                                ha='center', va='bottom', fontsize=9, fontweight='bold')
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
    if (plots_only or args.efficacy_only) and os.path.exists("benchmark_performance_data.csv"):
        df_perf = pd.read_csv("benchmark_performance_data.csv")
        perf_results = df_perf.to_dict('records')
        if args.efficacy_only:
            print(f"  [POMINIĘTO] Tryb --efficacy-only: wczytano {len(perf_results)} pomiarów wydajności z pamięci podręcznej.")
        else:
            print(f"  [CACHE] Załadowano {len(perf_results)} pomiarów z benchmark_performance_data.csv")
    elif args.efficacy_only:
        print("  [POMINIĘTO] Tryb --efficacy-only: brak pliku cache, pomijam testy wydajnościowe.")
    else:
        for app_group, (executables, arg) in perf_apps.items():
            print(f"\n  Grupa: {app_group}")
            for exe in executables:
                print(f"    -> {exe}...", end="", flush=True)

                # Warmup
                for _ in range(warmup_runs):
                    run_performance_test(exe, arg)

                exe_failed = False
                for i in range(iterations):
                    res = run_performance_test(exe, arg)
                    if res and not res['Error']:
                        res['Grupa'] = app_group
                        perf_results.append(res)
                    elif res and res['Error']:
                        print(f" BŁĄD! (ReturnCode: {res['ReturnCode']})")
                        if res.get('Stderr'):
                            err_lines = [l.strip() for l in res['Stderr'].splitlines() if l.strip() and not any(k in l for k in ["Command being timed", "User time", "System time", "Percent of CPU", "Elapsed", "Average", "Maximum resident", "Minor", "Major", "Voluntary", "Involuntary", "Swaps", "File system", "Socket", "Signals delivered", "Page size", "Exit status"])]
                            print(f"       [Komunikat]: {' | '.join(err_lines[:5]) if err_lines else res['Stderr'].strip()[:200]}")
                        exe_failed = True
                        break
                if not exe_failed:
                    times = [r['Czas Wewnętrzny (s)'] for r in perf_results if r['Wariant'] == exe]
                    med_t = np.median(times)
                    std_t = np.std(times)
                    print(f" OK (mediana: {med_t:.4f}s, σ: {std_t:.4f}s, n={len(times)})")

        if perf_results:
            df_perf = pd.DataFrame(perf_results)
            df_perf.to_csv("benchmark_performance_data.csv", index=False)

    if perf_results:
        df_perf = pd.DataFrame(perf_results) if not isinstance(perf_results, pd.DataFrame) else perf_results
        sns.set_theme(style="whitegrid")

        # Wykresy boxplot: czas wykonania
        for app_group in df_perf['Grupa'].unique():
            group_df = df_perf[df_perf['Grupa'] == app_group].copy()
            unique_vars = sorted(group_df['Wariant'].unique(), key=variant_sort_key)

            med_times = group_df.groupby('Wariant')['Czas Wewnętrzny (s)'].median()
            time_ratio = med_times.max() / max(med_times.min(), 0.0001)

            if time_ratio > 8:
                fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(16, 6))
                sns.boxplot(x='Wariant', y='Czas Wewnętrzny (s)', data=group_df,
                            order=unique_vars, hue='Wariant', palette="Set2", legend=False, ax=ax1)
                ax1.set_title(f'Czas wykonania (skala liniowa) – {app_group}', fontsize=12, fontweight='bold')
                ax1.set_ylabel('Czas Wewnętrzny (s)', fontsize=11, fontweight='bold')
                ax1.tick_params(axis='x', rotation=20)

                sns.boxplot(x='Wariant', y='Czas Wewnętrzny (s)', data=group_df,
                            order=unique_vars, hue='Wariant', palette="Set2", legend=False, ax=ax2)
                ax2.set_yscale('log')
                ax2.set_title(f'Czas wykonania (skala logarytmiczna) – {app_group}', fontsize=12, fontweight='bold')
                ax2.set_ylabel('Czas Wewnętrzny (s, skala log)', fontsize=11, fontweight='bold')
                ax2.tick_params(axis='x', rotation=20)

                fig.tight_layout()
                fig.savefig(f"benchmark_time_{app_group}.png", dpi=300)
                plt.close(fig)
            else:
                plt.figure(figsize=(12, 6))
                sns.boxplot(x='Wariant', y='Czas Wewnętrzny (s)', data=group_df,
                            order=unique_vars, hue='Wariant', palette="Set2", legend=False)
                plt.title(f'Czas wykonania – {app_group} ({iterations} iteracji)', fontsize=13, fontweight='bold')
                plt.ylabel('Czas Wewnętrzny (s)', fontsize=11, fontweight='bold')
                plt.xticks(rotation=20, ha='right')
                plt.tight_layout()
                plt.savefig(f"benchmark_time_{app_group}.png", dpi=300)
                plt.close()

        # Wykresy boxplot: zużycie RAM
        for app_group in df_perf['Grupa'].unique():
            group_df = df_perf[df_perf['Grupa'] == app_group]
            unique_vars = sorted(group_df['Wariant'].unique(), key=variant_sort_key)
            plt.figure(figsize=(12, 6))
            sns.boxplot(x='Wariant', y='RAM (KB)', data=group_df,
                        order=unique_vars, hue='Wariant', palette="Pastel1", legend=False)
            plt.title(f'Zużycie pamięci RAM (RSS) – {app_group} ({iterations} iteracji)', fontsize=13, fontweight='bold')
            plt.ylabel('RAM (KB)', fontsize=11, fontweight='bold')
            plt.xticks(rotation=20, ha='right')
            plt.tight_layout()
            plt.savefig(f"benchmark_ram_{app_group}.png", dpi=300)
            plt.close()

        # ==============================================================
        # TABELA PODSUMOWUJĄCA: narzut % względem baseline
        # ==============================================================
        print(f"\n{'=' * 70}")
        print(f"   PODSUMOWANIE WYDAJNOŚCI (narzut % względem baseline)")
        print(f"{'=' * 70}")

        summary_rows = []
        for app_group in df_perf['Grupa'].unique():
            group_df = df_perf[df_perf['Grupa'] == app_group]
            variants = sorted(group_df['Wariant'].unique(), key=variant_sort_key)

            # Znajdz wariant baseline (konczy sie na _base)
            baseline_name = None
            for v in variants:
                if v.endswith('_base'):
                    baseline_name = v
                    break
            if baseline_name is None:
                baseline_name = variants[0]

            base_times = group_df[group_df['Wariant'] == baseline_name]['Czas Wewnętrzny (s)']
            base_ram = group_df[group_df['Wariant'] == baseline_name]['RAM (KB)']
            base_med_t = np.median(base_times)
            base_med_ram = np.median(base_ram)

            print(f"\n  [{app_group}]  baseline = {baseline_name}")
            print(f"  {'Wariant':40s} {'Med. czas':>10s} {'Narzut %':>10s}"
                  f" {'σ czasu':>10s} {'IQR':>10s}"
                  f" {'Med. RAM':>10s} {'Narzut %':>10s}")
            print(f"  {'-'*40} {'-'*10} {'-'*10} {'-'*10} {'-'*10} {'-'*10} {'-'*10}")

            for v in variants:
                v_times = group_df[group_df['Wariant'] == v]['Czas Wewnętrzny (s)']
                v_ram = group_df[group_df['Wariant'] == v]['RAM (KB)']

                med_t = np.median(v_times)
                mean_t = np.mean(v_times)
                std_t = np.std(v_times)
                iqr_t = np.percentile(v_times, 75) - np.percentile(v_times, 25)
                overhead_t = ((med_t - base_med_t) / base_med_t * 100) if base_med_t > 0 else 0
                med_ram = np.median(v_ram)
                overhead_ram = ((med_ram - base_med_ram) / base_med_ram * 100) if base_med_ram > 0 else 0

                row = {
                    'Grupa': app_group,
                    'Wariant': v,
                    'Mediana czasu (s)': round(med_t, 6),
                    'Średnia czasu (s)': round(mean_t, 6),
                    'Odch. std. czasu (s)': round(std_t, 6),
                    'IQR czasu (s)': round(iqr_t, 6),
                    'Narzut czasowy (%)': round(overhead_t, 2),
                    'Mediana RAM (KB)': int(med_ram),
                    'Narzut RAM (%)': round(overhead_ram, 2),
                }

                # Dołącz metrykę rozmiaru binarki, jeśli dostępna
                if binary_metrics:
                    bin_row = [b for b in binary_metrics if b['Wariant'] == v]
                    if bin_row:
                        row['Rozmiar .text (B)'] = bin_row[0]['Rozmiar .text (B)']
                        row['Rozmiar binarki (B)'] = bin_row[0]['Rozmiar binarki (B)']
                        base_bin = [b for b in binary_metrics if b['Wariant'] == baseline_name]
                        if base_bin and base_bin[0]['Rozmiar .text (B)'] > 0:
                            overhead_text = ((bin_row[0]['Rozmiar .text (B)'] - base_bin[0]['Rozmiar .text (B)'])
                                             / base_bin[0]['Rozmiar .text (B)'] * 100)
                            row['Narzut .text (%)'] = round(overhead_text, 2)

                summary_rows.append(row)

                marker = " [BASE]" if v == baseline_name else ""
                print(f"  {v:40s} {med_t:>10.4f}s {overhead_t:>+9.1f}%"
                      f" {std_t:>10.4f}s {iqr_t:>10.4f}s"
                      f" {int(med_ram):>8d} KB {overhead_ram:>+9.1f}%{marker}")

        df_summary = pd.DataFrame(summary_rows)
        df_summary.to_csv("benchmark_summary.csv", index=False)
        print(f"\n  -> Zapisano podsumowanie do benchmark_summary.csv")

        # Wykresy slupkowe narzutu % (czas + RAM obok siebie)
        for app_group in df_summary['Grupa'].unique():
            group_sum = df_summary[df_summary['Grupa'] == app_group].copy()
            # Sortuj logicznie wg variant_sort_key: ascending=False aby w barh wariant referencyjny base był na samej górze
            group_sum['sort_key'] = group_sum['Wariant'].apply(variant_sort_key)
            group_sum = group_sum.sort_values('sort_key', ascending=False)

            fig, axes = plt.subplots(1, 2, figsize=(16, 6))

            def draw_horizontal_overhead(ax, values, y_labels, title, xlabel, threshold_yellow=5, threshold_red=50):
                colors = ['#2ecc71' if abs(x) <= threshold_yellow else '#f39c12' if abs(x) <= threshold_red else '#e74c3c'
                          for x in values]
                ax.barh(y_labels, values, color=colors)
                ax.set_xlabel(xlabel, fontsize=11, fontweight='bold')
                ax.set_title(title, fontsize=12, fontweight='bold')
                ax.axvline(x=0, color='black', linewidth=0.7)

                min_v = min(0.0, float(values.min()))
                max_v = max(0.0, float(values.max()))
                span = max_v - min_v
                if span <= 0:
                    span = 10.0

                pad_right = span * 0.22  # Zapas 22% na tekst po prawej stronie
                pad_left = span * 0.15 if min_v < 0 else span * 0.05
                ax.set_xlim(min_v - pad_left, max_v + pad_right)

                offset = span * 0.025
                for i, val in enumerate(values):
                    txt_x = val + (offset if val >= 0 else -offset)
                    ha = 'left' if val >= 0 else 'right'
                    ax.text(txt_x, i, f'{val:+.1f}%', va='center', ha=ha, fontsize=9, fontweight='bold')

            # Narzut czasowy
            draw_horizontal_overhead(axes[0], group_sum['Narzut czasowy (%)'], group_sum['Wariant'],
                                     f'Narzut czasu vs baseline – {app_group}', 'Narzut czasowy (%)',
                                     threshold_yellow=5, threshold_red=50)

            # Narzut RAM
            draw_horizontal_overhead(axes[1], group_sum['Narzut RAM (%)'], group_sum['Wariant'],
                                     f'Narzut pamięci vs baseline – {app_group}', 'Narzut RAM (%)',
                                     threshold_yellow=10, threshold_red=100)

            fig.subplots_adjust(left=0.22, right=0.96, top=0.90, bottom=0.10, wspace=0.45)
            fig.savefig(f"benchmark_overhead_{app_group}.png", dpi=300)
            plt.close(fig)

        # Wykres narzutu .text (jesli metryki sa dostepne)
        if any('Narzut .text (%)' in r for r in summary_rows):
            for app_group in df_summary['Grupa'].unique():
                group_sum = df_summary[df_summary['Grupa'] == app_group]
                if 'Narzut .text (%)' not in group_sum.columns:
                    continue
                valid = group_sum.dropna(subset=['Narzut .text (%)']).copy()
                if valid.empty:
                    continue

                valid['sort_key'] = valid['Wariant'].apply(variant_sort_key)
                valid = valid.sort_values('sort_key', ascending=False)

                fig, ax = plt.subplots(figsize=(12, 5))
                colors_b = ['#2ecc71' if abs(x) <= 5 else '#f39c12' if abs(x) <= 50 else '#e74c3c'
                            for x in valid['Narzut .text (%)']]
                ax.barh(valid['Wariant'], valid['Narzut .text (%)'], color=colors_b)
                ax.set_xlabel('Narzut rozmiaru sekcji .text (%)', fontsize=11, fontweight='bold')
                ax.set_title(f'Narzut rozmiaru kodu vs baseline – {app_group}', fontsize=12, fontweight='bold')
                ax.axvline(x=0, color='black', linewidth=0.7)

                # Bezpieczne granice i etykiety tekstowe z procentami
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
    if (plots_only or args.perf_only) and os.path.exists("benchmark_efficacy_data.csv"):
        df_eff = pd.read_csv("benchmark_efficacy_data.csv")
        efficacy_results = df_eff.to_dict('records')
        if args.perf_only:
            print(f"  [POMINIĘTO] Tryb --perf-only: wczytano {len(efficacy_results)} wyników ataków z pamięci podręcznej.")
        else:
            print(f"  [CACHE] Załadowano {len(efficacy_results)} wyników z benchmark_efficacy_data.csv")
    elif args.perf_only:
        print("  [POMINIĘTO] Tryb --perf-only: brak pliku cache, pomijam testy ataków.")
    else:
        for app_group, (executables, arg) in efficacy_apps.items():
            print(f"\n  Atak: {app_group}")
            for exe in executables:
                res = run_efficacy_test(exe, arg, trials=trials_count)
                if res:
                    if "BŁĄD" in res['Status']:
                        icon = "❌ BŁĄD"
                    elif "100%" in res['Status']:
                        icon = "✓ ZABLOKOWANO"
                    elif "0/" in res['Status'] and "OMINIĘTO" in res['Status']:
                        icon = "✗ OMINIĘTO"
                    elif "CZĘŚCIOWO" in res['Status']:
                        icon = "◐ CZĘŚCIOWO"
                    else:
                        icon = "⚠ CRASH"
                    print(f"    [{exe:35s}] {icon:15s} {res['Status']:30s} (Sygnał: {res['Sygnal']})")
                    res['Atak'] = app_group
                    efficacy_results.append(res)

        if efficacy_results:
            df_eff = pd.DataFrame(efficacy_results)
            df_eff.to_csv("benchmark_efficacy_data.csv", index=False)

    if efficacy_results:
        df_eff = pd.DataFrame(efficacy_results) if not isinstance(efficacy_results, pd.DataFrame) else df_eff

        # ==============================================================
        # MACIERZ SKUTECZNOŚCI: mechanizm × klasa ataku
        # ==============================================================
        print(f"\n{'=' * 70}")
        print(f"   MACIERZ SKUTECZNOŚCI DETEKCJI (%) – mechanizm × atak")
        print(f"{'=' * 70}")

        df_eff['Mechanizm'] = df_eff['Wariant'].apply(extract_mechanism)
        df_eff['Klasa ataku'] = df_eff['Atak'].map(ATTACK_CLASSES)

        # Filtrujemy warianty 'base', 'lto' oraz scenariusze ominięcia ('bypass_*')
        df_mechanisms_raw = df_eff[~df_eff['Mechanizm'].isin(['base', 'lto', 'bypass_cfi', 'bypass_lto'])].copy()

        # Pełna siatka (Mechanizm x Atak): jeśli mechanizm nie chroni danego ataku (brak binarki w teście),
        # dostaje 0 zablokowanych prób na trials_count, żeby nie zawyżać średnich klasowych (np. ASan/Canary w D2-D4).
        all_mechs = sorted(df_mechanisms_raw['Mechanizm'].unique(), key=variant_sort_key)
        all_attacks = list(ATTACK_CLASSES.keys())
        full_rows = []
        for m in all_mechs:
            for a in all_attacks:
                existing = df_mechanisms_raw[(df_mechanisms_raw['Mechanizm'] == m) & (df_mechanisms_raw['Atak'] == a)]
                if not existing.empty:
                    full_rows.append(existing.iloc[0].to_dict())
                else:
                    full_rows.append({
                        'Wariant': f"{a}_{m}",
                        'Status': f"OMINIĘTO (Brak ochrony w tej klasie, 0/{trials_count})",
                        'Zablokowano': 0,
                        'Skutecznosc_Procent': 0.0,
                        'Zablokowane_Proby': 0,
                        'Liczba_Prob': trials_count,
                        'Sanitizer': 'Brak',
                        'Sygnal': 'Brak',
                        'PC': 'Brak',
                        'ReturnCode': 0,
                        'Atak': a,
                        'Mechanizm': m,
                        'Klasa ataku': ATTACK_CLASSES[a],
                    })
        df_mechanisms = pd.DataFrame(full_rows)

        pivot = df_mechanisms.pivot_table(
            index='Mechanizm',
            columns='Atak',
            values='Skutecznosc_Procent',
            aggfunc='mean',
            fill_value=0.0
        )

        fmt_pivot = pivot.copy()
        for col in fmt_pivot.columns:
            fmt_pivot[col] = fmt_pivot[col].apply(lambda v: f"{v:5.1f}%")
        print(fmt_pivot.to_string())
        pivot.to_csv("benchmark_efficacy_matrix.csv")

        # ============================================
        # WYKRES 1: Heatmapa mechanizm × atak (%)
        # ============================================
        def get_mech_sort_order(mech):
            logical_order = ['canary', 'pac', 'bti', 'pac_bti', 'cfi', 'cfi_pac_bti', 'mte_async', 'mte_sync', 'combined', 'hardened_prod', 'scudo', 'hwasan', 'asan']
            if mech in logical_order:
                return logical_order.index(mech)
            return 99

        sorted_mechs = sorted(pivot.index, key=get_mech_sort_order)
        attack_col_order = ['D1_stack_smash', 'D2_indirect_call_hijack', 'D3_vtable_hijack', 'D4_bti_landing',
                            'P1_heap_overflow', 'P2_stack_overflow', 'P3_global_overflow', 'P4_heap_oob_read',
                            'P5_subgranule_overflow', 'P6_stack_dop',
                            'M1_use_after_free', 'M2_double_free', 'M3_stack_use_after_scope']
        sorted_cols = [c for c in attack_col_order if c in pivot.columns] + [c for c in pivot.columns if c not in attack_col_order]
        pivot_sorted = pivot.reindex(index=sorted_mechs, columns=sorted_cols)

        fig, ax = plt.subplots(figsize=(16, 8))
        sns.heatmap(pivot_sorted, annot=True, cmap='RdYlGn', vmin=0, vmax=100,
                    fmt='.0f', linewidths=0.8, linecolor='white', ax=ax,
                    cbar_kws={'label': 'Skuteczność detekcji (%)'})
        ax.set_title('Macierz skuteczności detekcji ataków przez mechanizmy bezpieczeństwa ARM64 (%)',
                     fontsize=14, fontweight='bold', pad=15)
        ax.set_xlabel('Scenariusz ataku', fontsize=12, fontweight='bold', labelpad=10)
        ax.set_ylabel('Mechanizm bezpieczeństwa', fontsize=12, fontweight='bold', labelpad=10)
        plt.xticks(rotation=25, ha='right', fontsize=10)
        plt.yticks(rotation=0, fontsize=10)
        fig.tight_layout()
        fig.savefig("benchmark_efficacy_heatmap.png", dpi=300)
        plt.close(fig)

        # ============================================
        # WYKRES 2: Skuteczność per mechanizm (bar chart)
        # ============================================
        mech_summary = df_mechanisms.groupby('Mechanizm').agg(
            Testy=('Liczba_Prob', 'sum'),
            Zablokowane=('Zablokowane_Proby', 'sum')
        ).reset_index()
        mech_summary['Skuteczność (%)'] = (mech_summary['Zablokowane'] / mech_summary['Testy'] * 100).round(1)
        mech_summary = mech_summary.sort_values('Skuteczność (%)', ascending=True)
        mech_summary.to_csv("benchmark_efficacy_per_mechanism.csv", index=False)

        print(f"\n  Skuteczność per mechanizm:")
        print(f"  {'Mechanizm':25s} {'Testy':>6s} {'Zablokowane':>12s} {'Skuteczność':>12s}")
        print(f"  {'-'*25} {'-'*6} {'-'*12} {'-'*12}")
        for _, row in mech_summary.iterrows():
            print(f"  {row['Mechanizm']:25s} {int(row['Testy']):>6d} {int(row['Zablokowane']):>12d}"
                  f" {row['Skuteczność (%)']:>11.1f}%")

        fig, ax = plt.subplots(figsize=(12, 6))
        colors = ['#e74c3c' if x < 30 else '#f39c12' if x < 60 else '#2ecc71'
                  for x in mech_summary['Skuteczność (%)']]
        bars = ax.barh(mech_summary['Mechanizm'], mech_summary['Skuteczność (%)'], color=colors)
        ax.set_xlabel('Skuteczność detekcji (%)', fontsize=12, fontweight='bold')
        ax.set_title('Skuteczność mechanizmów bezpieczeństwa ARM64\n(% zablokowanych ataków spośród testowanych)',
                     fontsize=13, fontweight='bold', pad=12)
        ax.set_xlim(0, 115)
        for bar, pct, blocked, total in zip(bars,
                                            mech_summary['Skuteczność (%)'],
                                            mech_summary['Zablokowane'],
                                            mech_summary['Testy']):
            ax.text(bar.get_width() + 1.5, bar.get_y() + bar.get_height()/2,
                    f'{pct:.0f}% ({int(blocked)}/{int(total)})',
                    va='center', fontsize=9.5, fontweight='bold')
        ax.axvline(x=50, color='gray', linewidth=0.7, linestyle='--', alpha=0.6)
        fig.tight_layout()
        fig.savefig("benchmark_efficacy_per_mechanism.png", dpi=300)
        plt.close(fig)

        # ============================================
        # WYKRES 3: Dashboard skuteczności per scenariusz ataku
        # ============================================
        attacks_order = [
            'D1_stack_smash', 'D2_indirect_call_hijack', 'D3_vtable_hijack', 'D4_bti_landing',
            'P1_heap_overflow', 'P2_stack_overflow', 'P3_global_overflow', 'P4_heap_oob_read',
            'P5_subgranule_overflow', 'P6_stack_dop',
            'M1_use_after_free', 'M2_double_free', 'M3_stack_use_after_scope'
        ]
        active_attacks = [a for a in attacks_order if a in df_mechanisms['Atak'].unique()]

        n_attacks = len(active_attacks)
        n_cols = 2
        n_rows = (n_attacks + n_cols - 1) // n_cols

        fig, axes = plt.subplots(n_rows, n_cols, figsize=(16, 3.2 * n_rows), sharex=True)
        axes_flat = axes.flatten() if hasattr(axes, 'flatten') else [axes]

        for idx, attack in enumerate(active_attacks):
            ax = axes_flat[idx]
            subset = df_mechanisms[df_mechanisms['Atak'] == attack].copy()
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

        # ============================================
        # WYKRES 4: Skuteczność per klasa ataku
        # ============================================
        class_summary = df_mechanisms.groupby(['Klasa ataku', 'Mechanizm']).agg(
            Testy=('Liczba_Prob', 'sum'),
            Zablokowane=('Zablokowane_Proby', 'sum')
        ).reset_index()
        class_summary['Skuteczność (%)'] = (class_summary['Zablokowane'] / class_summary['Testy'] * 100).round(1)
        class_summary.to_csv("benchmark_efficacy_per_class.csv", index=False)

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

        # ============================================
        # WYKRES 5: Stacked bar – zablokowane vs ominięte per mechanizm
        # ============================================
        mech_stacked = df_mechanisms.groupby('Mechanizm').agg(
            Zablokowane=('Zablokowano', 'sum'),
            Testy=('Zablokowano', 'count')
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
        ax.set_xlabel('Liczba scenariuszy ataku', fontsize=11, fontweight='bold')
        ax.set_title('Zablokowane vs ominięte ataki per mechanizm', fontsize=13, fontweight='bold')

        # Dodajemy etykiety liczbowe wewnątrz pasków
        for i, row in mech_stacked.reset_index().iterrows():
            bl = int(row['Zablokowane'])
            om = int(row['Ominięte'])
            if bl > 0:
                ax.text(bl / 2, i, str(bl), va='center', ha='center', color='white', fontweight='bold', fontsize=9)
            if om > 0:
                ax.text(bl + om / 2, i, str(om), va='center', ha='center', color='white', fontweight='bold', fontsize=9)
            tot = bl + om
            ax.text(tot + 0.15, i, f'Razem: {tot}', va='center', ha='left', fontsize=8.5, color='#333333')

        ax.set_xlim(0, mech_stacked['Testy'].max() + 1.5)
        ax.legend(loc='upper right', bbox_to_anchor=(0.98, 0.72), frameon=True)
        fig.tight_layout()
        fig.savefig("benchmark_efficacy_stacked.png", dpi=300)
        plt.close(fig)

    # ==================================================================
    # FAZA 4: AUTORSKA METODYKA OCENY (C_cloud, FTS, PPS, Front Pareto)
    # ==================================================================
    print(f"\n{'=' * 70}")
    print(f"   FAZA 4: AUTORSKA METODYKA OCENY (FTS vs PPS & KOSZT CHMUROWY)")
    print(f"{'=' * 70}")

    if os.path.exists("benchmark_summary.csv") and os.path.exists("benchmark_efficacy_data.csv"):
        df_sum_m = pd.read_csv("benchmark_summary.csv")
        df_eff_m = pd.read_csv("benchmark_efficacy_data.csv")

        df_sum_m['Mechanizm'] = df_sum_m['Wariant'].apply(extract_mechanism)
        df_eff_m['Mechanizm'] = df_eff_m['Wariant'].apply(extract_mechanism)

        # Parametry techniczne mechanizmów: (p_ent, tau_test, tau_prod)
        MECH_PARAMS = {
            'canary':        (0.9990, 0.85, 0.70),
            'pac':           (0.9990, 1.00, 1.00),
            'bti':           (1.0000, 1.00, 1.00),
            'pac_bti':       (0.9990, 1.00, 1.00),
            'cfi':           (1.0000, 1.00, 1.00),
            'cfi_pac_bti':   (0.9990, 1.00, 1.00),
            'scudo':         (0.9375, 1.00, 1.00),
            'mte_async':     (0.9375, 0.85, 0.10),
            'mte_sync':      (0.9375, 1.00, 1.00),
            'combined':      (0.9375, 1.00, 1.00),
            'hardened_prod': (0.9375, 1.00, 1.00),
            'hwasan':        (0.9961, 1.00, 1.00),
            'asan':          (1.0000, 1.00, 1.00),
        }

        # 1. Wyliczenie r_T, r_M, r_S oraz C_cloud dla każdego mechanizmu
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

                c_cloud = 0.70 * r_t + 0.25 * (r_t * r_m) + 0.05 * r_s
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
        avg_costs = df_costs.groupby('Mechanizm').agg(
            r_T=('r_T', 'mean'),
            r_M=('r_M', 'mean'),
            r_S=('r_S', 'mean'),
            C_cloud=('C_cloud', 'mean'),
            Omega_cloud_pct=('Omega_cloud_pct', 'mean')
        ).reset_index()

        # 2. Pełna macierz skuteczności (brakujące ataki dla danego mechanizmu = 0.0)
        all_attacks = list(ATTACK_CLASSES.keys())
        all_classes = ['Spatial (pamięć)', 'Temporal (pamięć)', 'Control Flow']
        eps = 0.05
        methodology_rows = []

        for mech in sorted(MECH_PARAMS.keys(), key=variant_sort_key):
            sub_raw = df_eff_m[df_eff_m['Mechanizm'] == mech]
            if sub_raw.empty:
                continue

            p_ent, tau_test, tau_prod = MECH_PARAMS[mech]

            # Budujemy pełny wektor 13 ataków (0.0 tam, gdzie mechanizm nie działa)
            full_atk_rows = []
            for a in all_attacks:
                match_row = sub_raw[sub_raw['Atak'] == a]
                d_emp = (float(match_row['Skutecznosc_Procent'].mean()) / 100.0) if not match_row.empty else 0.0
                full_atk_rows.append({
                    'Atak': a,
                    'Klasa ataku': ATTACK_CLASSES[a],
                    'Tested': not match_row.empty,
                    'E_test': d_emp * p_ent * tau_test,
                    'E_prod': d_emp * p_ent * tau_prod,
                })
            df_m_full = pd.DataFrame(full_atk_rows)

            # Wariant A: Skuteczność w obrębie badanych klas danego mechanizmu (Domain Efficacy)
            tested_df = df_m_full[df_m_full['Tested']]
            cls_scores_test = tested_df.groupby('Klasa ataku')['E_test'].mean().values
            cls_scores_prod = tested_df.groupby('Klasa ataku')['E_prod'].mean().values
            s_dom_test = float(np.prod([eps + x for x in cls_scores_test]) ** (1.0 / len(cls_scores_test)) - eps)
            s_dom_prod = float(np.prod([eps + x for x in cls_scores_prod]) ** (1.0 / len(cls_scores_prod)) - eps)

            # Wariant B: Pokrycie pełnosystemowe (System-Wide Coverage we wszystkich 3 klasach i 13 atakach)
            sys_vec_test = [float(df_m_full[df_m_full['Klasa ataku'] == c]['E_test'].mean()) for c in all_classes]
            sys_vec_prod = [float(df_m_full[df_m_full['Klasa ataku'] == c]['E_prod'].mean()) for c in all_classes]
            s_sys_test = float(np.prod([eps + x for x in sys_vec_test]) ** (1.0 / 3.0) - eps)
            s_sys_prod = float(np.prod([eps + x for x in sys_vec_prod]) ** (1.0 / 3.0) - eps)

            cost_row = avg_costs[avg_costs['Mechanizm'] == mech]
            c_cloud = float(cost_row['C_cloud'].iloc[0]) if not cost_row.empty else 1.0
            omega_pct = float(cost_row['Omega_cloud_pct'].iloc[0]) if not cost_row.empty else 0.0

            fts_domain = (s_dom_test / c_cloud) * 100.0
            pps_domain = ((s_dom_prod ** 2) / c_cloud) * 100.0
            fts_sys = (s_sys_test / c_cloud) * 100.0
            pps_sys = ((s_sys_prod ** 2) / c_cloud) * 100.0

            methodology_rows.append({
                'Mechanizm': mech,
                'C_cloud (mnoznik)': round(c_cloud, 3),
                'Narzut_Chmurowy (%)': round(omega_pct, 1),
                'S_dom_test (%)': round(s_dom_test * 100, 1),
                'S_dom_prod (%)': round(s_dom_prod * 100, 1),
                'S_sys_test (%)': round(s_sys_test * 100, 1),
                'S_sys_prod (%)': round(s_sys_prod * 100, 1),
                'FTS_Domena (pkt)': round(fts_domain, 1),
                'PPS_Domena (pkt)': round(pps_domain, 1),
                'FTS_System (pkt)': round(fts_sys, 1),
                'PPS_System (pkt)': round(pps_sys, 1),
            })

        df_meth = pd.DataFrame(methodology_rows)
        df_meth.to_csv("benchmark_methodology_scores.csv", index=False)
        print(df_meth.to_string(index=False))
        print("\n  -> Zapisano wyniki autorskiej metodyki do benchmark_methodology_scores.csv")

        # Wykres 1: Porównanie FTS_System (Testy/Fuzzing) vs PPS_System (Produkcja)
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(16, 6))
        df_plot_fts = df_meth.sort_values('FTS_System (pkt)', ascending=True)
        ax1.barh(df_plot_fts['Mechanizm'], df_plot_fts['FTS_System (pkt)'], color='#3498db')
        ax1.set_title('FTS_System (Fuzzing & Testing Throughput Score)\nPełnosystemowa opłacalność w CI/CD (wszystkie 3 klasy ataków)', fontsize=11, fontweight='bold')
        ax1.set_xlabel('Wskaźnik FTS_System (pkt)', fontsize=10)
        for i, v in enumerate(df_plot_fts['FTS_System (pkt)']):
            ax1.text(v + 1, i, f"{v:.1f}", va='center', fontweight='bold', fontsize=9)
        ax1.set_xlim(0, max(df_plot_fts['FTS_System (pkt)'].max() * 1.18, 10))

        df_plot_pps = df_meth.sort_values('PPS_System (pkt)', ascending=True)
        ax2.barh(df_plot_pps['Mechanizm'], df_plot_pps['PPS_System (pkt)'], color='#2ecc71')
        ax2.set_title('PPS_System (Production Protection Score)\nPełnosystemowa opłacalność na produkcji (wszystkie 3 klasy ataków)', fontsize=11, fontweight='bold')
        ax2.set_xlabel('Wskaźnik PPS_System (pkt)', fontsize=10)
        for i, v in enumerate(df_plot_pps['PPS_System (pkt)']):
            ax2.text(v + 1, i, f"{v:.1f}", va='center', fontweight='bold', fontsize=9)
        ax2.set_xlim(0, max(df_plot_pps['PPS_System (pkt)'].max() * 1.18, 10))

        fig.tight_layout()
        fig.savefig("benchmark_fts_vs_pps.png", dpi=300)
        plt.close(fig)

        # Wykres 2: Front Pareto (Koszt Chmurowy C_cloud vs Pełnosystemowa Skuteczność Produkcyjna S_sys_prod)
        fig, ax = plt.subplots(figsize=(11, 7))
        x_vals = df_meth['C_cloud (mnoznik)']
        y_vals = df_meth['S_sys_prod (%)']
        ax.scatter(x_vals, y_vals, s=140, c='#e74c3c', edgecolors='black', zorder=4)
        for _, r in df_meth.iterrows():
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
    # PODSUMOWANIE
    # ==================================================================
    print(f"\n{'=' * 70}")
    print(f"   ZAKOŃCZONO WSZYSTKIE TESTY")
    print(f"{'=' * 70}")
    print(f"\n  Wygenerowane pliki:")

    expected_files = [
        ("benchmark_binary_size.csv",          "Rozmiary binarek i sekcji .text"),
        ("benchmark_performance_data.csv",     "Surowe dane wydajnościowe (wszystkie iteracje)"),
        ("benchmark_summary.csv",              "Podsumowanie statystyczne z narzutami % i kosztem chmurowym"),
        ("benchmark_efficacy_data.csv",        "Wyniki testów skuteczności"),
        ("benchmark_efficacy_matrix.csv",      "Macierz mechanizm × atak"),
        ("benchmark_efficacy_per_mechanism.csv","Skuteczność per mechanizm"),
        ("benchmark_efficacy_per_class.csv",   "Skuteczność per klasa ataku"),
        ("benchmark_methodology_scores.csv",   "Autorska metodyka (C_cloud, FTS, PPS, S_dom, S_sys)"),
    ]
    for fname, desc in expected_files:
        marker = "✓" if os.path.exists(fname) else "✗"
        print(f"    {marker} {fname:47s} {desc}")

    png_files = sorted([f for f in os.listdir('.') if f.endswith('.png') and f.startswith('benchmark_')])
    for f in png_files:
        print(f"    ✓ {f:47s} Wykres")

    print(f"\n  Gotowe! Łącznie {len(expected_files)} plików CSV + {len(png_files)} wykresów PNG.")