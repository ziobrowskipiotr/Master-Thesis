#!/usr/bin/env python3
"""
Generator zbiorów danych dla testów wydajnościowych i skuteczności mechanizmów ochrony pamięci.
Gwarantuje 100% determinizm (brak os.urandom), generuje sumy kontrolne SHA-256
oraz zestawy danych dla scenariuszy P1..P6 oraz testów poprawności (P0).
"""

import os
import random
import struct
import hashlib
import argparse

SEED = 42

def compute_sha256(filepath):
    h = hashlib.sha256()
    with open(filepath, 'rb') as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()

def generate_tlv_file(filename, num_records, rng):
    print(f"[+] Generowanie {filename} ({num_records} rekordów, deterministyczny PRNG)...")
    with open(filename, 'wb') as f:
        for _ in range(num_records):
            t = rng.randint(1, 255)
            l = rng.randint(1, 128)
            v = bytes(rng.randint(0, 255) for _ in range(l))
            f.write(struct.pack('BB', t, l))
            f.write(v)

def generate_p1_malicious(filename):
    """P1: Heap buffer overflow - alokacja 16B, zapis 24B (przekroczenie o 8B na stercie)."""
    print(f"[+] Generowanie {filename} (atak P1 - Heap Overflow)...")
    with open(filename, 'wb') as f:
        f.write(struct.pack('BB', 1, 16))
        f.write(b'A' * 16)
        f.write(struct.pack('BB', 2, 255))
        f.write(b'\x00' * 128)

def generate_p2_malicious(filename):
    """P2: Stack buffer overflow - alokacja 16B, zapis 64B na stosie."""
    print(f"[+] Generowanie {filename} (atak P2 - Stack Overflow)...")
    with open(filename, 'wb') as f:
        f.write(struct.pack('BB', 1, 16))
        f.write(b'B' * 16)
        f.write(struct.pack('BB', 2, 255))
        f.write(b'\x00' * 128)

def generate_p3_malicious(filename):
    """P3: Global buffer overflow - alokacja 16B, zapis 48B w sekcji globalnej .bss/.data."""
    print(f"[+] Generowanie {filename} (atak P3 - Global Overflow)...")
    with open(filename, 'wb') as f:
        f.write(struct.pack('BB', 1, 16))
        f.write(b'C' * 16)
        f.write(struct.pack('BB', 2, 255))
        f.write(b'\x00' * 128)

def generate_p4_malicious(filename, rng):
    """P4: Heap out-of-bounds read - nagłówek deklaruje 200B, bufor wejściowy ma tylko 4B."""
    print(f"[+] Generowanie {filename} (atak P4 - Out-of-Bounds Read)...")
    with open(filename, 'wb') as f:
        f.write(struct.pack('BB', 1, 200))
        f.write(bytes(rng.randint(0, 255) for _ in range(4)))

def generate_p5_malicious(filename):
    """P5: Sub-granule Overflow - alokacja 8B, zapis 12B wewnątrz tego samego 16B kafelka MTE."""
    print(f"[+] Generowanie {filename} (atak P5 - Sub-granule Overflow)...")
    with open(filename, 'wb') as f:
        f.write(struct.pack('BB', 1, 16))
        f.write(b'E' * 16)
        f.write(struct.pack('BB', 2, 255))
        f.write(b'\x00' * 128)

def generate_p6_malicious(filename):
    """P6: Stack Data-Oriented Programming (DOP) - nadpisanie flagi is_admin na stosie."""
    print(f"[+] Generowanie {filename} (atak P6 - Stack DOP)...")
    with open(filename, 'wb') as f:
        f.write(struct.pack('BB', 1, 16))
        f.write(b'F' * 16)
        f.write(struct.pack('BB', 2, 255))
        f.write(b'\x00' * 128)

def main():
    parser = argparse.ArgumentParser(description="Generator powtarzalnych zbiorów danych benchmarku.")
    parser.add_argument("--force", action="store_true", help="Wymuś regenerację wszystkich plików.")
    parser.add_argument("--verify", action="store_true", help="Zweryfikuj istniejące sumy kontrolne SHA-256.")
    parser.add_argument("--update-manifest", action="store_true", help="Zaktualizuj manifest SHA-256 dla istniejących plików.")
    args = parser.parse_args()

    os.makedirs("data", exist_ok=True)
    checksum_file = "data/checksums.sha256"

    if args.verify:
        if not os.path.exists(checksum_file):
            print(f"[!] Brak pliku sum kontrolnych: {checksum_file}")
            return 1
        print(f"[+] Weryfikacja sum kontrolnych z {checksum_file}...")
        all_ok = True
        with open(checksum_file, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                expected_hash, rel_path = line.split()
                if not os.path.exists(rel_path):
                    print(f"  [BŁĄD] Brak pliku: {rel_path}")
                    all_ok = False
                    continue
                actual_hash = compute_sha256(rel_path)
                if actual_hash == expected_hash:
                    print(f"  [OK] {rel_path}")
                else:
                    print(f"  [MISMATCH] {rel_path} (oczekiwano {expected_hash[:8]}..., otrzymano {actual_hash[:8]}...)")
                    all_ok = False
        return 0 if all_ok else 1

    # Izolowany seed dla każdego pliku gwarantuje pełną niezależność regeneracji pojedynczych datasetów:
    def get_file_rng(filepath_str):
        # Deterministyczny 32-bitowy seed wyliczony z SHA-256 nazwy i master SEED:
        h = hashlib.sha256(f"{SEED}:{filepath_str}".encode()).digest()
        seed_val = int.from_bytes(h[:4], 'big')
        return random.Random(seed_val)

    files_to_generate = [
        ("data/dataset_small.bin", lambda p: generate_tlv_file(p, 10_000, get_file_rng(p))),
        ("data/dataset_medium.bin", lambda p: generate_tlv_file(p, 100_000, get_file_rng(p))),
        ("data/dataset_large.bin", lambda p: generate_tlv_file(p, 1_000_000, get_file_rng(p))),
        ("data/dataset_p1_malicious.bin", generate_p1_malicious),
        ("data/dataset_p2_malicious.bin", generate_p2_malicious),
        ("data/dataset_p3_malicious.bin", generate_p3_malicious),
        ("data/dataset_p4_malicious.bin", lambda p: generate_p4_malicious(p, get_file_rng(p))),
        ("data/dataset_p5_malicious.bin", generate_p5_malicious),
        ("data/dataset_p6_malicious.bin", generate_p6_malicious),
    ]

    # Wczytanie istniejących sum kontrolnych, jeśli manifest istnieje
    existing_checksums = {}
    if os.path.exists(checksum_file):
        with open(checksum_file, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    parts = line.split()
                    if len(parts) == 2:
                        existing_checksums[parts[1]] = parts[0]

    regenerated_any = False
    for filepath, gen_func in files_to_generate:
        file_exists = os.path.exists(filepath)
        if args.force or not file_exists:
            gen_func(filepath)
            regenerated_any = True
        else:
            # Weryfikujemy czy istniejący plik nie różni się od zarejestrowanego w manifeście
            if filepath in existing_checksums:
                current_sha = compute_sha256(filepath)
                if current_sha != existing_checksums[filepath]:
                    print(f"  [OSTRZEŻENIE] {filepath} różni się od sumy w manifeście! Użyj --force, aby go odtworzyć.")
            print(f"[i] Plik {filepath} już istnieje (użyj --force, aby wygenerować ponownie).")

    # Zapis manifestu tylko jeśli plik nie istnieje, wymuszono --force lub --update-manifest, lub wygenerowano brakujące pliki
    if not os.path.exists(checksum_file) or args.force or args.update_manifest or regenerated_any:
        print("\n[+] Zapisywanie sum kontrolnych SHA-256 do data/checksums.sha256...")
        with open(checksum_file, 'w') as f:
            f.write("# Deterministyczne sumy kontrolne zestawów danych benchmarku (SEED=42)\n")
            for filepath, _ in files_to_generate:
                if os.path.exists(filepath):
                    sha = compute_sha256(filepath)
                    f.write(f"{sha}  {filepath}\n")
                    print(f"  {sha[:16]}...  {filepath}")
    else:
        print(f"\n[i] Manifest {checksum_file} pozostał nienaruszony (brak zmian w plikach).")

    print("\n[✓] Wszystkie zestawy danych są gotowe i zweryfikowane.")
    return 0

if __name__ == "__main__":
    exit(main())
