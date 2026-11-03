import os
import random
import struct

def generate_tlv_file(filename, num_records):
    print(f"Generowanie {filename} ({num_records} rekordow)...")
    with open(filename, 'wb') as f:
        for _ in range(num_records):
            t = random.randint(1, 255)
            l = random.randint(1, 128) 
            v = os.urandom(l)
            f.write(struct.pack('BB', t, l))
            f.write(v)

def generate_p1_malicious(filename):
    print(f"Generowanie złośliwego {filename} (atak P1 - Heap Overflow, 1 rekord)...")
    with open(filename, 'wb') as f:
        f.write(struct.pack('BB', 1, 16))
        f.write(b'A' * 16)
        f.write(struct.pack('BB', 2, 255))
        f.write(b'\x00' * 44)

def generate_p2_malicious(filename):
    print(f"Generowanie złośliwego {filename} (atak P2 - Stack Overflow, 1 rekord)...")
    with open(filename, 'wb') as f:
        f.write(struct.pack('BB', 1, 16))
        f.write(b'B' * 16)
        f.write(struct.pack('BB', 2, 255))
        f.write(b'\x00' * 44)

def generate_p3_malicious(filename):
    print(f"Generowanie złośliwego {filename} (atak P3 - Global Overflow, 1 rekord)...")
    with open(filename, 'wb') as f:
        f.write(struct.pack('BB', 1, 16))
        f.write(b'C' * 16)
        f.write(struct.pack('BB', 2, 255))
        f.write(b'\x00' * 44)

def generate_p4_malicious(filename):
    print(f"Generowanie złośliwego {filename} (atak P4 - Out-of-Bounds Read)...")
    with open(filename, 'wb') as f:
        f.write(struct.pack('BB', 1, 200))
        f.write(os.urandom(4))

def generate_p5_malicious(filename):
    print(f"Generowanie złośliwego {filename} (atak P5 - Sub-granule Overflow, 1 rekord)...")
    with open(filename, 'wb') as f:
        f.write(struct.pack('BB', 1, 16))
        f.write(b'E' * 16)
        f.write(struct.pack('BB', 2, 255))
        f.write(b'\x00' * 44)

def generate_p6_malicious(filename):
    print(f"Generowanie złośliwego {filename} (atak P6 - Stack Data-Only Attack / DOP, 1 rekord)...")
    with open(filename, 'wb') as f:
        f.write(struct.pack('BB', 1, 16))
        f.write(b'F' * 16)
        f.write(struct.pack('BB', 2, 255))
        f.write(b'\x00' * 44)

if __name__ == "__main__":
    os.makedirs("data", exist_ok=True)
    random.seed(42) 
    
    if not os.path.exists("data/dataset_small.bin"):
        generate_tlv_file("data/dataset_small.bin", 10_000)
    if not os.path.exists("data/dataset_medium.bin"):
        generate_tlv_file("data/dataset_medium.bin", 100_000)
    if not os.path.exists("data/dataset_large.bin"):
        generate_tlv_file("data/dataset_large.bin", 1_000_000)

    generate_p1_malicious("data/dataset_p1_malicious.bin")
    generate_p2_malicious("data/dataset_p2_malicious.bin")
    generate_p3_malicious("data/dataset_p3_malicious.bin")
    generate_p4_malicious("data/dataset_p4_malicious.bin")
    generate_p5_malicious("data/dataset_p5_malicious.bin")
    generate_p6_malicious("data/dataset_p6_malicious.bin")
    
    print("Zestawy danych gotowe.")