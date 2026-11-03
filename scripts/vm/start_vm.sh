#!/usr/bin/env bash
set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$DIR/../.." && pwd)"
VM_DIR="$DIR/vm_data"

if [ ! -f "$VM_DIR/ubuntu-arm64.qcow2" ]; then
    echo "[!] Dysk maszyny nie istnieje. Uruchom najpierw: $DIR/init_vm.sh"
    exit 1
fi

EFI_BIOS="$VM_DIR/QEMU_EFI.fd"
if [ ! -f "$EFI_BIOS" ]; then
    if [ -f "/usr/share/edk2/aarch64/QEMU_EFI.fd" ]; then
        EFI_BIOS="/usr/share/edk2/aarch64/QEMU_EFI.fd"
    elif [ -f "/usr/share/AAVMF/AAVMF_CODE.fd" ]; then
        EFI_BIOS="/usr/share/AAVMF/AAVMF_CODE.fd"
    else
        echo "[!] Błąd: Brak pliku QEMU_EFI.fd. Zainstaluj pakiet edk2-aarch64."
        exit 1
    fi
fi

echo "================================================================="
echo "   URUCHAMIANIE MASZYNY WIRTUALNEJ ARM64 (QEMU)"
echo "   - Architektura: AArch64 (ARMv8.5-A+ / ARMv9)"
echo "   - Sprzętowe MTE (Memory Tagging): WŁĄCZONE (mte=on)"
echo "   - Sprzętowe PAC i BTI: WŁĄCZONE (-cpu max)"
echo "   - Port SSH forwardowany: localhost:2222"
echo "   - Katalog repozytorium podmontowany pod montażem: thesis"
echo "   - Logowanie: użytkownik 'piotr', hasło 'thesis'"
echo "   - Wyjście z konsoli QEMU: wciśnij Ctrl+A, a potem X"
echo "================================================================="

qemu-system-aarch64 \
    -M virt,mte=on,gic-version=3 \
    -cpu max \
    -smp 4 \
    -m 4G \
    -bios "$EFI_BIOS" \
    -drive if=virtio,format=qcow2,file="$VM_DIR/ubuntu-arm64.qcow2" \
    -drive if=virtio,format=raw,file="$VM_DIR/seed.iso" \
    -netdev user,id=net0,hostfwd=tcp::2222-:22 \
    -device virtio-net-pci,netdev=net0 \
    -virtfs local,path="$REPO_DIR",mount_tag=thesis,security_model=none \
    -nographic
