#!/usr/bin/env bash
set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VM_DIR="$DIR/vm_data"

mkdir -p "$VM_DIR"
cd "$VM_DIR"

IMG_NAME="noble-server-cloudimg-arm64.img"
IMG_URL="https://cloud-images.ubuntu.com/noble/current/$IMG_NAME"

if [ ! -f "$IMG_NAME" ]; then
    echo "[+] Pobieranie obrazu Ubuntu 24.04 Noble ARM64 (~650MB)..."
    curl -L -o "$IMG_NAME" "$IMG_URL"
else
    echo "[+] Obraz bazowy $IMG_NAME już istnieje."
fi

# Tworzymy kopię roboczą dysku w formacie qcow2
if [ ! -f "ubuntu-arm64.qcow2" ]; then
    echo "[+] Tworzenie dysku roboczego z obrazu bazowego..."
    qemu-img create -f qcow2 -b "$IMG_NAME" -F qcow2 ubuntu-arm64.qcow2 25G
fi

# Przygotowanie konfiguracji cloud-init (user-data i meta-data)
echo "[+] Generowanie konfiguracji cloud-init..."

SSH_KEY_ENTRY=""
if [ -f "$HOME/.ssh/id_ed25519.pub" ]; then
    SSH_KEY_ENTRY="      - $(cat "$HOME/.ssh/id_ed25519.pub")"
elif [ -f "$HOME/.ssh/id_rsa.pub" ]; then
    SSH_KEY_ENTRY="      - $(cat "$HOME/.ssh/id_rsa.pub")"
fi

cat <<EOF > user-data
#cloud-config
hostname: arm64-thesis-vm
users:
  - name: piotr
    sudo: ALL=(ALL) NOPASSWD:ALL
    shell: /bin/bash
    plain_text_passwd: thesis
    lock_passwd: false
    ssh_authorized_keys:
${SSH_KEY_ENTRY}

ssh_pwauth: true
chpasswd:
  expire: false

package_update: true
packages:
  - build-essential
  - clang
  - llvm
  - lld
  - cmake
  - ninja-build
  - time
  - git
  - binutils
  - python3
  - python3-pip
  - python3-pandas
  - python3-matplotlib
  - python3-seaborn

runcmd:
  - mkdir -p /home/piotr/Master-Thesis
  - chown -R piotr:piotr /home/piotr/Master-Thesis
  - echo "thesis /home/piotr/Master-Thesis 9p trans=virtio,version=9p2000.L,rw 0 0" >> /etc/fstab
  - mount -a || true
  - echo "VM ARM64 gotowa do badan!" > /etc/motd
EOF

cat <<EOF > meta-data
instance-id: arm64-thesis-01
local-hostname: arm64-thesis-vm
EOF

echo "[+] Generowanie obrazu seed.iso dla cloud-init..."
genisoimage -output seed.iso -volid cidata -joliet -rock user-data meta-data

# Kopiowanie UEFI VARS jeśli potrzebne
if [ ! -f "QEMU_EFI.fd" ]; then
    echo "[+] Lokalizowanie firmware UEFI (EDK2) na Fedorze..."
    if [ -f "/usr/share/edk2/aarch64/QEMU_EFI.fd" ]; then
        cp /usr/share/edk2/aarch64/QEMU_EFI.fd ./QEMU_EFI.fd
    elif [ -f "/usr/share/AAVMF/AAVMF_CODE.fd" ]; then
        cp /usr/share/AAVMF/AAVMF_CODE.fd ./QEMU_EFI.fd
    else
        echo "[!] Ostrzeżenie: Nie znaleziono firmware UEFI. Upewnij się, że pakiet edk2-aarch64 jest zainstalowany."
    fi
fi

echo "[+] Inicjalizacja zakończona sukcesem! Możesz uruchomić maszynę za pomocą ./start_vm.sh"
