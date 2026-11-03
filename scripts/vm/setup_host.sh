#!/usr/bin/env bash
set -e

echo "[+] Instalacja pakietów QEMU i narzędzi pomocniczych na Fedorze..."
sudo dnf install -y \
    qemu-system-aarch64 \
    qemu-img \
    edk2-aarch64 \
    genisoimage \
    curl \
    openssh-clients

echo "[+] Pakiety zainstalowane pomyślnie!"
