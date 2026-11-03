#!/usr/bin/env bash
echo "[+] Łączenie z maszyną wirtualną ARM64 przez SSH (port 2222)..."
echo "    Hasło użytkownika (jeśli zapyta): thesis"
ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p 2222 piotr@localhost "$@"
