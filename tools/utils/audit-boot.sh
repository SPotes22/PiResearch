#!/usr/bin/env bash
# audit-boot.sh — Auditoría de arranque (solo lectura)
set -euo pipefail

echo "== Auditoría de arranque (read-only) =="

# 1) Estado de Secure Boot
if command -v mokutil >/dev/null 2>&1; then
  echo "[Secure Boot]"; mokutil --sb-state || true
else
  echo "[Secure Boot] mokutil no instalado"
fi
echo

# 2) Sistema de arranque (systemd-boot) si aplica
if command -v bootctl >/dev/null 2>&1; then
  echo "[bootctl status]"; bootctl status || true
  echo
fi

# 3) Montaje de la partición EFI y hashes de sus binarios
EFI_MNT=$(lsblk -o MOUNTPOINT,FSTYPE | awk '$2=="vfat" && $1 ~ /efi|boot/ {print $1; exit}')
if [ -z "${EFI_MNT:-}" ]; then
  # intento estándar
  [ -d /boot/efi ] && EFI_MNT=/boot/efi
fi

if [ -d "${EFI_MNT:-}" ]; then
  echo "[ESP] Montaje detectado en: $EFI_MNT"
  echo "[ESP Hashes] (muestra top 10 archivos por tamaño)"
  find "$EFI_MNT" -type f -printf "%s %p\n" 2>/dev/null | sort -nr | head -n 10 | awk '{print $2}' | xargs -r sha256sum
else
  echo "[ESP] No se detectó montaje EFI (vfat) estándar"
fi
echo

# 4) Últimos eventos de kernel/arranque
echo "[dmesg últimos 1000 líneas filtradas]"
dmesg | tail -n 1000 | grep -Ei "secure|efi|boot|grub" || echo "Sin coincidencias relevantes"
echo

# 5) Resumen de paquetes bootloader
echo "[Paquetes relacionados con bootloader]"
dpkg -l | grep -E "grub|shim|systemd-boot|fwupd" || echo "No se encontraron paquetes coincidentes"

echo "== Fin auditoría =="

