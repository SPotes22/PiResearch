#!/usr/bin/env bash
# audit-boot-advanced.sh — Auditoría avanzada de arranque y superficie de persistencia (read-only)
# Autor: tu compa senior
# Uso:
#   sudo ./audit-boot-advanced.sh            # Ejecuta auditoría (crea o compara snapshot automáticamente)
#   sudo ./audit-boot-advanced.sh --snapshot # Fuerza creación de snapshot nuevo (no compara)
#   sudo ./audit-boot-advanced.sh --compare  # Compara contra el último snapshot existente
#
# Características:
# - Revisión de paquetes y archivos críticos de arranque (GRUB, shim, kernel, initramfs, fwupd).
# - Hashes recursivos de ESP (/boot/efi) y /boot; diff contra snapshot previo.
# - Mapea archivos cambiados -> a qué paquete pertenecen (dpkg -S) o “no gestionado por paquete”.
# - Lista servicios systemd habilitados y los clasifica (whitelist/blacklist/sospechosos).
# - Señala módulos de kernel potencialmente fuera de árbol o sin firma conocida.
#
# NOTA: 100% lectura del sistema. Solo escribe snapshots en el directorio del usuario (~/.local/state/boot-audit).

set -euo pipefail

# ---------- Configuración ----------
STATE_DIR="${XDG_STATE_HOME:-$HOME/.local/state}/boot-audit"
SNAP_PREFIX="snapshot"
TIMESTAMP="$(date +%Y%m%d-%H%M%S)"
CURRENT_SNAPSHOT="${STATE_DIR}/${SNAP_PREFIX}-${TIMESTAMP}.txt"
LATEST_LINK="${STATE_DIR}/${SNAP_PREFIX}-latest.txt"

# Whitelist (servicios normalmente seguros)
WHITELIST_SERVICES_REGEX="^(ssh|ssh@|sshd|postgresql|cron|crond|rsyslog|systemd-timesyncd|systemd-resolved|network-manager|NetworkManager|ufw|firewalld|haveged|unattended-upgrades|mdmonitor|smartd)\\.service$"

# Blacklist (servicios típicamente no recomendados / legacy inseguros)
BLACKLIST_SERVICES_REGEX="^(telnet|telnetd|rsh|rlogin|rexec|tftp|vsftpd|xinetd|rwhod|nfs-kernel-server|ftp|proftpd)\\.service$"

# Firmas aceptadas de módulos
ALLOWED_MODULE_SIGNERS_REGEX="Ubuntu Secure Boot Module signing key|Debian Secure Boot Module signing key|kernel module signing key"

# ---------- Helpers ----------
info(){ echo -e "\033[1;34m[INFO]\033[0m $*"; }
warn(){ echo -e "\033[1;33m[WARN]\033[0m $*"; }
bad(){  echo -e "\033[1;31m[ALERTA]\033[0m $*"; }
sep(){  echo "------------------------------------------------------------"; }

require_cmd(){
  if ! command -v "$1" >/dev/null 2>&1; then
    warn "Comando requerido no encontrado: $1"
    return 1
  fi
}

detect_esp_mount(){
  # Intenta detectar partición EFI montada
  local guess
  guess="$(lsblk -o MOUNTPOINT,FSTYPE | awk '$2=="vfat" && $1 ~ /efi|EFI|boot/ {print $1; exit}')"
  if [ -z "${guess}" ] && [ -d /boot/efi ]; then
    guess="/boot/efi"
  fi
  echo "${guess}"
}

hash_tree(){
  local root="$1"
  if [ -d "$root" ]; then
    # Lista determinística para evitar ruido en diff
    find "$root" -type f -printf "%p\0" \
      | sort -z \
      | xargs -0 sha256sum 2>/dev/null || true
  fi
}

save_snapshot(){
  mkdir -p "$STATE_DIR"
  : > "$CURRENT_SNAPSHOT"
  echo "# Snapshot: $TIMESTAMP" >> "$CURRENT_SNAPSHOT"
  echo "# Host: $(hostnamectl --static 2>/dev/null || hostname)" >> "$CURRENT_SNAPSHOT"
  echo "# Kernel: $(uname -r)" >> "$CURRENT_SNAPSHOT"
  echo >> "$CURRENT_SNAPSHOT"

  local esp bootdir
  esp="$(detect_esp_mount)"
  bootdir="/boot"

  echo "## [ESP] ${esp:-no-montada}" >> "$CURRENT_SNAPSHOT"
  if [ -n "${esp}" ] && [ -d "$esp" ]; then
    hash_tree "$esp" >> "$CURRENT_SNAPSHOT"
  fi
  echo >> "$CURRENT_SNAPSHOT"

  echo "## [/boot]" >> "$CURRENT_SNAPSHOT"
  if [ -d "$bootdir" ]; then
    hash_tree "$bootdir" >> "$CURRENT_SNAPSHOT"
  fi

  ln -sf "$(basename "$CURRENT_SNAPSHOT")" "$LATEST_LINK" 2>/dev/null || cp "$CURRENT_SNAPSHOT" "$LATEST_LINK"
  info "Snapshot guardado en: $CURRENT_SNAPSHOT"
}

compare_with_latest(){
  if [ ! -f "$LATEST_LINK" ]; then
    warn "No existe snapshot previo. Creando uno ahora..."
    save_snapshot
    return 0
  fi

  # Guardamos snapshot actual temporal (no actualizamos 'latest' aún)
  local temp_snapshot="${STATE_DIR}/${SNAP_PREFIX}-current-${TIMESTAMP}.txt"
  mkdir -p "$STATE_DIR"
  cp "$LATEST_LINK" "$STATE_DIR/.baseline-$TIMESTAMP.txt" 2>/dev/null || true
  local esp bootdir
  esp="$(detect_esp_mount)"
  bootdir="/boot"

  : > "$temp_snapshot"
  echo "## [ESP] ${esp:-no-montada}" >> "$temp_snapshot"
  if [ -n "${esp}" ] && [ -d "$esp" ]; then
    hash_tree "$esp" >> "$temp_snapshot"
  fi
  echo >> "$temp_snapshot"
  echo "## [/boot]" >> "$temp_snapshot"
  if [ -d "$bootdir" ]; then
    hash_tree "$bootdir" >> "$temp_snapshot"
  fi

  info "Comparando snapshot actual con el último..."
  sep
  diff -u "$LATEST_LINK" "$temp_snapshot" || true
  sep

  # Identificar archivos cambiados y mapear a paquetes
  info "Archivos con cambios detectados:"
  local changed_files
  changed_files="$(diff -u "$LATEST_LINK" "$temp_snapshot" 2>/dev/null | awk '/^\+\/|^-\/|^[+-][0-9a-f]{64} \// {print $2}' | sed -E 's|^[+-]||' | sort -u)"
  if [ -n "$changed_files" ]; then
    while IFS= read -r path; do
      [ -f "$path" ] || continue
      local owner
      if owner="$(dpkg -S "$path" 2>/dev/null)"; then
        echo "• $path  ->  paquete: $owner"
      else
        echo "• $path  ->  (no pertenece a ningún paquete)"
      fi
    done <<< "$changed_files"
  else
    echo "No se detectaron cambios en contenido de ESP o /boot."
  fi

  # Una vez reportado, podemos actualizar el snapshot 'latest' si el usuario lo desea via --snapshot
  rm -f "$temp_snapshot"
}

audit_boot_packages(){
  echo
  info "Paquetes relacionados con arranque/firmware:"
  sep
  dpkg -l | grep -E "grub|shim|grub-efi|systemd-boot|linux-image|initramfs|fwupd" || echo "No se encontraron paquetes relevantes."
  echo
  info "Archivos críticos de /boot:"
  sep
  ls -lh /boot 2>/dev/null || echo "/boot no accesible"
  if [ -f /boot/grub/grub.cfg ]; then
    echo
    info "Primeras líneas de grub.cfg (por inspección rápida):"
    head -n 20 /boot/grub/grub.cfg || true
  fi
}

audit_systemd_services(){
  echo
  info "Servicios systemd habilitados en arranque (enabled):"
  sep
  local enabled
  enabled="$(systemctl list-unit-files --type=service --state=enabled --no-legend 2>/dev/null | awk '{print $1}')"
  if [ -z "$enabled" ]; then
    echo "No se detectaron servicios habilitados o systemd no está presente."
    return 0
  fi

  echo "== Clasificación =="
  echo "  - Seguros (whitelist):    $WHITELIST_SERVICES_REGEX"
  echo "  - Inseguros (blacklist):  $BLACKLIST_SERVICES_REGEX"
  echo

  local svc
  for svc in $enabled; do
    if [[ "$svc" =~ $WHITELIST_SERVICES_REGEX ]]; then
      echo "✔ $svc    [seguro]"
    elif [[ "$svc" =~ $BLACKLIST_SERVICES_REGEX ]]; then
      echo "✖ $svc    [inseguro]"
    else
      echo "• $svc    [revisar]"
    fi
  done
}

audit_kernel_modules(){
  echo
  info "Módulos de kernel potencialmente fuera de árbol o sin firma conocida:"
  sep
  if ! command -v lsmod >/dev/null 2>&1; then
    echo "lsmod no disponible en este sistema."
    return 0
  fi

  local flagged=0
  # Lee valor de tainted para contexto
  if [ -r /proc/sys/kernel/tainted ]; then
    local t
    t="$(cat /proc/sys/kernel/tainted)"
    echo "Tainted flags: $t (O=out-of-tree, E=unsigned, P=proprietary)"
  fi

  # Itera módulos cargados
  lsmod | awk 'NR>1 {print $1}' | while read -r mod; do
    local taint_file="/sys/module/$mod/taint"
    local taints=""
    [ -r "$taint_file" ] && taints="$(cat "$taint_file" 2>/dev/null)"
    local signer filename
    signer="$(modinfo -F signer "$mod" 2>/dev/null || true)"
    filename="$(modinfo -F filename "$mod" 2>/dev/null || true)"

    local suspicious_reason=""
    if [[ "$taints" =~ [OEPU] ]]; then
      suspicious_reason+="tainted($taints) "
    fi
    if [ -z "$signer" ]; then
      suspicious_reason+="no-signer "
    elif ! echo "$signer" | grep -Eq "$ALLOWED_MODULE_SIGNERS_REGEX"; then
      suspicious_reason+="signer-desconocido:$signer "
    fi
    if [ -n "$suspicious_reason" ]; then
      echo "⚠ $mod  ($filename)   -> $suspicious_reason"
      flagged=$((flagged+1))
    fi
  done

  if [ "${flagged}" -eq 0 ]; then
    echo "No se detectaron módulos fuera de árbol/firmas desconocidas."
  fi
}

main(){
  echo "== Auditoría avanzada de arranque y persistencia (read-only) =="
  echo "(Escribe snapshots en: $STATE_DIR)"
  echo

  audit_boot_packages
  audit_systemd_services
  audit_kernel_modules

  local mode="${1:-auto}"
  case "$mode" in
    --snapshot)
      save_snapshot
      ;;
    --compare)
      compare_with_latest
      ;;
    auto|*)
      if [ -f "$LATEST_LINK" ]; then
        compare_with_latest
      else
        save_snapshot
      fi
      ;;
  esac

  echo
  info "Auditoría finalizada."
}

main "$@"
