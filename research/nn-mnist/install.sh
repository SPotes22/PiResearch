#!/usr/bin/env bash
# =============================================================================
# install.sh — Deja listo y ejecuta el notebook MNIST (research/nn-mnist)
#
# Qué hace:
#   1. Instala `uv` (que trae `uvx`) si no lo tienes.
#   2. Verifica que uv/uvx quedaron en el PATH.
#   3. Abre el notebook con el comando del profe, usando mnist.py.
#
# No necesitas crear venv ni hacer `pip install` a mano: el flag --sandbox
# lee la cabecera del mnist.py e instala marimo/numpy/matplotlib/torch/
# torchvision en un entorno aislado y temporal.
#
# Uso:
#   bash install.sh              # instala uv y abre mnist.py
#   bash install.sh nn.py        # (opcional) abre otro notebook
#   SKIP_RUN=1 bash install.sh   # solo instala uv, no abre el notebook
# =============================================================================
set -euo pipefail

NOTEBOOK="${1:-mnist.py}"
cd "$(dirname "$0")"   # trabaja siempre dentro de research/nn-mnist

echo "==> Carpeta de trabajo: $(pwd)"

if [[ ! -f "$NOTEBOOK" ]]; then
  echo "ERROR: no encuentro '$NOTEBOOK' en esta carpeta." >&2
  echo "       Archivos disponibles:" >&2
  ls -1 *.py >&2 || true
  exit 1
fi

# --- 1. Instalar uv si falta -------------------------------------------------
if command -v uv >/dev/null 2>&1; then
  echo "==> uv ya está instalado: $(uv --version)"
else
  echo "==> Instalando uv (incluye uvx)..."
  if command -v curl >/dev/null 2>&1; then
    curl -LsSf https://astral.sh/uv/install.sh | sh
  elif command -v wget >/dev/null 2>&1; then
    wget -qO- https://astral.sh/uv/install.sh | sh
  else
    echo "ERROR: necesitas curl o wget para instalar uv." >&2
    exit 1
  fi
  # uv se instala en ~/.local/bin; añádelo al PATH de esta sesión.
  export PATH="$HOME/.local/bin:$HOME/.cargo/bin:$PATH"
fi

# --- 2. Verificar uv/uvx -----------------------------------------------------
if ! command -v uv >/dev/null 2>&1; then
  echo "ERROR: uv no quedó en el PATH. Cierra y abre la terminal, o ejecuta:" >&2
  echo '       export PATH="$HOME/.local/bin:$PATH"' >&2
  exit 1
fi
echo "==> uv  OK -> $(command -v uv)"
echo "==> uvx OK -> $(command -v uvx || echo 'uvx (viene con uv)')"

# --- 3. Abrir el notebook ----------------------------------------------------
if [[ "${SKIP_RUN:-0}" == "1" ]]; then
  echo "==> SKIP_RUN=1: instalación lista. Para abrir el notebook ejecuta:"
  echo "    uvx marimo@latest edit --no-token --sandbox $NOTEBOOK"
  exit 0
fi

echo "==> Abriendo '$NOTEBOOK' con marimo (se instalan las dependencias solas)..."
echo "    (la primera vez tarda: descarga torch y el dataset MNIST)"
exec uvx marimo@latest edit --no-token --sandbox "$NOTEBOOK"
