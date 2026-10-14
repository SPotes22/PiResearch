# Cómo ejecutar el notebook de MNIST (paso a paso)

Guía para correr `mnist.py`. La idea es simple: **no** se instala paquete por
paquete; `uv` crea un entorno aislado y temporal, y el flag `--sandbox` lee la
cabecera del `mnist.py` (que ya lista `marimo`, `numpy`, `matplotlib`, `torch`,
`torchvision`) e instala todo solo.

## TL;DR (el comando del profe, pero con mnist.py)

```bash
uvx marimo@latest edit --no-token --sandbox mnist.py
```

El comando del profe era el mismo pero con `nn.py`. **Lo único que cambia es el
nombre del archivo al final: `nn.py` → `mnist.py`.**

---

## Opción A — Script automático (recomendado)

Desde la carpeta `research/nn-mnist/`:

```bash
bash install.sh
```

Eso instala `uv` (que incluye `uvx`) si te falta, y abre `mnist.py`.

---

## Opción B — Paso a paso manual

### 1. Instalar uv (trae uvx)

**Linux / macOS:**
```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

**Windows (PowerShell):**
```powershell
powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
```

> `uvx` **no se instala aparte**: viene incluido con `uv`. Si tienes `uv`, tienes `uvx`.

### 2. Cerrar y volver a abrir la terminal

Para que el sistema encuentre `uv`/`uvx` en el PATH. Verifica:

```bash
uv --version
uvx --version
```

Si dice "command not found", añade esto y reintenta:
```bash
export PATH="$HOME/.local/bin:$PATH"
```

### 3. Entrar a la carpeta del notebook

```bash
cd research/nn-mnist
```

(o donde tengas el archivo `mnist.py`)

### 4. Ejecutar

```bash
uvx marimo@latest edit --no-token --sandbox mnist.py
```

Se abre marimo en el navegador (normalmente `http://localhost:2718`).

---

## Qué significa cada parte del comando

| Parte | Para qué sirve |
|---|---|
| `uvx` | corre una herramienta (marimo) sin instalarla permanentemente |
| `marimo@latest` | usa la última versión de marimo |
| `edit` | abre el notebook en modo edición |
| `--no-token` | no pide token de acceso en el navegador (más cómodo en local) |
| `--sandbox` | **clave**: lee las dependencias de la cabecera del `.py` y las instala en un entorno aislado |
| `mnist.py` | el notebook a abrir (aquí está el cambio respecto a `nn.py`) |

## Notas / errores comunes

- **La primera vez tarda varios minutos:** descarga `torch`, `torchvision` y el
  dataset MNIST (~`./data/`, unos 60 MB). Necesitas **conexión a internet**.
- **No hace falta crear un `venv` propio ni `pip install`**: `--sandbox` se
  encarga. (Si aun así quieres venv del proyecto para otras cosas, puedes, pero
  para *este* comando no es necesario.)
- **`uvx: command not found`** → no reabriste la terminal, o falta el PATH
  (paso 2).
- **Puerto ocupado** (`2718 in use`) → añade `-p 2720` al final del comando.
- **Python 3.14 / torch:** la cabecera pide Python ≥ 3.14; `uv` descarga la
  versión de Python adecuada automáticamente, no tienes que instalarla a mano.

## Para solo reproducir las gráficas (sin notebook)

Si tu compañero solo quiere las gráficas del análisis (α, neuronas, capas) sin
abrir marimo:

```bash
# necesita el MNIST crudo en ./data/MNIST/raw
python3 experiments.py ./data/MNIST/raw ./figures   # genera results.json
python3 plots.py ./figures                           # genera las 3 PNG
```
