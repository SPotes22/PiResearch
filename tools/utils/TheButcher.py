import os

# cogemos el archivo a leer

# iniciamos un contador.

# creamos una funcion que tenga varios contadores asyncrenos

# la division del archivo es len(total_file)/2 -> asi hasta llegar a 128 lineas.

# cada division de 128 lineas se guarda en parte_{n}.txt donde  n es el identificador del contador que teniamos


# i_1 = lineas 0-128
# i_2 = lineas 129-257donde  n es el identificador del contador que teniamos


# i_1 = lineas 0-128
# i_2 = lineas 129-257

import os
import asyncio

# Configuración
ARCHIVO_ORIGEN = "entrada.txt"
LINEAS_POR_PARTE = 128
DIRECTORIO_SALIDA = "partes"


async def guardar_parte(lineas: list[str], indice: int):
    """
    Guarda una parte del archivo en un archivo separado.
    """
    nombre_archivo = os.path.join(DIRECTORIO_SALIDA, f"parte_{indice}.txt")
    async with asyncio.Lock():  # asegurar que no choquen las escrituras
        with open(nombre_archivo, "w", encoding="utf-8") as f:
            f.writelines(lineas)
    print(f"[OK] Guardada {nombre_archivo}")


async def procesar_archivo():
    """
    Lee el archivo y lo divide en partes de N lineas.
    """
    if not os.path.exists(DIRECTORIO_SALIDA):
        os.makedirs(DIRECTORIO_SALIDA)

    with open(ARCHIVO_ORIGEN, "r", encoding="utf-8") as f:
        lineas = f.readlines()

    # calculamos cuántas partes salen
    total_lineas = len(lineas)
    total_partes = (total_lineas + LINEAS_POR_PARTE - 1) // LINEAS_POR_PARTE

    print(f"Archivo con {total_lineas} líneas -> {total_partes} partes")

    tareas = []
    for i in range(total_partes):
        inicio = i * LINEAS_POR_PARTE
        fin = inicio + LINEAS_POR_PARTE
        chunk = lineas[inicio:fin]
        tareas.append(asyncio.create_task(guardar_parte(chunk, i + 1)))

    await asyncio.gather(*tareas)


if __name__ == "__main__":
    asyncio.run(procesar_archivo())
