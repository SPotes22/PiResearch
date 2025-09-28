# src/services/logger_service.py
import csv
import os
import queue
import threading
from datetime import datetime
from typing import List, Dict, Any

class AdvancedLogger:
    def __init__(self, logs_dir='./logs', max_file_size_mb=10, buffer_size=100):
        self.logs_dir = logs_dir
        self.max_file_size = max_file_size_mb * 1024 * 1024
        self.buffer_size = buffer_size
        self.log_buffer = queue.Queue(maxsize=buffer_size)
        self.flush_lock = threading.Lock()
        self.flush_thread = None
        self.running = True
        
        # Crear directorios
        os.makedirs(logs_dir, exist_ok=True)
        os.makedirs(os.path.join(logs_dir, 'archive'), exist_ok=True)
        
        # ✅ INICIAR HILO DE FLUSH AUTOMÁTICO
        self.start_flush_thread()
    
    def start_flush_thread(self):
        """Hilo para flush automático del buffer"""
        def flush_worker():
            while self.running:
                try:
                    # Flush cada 5 segundos o cuando el buffer esté medio lleno
                    log_entry = self.log_buffer.get(timeout=5)
                    if log_entry:
                        self._write_log_entry_sync(log_entry)
                    self.log_buffer.task_done()
                except queue.Empty:
                    # Timeout, verificar si hay elementos en buffer
                    self._flush_buffer()
        self.flush_thread = threading.Thread(target=flush_worker, daemon=True)
        self.flush_thread.start()
    
    def _write_log_entry_sync(self, log_entry: Dict[str, Any]):
        """Escritura síncrona de log entry"""
        log_type = log_entry['type']
        headers = log_entry['headers']
        data = log_entry['data']
        
        log_path = self._get_current_log_path(log_type)
        
        if self._needs_rotation(log_path):
            self._rotate_log(log_type)
            log_path = self._get_current_log_path(log_type)
        
        file_exists = os.path.exists(log_path)
        
        try:
            with open(log_path, mode='a', newline='', encoding='utf-8') as file:
                writer = csv.writer(file)
                
                if not file_exists:
                    writer.writerow(headers + ['timestamp'])
                
                writer.writerow(data + [datetime.now().isoformat()])
            
            print(f"[{datetime.now()}] Log entry added to {log_path}")
            return True
            
        except Exception as e:
            print(f"[ERROR] Could not write to log: {e}")
            # Intentar escribir en log de emergencia
            self._write_emergency_log(log_entry, str(e))
            return False
    
    def _write_emergency_log(self, log_entry: Dict[str, Any], error: str):
        """Log de emergencia si el log principal falla"""
        emergency_path = os.path.join(self.logs_dir, 'emergency.log')
        try:
            with open(emergency_path, 'a', encoding='utf-8') as f:
                f.write(f"[{datetime.now()}] EMERGENCY: {error} | {log_entry}\n")
        except:
            pass  # Último recurso fallido
    
    def _flush_buffer(self):
        """Vaciar buffer completo de manera segura"""
        with self.flush_lock:
            while not self.log_buffer.empty():
                try:
                    log_entry = self.log_buffer.get_nowait()
                    self._write_log_entry_sync(log_entry)
                    self.log_buffer.task_done()
                except queue.Empty:
                    break
    
    def log_event(self, log_type: str, headers: List[str], data: List[Any]):
        """Log event con buffer para alta concurrencia"""
        log_entry = {
            'type': log_type,
            'headers': headers,
            'data': data,
            'timestamp': datetime.now()
        }
        
        try:
            # ✅ NO BLOQUEANTE - Si el buffer está lleno, hacer flush inmediato
            self.log_buffer.put_nowait(log_entry)
            
            # Si el buffer está medio lleno, hacer flush preventivo
            if self.log_buffer.qsize() >= self.buffer_size // 2:
                threading.Thread(target=self._flush_buffer, daemon=True).start()
                
            return True
        except queue.Full:
            # ✅ Buffer lleno - flush inmediato y reintentar
            self._flush_buffer()
            try:
                self.log_buffer.put_nowait(log_entry)
                return True
            except queue.Full:
                # Último intento - escribir directamente
                return self._write_log_entry_sync(log_entry)
    
    def _get_current_log_path(self, log_type: str) -> str:
        date_str = datetime.now().strftime('%Y%m%d')
        return os.path.join(self.logs_dir, f'{log_type}_{date_str}.csv')
    
    def _needs_rotation(self, file_path: str) -> bool:
        if not os.path.exists(file_path):
            return False
        return os.path.getsize(file_path) >= self.max_file_size
    
    def _rotate_log(self, log_type: str):
        current_path = self._get_current_log_path(log_type)
        if os.path.exists(current_path):
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            archived_path = os.path.join(self.logs_dir, f'archive/{log_type}_{timestamp}.csv')
            os.rename(current_path, archived_path)
    
    def log_archivo(self, usuario: str, accion: str, nombre_archivo: str, tamano: int = None):
        headers = ['usuario', 'accion', 'archivo', 'tamano_bytes']
        data = [usuario, accion, nombre_archivo, tamano or 0]
        return self.log_event('archivos', headers, data)
    
    def log_chat(self, usuario: str, accion: str, sala: str, tamano_mensaje: int = None):
        headers = ['usuario', 'accion', 'sala', 'tamano_mensaje_bytes']
        data = [usuario, accion, sala, tamano_mensaje or 0]
        return self.log_event('chat', headers, data)
    
    def shutdown(self):
        """Apagar logger de manera segura"""
        self.running = False
        if self.flush_thread:
            self.flush_thread.join(timeout=5)
        self._flush_buffer()  # Último flush

# Función de compatibilidad
def generar_log(path: str, headers: list, rows: list[list]):
    try:
        with open(path, mode='w', newline='', encoding='utf-8') as file:
            writer = csv.writer(file)
            writer.writerow(headers)
            writer.writerows(rows)
        print(f"[{datetime.now()}] Log successfully created at {path}")
        return True
    except Exception as e:
        print(f"[ERROR] Could not generate log: {e}")
        return False
