# app/core/file_loader.py
import os
import chardet
import re
from pathlib import Path

class SafeFileLoader:
    def __init__(self):
        self.suspicious_patterns = [
            r"__import__", r"eval\(", r"exec\(", r"subprocess",
            r"os\.system", r"open\(.*[wax]\+", r"import\s+os\s*$"
        ]
    
    def detect_encoding(self, file_path):
        """Detecta encoding automáticamente"""
        with open(file_path, 'rb') as f:
            raw_data = f.read()
            result = chardet.detect(raw_data)
            return result.get('encoding', 'utf-8')
    
    def security_scan(self, content):
        """Escaneo básico de seguridad"""
        warnings = []
        for pattern in self.suspicious_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                warnings.append(f"Patrón sospechoso detectado: {pattern}")
        return warnings
    
    def load_and_validate(self, file_path):
        """Carga segura con validación"""
        try:
            # Detectar encoding
            encoding = self.detect_encoding(file_path)
            
            # Leer archivo
            with open(file_path, 'r', encoding=encoding) as f:
                content = f.read()
            
            # Escanear seguridad
            security_warnings = self.security_scan(content)
            
            return {
                'success': True,
                'content': content,
                'encoding': encoding,
                'warnings': security_warnings,
                'file_size': len(content)
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'content': None,
                'warnings': []
            }