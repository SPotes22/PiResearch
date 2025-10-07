# main.py
#!/usr/bin/env python3
import os
import json
from datetime import datetime
from pathlib import Path

from app.core.file_loader import SafeFileLoader
from app.ui.text_interface import TextInterface
from app.core.template_engine import SafeTemplateEngine
from app.exporters.multi_exporter import MultiExporter

# En main.py
template_engine = SafeTemplateEngine("templates")  # ← APUNTA AL DIRECTORIO
exporter = MultiExporter(template_engine)

class BacklogReaderMVP:
    def __init__(self):
        self.loader = SafeFileLoader()
        self.ui = TextInterface()
        self.templates = SafeTemplateEngine()
        self.exporter = MultiExporter()
        
    def run(self):
        print("🚀 BACKLOG READER MVP - Tin Tan Generator")
        print("Cargando y procesando backlogs de forma segura...\n")
        
        # 1. Cargar y validar backlog.json
        if not self.ui.show_file_preview('backlog.json'):
            return
        
        # 2. Confirmación del usuario
        if not self.ui.get_user_confirmation():
            print("❌ Operación cancelada por el usuario")
            return
        
        # 3. Procesar backlog
        self.process_backlog()
    
    def process_backlog(self):
        """Procesa el backlog de forma segura"""
        result = self.loader.load_and_validate('backlog.json')
        
        if not result['success']:
            print(f"❌ Error cargando backlog: {result['error']}")
            return
        
        try:
            data = json.loads(result['content'])
            
            if not isinstance(data, list):
                print("❌ Formato inválido: El backlog debe ser una lista")
                return
            
            print(f"\n📦 Procesando {len(data)} entradas del backlog...")
            
            # Crear directorio de salida
            output_dir = Path('backlogs_generados_mvp')
            output_dir.mkdir(exist_ok=True)
            
            # Generar archivos para cada entrada
            for i, entry in enumerate(data):
                self.generate_safe_files(entry, i, output_dir)
            
            print(f"\n✅ GENERACIÓN COMPLETADA!")
            print(f"📁 Archivos guardados en: {output_dir}/")
            print("🎯 ¡Backlogs listos para ejecución segura!")
            
        except json.JSONDecodeError as e:
            print(f"❌ Error en formato JSON: {e}")

    def generate_safe_files(self, entry, index, output_dir):
        """Genera archivos seguros para una entrada"""
        backlog_id = entry.get('id', f'BL_{index}')
        base_name = f"backlog_derivado_{index+1}"
        
        # Datos seguros
        safe_data = {
            'id': backlog_id,
            'que': entry.get('contenido', 'Sin contenido'),
            'por_que': 'Automatización segura de ideas Tin-Tan',
            'para_que': 'Optimizar flujo de desarrollo',
            'como': 'Generator MVP con validación de seguridad',
            'timestamp': datetime.now().isoformat(),
            'usuario': os.getenv('USER', 'usuario')
        }
        
        # Generar archivos usando templates seguros
        self.exporter.export_all(safe_data, base_name, output_dir)
        print(f"   ✅ Generado: {base_name}.*")

if __name__ == "__main__":
    app = BacklogReaderMVP()
    app.run()