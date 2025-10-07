# app/core/template_engine.py
import os
from pathlib import Path

class SafeTemplateEngine:
    def __init__(self, templates_dir="templates"):
        self.templates_dir = Path(templates_dir)
        self._loaded_templates = {}
        self._load_all_templates()
    
    def _load_all_templates(self):
        """Carga todas las templates desde el directorio"""
        template_files = {
            'python': 'python.template',
            'shell': 'shell.template', 
            'json': 'json.template',
            'txt': 'txt.template'
        }
        
        for template_type, filename in template_files.items():
            template_path = self.templates_dir / filename
            
            if not template_path.exists():
                raise FileNotFoundError(f"Template no encontrada: {template_path}")
            
            with open(template_path, 'r', encoding='utf-8') as f:
                self._loaded_templates[template_type] = f.read()
        
        print(f"✅ Templates cargadas: {list(self._loaded_templates.keys())}")
    
    def get_template(self, template_type):
        """Obtiene una template específica"""
        if template_type not in self._loaded_templates:
            available = list(self._loaded_templates.keys())
            raise ValueError(f"Template '{template_type}' no existe. Disponibles: {available}")
        return self._loaded_templates[template_type]
    
    def render(self, template_type, data):
        """Renderiza una template con datos seguros"""
        template = self.get_template(template_type)
        
        # Limpieza básica de datos para seguridad
        safe_data = {}
        for key, value in data.items():
            if isinstance(value, str):
                # Escape básico para diferentes contextos
                if template_type == 'python':
                    safe_data[key] = value.replace('"', '\\"').replace("'", "\\'")
                elif template_type == 'json':
                    safe_data[key] = value.replace('"', '\\"')
                else:
                    safe_data[key] = value
            else:
                safe_data[key] = value
        
        try:
            return template.format(**safe_data)
        except KeyError as e:
            raise ValueError(f"Falta variable en template: {e}")