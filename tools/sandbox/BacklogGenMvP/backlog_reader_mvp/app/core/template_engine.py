# app/core/template_engine.py
class SafeTemplateEngine:
    def __init__(self):
        self.templates = {
            'python': self._get_python_template(),
            'shell': self._get_shell_template(),
            'json': self._get_json_template(),
            'txt': self._get_txt_template()
        }
    
    def _get_python_template(self):
        """Template Python seguro - SIN VULNERABILIDADES"""
        return '''#!/usr/bin/env python3
# Backlog Generator - Safe Template
# Backlog: {id}

def main():
    # VARIABLES PRE-DEFINIDAS (SEGURAS)
    backlog_data = {{
        "id": "{id}",
        "que": "{que}",
        "por_que": "{por_que}", 
        "para_que": "{para_que}",
        "como": "{como}",
        "timestamp": "{timestamp}",
        "usuario": "{usuario}"
    }}
    
    print("🚀 BACKLOG EJECUTÁNDOSE:")
    print(f"ID: {{backlog_data['id']}}")
    print(f"QUÉ: {{backlog_data['que']}}")
    print(f"POR QUÉ: {{backlog_data['por_que']}}")
    print(f"PARA QUÉ: {{backlog_data['para_que']}}") 
    print(f"CÓMO: {{backlog_data['como']}}")
    print(f"🕐 Generado: {{backlog_data['timestamp']}}")

if __name__ == "__main__":
    main()
'''
    
    def render_safe(self, template_type, data):
        """Renderizado seguro con escape de caracteres"""
        if template_type not in self.templates:
            raise ValueError(f"Template no encontrado: {template_type}")
        
        template = self.templates[template_type]
        
        # Escapar caracteres peligrosos
        safe_data = {}
        for key, value in data.items():
            if isinstance(value, str):
                # Escapar comillas y caracteres especiales
                safe_data[key] = value.replace('"', '\\"').replace("'", "\\'")
            else:
                safe_data[key] = value
        
        return template.format(**safe_data)