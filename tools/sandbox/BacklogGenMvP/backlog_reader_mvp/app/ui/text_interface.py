# app/ui/text_interface.py
class TextInterface:
    def __init__(self):
        self.loader = SafeFileLoader()
    
    def show_file_preview(self, file_path):
        """Muestra vista previa del archivo"""
        result = self.loader.load_and_validate(file_path)
        
        print("=" * 50)
        print("📁 BACKLOG READER MVP - VISTA PREVIA")
        print("=" * 50)
        
        if not result['success']:
            print(f"❌ Error: {result['error']}")
            return False
        
        print(f"✅ Archivo cargado: {file_path}")
        print(f"📊 Tamaño: {result['file_size']} caracteres")
        print(f"🔤 Encoding: {result['encoding']}")
        
        # Mostrar advertencias de seguridad
        if result['warnings']:
            print("\n⚠️  ADVERTENCIAS DE SEGURIDAD:")
            for warning in result['warnings']:
                print(f"   - {warning}")
        
        # Vista previa del contenido (primeras 10 líneas)
        print("\n📋 VISTA PREVIA (primeras 10 líneas):")
        lines = result['content'].split('\n')[:10]
        for i, line in enumerate(lines, 1):
            print(f"{i:2d}: {line}")
        
        return True
    
    def get_user_confirmation(self):
        """Obtiene confirmación del usuario"""
        print("\n" + "=" * 50)
        response = input("¿Proceder con la generación? (s/n): ").lower().strip()
        return response in ['s', 'si', 'sí', 'y', 'yes']