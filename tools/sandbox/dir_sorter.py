import os
import shutil

source = './'
ignore_dirs = {'env', 'venv', '__pycache__'}
files_extensions = {
    'docs': ['pdf', 'docx', 'txt','csv', 'md','xlsx','excalidraw'],
    'videos': ['mpeg', 'mp4', 'wav','webm'],
    'audio': ['m4a', 'mp3'],
    'images': ['png', 'svg', 'jpeg', 'jpg','gif'],
    'random_code': ['js', 'php', 'sql', 'html', 'css'],
    'comprimidos': ['7z','zip','rar','targz'],
    'ejecutables' : ['exe','deb']
    }

def organize_files(source_dir, extensions_map, ignore):
    # aseguramos que source exista
    if not os.path.isdir(source_dir):
        raise ValueError(f"El directorio {source_dir} no existe")

    # recorremos todos los archivos (O(n))
    for root, dirs, files in os.walk(source_dir):
        # ignorar carpetas innecesarias
        dirs[:] = [d for d in dirs if d not in ignore]

        for file in files:
            file_ext = file.split('.')[-1].lower()
            moved = False

            for category, exts in extensions_map.items():
                if file_ext in exts:
                    dest_folder = os.path.join(source_dir, category)
                    os.makedirs(dest_folder, exist_ok=True)

                    src_path = os.path.join(root, file)
                    dest_path = os.path.join(dest_folder, file)

                    # evitar sobreescribir
                    if not os.path.exists(dest_path):
                        shutil.move(src_path, dest_path)
                    else:
                        base, ext = os.path.splitext(file)
                        new_name = f"{base}_copy{ext}"
                        shutil.move(src_path, os.path.join(dest_folder, new_name))

                    moved = True
                    break

            # si no coincide con nada, lo mandamos a "otros"
            if not moved:
                other_folder = os.path.join(source_dir, 'otros')
                os.makedirs(other_folder, exist_ok=True)
                shutil.move(os.path.join(root, file), os.path.join(other_folder, file))

organize_files(source, files_extensions, ignore_dirs)
