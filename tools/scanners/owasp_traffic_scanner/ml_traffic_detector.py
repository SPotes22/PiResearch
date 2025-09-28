# src/services/advanced_traffic_analyzer.py
import re
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
import joblib
import pandas as pd
from datetime import datetime
import json

class AdvancedTrafficAnalyzer:
    """
    Analizador HÍBRIDO: Regex + Modelo de ML para detección OWASP
    Complejidad: O(1) para modelo entrenado + O(n) para regex
    """
    
    def __init__(self, model_path=None):
        self.regex_patterns = self._load_regex_patterns()
        
        # ✅ MODELO DE ML - Una vez entrenado es O(1) para predicción
        self.ml_model = None
        self.vectorizer = None
        self.model_accuracy = 0.0
        
        if model_path:
            self.load_model(model_path)
        else:
            self._init_ml_model()
    
    def _load_regex_patterns(self):
        """Patrones regex optimizados - O(1) en acceso"""
        return {
            'sql_injection': [
                r"(\bUNION\b.*\bSELECT\b)", r"(\bDROP\b.*\bTABLE\b)",
                r"(';\s*--|';$)", r"(\bOR\b.*1=1)", r"(\bEXEC\b.*\()"
            ],
            'xss': [
                r"<script[^>]*>.*?</script>", r"javascript:", 
                r"on\w+\s*=", r"alert\s*\(", r"<iframe.*?>"
            ],
            'scanners': ["sqlmap", "nmap", "burpsuite", "nikto", "wpscan"],
            'path_traversal': [r'\.\./', r'\.\.\\', r'etc/passwd', r'win.ini']
        }
    
    def _init_ml_model(self):
        """Inicializar modelo de ML con datos de entrenamiento sintéticos"""
        # ✅ DATOS DE ENTRENAMIENTO SINTÉTICOS (en producción usar datos reales)
        training_data = [
            # Ejemplos MALICIOSOS
            ("admin' OR '1'='1", 1), ("<script>alert('xss')</script>", 1),
            ("../../../etc/passwd", 1), ("UNION SELECT password FROM users", 1),
            ("'; DROP TABLE users; --", 1), ("<iframe src='javascript:alert(1)'>", 1),
            
            # Ejemplos LEGÍTIMOS  
            ("SELECT name FROM products", 0), ("user@example.com", 0),
            ("/api/users/list", 0), ("Hello world!", 0), ("password123", 0),
            ("<div class='header'>", 0), ("/images/photo.jpg", 0)
        ]
        
        texts, labels = zip(*training_data)
        
        # ✅ VECTORIZACIÓN TF-IDF
        self.vectorizer = TfidfVectorizer(
            max_features=1000,
            ngram_range=(1, 2),
            stop_words='english'
        )
        
        X = self.vectorizer.fit_transform(texts)
        
        # ✅ MODELO RANDOM FOREST
        self.ml_model = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            random_state=42
        )
        
        self.ml_model.fit(X, labels)
        
        # Calcular accuracy básico
        self.model_accuracy = self.ml_model.score(X, labels)
        print(f"✅ Modelo ML entrenado - Accuracy: {self.model_accuracy:.2f}")
    
    def analyze_with_ml(self, text: str) -> dict:
        """
        Análisis con modelo de ML - COMPLEJIDAD: O(1) después de entrenar
        """
        if not self.ml_model:
            return {"threat_level": 0, "confidence": 0.0}
        
        # Vectorizar texto de entrada - O(1) para transformación
        text_vectorized = self.vectorizer.transform([text])
        
        # Predecir - O(1) para Random Forest entrenado
        prediction = self.ml_model.predict(text_vectorized)[0]
        probability = self.ml_model.predict_proba(text_vectorized)[0][1]
        
        return {
            "threat_level": prediction,
            "confidence": float(probability),
            "model_accuracy": self.model_accuracy
        }
    
    def analyze_with_regex(self, text: str) -> dict:
        """
        Análisis con regex - COMPLEJIDAD: O(n*m) donde n=patrones, m=longitud texto
        """
        threats_detected = []
        
        for threat_type, patterns in self.regex_patterns.items():
            if threat_type == 'scanners':
                # Para scanners, verificar en user-agent
                if any(scanner in text.lower() for scanner in patterns):
                    threats_detected.append(threat_type)
            else:
                # Para regex patterns
                for pattern in patterns:
                    if re.search(pattern, text, re.IGNORECASE):
                        threats_detected.append(threat_type)
                        break  # Un match por categoría es suficiente
        
        return {
            "threats_detected": threats_detected,
            "threat_count": len(threats_detected)
        }
    
    def hybrid_analysis(self, log_data: dict) -> dict:
        """
        Análisis HÍBRIDO: ML + Regex
        COMPLEJIDAD: O(1) + O(n*m) ≈ O(n*m) pero optimizado
        """
        text_to_analyze = f"{log_data.get('path', '')} {log_data.get('payload', '')} {log_data.get('user_agent', '')}"
        
        # ✅ ANÁLISIS ML (RÁPIDO - O(1))
        ml_result = self.analyze_with_ml(text_to_analyze)
        
        # ✅ ANÁLISIS REGEX (DETALLADO - O(n*m))
        regex_result = self.analyze_with_regex(text_to_analyze)
        
        # ✅ FUSIÓN DE RESULTADOS
        combined_threat_level = ml_result['threat_level']
        confidence = ml_result['confidence']
        
        # Si regex detecta amenazas específicas, aumentar confianza
        if regex_result['threat_count'] > 0:
            confidence = min(1.0, confidence + 0.3)
            combined_threat_level = 1
        
        return {
            "final_threat_level": combined_threat_level,
            "confidence": confidence,
            "ml_analysis": ml_result,
            "regex_analysis": regex_result,
            "specific_threats": regex_result['threats_detected'],
            "timestamp": datetime.now().isoformat(),
            "ip": log_data.get('ip', 'unknown')
        }
    
    def save_model(self, path: str):
        """Guardar modelo entrenado"""
        if self.ml_model and self.vectorizer:
            joblib.dump({
                'model': self.ml_model,
                'vectorizer': self.vectorizer,
                'accuracy': self.model_accuracy
            }, path)
            print(f"✅ Modelo guardado en: {path}")
    
    def load_model(self, path: str):
        """Cargar modelo pre-entrenado"""
        try:
            model_data = joblib.load(path)
            self.ml_model = model_data['model']
            self.vectorizer = model_data['vectorizer']
            self.model_accuracy = model_data['accuracy']
            print(f"✅ Modelo cargado - Accuracy: {self.model_accuracy:.2f}")
        except Exception as e:
            print(f"❌ Error cargando modelo: {e}")
            self._init_ml_model()

# ✅ INTEGRACIÓN CON TU APP ACTUAL
class PiChatAdvancedTrafficAnalyzer:
    """
    Wrapper para integración fácil con tu Flask app
    """
    
    def __init__(self, use_ml=True):
        self.use_ml = use_ml
        self.analyzer = AdvancedTrafficAnalyzer() if use_ml else None
        self.stats = {
            'total_requests': 0,
            'threats_detected': 0,
            'threats_by_type': {},
            'requests_by_ip': {},
            'ml_predictions': 0,
            'regex_detections': 0
        }
    
    def analyze_log_line(self, log_data: dict):
        """Interfaz compatible con tu código actual"""
        self.stats['total_requests'] += 1
        
        if self.use_ml and self.analyzer:
            # ✅ USAR ANÁLISIS HÍBRIDO AVANZADO
            result = self.analyzer.hybrid_analysis(log_data)
            
            if result['final_threat_level'] == 1:
                self.stats['threats_detected'] += 1
                self.stats['ml_predictions'] += 1
                
                # Registrar tipo de amenaza
                for threat in result['specific_threats']:
                    self.stats['threats_by_type'][threat] = self.stats['threats_by_type'].get(threat, 0) + 1
                
                return self._create_alert(result)
        
        else:
            # ✅ FALLBACK A ANÁLISIS REGEX (como tenías antes)
            text = f"{log_data.get('path', '')} {log_data.get('payload', '')}"
            regex_result = self._basic_regex_analysis(text)
            
            if regex_result['threat_count'] > 0:
                self.stats['threats_detected'] += 1
                self.stats['regex_detections'] += 1
                return self._create_alert(regex_result)
        
        return None
    
    def _basic_regex_analysis(self, text: str):
        """Análisis básico regex (tu implementación original)"""
        # ... (tu código regex actual)
        return {"threats_detected": [], "threat_count": 0}
    
    def _create_alert(self, result):
        """Crear alerta de seguridad"""
        return {
            "threat_type": "|".join(result.get('specific_threats', ['Unknown'])),
            "severity": "HIGH" if result.get('confidence', 0) > 0.7 else "MEDIUM",
            "description": f"Threat detected with confidence {result.get('confidence', 0):.2f}",
            "payload": str(result)[:200],  # Limitar tamaño
            "timestamp": datetime.now().isoformat(),
            "source_ip": result.get('ip', 'unknown')
        }
    
    def get_security_stats(self):
        return self.stats

