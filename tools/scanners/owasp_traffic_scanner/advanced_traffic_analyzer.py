# src/services/advanced_traffic_analyzer.py
import re
import numpy as np
import pandas as pd
from datetime import datetime, timedelta
import json
import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from collections import defaultdict, deque
import pickle

class PiChatAdvancedTrafficAnalyzer:
    """
    Sistema HÍBRIDO: ML + Regex + Análisis Base para reducir falsos positivos
    """
    
    def __init__(self, use_ml=True, base_analyzer=None):
        self.use_ml = use_ml
        self.base_analyzer = base_analyzer  # traffic_analyzer_base para comparación
        
        # ✅ MODELO ML
        self.ml_model = None
        self.vectorizer = None
        self.model_trained = False
        
        # ✅ ESTADÍSTICAS AVANZADAS
        self.stats = {
            'total_requests': 0,
            'threats_detected': 0,
            'false_positives': 0,
            'true_positives': 0,
            'threats_by_type': defaultdict(int),
            'requests_by_ip': defaultdict(int),
            'confidence_distribution': defaultdict(int),
            'response_times': deque(maxlen=1000),
            'decision_history': []  # Para análisis de precisión
        }
        
        # ✅ PATRONES REGEX MEJORADOS
        self.regex_patterns = self._load_enhanced_regex_patterns()
        
        # ✅ UMBRALES INTELIGENTES
        self.confidence_threshold = 0.85  # Más alto para reducir falsos positivos
        self.reputation_scores = defaultdict(lambda: 100)  # Sistema de reputación por IP
        
        if use_ml:
            self._init_ml_model()
    
    def _load_enhanced_regex_patterns(self):
        """Patrones regex más específicos para reducir falsos positivos"""
        return {
            'sql_injection_high_confidence': [
                r"(\bUNION\s+ALL\s+SELECT\b)",  # Más específico
                r"(\bDROP\s+TABLE\s+\w+\b)",
                r"(';\s*(DROP|DELETE|UPDATE|INSERT))",
                r"(\bWAITFOR\s+DELAY\s+'[^']+')",
            ],
            'sql_injection_medium_confidence': [
                r"(\bOR\s+'1'='1')",
                r"(\bUNION\s+SELECT\b)",
                r"(';\s*--)",
            ],
            'xss_high_confidence': [
                r"<script[^>]*>alert\([^)]*\)</script>",
                r"javascript:(?:window\.open|document\.location)",
                r"onload\s*=\s*\"[^\"]*alert[^\"]*\"",
            ],
            'xss_medium_confidence': [
                r"<script[^>]*>.*</script>",
                r"javascript:[^;]+;",
                r"on\w+\s*=\s*[^>]+",
            ]
        }
    
    def _init_ml_model(self):
        """Inicializar modelo ML con datos balanceados para reducir falsos positivos"""
        try:
            # ✅ DATOS DE ENTRENAMIENTO MÁS BALANCEADOS
            training_data = [
                # ATAQUES REALES (alto riesgo)
                ("admin' OR '1'='1' --", 1, 0.95),
                ("<script>alert('xss')</script>", 1, 0.92),
                ("../../../etc/passwd", 1, 0.88),
                ("UNION SELECT username, password FROM users", 1, 0.96),
                
                # FALSOS POSITIVOS COMUNES (entrenar para ignorar)
                ("user'test", 0, 0.10),  # Apostrofes legítimos
                ("<div>hello</div>", 0, 0.05),  # HTML legítimo
                ("../../images/logo.png", 0, 0.15),  # Paths relativos legítimos
                ("SELECT * FROM products", 0, 0.20),  # SQL legítimo
                
                # TRÁFICO NORMAL
                ("/api/users/list", 0, 0.02),
                ("user@example.com", 0, 0.01),
                ("password123", 0, 0.03),
                ("Hello world!", 0, 0.01),
            ]
            
            texts, labels, _ = zip(*training_data)
            
            self.vectorizer = TfidfVectorizer(
                max_features=800,
                ngram_range=(1, 3),
                stop_words='english',
                min_df=2,
                max_df=0.8
            )
            
            X = self.vectorizer.fit_transform(texts)
            
            self.ml_model = RandomForestClassifier(
                n_estimators=150,
                max_depth=12,
                min_samples_split=5,
                min_samples_leaf=2,
                class_weight='balanced',  # Balancear clases para reducir FPs
                random_state=42
            )
            
            self.ml_model.fit(X, labels)
            self.model_trained = True
            
            # Validación rápida
            train_score = self.ml_model.score(X, labels)
            print(f"✅ Modelo ML entrenado - Precisión: {train_score:.3f}")
            
        except Exception as e:
            print(f"❌ Error entrenando modelo ML: {e}")
            self.model_trained = False
    
    def analyze_with_ml(self, text: str) -> dict:
        """Análisis ML con medición de confianza"""
        if not self.model_trained:
            return {"threat_level": 0, "confidence": 0.0, "features": 0}
        
        try:
            text_vectorized = self.vectorizer.transform([text])
            prediction = self.ml_model.predict(text_vectorized)[0]
            probabilities = self.ml_model.predict_proba(text_vectorized)[0]
            
            confidence = float(probabilities[1]) if prediction == 1 else float(probabilities[0])
            
            return {
                "threat_level": prediction,
                "confidence": confidence,
                "features": text_vectorized.shape[1]
            }
        except Exception as e:
            return {"threat_level": 0, "confidence": 0.0, "features": 0, "error": str(e)}
    
    def analyze_with_regex(self, text: str) -> dict:
        """Análisis regex con niveles de confianza"""
        threats_detected = []
        confidence_scores = []
        
        for pattern_category, patterns in self.regex_patterns.items():
            confidence_level = 0.9 if 'high_confidence' in pattern_category else 0.6
            
            for pattern in patterns:
                if re.search(pattern, text, re.IGNORECASE):
                    threat_type = pattern_category.split('_')[0]  # Extraer 'sql_injection' etc.
                    threats_detected.append(threat_type)
                    confidence_scores.append(confidence_level)
                    break  # Un match por categoría
        
        avg_confidence = sum(confidence_scores) / len(confidence_scores) if confidence_scores else 0.0
        
        return {
            "threats_detected": threats_detected,
            "confidence": avg_confidence,
            "pattern_matches": len(threats_detected)
        }
    
    def analyze_with_base(self, log_data: dict) -> dict:
        """Usar el analyzer base para comparación"""
        if not self.base_analyzer:
            return {"threat_level": 0, "confidence": 0.0}
        
        try:
            base_result = self.base_analyzer.analyze_log_line(log_data)
            return {
                "threat_level": 1 if base_result else 0,
                "confidence": 0.7 if base_result else 0.1,  # Confianza media para base
                "base_detection": base_result is not None
            }
        except Exception as e:
            return {"threat_level": 0, "confidence": 0.0, "error": str(e)}
    
    def calculate_reputation_score(self, ip: str, is_threat: bool) -> int:
        """Sistema de reputación para reducir FPs de IPs conocidas"""
        if is_threat:
            self.reputation_scores[ip] = max(0, self.reputation_scores[ip] - 20)
        else:
            self.reputation_scores[ip] = min(100, self.reputation_scores[ip] + 1)
        
        return self.reputation_scores[ip]
    
    def hybrid_analysis(self, log_data: dict) -> dict:
        """
        Análisis híbrido inteligente que combina todas las técnicas
        """
        start_time = datetime.now()
        self.stats['total_requests'] += 1
        
        ip = log_data.get('ip', 'unknown')
        text_to_analyze = f"{log_data.get('path', '')} {log_data.get('payload', '')}"
        
        # ✅ 1. ANÁLISIS BASE (regex simple)
        base_result = self.analyze_with_base(log_data)
        
        # ✅ 2. ANÁLISIS REGEX MEJORADO
        regex_result = self.analyze_with_regex(text_to_analyze)
        
        # ✅ 3. ANÁLISIS ML (si está activo)
        ml_result = self.analyze_with_ml(text_to_analyze) if self.use_ml else {"threat_level": 0, "confidence": 0.0}
        
        # ✅ 4. FUSIÓN INTELIGENTE DE RESULTADOS
        final_decision = self._fusion_decision(
            base_result, regex_result, ml_result, ip
        )
        
        # ✅ 5. CALCULAR TIEMPO DE RESPUESTA
        response_time = (datetime.now() - start_time).total_seconds() * 1000
        self.stats['response_times'].append(response_time)
        
        # ✅ 6. ACTUALIZAR REPUTACIÓN
        reputation = self.calculate_reputation_score(ip, final_decision['is_threat'])
        
        # ✅ 7. REGISTRAR DECISIÓN PARA ANÁLISIS
        decision_record = {
            'timestamp': datetime.now().isoformat(),
            'ip': ip,
            'final_decision': final_decision['is_threat'],
            'confidence': final_decision['final_confidence'],
            'base_confidence': base_result['confidence'],
            'regex_confidence': regex_result['confidence'],
            'ml_confidence': ml_result.get('confidence', 0),
            'reputation': reputation,
            'response_time_ms': response_time,
            'specific_threats': regex_result['threats_detected']
        }
        self.stats['decision_history'].append(decision_record)
        
        # ✅ 8. ACTUALIZAR ESTADÍSTICAS
        if final_decision['is_threat']:
            self.stats['threats_detected'] += 1
            for threat in regex_result['threats_detected']:
                self.stats['threats_by_type'][threat] += 1
            
            # Clasificar como verdadero/falso positivo basado en confianza
            if final_decision['final_confidence'] > self.confidence_threshold:
                self.stats['true_positives'] += 1
            else:
                self.stats['false_positives'] += 1
        
        # Agrupar confianza para el dashboard
        confidence_bucket = int(final_decision['final_confidence'] * 10) * 10
        self.stats['confidence_distribution'][confidence_bucket] += 1
        
        return final_decision
    
    def _fusion_decision(self, base_result, regex_result, ml_result, ip: str) -> dict:
        """Fusión inteligente de todos los análisis"""
        reputación = self.reputation_scores[ip] / 100.0  # Normalizar a 0-1
        
        # Pesos adaptativos basados en reputación
        if reputación > 0.8:  # IP de alta reputación
            weights = {'base': 0.2, 'regex': 0.3, 'ml': 0.5}
            confidence_threshold = 0.9  # Más estricto
        elif reputación < 0.3:  # IP de baja reputación
            weights = {'base': 0.4, 'regex': 0.4, 'ml': 0.2}
            confidence_threshold = 0.6  # Menos estricto
        else:  # Reputación media
            weights = {'base': 0.3, 'regex': 0.4, 'ml': 0.3}
            confidence_threshold = 0.75
        
        # Calcular confianza ponderada
        weighted_confidence = (
            base_result['confidence'] * weights['base'] +
            regex_result['confidence'] * weights['regex'] +
            ml_result.get('confidence', 0) * weights['ml']
        )
        
        # Ajustar por reputación
        adjusted_confidence = weighted_confidence * (1.0 + (1.0 - reputación) * 0.3)
        adjusted_confidence = min(1.0, adjusted_confidence)
        
        # Decisión final
        is_threat = adjusted_confidence > confidence_threshold
        
        return {
            'is_threat': is_threat,
            'final_confidence': adjusted_confidence,
            'weighted_confidence': weighted_confidence,
            'reputation_factor': reputación,
            'confidence_threshold': confidence_threshold,
            'components': {
                'base': base_result,
                'regex': regex_result,
                'ml': ml_result
            }
        }
    
    def analyze_log_line(self, log_data: dict):
        """Interfaz compatible con tu código existente"""
        result = self.hybrid_analysis(log_data)
        
        if result['is_threat']:
            return self._create_alert(result, log_data)
        return None
    
    def _create_alert(self, result, log_data: dict):
        """Crear alerta compatible con tu sistema"""
        return {
            "threat_type": "|".join(result['components']['regex']['threats_detected'] or ['Suspicious']),
            "severity": "HIGH" if result['final_confidence'] > 0.8 else "MEDIUM",
            "description": f"Threat detected with {result['final_confidence']:.1%} confidence",
            "payload": str(log_data.get('payload', ''))[:100],
            "timestamp": result['timestamp'],
            "source_ip": log_data.get('ip', 'unknown'),
            "confidence": result['final_confidence'],
            "reputation": result['reputation_factor']
        }
    
    def get_security_stats(self):
        """Estadísticas completas para el dashboard"""
        # Calcular métricas avanzadas
        total_detections = self.stats['threats_detected']
        precision = (
            self.stats['true_positives'] / total_detections 
            if total_detections > 0 else 0
        )
        
        avg_response_time = (
            sum(self.stats['response_times']) / len(self.stats['response_times']) 
            if self.stats['response_times'] else 0
        )
        
        # Preparar datos para series temporales
        time_series = self._prepare_time_series_data()
        
        return {
            'basic_stats': {
                'total_requests': self.stats['total_requests'],
                'threats_detected': total_detections,
                'false_positives': self.stats['false_positives'],
                'true_positives': self.stats['true_positives'],
                'precision_rate': precision,
                'avg_response_time_ms': avg_response_time,
                'model_accuracy': self.ml_model.score if self.model_trained else 0,
            },
            'threats_by_type': dict(self.stats['threats_by_type']),
            'confidence_distribution': dict(self.stats['confidence_distribution']),
            'reputation_stats': {
                'high_reputation_ips': len([ip for ip, score in self.reputation_scores.items() if score > 80]),
                'low_reputation_ips': len([ip for ip, score in self.reputation_scores.items() if score < 30]),
                'total_tracked_ips': len(self.reputation_scores),
            },
            'time_series_data': time_series,
            'recent_decisions': self.stats['decision_history'][-10:]  #Últimas 10 decisiones
        }
    
    def _prepare_time_series_data(self):
        """Preparar datos para gráficos temporales"""
        if not self.stats['decision_history']:
            return {'threats_over_time': [], 'confidence_over_time': []}
        
        # Agrupar por intervalos de tiempo
        threats_by_hour = defaultdict(int)
        confidence_by_hour = defaultdict(list)
        
        for decision in self.stats['decision_history']:
            hour = decision['timestamp'][:13] + ":00:00"  # Agrupar por hora
            
            if decision['final_decision']:
                threats_by_hour[hour] += 1
            
            confidence_by_hour[hour].append(decision['confidence'])
        
        # Calcular promedios
        avg_confidence_by_hour = {
            hour: sum(confs)/len(confs) 
            for hour, confs in confidence_by_hour.items()
        }
        
        return {
            'threats_over_time': [
                {'time': hour, 'count': count} 
                for hour, count in threats_by_hour.items()
            ],
            'confidence_over_time': [
                {'time': hour, 'confidence': avg} 
                for hour, avg in avg_confidence_by_hour.items()
            ]
        }
    
    def export_model(self, filepath: str):
        """Exportar modelo entrenado"""
        if not self.model_trained:
            return False
        
        try:
            model_data = {
                'model': self.ml_model,
                'vectorizer': self.vectorizer,
                'stats': self.stats,
                'reputation_scores': dict(self.reputation_scores),
                'export_time': datetime.now().isoformat()
            }
            
            with open(filepath, 'wb') as f:
                pickle.dump(model_data, f)
            
            return True
        except Exception as e:
            print(f"❌ Error exportando modelo: {e}")
            return False
    
    def import_model(self, filepath: str):
        """Importar modelo pre-entrenado"""
        try:
            with open(filepath, 'rb') as f:
                model_data = pickle.load(f)
            
            self.ml_model = model_data['model']
            self.vectorizer = model_data['vectorizer']
            self.stats.update(model_data.get('stats', {}))
            self.reputation_scores.update(model_data.get('reputation_scores', {}))
            self.model_trained = True
            
            return True
        except Exception as e:
            print(f"❌ Error importando modelo: {e}")
            return False
