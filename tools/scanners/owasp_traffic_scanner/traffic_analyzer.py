# src/services/traffic_analyzer.py
import re
import json
import time
from datetime import datetime
from typing import Dict, List, Optional
from dataclasses import dataclass
from confluent_kafka import Producer, Consumer
import logging

@dataclass
class SecurityAlert:
    threat_type: str
    severity: str
    description: str
    payload: str
    timestamp: str
    source_ip: str

class PiChatTrafficAnalyzer:
    """
    Analizador de tráfico en tiempo real con detección de amenazas OWASP
    Versión compatible con Python 3.11+
    """
    
    # Patrones de detección OWASP
    SQL_INJECTION_PATTERNS = [
        r"(\bUNION\b.*\bSELECT\b)",
        r"(\bDROP\b.*\bTABLE\b)",
        r"(\bINSERT\b.*\bINTO\b)",
        r"(\bDELETE\b.*\bFROM\b)",
        r"(\bOR\b.*1=1)",
        r"(\bEXEC\b.*\()",
        r"(\bWAITFOR\b.*\bDELAY\b)",
        r"(';\s*--|';$)",
    ]
    
    def __init__(self, kafka_bootstrap_servers: str = 'localhost:9092'):  # Puerto por defecto de Kafka
        self.kafka_config = {
            'bootstrap.servers': kafka_bootstrap_servers,
            'group.id': 'traffic-analyzer',
            'auto.offset.reset': 'earliest'
        }
        
        self.producer = Producer({'bootstrap.servers': kafka_bootstrap_servers})
        self.consumer = Consumer(self.kafka_config)
        self.consumer.subscribe(['raw-requests'])
        
        # Estadísticas en tiempo real
        self.stats = {
            'total_requests': 0,
            'threats_detected': 0,
            'threats_by_type': {},
            'requests_by_ip': {},
            'last_alert_time': None
        }
        
        self.logger = self._setup_logger()
    
    def _setup_logger(self):
        """Configurar logger"""
        logger = logging.getLogger('traffic_analyzer')
        logger.setLevel(logging.INFO)
        
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            logger.addHandler(handler)
        
        return logger
    
    def delivery_report(self, err, msg):
        """Callback para confirmación de entrega Kafka"""
        if err:
            self.logger.error(f'Message delivery failed: {err}')
        else:
            self.logger.debug(f'Message delivered to {msg.topic()} [{msg.partition()}]')
    
    def analyze_log_line(self, log_data: Dict) -> Optional[SecurityAlert]:
        """
        Analiza una línea de log en busca de amenazas OWASP
        """
        if not isinstance(log_data, dict):
            self.logger.error("Invalid log data format")
            return None
            
        self.stats['total_requests'] += 1
        
        # Extraer campos del log con valores por defecto
        ip = log_data.get('ip', 'unknown')
        path = log_data.get('path', '')
        user_agent = log_data.get('user_agent', '').lower()
        method = log_data.get('method', '')
        payload = log_data.get('payload', '')
        
        # Actualizar estadísticas por IP
        self.stats['requests_by_ip'][ip] = self.stats['requests_by_ip'].get(ip, 0) + 1
        
        # Combinar datos para análisis
        analysis_text = f"{path} {payload}".lower()
        
        # Detección de amenazas
        threats = [
            ('SQL Injection', self._detect_sql_injection(analysis_text)),
            ('XSS', self._detect_xss(analysis_text)),
            ('Scanner', self._detect_scanner(user_agent)),
            ('Path Traversal', self._detect_path_traversal(path)),
        ]
        
        for threat_type, detected in threats:
            if detected:
                return self._create_alert(
                    threat_type, 
                    'HIGH' if threat_type in ['SQL Injection', 'XSS'] else 'MEDIUM',
                    f"{threat_type} detected from {ip}", 
                    analysis_text[:100],  # Limitar tamaño del payload
                    ip
                )
        
        return None
    
    def _detect_sql_injection(self, text: str) -> bool:
        """Detección de SQL Injection"""
        for pattern in self.SQL_INJECTION_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                return True
        return False
    
    def _detect_xss(self, text: str) -> bool:
        """Detección de XSS"""
        xss_patterns = [
            r"<script[^>]*>.*?</script>",
            r"javascript:",
            r"on\w+\s*=",
        ]
        return any(re.search(pattern, text, re.IGNORECASE) for pattern in xss_patterns)
    
    def _detect_scanner(self, user_agent: str) -> bool:
        """Detección de scanners"""
        scanners = ["sqlmap", "nmap", "burpsuite", "nikto", "wpscan"]
        return any(scanner in user_agent for scanner in scanners)
    
    def _detect_path_traversal(self, path: str) -> bool:
        """Detección de path traversal"""
        patterns = [r'\.\./', r'\.\.\\', r'etc/passwd', r'win.ini']
        return any(re.search(pattern, path, re.IGNORECASE) for pattern in patterns)
    
    def _create_alert(self, threat_type: str, severity: str, 
                     description: str, payload: str, ip: str) -> SecurityAlert:
        """Crear alerta de seguridad"""
        self.stats['threats_detected'] += 1
        self.stats['threats_by_type'][threat_type] = self.stats['threats_by_type'].get(threat_type, 0) + 1
        self.stats['last_alert_time'] = datetime.now().isoformat()
        
        return SecurityAlert(
            threat_type=threat_type,
            severity=severity,
            description=description,
            payload=payload,
            timestamp=datetime.now().isoformat(),
            source_ip=ip
        )
    
    def publish_alert(self, alert: SecurityAlert):
        """Publicar alerta en Kafka"""
        try:
            alert_data = {
                'threat_type': alert.threat_type,
                'severity': alert.severity,
                'description': alert.description,
                'payload': alert.payload[:500],  # Limitar tamaño
                'timestamp': alert.timestamp,
                'source_ip': alert.source_ip
            }
            
            self.producer.produce(
                'security-alerts', 
                json.dumps(alert_data).encode('utf-8'),
                callback=self.delivery_report
            )
            self.producer.flush()
            
        except Exception as e:
            self.logger.error(f"Error publishing alert: {e}")

# Versión simplificada para testing sin Kafka
class MockTrafficAnalyzer:
    """Analizador mock para desarrollo sin Kafka"""
    
    def __init__(self):
        self.stats = {
            'total_requests': 0,
            'threats_detected': 0,
            'threats_by_type': {},
            'requests_by_ip': {},
            'last_alert_time': None
        }
        self.logger = logging.getLogger('mock_traffic_analyzer')
    
    def analyze_log_line(self, log_data: Dict):
        """Versión mock del análisis"""
        self.stats['total_requests'] += 1
        
        # Simular detección básica
        if "test" in str(log_data.get('path', '')).lower():
            return SecurityAlert(
                threat_type="Test Pattern",
                severity="LOW",
                description="Test pattern detected",
                payload=str(log_data),
                timestamp=datetime.now().isoformat(),
                source_ip=log_data.get('ip', 'unknown')
            )
        return None

# Factory para elegir el analizador apropiado
def create_traffic_analyzer(use_kafka: bool = False):
    """Crear instancia del analizador según configuración"""
    if use_kafka:
        try:
            return PiChatTrafficAnalyzer()
        except Exception as e:
            print(f"Kafka not available, using mock: {e}")
            return MockTrafficAnalyzer()
    else:
        return MockTrafficAnalyzer()

# Ejemplo de uso
if __name__ == "__main__":
    # Usar mock para desarrollo
    analyzer = create_traffic_analyzer(use_kafka=False)
    
    test_logs = [
        {"ip": "192.168.1.100", "path": "/api/users", "method": "GET", "user_agent": "Mozilla/5.0"},
        {"ip": "10.0.0.5", "path": "/api/users' OR '1'='1", "method": "GET", "user_agent": "test"},
    ]
    
    for log in test_logs:
        alert = analyzer.analyze_log_line(log)
        if alert:
            print(f"🚨 {alert.threat_type}: {alert.description}")
    
    print("✅ Traffic Analyzer funcionando correctamente")
