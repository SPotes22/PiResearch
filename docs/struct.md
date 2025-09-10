PiTech-research/
│
├── README.md              -> Presentación, disclaimer ético, objetivos del repo
├── docs/                  -> Documentación, papers cortos, resúmenes de investigación
├── malware-labs/          -> Laboratorios de malware controlado
│   ├── payloads/          -> Payloads de prueba (shells reversas, bind shells, etc.)
│   ├── obfuscation/       -> Técnicas de evasión y camuflaje
│   └── analysis/          -> Scripts y reportes de análisis de muestras
│
├── exploits/              -> Exploits y PoCs
│   ├── win10/             -> Vulnerabilidades específicas Windows 10
│   ├── crostini/          -> Experimentos con Chromebook/Crostini
│   └── linux/             -> General Linux payloads/exploits
│
├── networking/            -> Investigación en redes
│   ├── ddos/              -> Algoritmos, simulaciones y mitigación
│   ├── firewalls/         -> Bypasses y configuraciones seguras
│   └── api-abuse/         -> Ejemplos de APIs maliciosas o inseguras
│
├── API_AS_A_Service/        
│   ├── api/               -> Implementación de la "API malvada"
│   ├── api_rpc/               -> Implementación de la "API RPC"
│   └── docs/              -> Especificaciones técnicas, diagramas
│
└── tools/
    ├── scanners/ -> Descubrimiento de vulnerabilidades, scripts de auditoría básica. monitoreo perimetral.
    ├── utils/             -> Documentos y scripts de apoyo (loggers, encoders, etc.) 
    └── sandbox/           -> Mini entornos de prueba 