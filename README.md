# Snyk-Auto-Reporter 🛡️🐍

Este proyecto es un automatizador de auditorías de seguridad diseñado para desarrolladores que buscan integrar DevSecOps en su flujo de trabajo local. Utiliza la CLI de Snyk para escanear dependencias y genera reportes profesionales en PDF de forma automática.

## 🚀 Funcionalidades
- **Escaneo Automatizado:** Ejecuta pruebas de vulnerabilidades en el proyecto actual.
- **Análisis de Datos:** Filtra y clasifica vulnerabilidades por niveles de severidad (Critical, High, Medium, Low).
- **Generación de Reportes:** Crea un PDF detallado con fecha y estadísticas clave.
- **Programación Automática:** Configurable con `crontab` para auditorías semanales.

## 🛠️ Tecnologías Usadas
- **Lenguaje:** Python 3.10+
- **Seguridad:** Snyk CLI
- **Librerías Python:** `fpdf2`, `subprocess`, `json`, `python-dotenv`
- **SO:** macOS (Optimizado para Apple Silicon M2)

## 📋 Estructura del Proyecto
snyk-auto-reporter/
├── src/                # Lógica del escáner y generador de PDF
├── reports/            # Historial de auditorías generadas
├── .env                # Variables de entorno (Token de Snyk)
└── requirements.txt    # Dependencias del proyecto

## ⚙️ Instalación y Uso

1. **Clonar el repositorio:**
   git clone https://github.com/AngelP255/snyk-auto-reporter.git
   cd snyk-auto-reporter

2. **Instalar dependencias:**
   pip install -r requirements.txt

3. **Configurar Snyk:**
   Asegúrate de tener el Snyk CLI instalado y haber iniciado sesión:
   snyk auth

4. **Ejecutar:**
   python3 src/main.py