"""Configuracion central del Gestor WiFi KAON.

Este modulo resuelve rutas absolutas del proyecto y carga credenciales desde
variables de entorno. Primero lee `env/credenciales.env`, orientado al uso local,
y despues `.env`, util para sobrescribir valores durante pruebas o despliegues.
Los demas modulos importan estas constantes para evitar rutas o credenciales
duplicadas.
"""

from pathlib import Path
import os

from dotenv import load_dotenv


# Directorio raiz del repositorio. Se calcula desde `src/config.py` para que el
# proyecto pueda ejecutarse desde la consola sin depender del directorio actual.
BASE_DIR = Path(__file__).resolve().parents[1]
DATA_DIR = BASE_DIR / "data"
ENV_FILE = BASE_DIR / "env" / "credenciales.env"

# Carga incremental: el archivo local define valores base y `.env` puede
# complementar o reemplazar configuraciones durante pruebas.
load_dotenv(ENV_FILE)
load_dotenv()

# Parametros de conexion contra el router administrado.
ROUTER_URL = os.getenv("ROUTER_URL", "http://192.168.1.1").rstrip("/")
ROUTER_HOST = os.getenv("ROUTER_HOST", "192.168.1.1")
ROUTER_USER = os.getenv("ROUTER_USER")
ROUTER_PASS = os.getenv("ROUTER_PASS")

# Recursos persistentes usados por el escaneo de red y por el panel web.
OUI_JSON_PATH = DATA_DIR / "oui.json"
DATABASE_PATH = DATA_DIR / "red.db"
