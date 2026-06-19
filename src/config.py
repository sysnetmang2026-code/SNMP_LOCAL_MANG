from pathlib import Path
import os

from dotenv import load_dotenv


BASE_DIR = Path(__file__).resolve().parents[1]
DATA_DIR = BASE_DIR / "data"
GLOBAL_DATA_DIR = BASE_DIR / "globales"
ENV_FILE = BASE_DIR / "env" / "credenciales.env"

load_dotenv(ENV_FILE)
load_dotenv()

ROUTER_URL = os.getenv("ROUTER_URL", "http://192.168.1.1").rstrip("/")
ROUTER_HOST = os.getenv("ROUTER_HOST", "192.168.1.1")
ROUTER_USER = os.getenv("ROUTER_USER")
ROUTER_PASS = os.getenv("ROUTER_PASS")

OUI_JSON_PATH = GLOBAL_DATA_DIR / "oui.json"
DATABASE_PATH = DATA_DIR / "red.db"

