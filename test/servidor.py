"""
servidor.py - Mini servidor Flask
===================================
Sirve el Interfaz.html y expone los datos
de OIDS/oids.txt como API para el HTML.

Instalar dependencia:
    pip install flask

Ejecutar:
    python servidor.py

Luego abrir en el navegador:
    http://127.0.0.1:5000
"""

from flask import Flask, jsonify, send_from_directory
import os

app = Flask(__name__, static_folder='.')

ARCHIVO = os.path.join(os.path.dirname(__file__), 'OIDS', 'oids.txt')


def leer_oids():
    """Lee OIDS/oids.txt y retorna un diccionario."""
    datos = {}
    try:
        with open(ARCHIVO, 'r', encoding='utf-8') as f:
            for linea in f:
                linea = linea.strip()
                if '=' in linea:
                    clave, valor = linea.split('=', 1)
                    datos[clave.strip()] = valor.strip()
    except FileNotFoundError:
        return None
    return datos


# ── Ruta principal: sirve el Interfaz.html ──
@app.route('/')
def index():
    return send_from_directory('.', 'Interfaz.html')


# ── API: devuelve los datos del router en JSON ──
@app.route('/api/datos')
def api_datos():
    datos = leer_oids()
    if datos is None:
        return jsonify({
            'error': 'Archivo OIDS/oids.txt no encontrado. Ejecuta Menu.py primero.'
        }), 404
    resp = jsonify(datos)
    # Sin cache: fuerza que siempre lea el archivo actualizado
    resp.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate'
    resp.headers['Pragma'] = 'no-cache'
    return resp


if __name__ == '__main__':
    print('\n  Servidor iniciado en http://127.0.0.1:5000')
    print('  Presiona Ctrl+C para detenerlo.\n')
    app.run(debug=False, port=5000)