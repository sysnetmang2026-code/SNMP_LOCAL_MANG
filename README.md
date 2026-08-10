# Gestor WiFi KAON

Panel local para administrar un router KAON: lista clientes, guarda alias,
bloquea MAC, administra redes WiFi/invitados y ejecuta escaneos locales.

## Requisitos

- Python 3.10 o superior.
- Nmap instalado en Windows si se usara el escaneo de red.
- Estar conectado a la misma red del router KAON.

## Instalacion

Ejecutar desde la raiz del proyecto:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

El panel web solicita el usuario y la contrasena del router al abrirse. No es
necesario guardar `ROUTER_USER` ni `ROUTER_PASS` en un archivo. Si el router usa
otra direccion, se puede definir solamente:

```text
ROUTER_URL=http://192.168.1.1
ROUTER_HOST=192.168.1.1
```

## Ejecutar el panel

No abrir `view/panel-red.html` con Live Server. Live Server solo sirve archivos
estaticos y no crea las rutas `/api/`, por eso aparece un 404 en
`http://127.0.0.1:5500/api/devices`.

Arrancar el servidor Python:

```powershell
python src/main_web.py
```

Luego abrir:

```text
http://127.0.0.1:8765
```

Si otro equipo de la misma red necesita abrir el panel que corre en tu PC:

```powershell
python src/main_web.py --host 0.0.0.0 --port 8765
```

Y desde ese equipo abrir `http://IP_DE_TU_PC:8765`.

Si Windows muestra `WinError 10013`, el puerto elegido esta reservado o
bloqueado. Pruebe con otro puerto libre:

```powershell
python src/main_web.py --port 9000
```

Nota: `127.0.0.1` siempre apunta a la propia computadora. Si tu companero corre
el proyecto en su PC, tambien debe ejecutar el servidor Python y configurar sus
credenciales locales.
