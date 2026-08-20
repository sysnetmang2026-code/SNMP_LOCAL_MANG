# Convertir el panel en app web usable

Este proyecto ya tiene interfaz web y API local. Para que otras personas lo usen,
el servidor debe ejecutarse en una maquina que pueda ver el router KAON por red,
normalmente la laptop, una mini PC, o un servidor dentro de la misma LAN.

## Arquitectura recomendada para testers externos

Un servidor publico no puede administrar directamente el router privado de cada
casa, porque las IP como `192.168.1.1`, `192.168.0.1` o `192.168.100.1` solo
existen dentro de la red local del usuario. Por eso, para usuarios fuera de tu
red hay dos piezas:

- Sitio publico: landing/login/descarga/documentacion, con dominio propio.
- Agente local: esta app corriendo en la computadora del usuario, conectada al
  WiFi del router que quiere administrar.

Para una defensa de tesis y primeros testers, la ruta mas practica es publicar
un sitio publico sencillo y entregar el agente local con Docker o un instalador.
El usuario entra al sitio, descarga/ejecuta el agente y abre el panel local.

## Deteccion de router por usuario

El panel intenta detectar automaticamente la puerta de enlace IPv4 del equipo
que lo ejecuta. Esa puerta de enlace normalmente es la IP del router local. Si
no detecta una red activa, el login responde:

```text
No se detecto una red local activa. Conectese al WiFi del router KAON e intente nuevamente.
```

Esto cubre casos donde el router no sea `192.168.1.1`, por ejemplo
`192.168.0.1` o `192.168.100.1`.

## Opciones de despliegue local

### 1. Piloto en la misma red WiFi

Es la forma mas rapida para primeros usuarios de prueba.

```powershell
python src/main_web.py --host 0.0.0.0 --port 8765
```

Luego los usuarios abren:

```text
http://IP_DE_TU_LAPTOP:8765
```

La laptop debe permanecer encendida y conectada a la misma red del router.

### 2. Piloto con Docker

Docker sirve para correr la app con el mismo entorno siempre, sin instalar
dependencias Python a mano en cada maquina. Tambien facilita reiniciar la app si
se cae y conservar la base SQLite en `data/`.

Crear un `.env` local si tu router usa otra direccion:

```text
ROUTER_URL=http://192.168.1.1
ROUTER_HOST=192.168.1.1
```

Arrancar:

```powershell
docker compose up --build
```

Abrir:

```text
http://127.0.0.1:8765
```

Desde otro equipo en la misma red:

```text
http://IP_DE_TU_LAPTOP:8765
```

Nota: el acceso HTTP al router suele funcionar desde Docker. El escaneo Nmap
puede variar en Windows con Docker Desktop; si el escaneo no detecta todo, usa
la ejecucion directa con Python para pruebas de red local.

### 3. Usuarios externos por internet

No conviene exponer este panel con port forwarding directo, porque controla
bloqueos, WiFi e invitados del router. Para pruebas externas usa una capa segura:

- VPN tipo Tailscale/WireGuard, recomendada para beta cerrada.
- Cloudflare Tunnel con login o Access, si quieres usar dominio sin abrir puertos.
- VPS solo si ese VPS tiene conexion privada hacia la red donde esta el router.

Un hosting web normal no sirve para controlar el router local, porque no puede
alcanzar `192.168.1.1` dentro de tu casa/oficina.

## Que se necesita para dejarlo listo

- Donde correra la app: laptop, mini PC, servidor local o VPS con VPN.
- Dominio o subdominio, solo si quieres acceso externo con nombre publico.
- Metodo de acceso seguro: misma red, VPN, o tunnel con autenticacion.
- IP local del equipo host y del router.
- Lista de primeros usuarios de prueba y desde donde entraran: misma red o fuera
  de la red.
