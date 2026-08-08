# Documentacion tecnica del codigo fuente

Este documento describe formalmente el codigo fuente del proyecto
`SNMP_LOCAL_MANG`. La aplicacion combina administracion de routers KAON,
escaneo de red con Nmap, almacenamiento local en SQLite, panel web local y
pruebas SNMP/MikroTik aisladas en `test/`.

## Vision general

El flujo principal inicia en `src/main.py` para consola o en `src/main_web.py`
para el panel web. Ambos cargan configuracion desde `src/config.py`, usan
validaciones compartidas de `src/validators.py` y delegan las operaciones reales
al cliente KAON (`src/routers/kaon_client.py`), al escaner Nmap
(`src/network/nmap_scanner.py`) y al almacen local (`src/app/device_store.py`).

El panel web se sirve desde `src/app/web.py`. Ese servidor entrega los archivos
de `view/` y expone rutas JSON bajo `/api/` para que `view/panel-red.js` pueda
listar dispositivos, guardar alias, bloquear o desbloquear MAC, administrar la
red de invitados y ejecutar escaneos. La consola tambien permite probar reglas
de control parental KAON antes de llevarlas al panel web.

## Dependencias principales

- `requests`: comunicacion HTTP con formularios del router KAON.
- `beautifulsoup4`: extraccion de tablas y formularios HTML del router.
- `python-dotenv`: carga de credenciales y parametros desde archivos `.env`.
- `python-nmap`: invocacion de Nmap desde Python.
- `ifaddr`: deteccion de adaptadores de red locales.
- `sqlite3`: persistencia local incluida en la biblioteca estandar.
- `paramiko`: alternativa SSH para routers OpenWrt.
- `pysnmp`: pruebas SNMP/MikroTik dentro de `test/`.

## Configuracion y datos

- `.env.example`: plantilla de variables requeridas para conectar al router.
  Define `ROUTER_URL`, `ROUTER_HOST`, `ROUTER_USER` y `ROUTER_PASS`.
- `env/credenciales.env`: archivo local de credenciales. No debe compartirse si
  contiene secretos reales.
- `data/oui.json`: catalogo OUI usado para traducir prefijos MAC a fabricantes.
- `data/red.db`: base SQLite generada o actualizada por el escaner y el panel.
  No es codigo fuente; se documenta como artefacto persistente.

## Base de datos

La tabla `dispositivos` se crea desde `EscanerRedDB.create_table`:

- `id`: clave primaria autoincremental.
- `ip`: direccion IP detectada.
- `mac`: direccion MAC unica.
- `fabricante`: fabricante calculado desde `data/oui.json`.
- `hostname`: nombre resuelto por Nmap, DNS inverso o scripts NSE.

La tabla `device_aliases` se crea desde `app.device_store.ensure_alias_table`:

- `mac`: clave primaria normalizada.
- `alias`: nombre visible definido por el usuario.
- `updated_at`: fecha UTC ISO 8601 de la ultima actualizacion.

## API local

`src/app/web.py` expone estas rutas:

- `GET /`: entrega `view/panel-red.html`.
- `GET /api/devices`: lista clientes del router en 2.4/5 GHz y suma
  dispositivos guardados por Nmap; si el router falla, usa SQLite.
- `GET /api/blocked`: lista las MAC bloqueadas en el router.
- `GET /api/guest?band=2.4|5`: devuelve configuracion de invitados.
- `GET /api/primary?band=2.4|5`: devuelve configuracion de red primaria.
- `GET /api/scan/devices`: devuelve dispositivos historicos escaneados.
- `GET /api/parental/sites`: devuelve perfiles de sitios y juegos bloqueables.
- `POST /api/devices/alias`: guarda un alias visible por MAC.
- `POST /api/devices/block`: agrega una MAC al filtro de bloqueo en todas las
  interfaces WiFi activas que el KAON expone para 2.4/5 GHz, incluyendo
  invitados. No responde como exitoso si una interfaz queda sin confirmar.
- `POST /api/devices/unblock`: elimina una MAC de esas mismas interfaces y
  tambien exige confirmacion completa.
- `POST /api/guest`: activa o desactiva invitados y actualiza SSID, clave,
  visibilidad y limite de usuarios cuando el firmware lo expone.
- `POST /api/primary`: actualiza SSID, clave, visibilidad y limite de usuarios
  cuando el firmware lo expone.
- `POST /api/scan`: detecta subred local, ejecuta Nmap y devuelve resultados.
- `POST /api/parental/block`: crea reglas de bloqueo para un perfil.
- `POST /api/parental/unblock`: elimina reglas de bloqueo para un perfil.

## Archivos fuente Python

### `src/config.py`

Centraliza rutas y variables de entorno. Calcula `BASE_DIR`, `DATA_DIR`,
`OUI_JSON_PATH` y `DATABASE_PATH` desde la ubicacion real del archivo, lo que
permite ejecutar el proyecto desde distintos directorios. Carga primero
`env/credenciales.env` y despues `.env`, de modo que `.env` puede complementar
o sobrescribir valores durante pruebas.

### `src/validators.py`

Define la expresion regular oficial para direcciones MAC y funciones
compartidas: `normalize_mac`, que elimina espacios laterales y convierte a
mayusculas, `is_valid_mac`, que valida el formato `AA:BB:CC:DD:EE:FF`,
`normalize_url_keyword`, que convierte una URL en dominio/palabra clave para el
router, e `is_valid_url_keyword`, que valida entradas de control parental.

### `src/main.py`

Punto de entrada de consola. Importa y ejecuta `app.console.main`.

### `src/main_web.py`

Punto de entrada del panel web. Importa y ejecuta `app.web.main`.

### `src/app/__init__.py`

Marca `src/app` como paquete y documenta que ahi reside la capa de aplicacion:
consola, servidor web y persistencia auxiliar.
### `src/app/console.py`

Implementa el menu interactivo de consola para administracion KAON. Sus
funciones cubren listado de clientes, consulta de MAC bloqueadas, bloqueo y
desbloqueo en todas las interfaces WiFi visibles, configuracion de SSID y clave
WPA, visibilidad de SSID, activacion o desactivacion de red primaria e
invitados, limite de usuarios por interfaz cuando el firmware lo expone,
creacion y eliminacion de reglas de control parental por dominio, refuerzo
anti-evasion por puerto, y escaneo Nmap. El modulo usa confirmaciones
explicitas antes de cambios sensibles.

### `src/app/device_store.py`

Gestiona persistencia auxiliar en SQLite. Crea la tabla `device_aliases`,
consulta alias como diccionario, guarda alias validados y lista dispositivos
escaneados uniendo `dispositivos` con `device_aliases`.

### `src/app/web.py`

Contiene el servidor HTTP local. Sirve archivos estaticos desde `view/` con
proteccion contra traversal y despacha rutas JSON mediante `WebHandler`. Tambien
normaliza dispositivos para que el frontend consuma una estructura unica aunque
los datos provengan del router o de SQLite. Usa un servidor HTTP con manejo
silencioso de cortes normales del navegador local para evitar trazas
`ConnectionAbortedError` cuando una pestaña cancela una solicitud.

### `src/network/__init__.py`

Marca `src/network` como paquete de utilidades de red local.

### `src/network/adapters.py`

Detecta la informacion IPv4 del adaptador local cuyo nombre contiene una pista
configurable, por defecto `wi-fi 6`. Calcula IP local, prefijo CIDR, direccion
de red, broadcast y objeto de subred para alimentar los escaneos Nmap.

### `src/network/nmap_scanner.py`

Define `EscanerRedDB`, clase que abre SQLite, garantiza la tabla
`dispositivos`, carga el catalogo OUI, ejecuta Nmap con `-sn -PR -n`, resuelve
hostnames por Nmap, DNS inverso o scripts NSE, guarda dispositivos y muestra
una tabla de resultados por consola.

### `src/app/site_blocking_profiles.py`

Catalogo de perfiles usados por la vista web de control parental. Agrupa los
dominios de servicios sociales y juegos moviles para crear o eliminar reglas en
el router KAON.

### `src/routers/__init__.py`

Marca `src/routers` como paquete para clientes de routers.

### `src/routers/kaon_client.py`

Cliente principal para routers KAON. Mantiene una sesion HTTP con autenticacion
basica, lee paginas HTML, extrae formularios, aplica cambios por endpoints
`goform` y confirma estado despues de timeouts. Soporta clientes conectados,
MAC bloqueadas, red de invitados, red primaria en bandas 2.4 GHz y 5 GHz, y
reglas de control parental desde `/RgFiltering.asp`, incluyendo alta y baja por
indice de tabla, reglas por dominio y reglas por puerto. Para bloqueo MAC usa
`wlanAccessCurrentNetworks` para seleccionar cada interfaz visible, confirma
que el router quedo en la banda e indice solicitados antes de escribir y despues
relee `WirelessMac01..20` para comprobar que la lista quedo aplicada. Reintenta
el cambio cuando el KAON pierde el contexto y no marca exito parcial. Los
formularios reales adjuntos usan `ClosedNetwork` para ocultar SSID primario y
`ClosedNetworkGuest` para invitados; el limite de usuarios se aplica solo si la
pagina del firmware incluye un campo compatible.

El selector de 2.4/5 GHz del firmware entrega una pagina que navega por
JavaScript a `wlanRadio.asp`. `KaonRouterClient` realiza esa segunda lectura de
forma explicita para que las peticiones HTTP operen sobre la banda correcta.

### `src/routers/openwrt_ssh_access_control.py`

Integracion alternativa para OpenWrt mediante SSH. Valida MAC, conecta con
Paramiko y ejecuta comandos UCI para activar `macfilter='deny'`, agregar la MAC
a `maclist`, confirmar configuracion y recargar WiFi.

## Frontend

### `view/panel-red.html`

Documento HTML del panel. Define sidebar, barra superior, dashboard, vista de
dispositivos, control MAC, red primaria, redes de invitados, escaneo Nmap y
modal reutilizable. El contenido dinamico se llena desde `panel-red.js`.

### `view/panel-red.css`

Hoja de estilos del panel. Incluye tokens de color, layout de escritorio,
navegacion movil, tarjetas de dispositivos, formularios, avisos, tooltips,
modal y media queries para pantallas pequenas. La vista de control parental usa
tarjetas animadas tipo dispositivo, crecimiento en hover y pulso tactil en
moviles.

### `view/panel-red.js`

Controlador del panel. Gestiona navegacion entre vistas, estado en memoria,
llamadas `fetch` a `/api/`, renderizado seguro de tarjetas, filtros de busqueda,
red primaria e invitados por banda, escaneo Nmap y modal de acciones por
dispositivo. Tambien alterna la visibilidad local de las claves WPA desde los
botones de ojo y muestra una vista previa tactil antes de ejecutar bloqueos de
control parental en moviles. En los campos de limite de usuarios muestra el
rango permitido cuando el router lo reporta y deshabilita el control cuando el
firmware no expone ningun campo compatible.

### `view/assets/icons/`

Carpeta de iconos reales usados por la vista de control parental. Los perfiles
web pueden declarar la ruta en `src/app/site_blocking_profiles.py` mediante el
campo `icon`; si un perfil no tiene icono, el panel conserva sus iniciales como
respaldo visual.

## Pruebas y utilidades SNMP

### `test/Menu.py`

Menu experimental para listar OIDs y solicitar consultas SNMP usando funciones
de `test/prueba.py`. Se conserva separado del flujo KAON.

### `test/prueba.py`

Utilidad asincrona con `pysnmp` para consultar OIDs de un agente Mikrotik,
mostrar resultados y guardar el ultimo valor conocido en `test/OIDS/oids.txt`.

### `test/OIDS/oids.txt`

Archivo de datos simple con pares `OID=valor`. Sirve como referencia persistida
para las pruebas SNMP.

### `test/.vscode/settings.json`

Configuracion local de VS Code para seleccionar el administrador de entorno
Python del editor.

## Documentacion y muestras

### `docs/STRUCTURE.md`

Resumen de estructura del proyecto, comandos de ejecucion y notas del router
KAON.

### `docs/router_samples/kaon_wlanAccess.asp`

Muestra HTML de la pantalla real del router KAON. Sirve como referencia para
validar nombres de campos, tabla de clientes y payloads usados por
`KaonRouterClient`.

### `docs/CONTROL_PARENTAL.md`

Documenta los campos descubiertos en `/RgFiltering.asp`, el flujo de creacion
por `/goform/RgFiltering`, el uso desde consola, fuentes investigadas y notas
para diagnosticar bloqueos que no aplican en celulares.

## Artefactos no fuente

- `server.out.log` y `server.err.log`: logs locales del servidor, actualmente
  vacios. No contienen logica de aplicacion.
- `src/**/__pycache__/*.pyc`: bytecode generado por Python. No debe editarse ni
  documentarse como fuente.
- `data/red.db`: base de datos local generada por la aplicacion.

