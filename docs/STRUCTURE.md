# Estructura del proyecto

Esta organizacion mantiene las pruebas de SNMP intactas en `test/` y separa el codigo principal por responsabilidad.

La documentacion tecnica completa por archivo esta en
`docs/SOURCE_DOCUMENTATION.md`.

La integracion de control parental del router KAON esta documentada en
`docs/CONTROL_PARENTAL.md`.

```text
src/
  app/                 Entrada de consola actual y futura capa de app
  network/             Escaneo Nmap y deteccion de red local
  routers/             Integraciones especificas por modelo/fabricante
  config.py            Rutas y credenciales desde env/credenciales.env
  validators.py        Validaciones compartidas
  main.py              Entrada recomendada para pruebas de consola
  main_web.py          Servidor web local para el panel frontend/backend

data/
  red.db               Base de datos local
  oui.json             Referencia OUI para fabricantes por MAC
```

## Router KAON

El bloqueo por MAC usa:

- `GET /wlanAccess.asp` para leer clientes y MAC ya bloqueadas.
- `POST /goform/wlanAccess` para aplicar cambios.
- `MacRestrictMode=2` para modo `Denegar`.
- `MacProbeResponse=1` para mantener el filtro encendido.
- `WirelessMac01` a `WirelessMac20` para la lista de MAC.
- `commitwlanAccess=1` para confirmar el formulario.

La muestra del formulario original esta en `docs/router_samples/kaon_wlanAccess.asp`.

El control parental usa `/RgFiltering.asp` y `/goform/RgFiltering` para crear o
quitar reglas por dominio con MAC opcional. Las reglas nuevas del menu se envian
con `FilteringProtocol=254` para bloquear TCP y UDP. El modo reforzado agrega
reglas por puerto para reducir evasion por QUIC, DNS privado e iCloud Private
Relay.

## Pruebas actuales

Ejecutar desde la raiz del proyecto:

```powershell
python src/main.py
```

## Panel web local

Ejecutar desde la raiz del proyecto:

```powershell
python src/main_web.py
```

Luego abrir:

```text
http://127.0.0.1:8000
```

El panel usa rutas JSON bajo `/api/` para listar dispositivos, guardar nombres
visibles por MAC, bloquear/desbloquear MAC, administrar invitados y ejecutar
escaneo Nmap.

La carpeta `test/` queda sin cambios para que el equipo que trabaja SNMP pueda seguir subiendo sus archivos.
