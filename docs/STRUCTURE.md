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

view/assets/icons/
  *.svg                Iconos reales de perfiles del control parental
```

## Router KAON

El bloqueo por MAC usa:

- `GET /wlanAccess.asp` para leer clientes y MAC ya bloqueadas.
- `POST /goform/wlanAccess` para aplicar cambios.
- `wlanAccessCurrentNetworks` para cambiar entre red principal e invitados.
- `MacRestrictMode=2` para modo `Denegar`.
- `MacProbeResponse=1` para mantener el filtro encendido.
- `WirelessMac01` a `WirelessMac20` para la lista de MAC.
- `commitwlanAccess=1` para confirmar el formulario.

Antes de escribir, el cliente confirma tanto la banda solicitada (2.4 o 5 GHz)
como la interfaz elegida. Despues del `POST`, vuelve a leer la lista para
verificar que las MAC visibles coinciden exactamente con lo enviado y reintenta
si el KAON pierde el contexto. La API solo marca el bloqueo o desbloqueo como
exitoso cuando confirma todas las interfaces WiFi activas.

Este firmware cambia de banda con una pagina intermedia que abre
`wlanRadio.asp` mediante JavaScript. El cliente reproduce esa navegacion porque
las solicitudes HTTP de Python no ejecutan JavaScript; asi llega a
`wlanAccess.asp` con la banda real seleccionada antes de editar el filtro.

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
http://127.0.0.1:8765
```

El panel usa rutas JSON bajo `/api/` para listar dispositivos, guardar nombres
visibles por MAC, bloquear/desbloquear MAC, administrar redes principales,
administrar invitados por banda, ocultar SSID, alternar la vista de claves WPA,
guardar limites de usuarios por interfaz y aplicarlos desde el panel cuando se
actualiza o escanea la red.

La carpeta `test/` queda sin cambios para que el equipo que trabaja SNMP pueda seguir subiendo sus archivos.
