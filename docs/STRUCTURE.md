# Estructura del proyecto

Esta organizacion mantiene las pruebas de SNMP intactas en `test/` y separa el codigo principal por responsabilidad.

```text
src/
  app/                 Entrada de consola actual y futura capa de app
  network/             Escaneo Nmap y deteccion de red local
  routers/             Integraciones especificas por modelo/fabricante
  config.py            Rutas y credenciales desde env/credenciales.env
  validators.py        Validaciones compartidas
  main.py              Entrada recomendada para pruebas de consola

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

## Pruebas actuales

Ejecutar desde la raiz del proyecto:

```powershell
python src/main.py
```

La carpeta `test/` queda sin cambios para que el equipo que trabaja SNMP pueda seguir subiendo sus archivos.
