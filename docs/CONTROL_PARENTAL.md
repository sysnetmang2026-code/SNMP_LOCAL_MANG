# Control parental KAON

Esta nota documenta la integracion inicial probada desde consola con
`python src/main.py`. La version web puede reutilizar los metodos agregados en
`src/routers/kaon_client.py`.

## Endpoint del router

La pantalla del router usa:

- `GET /RgFiltering.asp` para leer reglas existentes.
- `POST /goform/RgFiltering` con `FilteringCreateRemove=1` para abrir el
  formulario de nueva regla.
- `POST /goform/RgFiltering` con `FilteringApply=2` para aplicar la regla.
- `POST /goform/RgFiltering` con `FilteringCreateRemove=3` y `FilteringTable`
  para quitar una regla por indice.
- `FilteringApply=1` equivale a cancelar.

Campos principales descubiertos en el formulario:

- `FilteringDescription`: descripcion visible de la regla.
- `FilteringMacAddress`: MAC destino. Vacia aplica a todos los dispositivos.
- `FilteringUrlKeyword`: dominio o palabra clave a bloquear.
- `FilteringPortStart=0` y `FilteringPortEnd=0`: todos los puertos.
- `FilteringProtocol=4`: TCP.
- `FilteringProtocol=3`: UDP.
- `FilteringProtocol=254`: ambos protocolos.
- `FilteringEveryDay=128`: todos los dias.
- `FilteringAllDay=1`: todo el dia.
- `FilteringAllowBlock=0`: denegar.
- `FilteringAllowBlock=1`: permitir.
- `FilteringEnabled=1`: regla habilitada.

## Uso desde consola

Ejecutar desde la raiz del proyecto:

```powershell
python src/main.py
```

Opciones agregadas:

- `8. Control parental: ver reglas`
- `9. Control parental: bloquear sitios o juegos`
- `10. Control parental: desbloquear sitios o juegos`

La opcion 9 permite elegir perfiles para Facebook/Messenger, YouTube, Free Fire,
Clash Royale/Supercell o dominios personalizados. Todas las reglas nuevas se
crean con protocolo `BOTH` para cubrir trafico TCP y UDP.

La opcion 10 usa los mismos perfiles para eliminar reglas `Denegar` que coincidan
con el dominio y la MAC indicada. Si se deja la MAC vacia, solo elimina reglas
globales sin MAC.

## Prueba recomendada para celular

Para bloquear Facebook en un telefono especifico:

1. Confirmar la MAC real del telefono en la tabla de clientes del router.
2. Desactivar en el telefono la opcion de MAC aleatoria, MAC privada o direccion
   WiFi privada para esta red.
3. Crear el perfil `Facebook / Messenger` para esa MAC desde la opcion 9.
4. Desconectar y reconectar el WiFi del telefono.
5. Probar desde navegador y desde la app de Facebook.

Si por MAC no funciona, repetir una prueba sin MAC para aplicar a todos los
dispositivos. Si asi bloquea, el problema era la MAC usada por el telefono.

## Motivos comunes por los que falla en celular

- El telefono usa MAC privada/aleatoria y el router recibe otra MAC.
- La regla solo usa TCP, pero la app intenta salir por UDP/QUIC.
- La app usa dominios auxiliares como `graph.facebook.com`, `fbcdn.net`,
  `connect.facebook.net` o `messenger.com`.
- El router filtra mejor dominios que URLs completas; por eso el codigo
  normaliza `https://www.facebook.com/` a `www.facebook.com`.
- Algunas apps pueden usar DNS seguro o trafico cifrado que el filtro basico del
  firmware KAON no inspecciona completamente.
