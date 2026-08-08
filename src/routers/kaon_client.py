"""Cliente HTTP para administrar routers KAON desde formularios web.

La clase `KaonRouterClient` encapsula autenticacion basica, lectura de paginas
HTML, extraccion de formularios, aplicacion de cambios por `goform` y
verificacion posterior cuando el router corta la conexion o responde con timeout.
El cliente esta especializado en control de acceso MAC y configuracion de redes
WiFi primaria e invitados.
"""

import time

import requests
from bs4 import BeautifulSoup
from requests.auth import HTTPBasicAuth
from requests.exceptions import Timeout

from validators import (
    is_valid_mac,
    is_valid_url_keyword,
    normalize_mac,
    normalize_url_keyword,
)


WIRELESS_MAC_FIELDS = [f"WirelessMac{number:02d}" for number in range(1, 21)]
WIFI_CLIENT_LIMIT_MAX = 20
ACCESS_INTERFACE_SETTLE_SECONDS = 0.5
ACCESS_CONFIRM_TIMEOUT = 8
ACCESS_CONFIRM_INTERVAL = 1
ACCESS_WRITE_ATTEMPTS = 3
ACCESS_RETRY_INTERVAL = 0.75
ACCESS_INTERFACE_ATTEMPTS = 3
# Paginas que cambian la banda activa antes de leer formularios WiFi.
BAND_URLS = {
    "2.4": "/wlan24G.asp",
    "5": "/wlan5G.asp",
}
BAND_CONTEXT_URL = "/wlanRadio.asp"


# Nombres de campos observados en el formulario de red de invitados KAON.
GUEST_NETWORK_FIELDS = {
    "GuestNetworkEnable": "estado",
    "GuestServiceSetIdentifier": "ssid",
    "WpaPreSharedKeyGN": "password",
}

# Los firmwares KAON no siempre usan los mismos nombres. Estas tuplas agrupan
# variantes equivalentes para SSID, clave, ocultamiento, limite y estado.
PRIMARY_SSID_FIELDS = (
    "ServiceSetIdentifier",
    "PrimaryServiceSetIdentifier",
    "SSID",
    "Ssid",
)
PRIMARY_PASSWORD_FIELDS = (
    "WpaPreSharedKey",
    "PreSharedKey",
    "WpaPskKey",
    "KeyPassphrase",
)
PRIMARY_HIDE_FIELDS = (
    "ClosedNetwork",
    "HideAccessPoint",
    "HideSSID",
    "HideSsid",
    "SsidHidden",
    "BroadcastSSID",
    "SSIDBroadcast",
)
PRIMARY_ENABLE_FIELDS = (
    "PrimaryNetworkEnable",
    "PrimaryNetworkEnabled",
)
PRIMARY_CLIENT_LIMIT_FIELDS = (
    "MaxAssociatedDevices",
    "MaxAssociatedClients",
    "MaxAssoc",
    "MaxAssocClients",
    "MaxClients",
    "MaxNumClients",
    "MaxNumSta",
    "MaxNumStation",
    "MaxSta",
    "MaxStaNum",
    "MaxStationNum",
    "MaxStations",
    "MaxUsers",
    "StationLimit",
    "StaLimit",
    "AssociatedClientsLimit",
    "ClientLimit",
    "UserLimit",
    "WirelessMaxClients",
    "WlanMaxClients",
    "WlMaxAssoc",
    "wlMaxAssoc",
    "wl_maxassoc",
    "wl0_maxassoc",
    "wl1_maxassoc",
)
GUEST_HIDE_FIELDS = (
    "ClosedNetworkGuest",
    "GuestClosedNetwork",
    "HideAccessPointGN",
    "HideSSIDGN",
    "HideSsidGN",
    "GuestBroadcastSSID",
    "SSIDBroadcastGN",
)
GUEST_CLIENT_LIMIT_FIELDS = (
    "MaxAssociatedDevicesGN",
    "MaxAssociatedClientsGN",
    "MaxAssocGN",
    "MaxAssocClientsGN",
    "MaxClientsGN",
    "MaxNumClientsGN",
    "MaxNumStaGN",
    "MaxNumStationGN",
    "MaxStaGN",
    "MaxStaNumGN",
    "MaxStationNumGN",
    "MaxStationsGN",
    "MaxUsersGN",
    "StationLimitGN",
    "StaLimitGN",
    "AssociatedClientsLimitGN",
    "ClientLimitGN",
    "UserLimitGN",
    "WirelessMaxClientsGN",
    "WlanMaxClientsGN",
    "GuestMaxAssociatedDevices",
    "GuestMaxAssociatedClients",
    "GuestMaxClients",
    "GuestMaxNumClients",
    "GuestMaxNumSta",
    "GuestMaxUsers",
    "WlMaxAssocGN",
    "wlMaxAssocGN",
    "wl_maxassoc_gn",
    "wl0_maxassoc_gn",
    "wl1_maxassoc_gn",
)

PARENTAL_CONTROL_PROTOCOLS = {
    "TCP": "4",
    "UDP": "3",
    "BOTH": "254",
    "AMBOS": "254",
}
PARENTAL_CONTROL_PROTOCOL_LABELS = {
    "4": "TCP",
    "3": "UDP",
    "254": "BOTH",
}


class KaonRouterClient:
    """Cliente de alto nivel para operaciones administrativas KAON."""

    def __init__(self, router_url, username, password, timeout=10, post_timeout=3):
        """Inicializa una sesion HTTP autenticada.

        Args:
            router_url: URL base del router, por ejemplo `http://192.168.1.1`.
            username: Usuario de autenticacion HTTP basica.
            password: Contrasena de autenticacion HTTP basica.
            timeout: Tiempo maximo para lecturas GET.
            post_timeout: Tiempo maximo para envios POST.

        Raises:
            ValueError: Si faltan usuario o contrasena.
        """

        if not username or not password:
            raise ValueError("Faltan ROUTER_USER o ROUTER_PASS en env/credenciales.env")

        self.router_url = router_url.rstrip("/")
        self.username = username
        self.password = password
        self.timeout = timeout
        self.post_timeout = post_timeout
        self.session = self._crear_sesion()
        self._access_band_signatures = {}

    def _crear_sesion(self):
        """Crea una sesion `requests` con autenticacion basica configurada."""

        session = requests.Session()
        session.auth = HTTPBasicAuth(self.username, self.password)
        return session

    def _reiniciar_sesion(self):
        """Descarta la sesion actual y crea una nueva autenticada."""

        self.session.close()
        self.session = self._crear_sesion()

    @property
    def access_url(self):
        """URL de la pantalla de control de acceso MAC."""

        return f"{self.router_url}/wlanAccess.asp"

    @property
    def access_form_url(self):
        """URL del formulario que aplica el control de acceso MAC."""

        return f"{self.router_url}/goform/wlanAccess"

    @property
    def guest_network_url(self):
        """URL de lectura de la red de invitados."""

        return f"{self.router_url}/wlanGuestNetwork.asp"

    @property
    def guest_network_form_url(self):
        """URL del formulario que aplica cambios de red de invitados."""

        return f"{self.router_url}/goform/wlanGuestNetwork"

    @property
    def primary_network_url(self):
        """URL de lectura de la red primaria."""

        return f"{self.router_url}/wlanPrimaryNetwork.asp"

    @property
    def primary_network_form_url(self):
        """URL del formulario que aplica cambios de red primaria."""

        return f"{self.router_url}/goform/wlanPrimaryNetwork"

    @property
    def parental_control_url(self):
        """URL de lectura de reglas de control parental."""

        return f"{self.router_url}/RgFiltering.asp"

    @property
    def parental_control_form_url(self):
        """URL del formulario que aplica reglas de control parental."""

        return f"{self.router_url}/goform/RgFiltering"

    def obtener_pagina_acceso(self, band=None, network_index=None):
        """Obtiene la pantalla de acceso para una banda e interfaz WiFi."""

        if band is not None:
            band = self._normalizar_banda(band)
            html = self._obtener_pagina_acceso_en_banda(band)
        else:
            html = self._get_autenticado(self.access_url)

        if network_index is None:
            return html

        target_index = str(network_index)

        if self._indice_interfaz_acceso(html) == target_index:
            return html

        last_error = None

        for attempt in range(ACCESS_INTERFACE_ATTEMPTS):
            try:
                payload = self._obtener_payload_formulario(
                    html,
                    "wlanAccess",
                    "acceso WiFi",
                )
                payload["wlanAccessMbssIndexChanged"] = "1"
                payload["wlanAccessCurrentNetworks"] = target_index
                payload["commitwlanAccess"] = "0"
                response = self._post_autenticado(self.access_form_url, payload)

                if response.status_code not in (200, 302):
                    raise RuntimeError(
                        "El router no permitio seleccionar la interfaz WiFi: "
                        f"HTTP {response.status_code}"
                    )

                time.sleep(ACCESS_INTERFACE_SETTLE_SECONDS)
                html = self._get_autenticado(self.access_url)

                if band is not None and not self._confirmar_firma_banda_acceso(band, html):
                    raise RuntimeError(
                        "El router cambio de banda antes de confirmar la interfaz WiFi. "
                        f"Solicitada: {band} GHz."
                    )

                selected_index = self._indice_interfaz_acceso(html)

                if selected_index == target_index:
                    return html

                available = ", ".join(
                    interface["index"]
                    for interface in self._interfaces_acceso(html)
                )
                last_error = RuntimeError(
                    "El router no confirmo la interfaz WiFi solicitada. "
                    f"Actual: {selected_index or '(sin leer)'}. "
                    f"Solicitada: {target_index}. "
                    f"Disponibles: {available or '(ninguna)'}."
                )
            except (requests.RequestException, RuntimeError) as error:
                last_error = error

            self._reiniciar_sesion()

            if attempt < ACCESS_INTERFACE_ATTEMPTS - 1:
                time.sleep(ACCESS_RETRY_INTERVAL)
                html = (
                    self._obtener_pagina_acceso_en_banda(band)
                    if band is not None
                    else self._get_autenticado(self.access_url)
                )

        raise RuntimeError(
            "No se pudo confirmar la interfaz WiFi solicitada despues de "
            f"{ACCESS_INTERFACE_ATTEMPTS} intentos. Ultimo error: {last_error}"
        ) from last_error

    def _obtener_pagina_acceso_en_banda(self, band):
        """Abre `wlanAccess.asp` y confirma que conserva la banda pedida."""

        band = self._normalizar_banda(band)
        last_error = None

        for attempt in range(ACCESS_WRITE_ATTEMPTS):
            try:
                self.seleccionar_banda_wifi(band)
                time.sleep(ACCESS_INTERFACE_SETTLE_SECONDS)
                html = self._get_autenticado(self.access_url)

                if self._confirmar_firma_banda_acceso(band, html):
                    return html

                last_error = RuntimeError(
                    "El router cambio de banda antes de abrir el control de acceso. "
                    f"Solicitada: {band} GHz."
                )
            except (requests.RequestException, RuntimeError) as error:
                last_error = error

            self._reiniciar_sesion()

            if attempt < ACCESS_WRITE_ATTEMPTS - 1:
                time.sleep(ACCESS_RETRY_INTERVAL)

        raise RuntimeError(
            f"No se pudo confirmar la banda {band} GHz para el control de acceso. "
            f"Ultimo error: {last_error}"
        ) from last_error

    def _indice_interfaz_acceso(self, html):
        """Lee el indice de interfaz seleccionado en `wlanAccess.asp`."""

        soup = BeautifulSoup(html, "html.parser")
        network_select = soup.find("select", {"name": "wlanAccessCurrentNetworks"})
        return self._valor_select(network_select) if network_select else "0"

    def obtener_pagina_red_invitados(self, band="2.4"):
        """Selecciona la banda y obtiene el HTML de red de invitados."""

        self.seleccionar_banda_wifi(band)
        return self._get_autenticado(self.guest_network_url)

    def obtener_pagina_red_primaria(self, band="2.4"):
        """Selecciona la banda y obtiene el HTML de red primaria."""

        self.seleccionar_banda_wifi(band)
        return self._get_autenticado(self.primary_network_url)

    def obtener_pagina_control_parental(self):
        """Obtiene el HTML de la pantalla `ParentalControl`."""

        return self._get_autenticado(self.parental_control_url)

    def seleccionar_banda_wifi(self, band):
        """Solicita al router cambiar la banda activa del panel web."""

        band = self._normalizar_banda(band)
        html = self._get_autenticado(f"{self.router_url}{BAND_URLS[band]}")

        # El KAON responde al selector con JavaScript que abre wlanRadio.asp.
        # Requests no ejecuta JavaScript, asi que reproducimos esa navegacion.
        if "wlanRadio.asp" in html:
            html = self._get_autenticado(f"{self.router_url}{BAND_CONTEXT_URL}")

        active_band = self._banda_wifi_activa(html)

        if active_band not in (None, band):
            raise RuntimeError(
                "El router no confirmo el cambio de banda WiFi. "
                f"Solicitada: {band} GHz. Activa: {active_band or '(sin confirmar)'} GHz."
            )

        return html

    def _confirmar_firma_banda_acceso(self, band, html):
        """Evita escribir en otra banda cuando el KAON pierde su contexto."""

        signature = self._firma_pagina_acceso(html)

        for known_band, known_signature in self._access_band_signatures.items():
            if known_band != band and known_signature == signature:
                return False

        self._access_band_signatures[band] = signature
        return True

    def _firma_pagina_acceso(self, html):
        """Genera una firma estable de las interfaces visibles en el formulario."""

        soup = BeautifulSoup(html, "html.parser")
        network_select = soup.find("select", {"name": "wlanAccessCurrentNetworks"})

        if not network_select:
            raise RuntimeError(
                "El router no devolvio las interfaces WiFi en el control de acceso."
            )

        signature = []

        for option in network_select.find_all("option"):
            signature.append((
                str(option.get("value", "")).strip(),
                " ".join(option.get_text(" ", strip=True).split()),
            ))

        if not signature:
            raise RuntimeError(
                "El router no devolvio opciones de interfaz WiFi para el filtro MAC."
            )

        return tuple(signature)

    def _banda_wifi_activa(self, html):
        """Obtiene la banda marcada como activa por el menu del router."""

        soup = BeautifulSoup(html, "html.parser")

        for link in soup.find_all("a"):
            classes = {value.lower() for value in link.get("class", [])}

            if "active" not in classes:
                continue

            href = (link.get("href") or "").split("?", 1)[0]

            for band, band_url in BAND_URLS.items():
                if href == band_url:
                    return band

        return None

    def _get_autenticado(self, url):
        """Realiza un GET autenticado y renueva sesion si recibe HTTP 401."""

        response = self.session.get(url, timeout=self.timeout)

        if response.status_code == 401:
            self._reiniciar_sesion()
            response = self.session.get(url, timeout=self.timeout)

        response.raise_for_status()
        return response.text

    def _post_autenticado(self, url, payload):
        """Realiza un POST autenticado sin seguir redirecciones del router."""

        response = self.session.post(
            url,
            data=payload,
            timeout=self.post_timeout,
            allow_redirects=False,
        )

        if response.status_code == 401:
            self._reiniciar_sesion()
            response = self.session.post(
                url,
                data=payload,
                timeout=self.post_timeout,
                allow_redirects=False,
            )

        return response

    def _interfaces_acceso(self, html):
        """Lista las interfaces principal e invitadas visibles en el formulario."""

        soup = BeautifulSoup(html, "html.parser")
        network_select = soup.find("select", {"name": "wlanAccessCurrentNetworks"})

        if not network_select:
            return [{"index": "0", "ssid": "", "guest": False}]

        interfaces = []

        for option in network_select.find_all("option"):
            index = str(option.get("value", "0")).strip()
            direct_text = option.find(string=True, recursive=False)
            label = str(direct_text or "").strip()
            ssid = label.rsplit(" (", 1)[0].strip()
            interfaces.append({
                "index": index,
                "ssid": ssid,
                "guest": index != "0",
            })

        return interfaces or [{"index": "0", "ssid": "", "guest": False}]

    def listar_interfaces_banda(self, band="2.4"):
        """Devuelve las interfaces WiFi disponibles en una banda."""

        band = self._normalizar_banda(band)
        return self._interfaces_acceso(self.obtener_pagina_acceso(band=band))

    def listar_clientes_banda(
        self,
        band="2.4",
        network_index=0,
        network_name="",
        guest=False,
    ):
        """Extrae clientes de una interfaz principal o invitada de la banda."""

        band = self._normalizar_banda(band)
        network_index = str(network_index)
        html = self.obtener_pagina_acceso(
            band=band,
            network_index=network_index,
        )
        soup = BeautifulSoup(html, "html.parser")
        table = soup.find("table", {"class": "ListTypeA"})

        if not table:
            return []

        if not network_name:
            selected = soup.find("select", {"name": "wlanAccessCurrentNetworks"})
            selected_option = selected.find("option", selected=True) if selected else None
            direct_text = (
                selected_option.find(string=True, recursive=False)
                if selected_option
                else ""
            )
            label = str(direct_text or "").strip()
            network_name = label.rsplit(" (", 1)[0].strip()

        guest = bool(guest or network_index != "0")
        network_label = f"Invitados {band} GHz" if guest else f"WiFi {band} GHz"
        clients = []

        for row in table.find_all("tr")[1:]:
            columns = row.find_all("td")

            if len(columns) < 7:
                continue

            clients.append({
                "mac": columns[0].get_text(strip=True).upper(),
                "duracion": columns[1].get_text(strip=True),
                "rssi": columns[2].get_text(strip=True),
                "ip": columns[3].get_text(strip=True),
                "hostname": columns[4].get_text(strip=True) or "Desconocido",
                "modo": columns[5].get_text(strip=True),
                "velocidad": columns[6].get_text(strip=True),
                "band": band,
                "network": network_label,
                "network_index": network_index,
                "ssid": network_name,
                "guest": guest,
            })

        return clients

    def listar_clientes_todas_las_bandas(self):
        """Lista clientes de redes principales e invitadas en todas las bandas."""

        clients = []
        successful_networks = 0
        errors = []

        for band in BAND_URLS:
            try:
                interfaces = self.listar_interfaces_banda(band)
            except Exception as error:
                errors.append(f"{band} GHz: {error}")
                continue

            for interface in interfaces:
                try:
                    clients.extend(self.listar_clientes_banda(
                        band=band,
                        network_index=interface["index"],
                        network_name=interface["ssid"],
                        guest=interface["guest"],
                    ))
                    successful_networks += 1
                except Exception as error:
                    errors.append(
                        f"{band} GHz/{interface['ssid'] or interface['index']}: {error}"
                    )

        if successful_networks == 0 and errors:
            raise RuntimeError(
                "No se pudieron leer clientes WiFi: " + "; ".join(errors)
            )

        return clients

    def listar_clientes_24ghz(self):
        """Extrae la tabla de clientes conectados de la banda 2.4 GHz."""

        return self.listar_clientes_banda("2.4", network_index=0)

    def obtener_macs_bloqueadas(self, band=None, network_index=0):
        """Lee las MAC cargadas en los campos `WirelessMac01..20`."""

        soup = BeautifulSoup(
            self.obtener_pagina_acceso(
                band=band,
                network_index=network_index,
            ),
            "html.parser",
        )
        blocked_macs = []

        for field_name in WIRELESS_MAC_FIELDS:
            input_field = soup.find("input", {"name": field_name})
            value = input_field.get("value", "").strip() if input_field else ""

            if value:
                blocked_macs.append(value)

        return self._normalizar_lista_macs_bloqueo(blocked_macs)

    def obtener_macs_bloqueadas_todas_las_bandas(self):
        """Lee la union de bloqueos en redes principales e invitadas."""

        blocked_macs = set()
        successful_networks = 0
        errors = []

        for band in BAND_URLS:
            try:
                interfaces = self.listar_interfaces_banda(band)
            except Exception as error:
                errors.append(f"{band} GHz: {error}")
                continue

            for interface in interfaces:
                try:
                    blocked_macs.update(self.obtener_macs_bloqueadas(
                        band=band,
                        network_index=interface["index"],
                    ))
                    successful_networks += 1
                except Exception as error:
                    errors.append(
                        f"{band} GHz/{interface['ssid'] or interface['index']}: {error}"
                    )

        if successful_networks == 0 and errors:
            raise RuntimeError(
                "No se pudieron leer MAC bloqueadas: " + "; ".join(errors)
            )

        return sorted(blocked_macs)

    def bloquear_mac(self, mac, network_index=0, band=None):
        """Agrega una MAC al filtro de denegacion del router."""

        mac = normalize_mac(mac)

        if not is_valid_mac(mac):
            raise ValueError("La direccion MAC no es valida.")

        blocked_macs = self.obtener_macs_bloqueadas(
            band=band,
            network_index=network_index,
        )

        if mac not in blocked_macs:
            blocked_macs.append(mac)

        if len(blocked_macs) > len(WIRELESS_MAC_FIELDS):
            raise ValueError("El router solo permite hasta 20 MAC en esta pantalla.")

        return self.aplicar_lista_bloqueo(
            blocked_macs,
            network_index=network_index,
            band=band,
        )

    def desbloquear_mac(self, mac, network_index=0, band=None):
        """Elimina una MAC del filtro de denegacion del router."""

        mac = normalize_mac(mac)

        if not is_valid_mac(mac):
            raise ValueError("La direccion MAC no es valida.")

        blocked_macs = [
            blocked_mac
            for blocked_mac in self.obtener_macs_bloqueadas(
                band=band,
                network_index=network_index,
            )
            if blocked_mac != mac
        ]

        return self.aplicar_lista_bloqueo(
            blocked_macs,
            network_index=network_index,
            band=band,
        )

    def aplicar_lista_bloqueo(self, blocked_macs, network_index=0, band=None):
        """Aplica la lista completa de MAC bloqueadas en el formulario KAON."""

        blocked_macs = self._normalizar_lista_macs_bloqueo(blocked_macs)
        last_error = None

        for attempt in range(ACCESS_WRITE_ATTEMPTS):
            try:
                html = self.obtener_pagina_acceso(
                    band=band,
                    network_index=network_index,
                )
                payload = self._obtener_payload_formulario(
                    html,
                    "wlanAccess",
                    "acceso WiFi",
                )
                payload["wlanAccessMbssIndexChanged"] = "0"
                payload["wlanAccessCurrentNetworks"] = str(network_index)
                payload["MacRestrictMode"] = "2"
                payload["MacProbeResponse"] = "1"
                payload["commitwlanAccess"] = "1"

                for index, field_name in enumerate(WIRELESS_MAC_FIELDS):
                    payload[field_name] = (
                        blocked_macs[index] if index < len(blocked_macs) else ""
                    )

                response = self._post_autenticado(self.access_form_url, payload)

                if response.status_code not in (200, 302):
                    raise RuntimeError(
                        f"El router rechazo el cambio: HTTP {response.status_code}"
                    )
            except requests.RequestException:
                self._reiniciar_sesion()

                if self._lista_bloqueo_fue_aplicada(
                    blocked_macs,
                    band=band,
                    network_index=network_index,
                ):
                    return True

                last_error = RuntimeError(
                    "El router corto la conexion antes de confirmar el cambio de bloqueo."
                )
            except RuntimeError as error:
                last_error = error
            else:
                if self._lista_bloqueo_fue_aplicada(
                    blocked_macs,
                    band=band,
                    network_index=network_index,
                ):
                    return True

                last_error = RuntimeError(
                    "El router recibio el cambio, pero no confirmo la lista de MAC "
                    "en la interfaz WiFi seleccionada."
                )

            self._reiniciar_sesion()

            if attempt < ACCESS_WRITE_ATTEMPTS - 1:
                time.sleep(ACCESS_RETRY_INTERVAL)

        raise RuntimeError(
            "No se pudo confirmar el bloqueo en la interfaz WiFi despues de "
            f"{ACCESS_WRITE_ATTEMPTS} intentos. Ultimo error: {last_error}"
        ) from last_error

    def _cambiar_bloqueo_todas_las_redes(self, mac, blocked):
        """Aplica un bloqueo o desbloqueo en interfaces principales e invitadas."""

        mac = normalize_mac(mac)

        if not is_valid_mac(mac):
            raise ValueError("La direccion MAC no es valida.")

        successful_networks = 0
        applied_interfaces = []
        expected_interfaces = []
        errors = []

        for band in BAND_URLS:
            try:
                interfaces = self.listar_interfaces_banda(band)
            except Exception as error:
                errors.append(f"{band} GHz: {error}")
                continue

            for interface in interfaces:
                expected_interfaces.append({
                    "band": band,
                    "network_index": interface["index"],
                    "ssid": interface["ssid"],
                    "guest": interface["guest"],
                })

                try:
                    if blocked:
                        self.bloquear_mac(
                            mac,
                            band=band,
                            network_index=interface["index"],
                        )
                    else:
                        self.desbloquear_mac(
                            mac,
                            band=band,
                            network_index=interface["index"],
                        )
                    successful_networks += 1
                    applied_interfaces.append({
                        "band": band,
                        "network_index": interface["index"],
                        "ssid": interface["ssid"],
                        "guest": interface["guest"],
                    })
                except Exception as error:
                    errors.append(
                        f"{band} GHz/{interface['ssid'] or interface['index']}: {error}"
                    )

        if successful_networks == 0 and errors:
            action = "bloquear" if blocked else "desbloquear"
            raise RuntimeError(
                f"No se pudo {action} el usuario: " + "; ".join(errors)
            )

        return {
            "success_count": successful_networks,
            "expected_count": len(expected_interfaces),
            "all_interfaces_confirmed": not errors and (
                successful_networks == len(expected_interfaces)
            ),
            "interfaces": applied_interfaces,
            "errors": errors,
        }

    def bloquear_mac_todas_las_redes(self, mac):
        """Bloquea una MAC en redes principales e invitadas."""

        return self._cambiar_bloqueo_todas_las_redes(mac, blocked=True)

    def desbloquear_mac_todas_las_redes(self, mac):
        """Desbloquea una MAC en redes principales e invitadas."""

        return self._cambiar_bloqueo_todas_las_redes(mac, blocked=False)

    def _lista_bloqueo_fue_aplicada(
        self,
        expected_macs,
        band=None,
        network_index=0,
        timeout=ACCESS_CONFIRM_TIMEOUT,
        interval=ACCESS_CONFIRM_INTERVAL,
    ):
        """Verifica si el router ya refleja la lista de bloqueo esperada."""

        expected = set(self._normalizar_lista_macs_bloqueo(expected_macs))
        deadline = time.monotonic() + timeout

        while time.monotonic() <= deadline:
            try:
                current_macs = self.obtener_macs_bloqueadas(
                    band=band,
                    network_index=network_index,
                )
            except (requests.RequestException, RuntimeError):
                self._reiniciar_sesion()
                time.sleep(interval)
                continue

            if set(current_macs) == expected:
                return True

            time.sleep(interval)

        return False

    def _normalizar_lista_macs_bloqueo(self, macs):
        """Normaliza, valida y deduplica una lista de MAC para el filtro KAON."""

        normalized_macs = []

        for value in macs:
            mac = normalize_mac(value)

            if not mac:
                continue

            if not is_valid_mac(mac):
                raise ValueError(f"La MAC guardada en el router no es valida: {value}")

            if mac not in normalized_macs:
                normalized_macs.append(mac)

        if len(normalized_macs) > len(WIRELESS_MAC_FIELDS):
            raise ValueError("El router solo permite hasta 20 MAC en esta pantalla.")

        return normalized_macs

    def obtener_reglas_control_parental(self):
        """Extrae las reglas visibles en la tabla `ParentalControl`."""

        soup = BeautifulSoup(self.obtener_pagina_control_parental(), "html.parser")
        table = soup.find("table", {"class": "ListTypeA"})

        if not table:
            return []

        rules = []

        for index, row in enumerate(table.find_all("tr")[1:]):
            columns = row.find_all("td")

            if len(columns) < 10:
                continue

            rules.append({
                "indice": index,
                "descripcion": columns[0].get_text(strip=True),
                "mac": self._normalizar_mac_control_parental(columns[1].get_text(strip=True)),
                "url": normalize_url_keyword(columns[2].get_text(strip=True)),
                "dias": columns[3].get_text(strip=True),
                "hora_inicio": columns[4].get_text(strip=True),
                "hora_fin": columns[5].get_text(strip=True),
                "puerto_inicio": columns[6].get_text(strip=True),
                "puerto_fin": columns[7].get_text(strip=True),
                "protocolo": self._normalizar_protocolo_control_parental(
                    columns[8].get_text(strip=True)
                ),
                "accion": columns[9].get_text(strip=True),
            })

        return rules

    def crear_regla_control_parental(
        self,
        descripcion,
        url_keyword="",
        mac=None,
        protocol="BOTH",
        deny=True,
        port_start=0,
        port_end=0,
    ):
        """Crea una regla de control parental para bloquear o permitir un dominio."""

        keyword = normalize_url_keyword(url_keyword) if url_keyword else ""
        port_start = self._normalizar_puerto_control_parental(port_start)
        port_end = self._normalizar_puerto_control_parental(port_end)

        if keyword and not is_valid_url_keyword(keyword):
            raise ValueError("El dominio o palabra clave URL no es valida.")

        if not keyword and port_start == "0" and port_end == "0":
            raise ValueError("La regla necesita dominio o puerto especifico.")

        if port_start != "0" and port_end != "0" and int(port_start) > int(port_end):
            raise ValueError("El puerto inicial no puede ser mayor al puerto final.")

        mac = self._normalizar_mac_control_parental(mac or "")

        if mac and not is_valid_mac(mac):
            raise ValueError("La direccion MAC no es valida.")

        protocol_value = self._valor_protocolo_control_parental(protocol)
        payload = self._obtener_payload_nueva_regla_control_parental()
        payload.update({
            "FilteringCreateRemove": "0",
            "FilteringDescription": self._descripcion_control_parental(descripcion, keyword),
            "FilteringMacAddress": mac,
            "FilteringUrlKeyword": keyword,
            "FilteringPortStart": port_start,
            "FilteringPortEnd": port_end,
            "FilteringProtocol": protocol_value,
            "FilteringEveryDay": "128",
            "FilteringAllDay": "1",
            "FilteringHourStart": "12",
            "FilteringMinuteStart": "00",
            "FilteringStartAmPm": "0",
            "FilteringHourEnd": "12",
            "FilteringMinuteEnd": "00",
            "FilteringEndAmPm": "0",
            "FilteringAllowBlock": "0" if deny else "1",
            "FilteringEnabled": "1",
            "FilteringApply": "2",
            "FilteringTable": "0",
        })

        try:
            response = self._post_autenticado(self.parental_control_form_url, payload)
        except requests.RequestException as error:
            self._reiniciar_sesion()

            if self._regla_control_parental_existe(
                keyword,
                mac,
                protocol,
                deny,
                port_start,
                port_end,
            ):
                return True

            if isinstance(error, (Timeout, requests.ConnectionError)):
                return True

            raise

        if response.status_code not in (200, 302):
            raise RuntimeError(f"El router rechazo el cambio: HTTP {response.status_code}")

        return True

    def bloquear_dominios_control_parental(self, dominios, mac=None, descripcion="Bloqueo web"):
        """Crea reglas `Denegar` para varios dominios usando protocolo BOTH."""

        keywords = []

        for dominio in dominios:
            keyword = normalize_url_keyword(dominio)

            if not is_valid_url_keyword(keyword):
                raise ValueError(f"Dominio no valido para control parental: {dominio}")

            if keyword not in keywords:
                keywords.append(keyword)

        mac = self._normalizar_mac_control_parental(mac or "")

        if mac and not is_valid_mac(mac):
            raise ValueError("La direccion MAC no es valida.")

        existentes = self.obtener_reglas_control_parental()
        resultado = {"creadas": [], "omitidas": []}

        for keyword in keywords:
            if self._regla_control_parental_en_lista(existentes, keyword, mac, "BOTH", True):
                resultado["omitidas"].append(keyword)
                continue

            self.crear_regla_control_parental(
                descripcion=descripcion,
                url_keyword=keyword,
                mac=mac,
                protocol="BOTH",
                deny=True,
            )
            resultado["creadas"].append(keyword)
            existentes.append({
                "mac": mac,
                "url": keyword,
                "protocolo": "BOTH",
                "accion": "Denegar",
            })

        return resultado

    def bloquear_reglas_control_parental(self, reglas, mac=None):
        """Crea reglas avanzadas de control parental por dominio o puerto."""

        mac = self._normalizar_mac_control_parental(mac or "")

        if mac and not is_valid_mac(mac):
            raise ValueError("La direccion MAC no es valida.")

        existentes = self.obtener_reglas_control_parental()
        resultado = {"creadas": [], "omitidas": []}

        for regla in reglas:
            keyword = normalize_url_keyword(regla.get("url", "")) if regla.get("url") else ""
            port_start = self._normalizar_puerto_control_parental(
                regla.get("puerto_inicio", 0)
            )
            port_end = self._normalizar_puerto_control_parental(regla.get("puerto_fin", 0))
            protocol = regla.get("protocolo", "BOTH")
            etiqueta = self._etiqueta_regla_control_parental(
                keyword,
                port_start,
                port_end,
                protocol,
            )

            if self._regla_control_parental_en_lista(
                existentes,
                keyword,
                mac,
                protocol,
                True,
                port_start,
                port_end,
            ):
                resultado["omitidas"].append(etiqueta)
                continue

            self.crear_regla_control_parental(
                descripcion=regla.get("descripcion", "Bloqueo web"),
                url_keyword=keyword,
                mac=mac,
                protocol=protocol,
                deny=True,
                port_start=port_start,
                port_end=port_end,
            )
            resultado["creadas"].append(etiqueta)
            existentes.append({
                "mac": mac,
                "url": keyword,
                "puerto_inicio": port_start,
                "puerto_fin": port_end,
                "protocolo": self._normalizar_protocolo_control_parental(protocol),
                "accion": "Denegar",
            })

        return resultado

    def eliminar_regla_control_parental(self, indice):
        """Elimina una regla de control parental por indice visible en la tabla."""

        payload = {
            "FilteringCreateRemove": "3",
            "FilteringTable": str(indice),
        }

        try:
            response = self._post_autenticado(self.parental_control_form_url, payload)
        except requests.RequestException as error:
            self._reiniciar_sesion()

            if isinstance(error, (Timeout, requests.ConnectionError)):
                return True

            raise

        if response.status_code not in (200, 302):
            raise RuntimeError(f"El router rechazo el cambio: HTTP {response.status_code}")

        return True

    def desbloquear_dominios_control_parental(self, dominios, mac=None):
        """Elimina reglas `Denegar` que coincidan con dominios y MAC indicada."""

        keywords = []

        for dominio in dominios:
            keyword = normalize_url_keyword(dominio)

            if not is_valid_url_keyword(keyword):
                raise ValueError(f"Dominio no valido para control parental: {dominio}")

            if keyword not in keywords:
                keywords.append(keyword)

        mac = self._normalizar_mac_control_parental(mac or "")

        if mac and not is_valid_mac(mac):
            raise ValueError("La direccion MAC no es valida.")

        reglas = self.obtener_reglas_control_parental()
        reglas_objetivo = [
            regla
            for regla in reglas
            if self._regla_control_parental_debe_eliminarse(regla, keywords, mac)
        ]

        for regla in sorted(reglas_objetivo, key=lambda item: item["indice"], reverse=True):
            self.eliminar_regla_control_parental(regla["indice"])

        eliminadas = [regla["url"] for regla in reglas_objetivo]
        no_encontradas = [keyword for keyword in keywords if keyword not in eliminadas]

        return {
            "eliminadas": eliminadas,
            "no_encontradas": no_encontradas,
        }

    def desbloquear_reglas_control_parental(self, reglas, mac=None):
        """Elimina reglas avanzadas que coincidan con dominio, puerto, protocolo y MAC."""

        mac = self._normalizar_mac_control_parental(mac or "")

        if mac and not is_valid_mac(mac):
            raise ValueError("La direccion MAC no es valida.")

        objetivos = [
            self._normalizar_especificacion_control_parental(regla)
            for regla in reglas
        ]
        reglas_actuales = self.obtener_reglas_control_parental()
        reglas_objetivo = [
            regla
            for regla in reglas_actuales
            if self._regla_control_parental_coincide_con_especificacion(
                regla,
                objetivos,
                mac,
            )
        ]

        for regla in sorted(reglas_objetivo, key=lambda item: item["indice"], reverse=True):
            self.eliminar_regla_control_parental(regla["indice"])

        eliminadas = [
            self._etiqueta_regla_control_parental(
                regla.get("url", ""),
                regla.get("puerto_inicio", "0"),
                regla.get("puerto_fin", "0"),
                regla.get("protocolo", "BOTH"),
            )
            for regla in reglas_objetivo
        ]
        no_encontradas = [
            self._etiqueta_regla_control_parental(
                objetivo["url"],
                objetivo["puerto_inicio"],
                objetivo["puerto_fin"],
                objetivo["protocolo"],
            )
            for objetivo in objetivos
            if not any(
                self._regla_control_parental_iguala_objetivo(regla, objetivo, mac)
                for regla in reglas_objetivo
            )
        ]

        return {
            "eliminadas": eliminadas,
            "no_encontradas": no_encontradas,
        }

    def _obtener_payload_nueva_regla_control_parental(self):
        """Abre el formulario de creacion y devuelve sus campos actuales."""

        response = self.session.post(
            self.parental_control_form_url,
            data={"FilteringCreateRemove": "1", "FilteringTable": "0"},
            timeout=self.timeout,
            allow_redirects=True,
        )

        if response.status_code == 401:
            self._reiniciar_sesion()
            response = self.session.post(
                self.parental_control_form_url,
                data={"FilteringCreateRemove": "1", "FilteringTable": "0"},
                timeout=self.timeout,
                allow_redirects=True,
            )

        response.raise_for_status()
        payload = self._obtener_payload_formulario(
            response.text,
            "RgFiltering",
            "control parental",
        )

        if "FilteringUrlKeyword" not in payload:
            raise RuntimeError("No se pudo abrir el formulario de control parental.")

        return payload

    def _regla_control_parental_existe(
        self,
        keyword,
        mac,
        protocol,
        deny,
        port_start="0",
        port_end="0",
    ):
        """Verifica contra el router si una regla ya esta creada."""

        time.sleep(1)

        try:
            rules = self.obtener_reglas_control_parental()
        except (requests.RequestException, RuntimeError):
            return False

        return self._regla_control_parental_en_lista(
            rules,
            keyword,
            mac,
            protocol,
            deny,
            port_start,
            port_end,
        )

    def _regla_control_parental_en_lista(
        self,
        rules,
        keyword,
        mac,
        protocol,
        deny,
        port_start="0",
        port_end="0",
    ):
        """Busca una regla equivalente en una lista ya leida."""

        objetivo = {
            "url": normalize_url_keyword(keyword) if keyword else "",
            "mac": self._normalizar_mac_control_parental(mac or ""),
            "protocolo": self._normalizar_protocolo_control_parental(protocol),
            "puerto_inicio": self._normalizar_puerto_control_parental(port_start),
            "puerto_fin": self._normalizar_puerto_control_parental(port_end),
            "deny": deny,
        }

        for rule in rules:
            if self._regla_control_parental_iguala_objetivo(rule, objetivo, objetivo["mac"]):
                return True

        return False

    def _regla_control_parental_debe_eliminarse(self, regla, keywords, mac):
        """Indica si una regla coincide con la solicitud de desbloqueo."""

        rule_action = regla.get("accion", "").strip().lower()
        rule_denies = rule_action.startswith("deneg") or rule_action.startswith("deny")

        return (
            rule_denies
            and regla.get("url") in keywords
            and self._normalizar_mac_control_parental(regla.get("mac", "")) == mac
        )

    def _normalizar_especificacion_control_parental(self, regla):
        """Normaliza una especificacion avanzada de control parental."""

        keyword = normalize_url_keyword(regla.get("url", "")) if regla.get("url") else ""

        return {
            "url": keyword,
            "puerto_inicio": self._normalizar_puerto_control_parental(
                regla.get("puerto_inicio", 0)
            ),
            "puerto_fin": self._normalizar_puerto_control_parental(
                regla.get("puerto_fin", 0)
            ),
            "protocolo": self._normalizar_protocolo_control_parental(
                regla.get("protocolo", "BOTH")
            ),
            "deny": True,
        }

    def _regla_control_parental_coincide_con_especificacion(self, regla, objetivos, mac):
        """Indica si una regla coincide con alguna especificacion normalizada."""

        return any(
            self._regla_control_parental_iguala_objetivo(regla, objetivo, mac)
            for objetivo in objetivos
        )

    def _regla_control_parental_iguala_objetivo(self, regla, objetivo, mac):
        """Compara una regla existente contra una especificacion exacta."""

        rule_action = regla.get("accion", "").strip().lower()
        rule_denies = rule_action.startswith("deneg") or rule_action.startswith("deny")
        rule_protocol = self._normalizar_protocolo_control_parental(
            regla.get("protocolo", "")
        )

        return (
            rule_denies == objetivo["deny"]
            and regla.get("url", "") == objetivo["url"]
            and self._normalizar_mac_control_parental(regla.get("mac", "")) == mac
            and rule_protocol == objetivo["protocolo"]
            and self._normalizar_puerto_control_parental(regla.get("puerto_inicio", 0))
            == objetivo["puerto_inicio"]
            and self._normalizar_puerto_control_parental(regla.get("puerto_fin", 0))
            == objetivo["puerto_fin"]
        )

    def _normalizar_mac_control_parental(self, mac):
        """Normaliza la MAC de una regla; vacia o cero significa regla global."""

        mac = (mac or "").strip()

        if not mac or mac == "00:00:00:00:00:00":
            return ""

        return normalize_mac(mac)

    def _normalizar_puerto_control_parental(self, port):
        """Valida y normaliza un puerto del formulario de control parental."""

        try:
            port_number = int(str(port).strip() or "0")
        except ValueError as error:
            raise ValueError("El puerto debe ser un numero entre 0 y 65535.") from error

        if port_number < 0 or port_number > 65535:
            raise ValueError("El puerto debe estar entre 0 y 65535.")

        return str(port_number)

    def _etiqueta_regla_control_parental(self, keyword, port_start, port_end, protocol):
        """Construye una etiqueta corta para reportar reglas creadas u omitidas."""

        protocol = self._normalizar_protocolo_control_parental(protocol)

        if keyword:
            if port_start != "0" or port_end != "0":
                return f"{keyword} {protocol} {port_start}-{port_end}"

            return keyword

        if port_start == port_end:
            return f"{protocol} puerto {port_start}"

        return f"{protocol} puertos {port_start}-{port_end}"

    def _valor_protocolo_control_parental(self, protocol):
        """Convierte una etiqueta de protocolo al valor interno del KAON."""

        protocol = self._normalizar_protocolo_control_parental(protocol)

        if protocol not in PARENTAL_CONTROL_PROTOCOLS:
            raise ValueError("El protocolo debe ser TCP, UDP o BOTH.")

        return PARENTAL_CONTROL_PROTOCOLS[protocol]

    def _normalizar_protocolo_control_parental(self, protocol):
        """Normaliza protocolo desde valor interno, texto ingles o texto espanol."""

        protocol = str(protocol or "").strip().upper()

        if protocol in PARENTAL_CONTROL_PROTOCOL_LABELS:
            return PARENTAL_CONTROL_PROTOCOL_LABELS[protocol]

        if protocol in ("AMBOS", "BOTH"):
            return "BOTH"

        if protocol in ("TCP", "UDP"):
            return protocol

        return protocol

    def _descripcion_control_parental(self, descripcion, keyword):
        """Ajusta la descripcion para evitar entradas vacias o demasiado largas."""

        descripcion = (descripcion or "").strip() or "Bloqueo web"
        texto = f"{descripcion} {keyword}".strip()
        return texto[:48]

    def obtener_config_red_invitados(self, band="2.4"):
        """Devuelve estado, SSID, clave WPA, visibilidad y limite de invitados."""

        payload = self._obtener_payload_red_invitados(band=band)
        hide_field = self._buscar_campo(payload, GUEST_HIDE_FIELDS)
        limit_field = self._buscar_campo_limite_clientes(
            payload,
            GUEST_CLIENT_LIMIT_FIELDS,
            band,
        )

        return {
            "habilitada": payload.get("GuestNetworkEnable") == "1",
            "ssid": payload.get("GuestServiceSetIdentifier", ""),
            "password": payload.get("WpaPreSharedKeyGN", ""),
            "oculto": self._valor_ocultar_ssid(payload[hide_field], hide_field)
            if hide_field
            else None,
            "limite_clientes": self._obtener_limite_clientes(payload, limit_field),
            "limite_clientes_soportado": bool(limit_field),
            "limite_clientes_max": WIFI_CLIENT_LIMIT_MAX,
        }

    def obtener_config_red_primaria(self, band="2.4"):
        """Devuelve estado, SSID, clave WPA, visibilidad y limite primario."""

        payload = self._obtener_payload_red_primaria(band=band)
        enable_field = self._buscar_campo(payload, PRIMARY_ENABLE_FIELDS)
        hide_field = self._buscar_campo(payload, PRIMARY_HIDE_FIELDS)
        limit_field = self._buscar_campo_limite_clientes(
            payload,
            PRIMARY_CLIENT_LIMIT_FIELDS,
            band,
        )

        return {
            "habilitada": payload.get(enable_field) == "1" if enable_field else None,
            "ssid": self._obtener_valor_campo(payload, PRIMARY_SSID_FIELDS),
            "password": self._obtener_valor_campo(payload, PRIMARY_PASSWORD_FIELDS),
            "oculto": self._valor_ocultar_ssid(payload[hide_field], hide_field)
            if hide_field
            else None,
            "limite_clientes": self._obtener_limite_clientes(payload, limit_field),
            "limite_clientes_soportado": bool(limit_field),
            "limite_clientes_max": WIFI_CLIENT_LIMIT_MAX,
        }

    def cambiar_ssid_red_primaria(self, ssid, band="2.4", network_index=0):
        """Actualiza solo el SSID de la red primaria."""

        return self._aplicar_config_red_primaria(
            ssid=ssid,
            band=band,
            network_index=network_index,
        )

    def cambiar_password_red_primaria(self, password, band="2.4", network_index=0):
        """Actualiza solo la contrasena WPA de la red primaria."""

        return self._aplicar_config_red_primaria(
            password=password,
            band=band,
            network_index=network_index,
        )

    def configurar_ocultar_ssid_red_primaria(self, ocultar, band="2.4", network_index=0):
        """Configura si la red primaria debe ocultar su SSID."""

        return self._aplicar_config_red_primaria(
            ocultar_ssid=ocultar,
            band=band,
            network_index=network_index,
        )

    def configurar_red_primaria(
        self,
        ssid=None,
        password=None,
        ocultar_ssid=None,
        limite_clientes=None,
        habilitada=None,
        band="2.4",
        network_index=0,
    ):
        """Aplica SSID, clave WPA, visibilidad, limite y estado."""

        return self._aplicar_config_red_primaria(
            ssid=ssid,
            password=password,
            ocultar_ssid=ocultar_ssid,
            limite_clientes=limite_clientes,
            habilitada=habilitada,
            band=band,
            network_index=network_index,
        )

    def activar_red_primaria(self, band="2.4", network_index=0):
        """Marca como habilitada la red primaria de la banda indicada."""

        return self._aplicar_config_red_primaria(
            habilitada=True,
            band=band,
            network_index=network_index,
        )

    def desactivar_red_primaria(self, band="2.4", network_index=0):
        """Marca como deshabilitada la red primaria de la banda indicada."""

        return self._aplicar_config_red_primaria(
            habilitada=False,
            band=band,
            network_index=network_index,
        )

    def _aplicar_config_red_primaria(
        self,
        ssid=None,
        password=None,
        ocultar_ssid=None,
        limite_clientes=None,
        habilitada=None,
        band="2.4",
        network_index=0,
    ):
        """Aplica cambios parciales sobre el formulario de red primaria."""

        payload = self._obtener_payload_red_primaria(band=band)

        if habilitada is not None:
            enable_field = self._buscar_campo(payload, PRIMARY_ENABLE_FIELDS)

            if not enable_field:
                self._error_campo_no_encontrado("estado de red primaria", PRIMARY_ENABLE_FIELDS)

            payload[enable_field] = "1" if habilitada else "0"

        if ssid is not None:
            self._validar_ssid(ssid)
            ssid_field = self._buscar_campo(payload, PRIMARY_SSID_FIELDS)

            if not ssid_field:
                self._error_campo_no_encontrado("SSID", PRIMARY_SSID_FIELDS)

            payload[ssid_field] = ssid

        if password is not None:
            self._validar_password_wpa(password)
            password_field = self._buscar_campo(payload, PRIMARY_PASSWORD_FIELDS)

            if not password_field:
                self._error_campo_no_encontrado("contrasena WPA", PRIMARY_PASSWORD_FIELDS)

            payload[password_field] = password

        if ocultar_ssid is not None:
            hide_field = self._buscar_campo(payload, PRIMARY_HIDE_FIELDS)

            if not hide_field:
                self._error_campo_no_encontrado("ocultar SSID", PRIMARY_HIDE_FIELDS)

            payload[hide_field] = self._valor_para_ocultar_ssid(ocultar_ssid, hide_field)

        if limite_clientes is not None:
            limit_field = self._buscar_campo_limite_clientes(
                payload,
                PRIMARY_CLIENT_LIMIT_FIELDS,
                band,
            )

            if not limit_field:
                self._error_campo_no_encontrado(
                    "limite de usuarios",
                    PRIMARY_CLIENT_LIMIT_FIELDS,
                )

            payload[limit_field] = self._validar_limite_clientes(limite_clientes)

        self._preparar_payload_red_primaria(payload, network_index)

        try:
            response = self._post_autenticado(self.primary_network_form_url, payload)
        except requests.RequestException as error:
            self._reiniciar_sesion()

            if self._config_red_primaria_fue_aplicada(
                ssid,
                password,
                ocultar_ssid,
                limite_clientes,
                habilitada,
                band,
            ):
                return True

            if isinstance(error, (Timeout, requests.ConnectionError)):
                return True

            raise

        if response.status_code not in (200, 302):
            raise RuntimeError(f"El router rechazo el cambio: HTTP {response.status_code}")

        return True

    def configurar_red_invitados(
        self,
        ssid=None,
        password=None,
        ocultar_ssid=None,
        limite_clientes=None,
        habilitada=None,
        band="2.4",
        network_index=0,
    ):
        """Aplica estado, SSID, clave WPA, visibilidad y limite de invitados."""

        payload = self._obtener_payload_red_invitados(band=band)

        if ssid is not None:
            self._validar_ssid(ssid)
            payload["GuestServiceSetIdentifier"] = ssid

        if password is not None:
            self._validar_password_wpa(password)
            payload["WpaPreSharedKeyGN"] = password

        if ocultar_ssid is not None:
            hide_field = self._buscar_campo(payload, GUEST_HIDE_FIELDS)

            if not hide_field:
                self._error_campo_no_encontrado("ocultar SSID", GUEST_HIDE_FIELDS)

            payload[hide_field] = self._valor_para_ocultar_ssid(ocultar_ssid, hide_field)

        if limite_clientes is not None:
            limit_field = self._buscar_campo_limite_clientes(
                payload,
                GUEST_CLIENT_LIMIT_FIELDS,
                band,
            )

            if not limit_field:
                self._error_campo_no_encontrado(
                    "limite de usuarios invitados",
                    GUEST_CLIENT_LIMIT_FIELDS,
                )

            payload[limit_field] = self._validar_limite_clientes(limite_clientes)

        if habilitada is not None:
            payload["GuestNetworkEnable"] = "1" if habilitada else "0"

        if payload.get("GuestNetworkEnable") == "1" and not payload.get("WpaPreSharedKeyGN"):
            raise ValueError("La red de invitados no tiene contrasena WPA configurada.")

        if payload.get("GuestNetworkEnable") == "1":
            self._preparar_seguridad_red_invitados(payload)

        payload["CurrentNetworks"] = str(network_index)
        payload["MbssIndexChanged"] = "0"
        payload["GenerateWepKeysGN"] = "0"
        payload["RestoreGuestNetworkDefaults"] = "0"
        payload["commitwlanGuestNetwork"] = "1"

        try:
            response = self._post_autenticado(self.guest_network_form_url, payload)
        except requests.RequestException as error:
            self._reiniciar_sesion()

            if self._config_red_invitados_fue_aplicada(
                habilitada,
                ssid,
                password,
                ocultar_ssid,
                limite_clientes,
                band,
            ):
                return True

            if isinstance(error, (Timeout, requests.ConnectionError)):
                return True

            raise

        if response.status_code not in (200, 302):
            raise RuntimeError(f"El router rechazo el cambio: HTTP {response.status_code}")

        return True

    def activar_red_invitados(
        self,
        ssid=None,
        password=None,
        ocultar_ssid=None,
        limite_clientes=None,
        band="2.4",
        network_index=0,
    ):
        """Habilita la red de invitados y conserva o actualiza SSID/clave."""

        return self.configurar_red_invitados(
            ssid=ssid,
            password=password,
            ocultar_ssid=ocultar_ssid,
            limite_clientes=limite_clientes,
            habilitada=True,
            band=band,
            network_index=network_index,
        )

    def desactivar_red_invitados(self, band="2.4", network_index=0):
        """Deshabilita la red de invitados de la banda seleccionada."""

        return self.configurar_red_invitados(
            habilitada=False,
            band=band,
            network_index=network_index,
        )

    def esperar_config_red_invitados(
        self,
        habilitada=None,
        ssid=None,
        password=None,
        oculto=None,
        limite_clientes=None,
        band="2.4",
        timeout=25,
        interval=2,
    ):
        """Espera hasta que la red de invitados coincida con lo esperado."""

        limite = time.monotonic() + timeout
        ultima_config = None

        while time.monotonic() <= limite:
            try:
                config = self.obtener_config_red_invitados(band=band)
            except (requests.RequestException, RuntimeError):
                self._reiniciar_sesion()
                time.sleep(interval)
                continue

            ultima_config = config

            if self._config_red_invitados_coincide(
                config,
                habilitada,
                ssid,
                password,
                oculto,
                limite_clientes,
            ):
                return config

            time.sleep(interval)

        return ultima_config

    def _obtener_payload_red_invitados(self, band="2.4"):
        """Construye el payload actual del formulario de red de invitados."""

        return self._obtener_payload_formulario(
            self.obtener_pagina_red_invitados(band=band),
            "wlanGuestNetwork",
            "red de invitados",
        )

    def _obtener_payload_red_primaria(self, band="2.4"):
        """Construye el payload actual del formulario de red primaria."""

        return self._obtener_payload_formulario(
            self.obtener_pagina_red_primaria(band=band),
            "wlanPrimaryNetwork",
            "red primaria",
        )

    def _obtener_payload_formulario(self, html, form_name, nombre_formulario):
        """Extrae campos editables de un formulario HTML del router."""

        soup = BeautifulSoup(html, "html.parser")
        form = soup.find("form", {"name": form_name})

        if not form:
            raise RuntimeError(f"No se encontro el formulario de {nombre_formulario}.")

        payload = {}

        for field in form.find_all(["input", "select", "textarea"]):
            name = field.get("name")

            if not name:
                continue

            if field.has_attr("disabled"):
                if name in (*PRIMARY_CLIENT_LIMIT_FIELDS, *GUEST_CLIENT_LIMIT_FIELDS):
                    payload[name] = field.get("value", "")

                continue

            if field.name == "select":
                payload[name] = self._valor_select(field)
                continue

            if field.name == "textarea":
                payload[name] = field.get_text()
                continue

            input_type = field.get("type", "text").lower()

            if input_type in ("submit", "button", "image", "reset"):
                continue

            if input_type == "checkbox" and not field.has_attr("checked"):
                if name in PRIMARY_HIDE_FIELDS or name in GUEST_HIDE_FIELDS:
                    payload[name] = "0"

                continue

            if input_type == "radio" and not field.has_attr("checked"):
                continue

            payload[name] = field.get("value", "")

        for field_name in GUEST_NETWORK_FIELDS:
            if form_name == "wlanGuestNetwork":
                payload.setdefault(field_name, "")

        return payload

    def _valor_select(self, select_field):
        """Devuelve el valor seleccionado de un campo `<select>`."""

        selected = select_field.find("option", selected=True)

        if selected is None:
            selected = select_field.find("option")

        return selected.get("value", "") if selected else ""

    def _red_invitados_fue_activada(self, expected_payload, band):
        """Confirma si la red de invitados quedo activa con SSID y clave."""

        time.sleep(1)

        try:
            current = self.obtener_config_red_invitados(band=band)
        except (requests.RequestException, RuntimeError):
            return False

        return (
            current["habilitada"]
            and current["ssid"] == expected_payload.get("GuestServiceSetIdentifier", "")
            and current["password"] == expected_payload.get("WpaPreSharedKeyGN", "")
        )

    def _red_invitados_fue_desactivada(self, band):
        """Confirma si la red de invitados quedo deshabilitada."""

        time.sleep(1)

        try:
            current = self.obtener_config_red_invitados(band=band)
        except (requests.RequestException, RuntimeError):
            return False

        return not current["habilitada"]

    def esperar_config_red_primaria(
        self,
        habilitada=None,
        ssid=None,
        password=None,
        oculto=None,
        limite_clientes=None,
        band="2.4",
        timeout=25,
        interval=2,
    ):
        """Espera hasta que la red primaria coincida con lo esperado."""

        limite = time.monotonic() + timeout
        ultima_config = None

        while time.monotonic() <= limite:
            try:
                config = self.obtener_config_red_primaria(band=band)
            except (requests.RequestException, RuntimeError):
                self._reiniciar_sesion()
                time.sleep(interval)
                continue

            ultima_config = config

            if self._config_red_primaria_coincide(
                config,
                habilitada,
                ssid,
                password,
                oculto,
                limite_clientes,
            ):
                return config

            time.sleep(interval)

        return ultima_config

    def _config_red_primaria_fue_aplicada(
        self,
        ssid,
        password,
        oculto,
        limite_clientes,
        habilitada,
        band,
    ):
        """Verifica si el router refleja cambios enviados a red primaria."""

        time.sleep(1)

        try:
            current = self.obtener_config_red_primaria(band=band)
        except (requests.RequestException, RuntimeError):
            return False

        return self._config_red_primaria_coincide(
            current,
            habilitada,
            ssid,
            password,
            oculto,
            limite_clientes,
        )

    def _config_red_primaria_coincide(
        self,
        config,
        habilitada,
        ssid,
        password,
        oculto,
        limite_clientes,
    ):
        """Compara una configuracion primaria contra valores esperados."""

        if habilitada is not None and config["habilitada"] != habilitada:
            return False

        if ssid is not None and config["ssid"] != ssid:
            return False

        if password is not None and config["password"] != password:
            return False

        if oculto is not None and config["oculto"] != oculto:
            return False

        if (
            limite_clientes is not None
            and config["limite_clientes"] != int(self._validar_limite_clientes(limite_clientes))
        ):
            return False

        return True

    def _config_red_invitados_fue_aplicada(
        self,
        habilitada,
        ssid,
        password,
        oculto,
        limite_clientes,
        band,
    ):
        """Verifica si el router refleja cambios enviados a red de invitados."""

        time.sleep(1)

        try:
            current = self.obtener_config_red_invitados(band=band)
        except (requests.RequestException, RuntimeError):
            return False

        return self._config_red_invitados_coincide(
            current,
            habilitada,
            ssid,
            password,
            oculto,
            limite_clientes,
        )

    def _config_red_invitados_coincide(
        self,
        config,
        habilitada,
        ssid,
        password,
        oculto,
        limite_clientes,
    ):
        """Compara una configuracion de invitados contra valores esperados."""

        if habilitada is not None and config["habilitada"] != habilitada:
            return False

        if ssid is not None and config["ssid"] != ssid:
            return False

        if password is not None and config["password"] != password:
            return False

        if oculto is not None and config["oculto"] != oculto:
            return False

        if (
            limite_clientes is not None
            and config["limite_clientes"] != int(self._validar_limite_clientes(limite_clientes))
        ):
            return False

        return True

    def _preparar_payload_red_primaria(self, payload, network_index):
        """Ajusta indices y marca de confirmacion antes del POST primario."""

        for field_name in ("CurrentNetworks", "wlanPrimaryCurrentNetworks"):
            if field_name in payload:
                payload[field_name] = str(network_index)

        for field_name in ("MbssIndexChanged", "wlanPrimaryMbssIndexChanged"):
            if field_name in payload:
                payload[field_name] = "0"

        payload["commitwlanPrimaryNetwork"] = "1"

    def _preparar_seguridad_red_invitados(self, payload):
        """Fuerza WPA/WPA2-PSK con AES en redes de invitados habilitadas."""

        payload["WpaAuthGN"] = "0"
        payload["WpaPskAuthGN"] = "1"
        payload["Wpa2AuthGN"] = "0"
        payload["Wpa2PskAuthGN"] = "1"
        payload["WpaEncryptionGN"] = "2"

        if "AutoSecurityGN" in payload:
            payload["AutoSecurityGN"] = "1"

        if "WepEncryptionGN" in payload:
            payload["WepEncryptionGN"] = "0"

    def _buscar_campo(self, payload, field_names):
        """Devuelve el primer nombre de campo presente en `payload`."""

        for field_name in field_names:
            if field_name in payload:
                return field_name

        return None

    def _buscar_campo_limite_clientes(self, payload, field_names, band):
        """Busca el campo de limite dando prioridad al indice de banda."""

        band = self._normalizar_banda(band)
        preferred = (
            ("wl1_maxassoc", "wl1_maxassoc_gn")
            if band == "5"
            else ("wl0_maxassoc", "wl0_maxassoc_gn")
        )

        for field_name in preferred:
            if field_name in field_names and field_name in payload:
                return field_name

        return self._buscar_campo(payload, field_names)

    def _obtener_valor_campo(self, payload, field_names):
        """Obtiene el valor del primer campo disponible entre varias opciones."""

        field_name = self._buscar_campo(payload, field_names)
        return payload.get(field_name, "") if field_name else ""

    def _obtener_limite_clientes(self, payload, field_name):
        """Lee el limite de clientes de un campo opcional del firmware."""

        if not field_name:
            return None

        value = str(payload.get(field_name, "")).strip()

        if not value:
            return None

        try:
            return int(value)
        except ValueError:
            return None

    def _valor_ocultar_ssid(self, value, field_name):
        """Interpreta el valor del campo de visibilidad como booleano `oculto`."""

        if field_name in ("BroadcastSSID", "SSIDBroadcast"):
            return value != "1"

        return value == "1"

    def _valor_para_ocultar_ssid(self, ocultar, field_name):
        """Convierte el booleano `ocultar` al valor esperado por el formulario."""

        if field_name in ("BroadcastSSID", "SSIDBroadcast"):
            return "0" if ocultar else "1"

        return "1" if ocultar else "0"

    def _error_campo_no_encontrado(self, etiqueta, field_names):
        """Genera un error tecnico cuando falta un campo esperado del router."""

        campos = ", ".join(field_names)
        raise RuntimeError(
            f"No se encontro el campo de {etiqueta} en el formulario del router. "
            f"Campos esperados: {campos}."
        )

    def _normalizar_banda(self, band):
        """Normaliza entradas equivalentes a `2.4` o `5` GHz."""

        band = str(band).strip().lower().replace("ghz", "")

        if band in ("2.4", "24", "2"):
            return "2.4"

        if band in ("5", "5.0"):
            return "5"

        raise ValueError("La banda WiFi debe ser 2.4 o 5 GHz.")

    def _validar_ssid(self, ssid):
        """Valida que el SSID cumpla longitud y contenido minimo."""

        if not ssid or not ssid.strip():
            raise ValueError("El SSID no puede estar vacio.")

        if len(ssid) > 32:
            raise ValueError("El SSID no puede tener mas de 32 caracteres.")

    def _validar_password_wpa(self, password):
        """Valida la longitud permitida para una clave WPA/WPA2."""

        if len(password) < 8 or len(password) > 64:
            raise ValueError("La contrasena WPA debe tener entre 8 y 64 caracteres.")

    def _validar_limite_clientes(self, limite_clientes):
        """Valida el limite de usuarios conectados por interfaz WiFi."""

        try:
            limite = int(limite_clientes)
        except (TypeError, ValueError) as error:
            raise ValueError("El limite de usuarios debe ser un numero.") from error

        if limite < 0 or limite > WIFI_CLIENT_LIMIT_MAX:
            raise ValueError(
                f"El limite de usuarios debe estar entre 0 y {WIFI_CLIENT_LIMIT_MAX}."
            )

        return str(limite)
