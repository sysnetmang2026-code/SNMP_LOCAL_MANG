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
# Paginas que cambian la banda activa antes de leer formularios WiFi.
BAND_URLS = {
    "2.4": "/wlan24G.asp",
    "5": "/wlan5G.asp",
}


# Nombres de campos observados en el formulario de red de invitados KAON.
GUEST_NETWORK_FIELDS = {
    "GuestNetworkEnable": "estado",
    "GuestServiceSetIdentifier": "ssid",
    "WpaPreSharedKeyGN": "password",
}

# Los firmwares KAON no siempre usan los mismos nombres. Estas tuplas agrupan
# variantes equivalentes para SSID, clave, ocultamiento y estado de red primaria.
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

    def obtener_pagina_acceso(self, band=None):
        """Obtiene el HTML de la pantalla de control de acceso MAC."""

        if band is not None:
            self.seleccionar_banda_wifi(band)

        return self._get_autenticado(self.access_url)

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
        return self._get_autenticado(f"{self.router_url}{BAND_URLS[band]}")

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

    def listar_clientes_banda(self, band="2.4"):
        """Extrae clientes conectados de la banda activa en `wlanAccess.asp`."""

        band = self._normalizar_banda(band)
        soup = BeautifulSoup(self.obtener_pagina_acceso(band=band), "html.parser")
        table = soup.find("table", {"class": "ListTypeA"})

        if not table:
            return []

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
                "network": f"WiFi {band} GHz",
            })

        return clients

    def listar_clientes_todas_las_bandas(self):
        """Lista clientes visibles en las bandas WiFi soportadas por el router."""

        clients = []
        successful_bands = 0
        errors = []

        for band in BAND_URLS:
            try:
                clients.extend(self.listar_clientes_banda(band))
                successful_bands += 1
            except Exception as error:
                errors.append(f"{band} GHz: {error}")

        if successful_bands == 0 and errors:
            raise RuntimeError(
                "No se pudieron leer clientes WiFi: " + "; ".join(errors)
            )

        return clients

    def listar_clientes_24ghz(self):
        """Extrae la tabla de clientes conectados de la banda 2.4 GHz."""

        return self.listar_clientes_banda("2.4")

    def obtener_macs_bloqueadas(self, band=None):
        """Lee las MAC cargadas en los campos `WirelessMac01..20`."""

        soup = BeautifulSoup(self.obtener_pagina_acceso(band=band), "html.parser")
        blocked_macs = []

        for field_name in WIRELESS_MAC_FIELDS:
            input_field = soup.find("input", {"name": field_name})
            value = input_field.get("value", "").strip() if input_field else ""

            if value:
                blocked_macs.append(normalize_mac(value))

        return blocked_macs

    def obtener_macs_bloqueadas_todas_las_bandas(self):
        """Lee la union de MAC bloqueadas en todas las bandas WiFi."""

        blocked_macs = set()
        successful_bands = 0
        errors = []

        for band in BAND_URLS:
            try:
                blocked_macs.update(self.obtener_macs_bloqueadas(band=band))
                successful_bands += 1
            except Exception as error:
                errors.append(f"{band} GHz: {error}")

        if successful_bands == 0 and errors:
            raise RuntimeError(
                "No se pudieron leer MAC bloqueadas: " + "; ".join(errors)
            )

        return sorted(blocked_macs)

    def bloquear_mac(self, mac, network_index=0):
        """Agrega una MAC al filtro de denegacion del router."""

        mac = normalize_mac(mac)

        if not is_valid_mac(mac):
            raise ValueError("La direccion MAC no es valida.")

        blocked_macs = self.obtener_macs_bloqueadas()

        if mac not in blocked_macs:
            blocked_macs.append(mac)

        if len(blocked_macs) > len(WIRELESS_MAC_FIELDS):
            raise ValueError("El router solo permite hasta 20 MAC en esta pantalla.")

        return self.aplicar_lista_bloqueo(blocked_macs, network_index=network_index)

    def desbloquear_mac(self, mac, network_index=0):
        """Elimina una MAC del filtro de denegacion del router."""

        mac = normalize_mac(mac)

        if not is_valid_mac(mac):
            raise ValueError("La direccion MAC no es valida.")

        blocked_macs = [
            blocked_mac
            for blocked_mac in self.obtener_macs_bloqueadas()
            if blocked_mac != mac
        ]

        return self.aplicar_lista_bloqueo(blocked_macs, network_index=network_index)

    def aplicar_lista_bloqueo(self, blocked_macs, network_index=0):
        """Aplica la lista completa de MAC bloqueadas en el formulario KAON."""

        blocked_macs = [normalize_mac(mac) for mac in blocked_macs if mac]
        payload = {
            "wlanAccessMbssIndexChanged": "0",
            "wlanAccessCurrentNetworks": str(network_index),
            "MacRestrictMode": "2",
            "MacProbeResponse": "1",
            "commitwlanAccess": "1",
        }

        for index, field_name in enumerate(WIRELESS_MAC_FIELDS):
            payload[field_name] = blocked_macs[index] if index < len(blocked_macs) else ""

        try:
            response = self.session.post(
                self.access_form_url,
                data=payload,
                timeout=self.post_timeout,
                allow_redirects=False,
            )
        except requests.RequestException as error:
            self._reiniciar_sesion()

            if self._lista_bloqueo_fue_aplicada(blocked_macs):
                return True

            if isinstance(error, (Timeout, requests.ConnectionError)):
                return True

            raise

        if response.status_code not in (200, 302):
            raise RuntimeError(f"El router rechazo el cambio: HTTP {response.status_code}")

        return True

    def _lista_bloqueo_fue_aplicada(self, expected_macs):
        """Verifica si el router ya refleja la lista de bloqueo esperada."""

        time.sleep(1)

        try:
            current_macs = self.obtener_macs_bloqueadas()
        except requests.RequestException:
            return False

        return set(current_macs) == set(expected_macs)

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
        """Devuelve estado, SSID y clave WPA de la red de invitados."""

        payload = self._obtener_payload_red_invitados(band=band)

        return {
            "habilitada": payload.get("GuestNetworkEnable") == "1",
            "ssid": payload.get("GuestServiceSetIdentifier", ""),
            "password": payload.get("WpaPreSharedKeyGN", ""),
        }

    def obtener_config_red_primaria(self, band="2.4"):
        """Devuelve estado, SSID, clave WPA y visibilidad de red primaria."""

        payload = self._obtener_payload_red_primaria(band=band)
        enable_field = self._buscar_campo(payload, PRIMARY_ENABLE_FIELDS)
        hide_field = self._buscar_campo(payload, PRIMARY_HIDE_FIELDS)

        return {
            "habilitada": payload.get(enable_field) == "1" if enable_field else None,
            "ssid": self._obtener_valor_campo(payload, PRIMARY_SSID_FIELDS),
            "password": self._obtener_valor_campo(payload, PRIMARY_PASSWORD_FIELDS),
            "oculto": self._valor_ocultar_ssid(payload[hide_field], hide_field)
            if hide_field
            else None,
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

        self._preparar_payload_red_primaria(payload, network_index)

        try:
            response = self._post_autenticado(self.primary_network_form_url, payload)
        except requests.RequestException as error:
            self._reiniciar_sesion()

            if self._config_red_primaria_fue_aplicada(
                ssid,
                password,
                ocultar_ssid,
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

    def activar_red_invitados(self, ssid=None, password=None, band="2.4", network_index=0):
        """Habilita la red de invitados y conserva o actualiza SSID/clave."""

        payload = self._obtener_payload_red_invitados(band=band)

        if ssid is not None:
            self._validar_ssid(ssid)
            payload["GuestServiceSetIdentifier"] = ssid

        if password is not None:
            self._validar_password_wpa(password)
            payload["WpaPreSharedKeyGN"] = password

        if not payload.get("WpaPreSharedKeyGN"):
            raise ValueError("La red de invitados no tiene contrasena WPA configurada.")

        payload["CurrentNetworks"] = str(network_index)
        payload["MbssIndexChanged"] = "0"
        payload["GuestNetworkEnable"] = "1"
        payload["WpaAuthGN"] = "0"
        payload["WpaPskAuthGN"] = "1"
        payload["Wpa2AuthGN"] = "0"
        payload["Wpa2PskAuthGN"] = "1"
        payload["WpaEncryptionGN"] = payload.get("WpaEncryptionGN") or "2"
        payload["GenerateWepKeysGN"] = "0"
        payload["RestoreGuestNetworkDefaults"] = "0"
        payload["commitwlanGuestNetwork"] = "1"

        try:
            response = self._post_autenticado(self.guest_network_form_url, payload)
        except requests.RequestException as error:
            self._reiniciar_sesion()

            if self._red_invitados_fue_activada(payload, band):
                return True

            if isinstance(error, (Timeout, requests.ConnectionError)):
                return True

            raise

        if response.status_code not in (200, 302):
            raise RuntimeError(f"El router rechazo el cambio: HTTP {response.status_code}")

        return True

    def desactivar_red_invitados(self, band="2.4", network_index=0):
        """Deshabilita la red de invitados de la banda seleccionada."""

        payload = self._obtener_payload_red_invitados(band=band)
        payload["CurrentNetworks"] = str(network_index)
        payload["MbssIndexChanged"] = "0"
        payload["GuestNetworkEnable"] = "0"
        payload["GenerateWepKeysGN"] = "0"
        payload["RestoreGuestNetworkDefaults"] = "0"
        payload["commitwlanGuestNetwork"] = "1"

        try:
            response = self._post_autenticado(self.guest_network_form_url, payload)
        except requests.RequestException as error:
            self._reiniciar_sesion()

            if self._red_invitados_fue_desactivada(band):
                return True

            if isinstance(error, Timeout) or "Read timed out" in str(error):
                return True

            raise

        if response.status_code not in (200, 302):
            raise RuntimeError(f"El router rechazo el cambio: HTTP {response.status_code}")

        return True

    def esperar_config_red_invitados(
        self,
        habilitada=None,
        ssid=None,
        password=None,
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

            if self._config_red_invitados_coincide(config, habilitada, ssid, password):
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

            if not name or field.has_attr("disabled"):
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
                if name in PRIMARY_HIDE_FIELDS:
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
            ):
                return config

            time.sleep(interval)

        return ultima_config

    def _config_red_primaria_fue_aplicada(self, ssid, password, oculto, habilitada, band):
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
        )

    def _config_red_primaria_coincide(self, config, habilitada, ssid, password, oculto):
        """Compara una configuracion primaria contra valores esperados."""

        if habilitada is not None and config["habilitada"] != habilitada:
            return False

        if ssid is not None and config["ssid"] != ssid:
            return False

        if password is not None and config["password"] != password:
            return False

        if oculto is not None and config["oculto"] != oculto:
            return False

        return True

    def _config_red_invitados_coincide(self, config, habilitada, ssid, password):
        """Compara una configuracion de invitados contra valores esperados."""

        if habilitada is not None and config["habilitada"] != habilitada:
            return False

        if ssid is not None and config["ssid"] != ssid:
            return False

        if password is not None and config["password"] != password:
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

    def _buscar_campo(self, payload, field_names):
        """Devuelve el primer nombre de campo presente en `payload`."""

        for field_name in field_names:
            if field_name in payload:
                return field_name

        return None

    def _obtener_valor_campo(self, payload, field_names):
        """Obtiene el valor del primer campo disponible entre varias opciones."""

        field_name = self._buscar_campo(payload, field_names)
        return payload.get(field_name, "") if field_name else ""

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
