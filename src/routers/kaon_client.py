import time

import requests
from bs4 import BeautifulSoup
from requests.auth import HTTPBasicAuth
from requests.exceptions import Timeout

from validators import is_valid_mac, normalize_mac


WIRELESS_MAC_FIELDS = [f"WirelessMac{number:02d}" for number in range(1, 21)]


GUEST_NETWORK_FIELDS = {
    "GuestNetworkEnable": "estado",
    "GuestServiceSetIdentifier": "ssid",
    "WpaPreSharedKeyGN": "password",
}


class KaonRouterClient:
    def __init__(self, router_url, username, password, timeout=10, post_timeout=3):
        if not username or not password:
            raise ValueError("Faltan ROUTER_USER o ROUTER_PASS en env/credenciales.env")

        self.router_url = router_url.rstrip("/")
        self.username = username
        self.password = password
        self.timeout = timeout
        self.post_timeout = post_timeout
        self.session = self._crear_sesion()

    def _crear_sesion(self):
        session = requests.Session()
        session.auth = HTTPBasicAuth(self.username, self.password)
        return session

    def _reiniciar_sesion(self):
        self.session.close()
        self.session = self._crear_sesion()

    @property
    def access_url(self):
        return f"{self.router_url}/wlanAccess.asp"

    @property
    def access_form_url(self):
        return f"{self.router_url}/goform/wlanAccess"

    @property
    def guest_network_url(self):
        return f"{self.router_url}/wlanGuestNetwork.asp"

    @property
    def guest_network_form_url(self):
        return f"{self.router_url}/goform/wlanGuestNetwork"

    def obtener_pagina_acceso(self):
        return self._get_autenticado(self.access_url)

    def obtener_pagina_red_invitados(self):
        return self._get_autenticado(self.guest_network_url)

    def _get_autenticado(self, url):
        response = self.session.get(url, timeout=self.timeout)

        if response.status_code == 401:
            self._reiniciar_sesion()
            response = self.session.get(url, timeout=self.timeout)

        response.raise_for_status()
        return response.text

    def _post_autenticado(self, url, payload):
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

    def listar_clientes_24ghz(self):
        soup = BeautifulSoup(self.obtener_pagina_acceso(), "html.parser")
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
            })

        return clients

    def obtener_macs_bloqueadas(self):
        soup = BeautifulSoup(self.obtener_pagina_acceso(), "html.parser")
        blocked_macs = []

        for field_name in WIRELESS_MAC_FIELDS:
            input_field = soup.find("input", {"name": field_name})
            value = input_field.get("value", "").strip() if input_field else ""

            if value:
                blocked_macs.append(normalize_mac(value))

        return blocked_macs

    def bloquear_mac(self, mac, network_index=0):
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
        time.sleep(1)

        try:
            current_macs = self.obtener_macs_bloqueadas()
        except requests.RequestException:
            return False

        return set(current_macs) == set(expected_macs)

    def obtener_config_red_invitados(self):
        payload = self._obtener_payload_red_invitados()

        return {
            "habilitada": payload.get("GuestNetworkEnable") == "1",
            "ssid": payload.get("GuestServiceSetIdentifier", ""),
            "password": payload.get("WpaPreSharedKeyGN", ""),
        }

    def activar_red_invitados(self, ssid=None, password=None, network_index=0):
        payload = self._obtener_payload_red_invitados()

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

            if self._red_invitados_fue_activada(payload):
                return True

            if isinstance(error, (Timeout, requests.ConnectionError)):
                return True

            raise

        if response.status_code not in (200, 302):
            raise RuntimeError(f"El router rechazo el cambio: HTTP {response.status_code}")

        return True

    def desactivar_red_invitados(self, network_index=0):
        payload = self._obtener_payload_red_invitados()
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

            if self._red_invitados_fue_desactivada():
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
        timeout=25,
        interval=2,
    ):
        limite = time.monotonic() + timeout
        ultima_config = None

        while time.monotonic() <= limite:
            try:
                config = self.obtener_config_red_invitados()
            except (requests.RequestException, RuntimeError):
                self._reiniciar_sesion()
                time.sleep(interval)
                continue

            ultima_config = config

            if self._config_red_invitados_coincide(config, habilitada, ssid, password):
                return config

            time.sleep(interval)

        return ultima_config

    def _obtener_payload_red_invitados(self):
        soup = BeautifulSoup(self.obtener_pagina_red_invitados(), "html.parser")
        form = soup.find("form", {"name": "wlanGuestNetwork"})

        if not form:
            raise RuntimeError("No se encontro el formulario de red de invitados.")

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

            if input_type in ("checkbox", "radio") and not field.has_attr("checked"):
                continue

            payload[name] = field.get("value", "")

        for field_name in GUEST_NETWORK_FIELDS:
            payload.setdefault(field_name, "")

        return payload

    def _valor_select(self, select_field):
        selected = select_field.find("option", selected=True)

        if selected is None:
            selected = select_field.find("option")

        return selected.get("value", "") if selected else ""

    def _red_invitados_fue_activada(self, expected_payload):
        time.sleep(1)

        try:
            current = self.obtener_config_red_invitados()
        except (requests.RequestException, RuntimeError):
            return False

        return (
            current["habilitada"]
            and current["ssid"] == expected_payload.get("GuestServiceSetIdentifier", "")
            and current["password"] == expected_payload.get("WpaPreSharedKeyGN", "")
        )

    def _red_invitados_fue_desactivada(self):
        time.sleep(1)

        try:
            current = self.obtener_config_red_invitados()
        except (requests.RequestException, RuntimeError):
            return False

        return not current["habilitada"]

    def _config_red_invitados_coincide(self, config, habilitada, ssid, password):
        if habilitada is not None and config["habilitada"] != habilitada:
            return False

        if ssid is not None and config["ssid"] != ssid:
            return False

        if password is not None and config["password"] != password:
            return False

        return True

    def _validar_ssid(self, ssid):
        if not ssid or not ssid.strip():
            raise ValueError("El SSID no puede estar vacio.")

        if len(ssid) > 32:
            raise ValueError("El SSID no puede tener mas de 32 caracteres.")

    def _validar_password_wpa(self, password):
        if len(password) < 8 or len(password) > 64:
            raise ValueError("La contrasena WPA debe tener entre 8 y 64 caracteres.")
