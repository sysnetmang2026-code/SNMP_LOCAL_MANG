import time

import requests
from bs4 import BeautifulSoup
from requests.auth import HTTPBasicAuth
from requests.exceptions import Timeout

from validators import is_valid_mac, normalize_mac


WIRELESS_MAC_FIELDS = [f"WirelessMac{number:02d}" for number in range(1, 21)]
BAND_URLS = {
    "2.4": "/wlan24G.asp",
    "5": "/wlan5G.asp",
}


GUEST_NETWORK_FIELDS = {
    "GuestNetworkEnable": "estado",
    "GuestServiceSetIdentifier": "ssid",
    "WpaPreSharedKeyGN": "password",
}

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

    @property
    def primary_network_url(self):
        return f"{self.router_url}/wlanPrimaryNetwork.asp"

    @property
    def primary_network_form_url(self):
        return f"{self.router_url}/goform/wlanPrimaryNetwork"

    def obtener_pagina_acceso(self):
        return self._get_autenticado(self.access_url)

    def obtener_pagina_red_invitados(self, band="2.4"):
        self.seleccionar_banda_wifi(band)
        return self._get_autenticado(self.guest_network_url)

    def obtener_pagina_red_primaria(self, band="2.4"):
        self.seleccionar_banda_wifi(band)
        return self._get_autenticado(self.primary_network_url)

    def seleccionar_banda_wifi(self, band):
        band = self._normalizar_banda(band)
        return self._get_autenticado(f"{self.router_url}{BAND_URLS[band]}")

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

    def obtener_config_red_invitados(self, band="2.4"):
        payload = self._obtener_payload_red_invitados(band=band)

        return {
            "habilitada": payload.get("GuestNetworkEnable") == "1",
            "ssid": payload.get("GuestServiceSetIdentifier", ""),
            "password": payload.get("WpaPreSharedKeyGN", ""),
        }

    def obtener_config_red_primaria(self, band="2.4"):
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
        return self._aplicar_config_red_primaria(
            ssid=ssid,
            band=band,
            network_index=network_index,
        )

    def cambiar_password_red_primaria(self, password, band="2.4", network_index=0):
        return self._aplicar_config_red_primaria(
            password=password,
            band=band,
            network_index=network_index,
        )

    def configurar_ocultar_ssid_red_primaria(self, ocultar, band="2.4", network_index=0):
        return self._aplicar_config_red_primaria(
            ocultar_ssid=ocultar,
            band=band,
            network_index=network_index,
        )

    def activar_red_primaria(self, band="2.4", network_index=0):
        return self._aplicar_config_red_primaria(
            habilitada=True,
            band=band,
            network_index=network_index,
        )

    def desactivar_red_primaria(self, band="2.4", network_index=0):
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
        return self._obtener_payload_formulario(
            self.obtener_pagina_red_invitados(band=band),
            "wlanGuestNetwork",
            "red de invitados",
        )

    def _obtener_payload_red_primaria(self, band="2.4"):
        return self._obtener_payload_formulario(
            self.obtener_pagina_red_primaria(band=band),
            "wlanPrimaryNetwork",
            "red primaria",
        )

    def _obtener_payload_formulario(self, html, form_name, nombre_formulario):
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
        selected = select_field.find("option", selected=True)

        if selected is None:
            selected = select_field.find("option")

        return selected.get("value", "") if selected else ""

    def _red_invitados_fue_activada(self, expected_payload, band):
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
        if habilitada is not None and config["habilitada"] != habilitada:
            return False

        if ssid is not None and config["ssid"] != ssid:
            return False

        if password is not None and config["password"] != password:
            return False

        return True

    def _preparar_payload_red_primaria(self, payload, network_index):
        for field_name in ("CurrentNetworks", "wlanPrimaryCurrentNetworks"):
            if field_name in payload:
                payload[field_name] = str(network_index)

        for field_name in ("MbssIndexChanged", "wlanPrimaryMbssIndexChanged"):
            if field_name in payload:
                payload[field_name] = "0"

        payload["commitwlanPrimaryNetwork"] = "1"

    def _buscar_campo(self, payload, field_names):
        for field_name in field_names:
            if field_name in payload:
                return field_name

        return None

    def _obtener_valor_campo(self, payload, field_names):
        field_name = self._buscar_campo(payload, field_names)
        return payload.get(field_name, "") if field_name else ""

    def _valor_ocultar_ssid(self, value, field_name):
        if field_name in ("BroadcastSSID", "SSIDBroadcast"):
            return value != "1"

        return value == "1"

    def _valor_para_ocultar_ssid(self, ocultar, field_name):
        if field_name in ("BroadcastSSID", "SSIDBroadcast"):
            return "0" if ocultar else "1"

        return "1" if ocultar else "0"

    def _error_campo_no_encontrado(self, etiqueta, field_names):
        campos = ", ".join(field_names)
        raise RuntimeError(
            f"No se encontro el campo de {etiqueta} en el formulario del router. "
            f"Campos esperados: {campos}."
        )

    def _normalizar_banda(self, band):
        band = str(band).strip().lower().replace("ghz", "")

        if band in ("2.4", "24", "2"):
            return "2.4"

        if band in ("5", "5.0"):
            return "5"

        raise ValueError("La banda WiFi debe ser 2.4 o 5 GHz.")

    def _validar_ssid(self, ssid):
        if not ssid or not ssid.strip():
            raise ValueError("El SSID no puede estar vacio.")

        if len(ssid) > 32:
            raise ValueError("El SSID no puede tener mas de 32 caracteres.")

    def _validar_password_wpa(self, password):
        if len(password) < 8 or len(password) > 64:
            raise ValueError("La contrasena WPA debe tener entre 8 y 64 caracteres.")
