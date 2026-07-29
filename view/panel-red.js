/**
 * Controlador del panel web de administracion de red.
 *
 * Este script coordina navegacion entre vistas, renderizado de dispositivos,
 * consumo de la API local, configuracion de red de invitados, escaneo Nmap y
 * acciones modales para renombrar, bloquear o desbloquear equipos.
 */

// Referencias DOM usadas por las vistas principales del panel.
const navButtons = document.querySelectorAll("[data-view]");
const quickLinks = document.querySelectorAll("[data-view-link]");
const views = document.querySelectorAll(".view");
const deviceGrid = document.getElementById("deviceGrid");
const deviceNotice = document.getElementById("deviceNotice");
const deviceSearch = document.getElementById("deviceSearch");
const deviceTypeFilter = document.getElementById("deviceTypeFilter");
const refreshDevices = document.getElementById("refreshDevices");
const guestNotice = document.getElementById("guestNotice");
const guestEnabled = document.getElementById("guestEnabled");
const guestSsid = document.getElementById("guestSsid");
const guestPassword = document.getElementById("guestPassword");
const saveGuest = document.getElementById("saveGuest");
const scanNotice = document.getElementById("scanNotice");
const startScan = document.getElementById("startScan");
const parentalNotice = document.getElementById("parentalNotice");
const siteGrid = document.getElementById("siteGrid");
const siteScopeMac = document.getElementById("siteScopeMac");
const siteHardening = document.getElementById("siteHardening");
const refreshParentalSites = document.getElementById("refreshParentalSites");
const modal = document.getElementById("actionModal");
const modalTitle = document.getElementById("modalTitle");
const modalCopy = document.getElementById("modalCopy");
const renameField = document.getElementById("renameField");
const aliasInput = document.getElementById("aliasInput");
const modalConfirm = document.getElementById("modalConfirm");
const closeModalButtons = document.querySelectorAll(".modal-close, .modal-cancel");

// Datos de respaldo para mostrar una experiencia demo si no hay servidor Python.
const sampleDevices = [
  {
    mac: "0A:75:2A:6C:18:8B",
    name: "S23-FE-de-John-Steven",
    hostname: "S23-FE-de-John-Steven",
    type: "phone",
    ip: "192.168.1.29",
    rssi: "-75",
    blocked: false,
  },
  {
    mac: "E4:5E:37:C4:C1:7E",
    name: "DESKTOP-LJI5CB9",
    hostname: "DESKTOP-LJI5CB9",
    type: "pc",
    ip: "192.168.1.30",
    rssi: "-61",
    blocked: false,
  },
  {
    mac: "82:80:D5:C7:D8:A0",
    name: "43RCARokuTV",
    hostname: "43RCARokuTV",
    type: "tv",
    ip: "192.168.1.15",
    rssi: "-77",
    blocked: false,
  },
];

// Estado de cliente mantenido en memoria durante la sesion del navegador.
let devices = [];
let siteProfiles = [];
let pendingAction = null;
let guestLoaded = false;
let parentalLoaded = false;

/**
 * Activa una vista del panel y carga datos diferidos cuando corresponde.
 *
 * @param {string} viewId Identificador del `<section>` a mostrar.
 */
function showView(viewId) {
  views.forEach((view) => {
    view.classList.toggle("is-visible", view.id === viewId);
  });

  navButtons.forEach((button) => {
    button.classList.toggle("is-active", button.dataset.view === viewId);
  });

  if (viewId === "devices" && devices.length === 0) {
    loadDevices();
  }

  if (viewId === "guest" && !guestLoaded) {
    loadGuestConfig();
  }

  if (viewId === "parental" && !parentalLoaded) {
    loadSiteProfiles();
  }
}

/**
 * Escapa texto antes de insertarlo como HTML para evitar inyecciones visuales.
 *
 * @param {unknown} value Valor a convertir a texto seguro.
 * @returns {string} Texto con entidades HTML escapadas.
 */
function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

/**
 * Actualiza el aviso general de la vista de dispositivos.
 *
 * @param {string} message Texto a mostrar; si esta vacio oculta el aviso.
 * @param {string} type Variante visual: `info`, `warning` o `success`.
 */
function setNotice(message, type = "info") {
  if (!message) {
    deviceNotice.hidden = true;
    deviceNotice.textContent = "";
    return;
  }

  deviceNotice.hidden = false;
  deviceNotice.textContent = message;
  deviceNotice.className = `notice ${type}`;
}

/**
 * Actualiza un aviso asociado a una seccion especifica.
 *
 * @param {HTMLElement} element Contenedor de aviso.
 * @param {string} message Texto a mostrar; si esta vacio oculta el aviso.
 * @param {string} type Variante visual del aviso.
 */
function setBoxNotice(element, message, type = "info") {
  if (!message) {
    element.hidden = true;
    element.textContent = "";
    return;
  }

  element.hidden = false;
  element.textContent = message;
  element.className = `notice ${type}`;
}

/**
 * Traduce el tipo tecnico de dispositivo a una etiqueta de interfaz.
 *
 * @param {string} type Tipo normalizado recibido desde la API.
 * @returns {string} Etiqueta descriptiva para la tarjeta.
 */
function deviceTypeLabel(type) {
  const labels = {
    phone: "Celular conectado",
    pc: "Computadora conectada",
    tv: "Televisor conectado",
    camera: "Camara WiFi conectada",
    printer: "Impresora conectada",
    unknown: "Dispositivo conectado",
  };

  return labels[type] || labels.unknown;
}

/**
 * Describe de donde se obtuvo el dispositivo visible.
 *
 * @param {object} device Dispositivo normalizado por la API.
 * @returns {string} Etiqueta corta para la tarjeta.
 */
function deviceSourceLabel(device) {
  const network = device.network || (device.band ? `WiFi ${device.band} GHz` : "");

  if (device.source === "database") {
    return "Nmap";
  }

  if (device.source === "router+nmap") {
    return `${network || "Router"} + Nmap`;
  }

  return network || "Router";
}

/**
 * Devuelve el texto de estado de conexion segun el origen del dato.
 *
 * @param {object} device Dispositivo normalizado por la API.
 * @returns {string} Texto para tooltip de estado.
 */
function deviceStatusText(device) {
  if (device.blocked) {
    return "Bloqueado";
  }

  if (device.source === "database") {
    return "Escaneado por Nmap";
  }

  if (device.source === "router+nmap") {
    return "Conectado y detectado por Nmap";
  }

  return "Conectado";
}

/**
 * Traduce el estado de control parental a texto visible.
 *
 * @param {string} state Estado recibido desde la API.
 * @returns {string} Etiqueta corta.
 */
function siteStateLabel(state) {
  const labels = {
    blocked: "Bloqueado",
    partial: "Parcial",
    available: "Libre",
  };

  return labels[state] || labels.available;
}

/**
 * Renderiza el icono visible de un perfil, con texto de respaldo.
 *
 * @param {object} profile Perfil recibido desde la API.
 * @returns {string} Marcado HTML seguro.
 */
function siteMark(profile) {
  const theme = profile.theme || "default";
  const icon = profile.icon || "";
  const className = `site-mark site-${escapeHtml(theme)}${icon ? " has-icon" : ""}`;

  if (icon) {
    return `
      <span class="${className}">
        <img src="${escapeHtml(icon)}" alt="" aria-hidden="true" loading="lazy">
      </span>
    `;
  }

  return `<span class="${className}">${escapeHtml(profile.short)}</span>`;
}

/**
 * Renderiza una tarjeta de bloqueo para un perfil de sitio o juego.
 *
 * @param {object} profile Perfil recibido desde la API.
 * @returns {string} Marcado HTML seguro.
 */
function siteCard(profile) {
  const state = profile.state || "available";

  return `
    <article class="site-card ${state === "blocked" ? "is-blocked" : ""}">
      <div class="site-brand">
        ${siteMark(profile)}
        <div>
          <h3>${escapeHtml(profile.name)}</h3>
          <span>${escapeHtml(profile.category)}</span>
        </div>
      </div>
      <div class="site-status ${escapeHtml(state)}">
        ${escapeHtml(siteStateLabel(state))}
        <small>${escapeHtml(profile.blocked_count || 0)}/${escapeHtml(profile.domains_count || 0)} reglas</small>
      </div>
      <div class="site-actions">
        <button class="site-action block" type="button" data-site-action="block" data-profile-id="${escapeHtml(profile.id)}">
          <span aria-hidden="true"></span>
          Bloquear
        </button>
        <button class="site-action unblock" type="button" data-site-action="unblock" data-profile-id="${escapeHtml(profile.id)}">
          <span aria-hidden="true"></span>
          Desbloquear
        </button>
      </div>
    </article>
  `;
}

/**
 * Pinta la grilla de sitios y juegos del control parental.
 */
function renderSiteProfiles() {
  if (siteProfiles.length === 0) {
    siteGrid.innerHTML = `
      <article class="empty-state">
        <h3>No hay perfiles para mostrar</h3>
        <p>Actualice el control parental para volver a consultar el router.</p>
      </article>
    `;
    return;
  }

  siteGrid.innerHTML = siteProfiles.map(siteCard).join("");
}

/**
 * Devuelve el SVG usado como icono de tarjeta para un tipo de dispositivo.
 *
 * @param {string} type Tipo normalizado recibido desde la API.
 * @returns {string} Marcado SVG seguro definido por la aplicacion.
 */
function deviceIcon(type) {
  const icons = {
    phone: `
      <svg viewBox="0 0 48 48" aria-hidden="true">
        <rect x="15" y="5" width="18" height="38" rx="4"></rect>
        <path d="M21 10h6M22 37h4"></path>
      </svg>
    `,
    pc: `
      <svg viewBox="0 0 48 48" aria-hidden="true">
        <rect x="8" y="9" width="32" height="22" rx="3"></rect>
        <path d="M19 39h10M24 31v8"></path>
      </svg>
    `,
    tv: `
      <svg viewBox="0 0 48 48" aria-hidden="true">
        <rect x="7" y="12" width="34" height="24" rx="4"></rect>
        <path d="M18 42h12M19 7l5 5 5-5"></path>
      </svg>
    `,
    camera: `
      <svg viewBox="0 0 48 48" aria-hidden="true">
        <rect x="8" y="17" width="32" height="20" rx="5"></rect>
        <circle cx="24" cy="27" r="7"></circle>
        <path d="M15 17l3-6h12l3 6"></path>
      </svg>
    `,
    printer: `
      <svg viewBox="0 0 48 48" aria-hidden="true">
        <path d="M15 17V8h18v9"></path>
        <rect x="10" y="17" width="28" height="18" rx="4"></rect>
        <path d="M16 30h16v10H16zM34 23h1"></path>
      </svg>
    `,
    unknown: `
      <svg viewBox="0 0 48 48" aria-hidden="true">
        <circle cx="24" cy="24" r="16"></circle>
        <path d="M19 19a5 5 0 0 1 10 0c0 5-5 4-5 9M24 34h.01"></path>
      </svg>
    `,
  };

  return icons[type] || icons.unknown;
}

/**
 * Genera la ayuda contextual asociada a un boton de accion.
 *
 * @param {string} action Accion solicitada: `rename` o `block`.
 * @param {object} device Dispositivo sobre el que se opera.
 * @returns {string} Explicacion breve para tooltip y modal.
 */
function actionCopy(action, device) {
  if (action === "rename") {
    return "Este boton solo cambia el nombre que usted ve en este panel. No cambia el nombre real del equipo.";
  }

  if (device.blocked) {
    return "Este boton permite que el dispositivo vuelva a conectarse al WiFi.";
  }

  return "Este boton evita que este dispositivo vuelva a conectarse al WiFi. Uselo solo si no lo reconoce.";
}

/**
 * Filtra la lista local por texto de busqueda y tipo de dispositivo.
 *
 * @returns {Array<object>} Dispositivos visibles con los filtros actuales.
 */
function filteredDevices() {
  const query = deviceSearch.value.trim().toLowerCase();
  const type = deviceTypeFilter.value;

  return devices.filter((device) => {
    const matchesQuery = !query || `${device.name} ${device.hostname} ${device.ip}`.toLowerCase().includes(query);
    const matchesType = type === "Todos" || !type || device.type === type;
    return matchesQuery && matchesType;
  });
}

/**
 * Renderiza las tarjetas de dispositivos dentro de `deviceGrid`.
 */
function renderDevices() {
  const visibleDevices = filteredDevices();

  if (visibleDevices.length === 0) {
    deviceGrid.innerHTML = `
      <article class="empty-state">
        <h3>No hay dispositivos para mostrar</h3>
        <p>Pruebe actualizar, limpiar el buscador o ejecutar un escaneo Nmap.</p>
      </article>
    `;
    return;
  }

  const cards = visibleDevices.map((device) => {
    const blockLabel = device.blocked ? "Desbloquear" : "Bloquear";
    const blockClass = device.blocked ? "unblock" : "block";
    const signalClass = device.source === "database" ? "scanned" : Number.parseInt(device.rssi, 10) <= -75 ? "weak" : "";
    const statusText = deviceStatusText(device);

    return `
      <article class="device-card ${device.blocked ? "is-blocked" : ""}">
        <span class="connection-dot ${signalClass}" title="${statusText}"></span>
        <div class="device-avatar ${escapeHtml(device.type)}">
          ${deviceIcon(device.type)}
        </div>
        <h3>${escapeHtml(device.name)}</h3>
        <p>${escapeHtml(deviceTypeLabel(device.type))}</p>
        <div class="device-meta-row">
          <span class="device-meta">${escapeHtml(device.ip || "IP no disponible")}</span>
          <span class="device-meta source">${escapeHtml(deviceSourceLabel(device))}</span>
        </div>
        <div class="device-actions">
          <button class="action-button ${blockClass}" type="button" data-action="block" data-mac="${escapeHtml(device.mac)}" data-action-copy="${escapeHtml(actionCopy("block", device))}">
            ${blockLabel}
          </button>
          <button class="action-button rename" type="button" data-action="rename" data-mac="${escapeHtml(device.mac)}" data-action-copy="${escapeHtml(actionCopy("rename", device))}">
            Cambiar nombre
          </button>
        </div>
      </article>
    `;
  });

  cards.push(`
    <article class="device-card add-device">
      <div class="device-avatar add" aria-hidden="true">+</div>
      <h3>Escanear otra vez</h3>
      <p>Busca nuevos equipos conectados al WiFi.</p>
      <button class="button primary" type="button" data-view-link="scan">Ir a Nmap</button>
    </article>
  `);

  deviceGrid.innerHTML = cards.join("");
}

/**
 * Ejecuta una solicitud JSON contra la API local y normaliza errores.
 *
 * @param {string} url Ruta HTTP a consultar.
 * @param {RequestInit} options Opciones de `fetch`.
 * @returns {Promise<object>} Cuerpo JSON validado.
 */
async function apiRequest(url, options = {}) {
  const response = await fetch(url, {
    headers: {
      "Content-Type": "application/json",
      ...(options.headers || {}),
    },
    ...options,
  });
  const data = await response.json();

  if (!response.ok || data.ok === false) {
    throw new Error(data.error || "No se pudo completar la accion.");
  }

  return data;
}

/**
 * Carga dispositivos desde el router o desde el respaldo SQLite.
 */
async function loadDevices() {
  deviceGrid.innerHTML = `
    <article class="device-card skeleton">
      <div class="device-avatar"></div>
      <h3>Cargando dispositivos</h3>
      <p>Consultando WiFi 2.4/5 GHz y Nmap.</p>
    </article>
  `;

  try {
    const data = await apiRequest("/api/devices");
    devices = data.devices || [];

    if (data.source === "database") {
      setNotice("No se pudo leer el router ahora mismo. Estoy mostrando lo guardado en la base de datos.", "warning");
    } else if (Number(data.scanned_count || 0) > 0) {
      setNotice("Mostrando clientes WiFi de 2.4/5 GHz junto con dispositivos guardados por Nmap.", "success");
    } else {
      setNotice("");
    }

    renderDevices();
  } catch (error) {
    devices = sampleDevices;
    setNotice("Modo demo: abra el panel desde el servidor Python para usar funciones reales.", "warning");
    renderDevices();
  }
}

/**
 * Lee el estado actual de la red de invitados 2.4 GHz.
 */
async function loadGuestConfig() {
  setBoxNotice(guestNotice, "Leyendo configuracion de la red de invitados...");

  try {
    const data = await apiRequest("/api/guest?band=2.4");
    guestEnabled.checked = Boolean(data.guest.habilitada);
    guestSsid.value = data.guest.ssid || "";
    guestPassword.value = data.guest.password || "";
    guestLoaded = true;
    setBoxNotice(guestNotice, "");
  } catch (error) {
    setBoxNotice(guestNotice, `No se pudo leer el router: ${error.message}`, "warning");
  }
}

/**
 * Envia al servidor la configuracion visible de la red de invitados.
 */
async function updateGuestConfig() {
  saveGuest.disabled = true;
  saveGuest.textContent = "Guardando...";
  setBoxNotice(guestNotice, "Enviando cambios al router...");

  try {
    const data = await apiRequest("/api/guest", {
      method: "POST",
      body: JSON.stringify({
        band: "2.4",
        enabled: guestEnabled.checked,
        ssid: guestSsid.value,
        password: guestPassword.value,
      }),
    });
    setBoxNotice(guestNotice, data.message || "Cambios guardados.", "success");
    guestLoaded = false;
    await loadGuestConfig();
  } catch (error) {
    setBoxNotice(guestNotice, error.message, "warning");
  } finally {
    saveGuest.disabled = false;
    saveGuest.textContent = "Guardar cambios";
  }
}

/**
 * Solicita un escaneo Nmap de la subred local y actualiza la vista.
 */
async function runScan() {
  startScan.disabled = true;
  startScan.textContent = "Escaneando...";
  setBoxNotice(scanNotice, "Escaneando la red local. Esto puede tardar un poco.");

  try {
    const data = await apiRequest("/api/scan", { method: "POST" });
    devices = data.devices || [];
    setBoxNotice(scanNotice, "Escaneo terminado. Los dispositivos fueron guardados y unidos con los clientes WiFi.", "success");
    showView("devices");
    renderDevices();
  } catch (error) {
    setBoxNotice(scanNotice, error.message, "warning");
  } finally {
    startScan.disabled = false;
    startScan.textContent = "Iniciar escaneo";
  }
}

/**
 * Carga el catalogo de perfiles de control parental con su estado actual.
 */
async function loadSiteProfiles() {
  siteGrid.innerHTML = `
    <article class="site-card skeleton">
      <div class="site-brand">
        <span class="site-mark">CP</span>
        <div>
          <h3>Cargando perfiles</h3>
          <span>Control parental</span>
        </div>
      </div>
    </article>
  `;

  const mac = siteScopeMac.value.trim();
  const query = mac ? `?mac=${encodeURIComponent(mac)}` : "";

  try {
    const data = await apiRequest(`/api/parental/sites${query}`);
    siteProfiles = data.profiles || [];
    parentalLoaded = true;

    if (data.source === "catalog") {
      setBoxNotice(parentalNotice, `No se pudo leer el router: ${data.warning}`, "warning");
    } else {
      setBoxNotice(parentalNotice, "");
    }

    renderSiteProfiles();
  } catch (error) {
    siteProfiles = [];
    parentalLoaded = false;
    setBoxNotice(parentalNotice, error.message, "warning");
    renderSiteProfiles();
  }
}

/**
 * Bloquea o desbloquea un perfil de control parental.
 *
 * @param {string} profileId Identificador del perfil.
 * @param {string} action Accion solicitada: `block` o `unblock`.
 */
async function applySiteAction(profileId, action) {
  const path = action === "block" ? "/api/parental/block" : "/api/parental/unblock";
  const button = Array.from(document.querySelectorAll(`[data-site-action="${action}"]`))
    .find((element) => element.dataset.profileId === profileId);
  const originalHtml = button ? button.innerHTML : "";

  if (button) {
    button.disabled = true;
    button.textContent = action === "block" ? "Bloqueando..." : "Desbloqueando...";
  }

  setBoxNotice(parentalNotice, "Aplicando cambios en el router...");

  try {
    const data = await apiRequest(path, {
      method: "POST",
      body: JSON.stringify({
        profile_id: profileId,
        mac: siteScopeMac.value.trim(),
        hardening: siteHardening.checked,
      }),
    });
    siteProfiles = data.profiles || [];
    parentalLoaded = true;
    setBoxNotice(
      parentalNotice,
      data.warning ? `${data.message} No se pudo confirmar el estado: ${data.warning}` : data.message || "Control parental actualizado.",
      data.warning ? "warning" : "success",
    );
    renderSiteProfiles();
  } catch (error) {
    setBoxNotice(parentalNotice, error.message, "warning");
  } finally {
    if (button) {
      button.disabled = false;
      button.innerHTML = originalHtml || (action === "block" ? "Bloquear" : "Desbloquear");
    }
  }
}

/**
 * Busca en memoria un dispositivo por direccion MAC.
 *
 * @param {string} mac Direccion MAC normalizada.
 * @returns {object|undefined} Dispositivo coincidente.
 */
function getDeviceByMac(mac) {
  return devices.find((device) => device.mac === mac);
}

/**
 * Abre el modal de confirmacion para renombrar, bloquear o desbloquear.
 *
 * @param {HTMLElement} button Boton que contiene `data-action` y `data-mac`.
 */
function openActionModal(button) {
  const mac = button.dataset.mac;
  const action = button.dataset.action;
  const device = getDeviceByMac(mac);

  if (!device) {
    return;
  }

  pendingAction = { action, device };
  renameField.hidden = action !== "rename";
  aliasInput.value = device.alias || device.name || "";

  if (action === "rename") {
    modalTitle.textContent = "Cambiar nombre";
    modalCopy.textContent = "Escriba un nombre sencillo para reconocer este equipo. Se guardara en la base de datos por su direccion MAC.";
    modalConfirm.textContent = "Guardar nombre";
  } else if (device.blocked) {
    modalTitle.textContent = "Desbloquear dispositivo";
    modalCopy.textContent = "Este equipo podra volver a usar el WiFi despues de confirmar.";
    modalConfirm.textContent = "Desbloquear";
  } else {
    modalTitle.textContent = "Bloquear dispositivo";
    modalCopy.textContent = "Este equipo perdera acceso al WiFi. Confirme solo si no reconoce el dispositivo.";
    modalConfirm.textContent = "Bloquear";
  }

  modal.hidden = false;
  (action === "rename" ? aliasInput : modalConfirm).focus();
}

/**
 * Cierra el modal de accion y limpia la operacion pendiente.
 */
function closeActionModal() {
  modal.hidden = true;
  pendingAction = null;
}

/**
 * Ejecuta la accion pendiente del modal contra la API local.
 */
async function confirmAction() {
  if (!pendingAction) {
    return;
  }

  const originalConfirmText = modalConfirm.textContent;
  let successMessage = "";

  modalConfirm.disabled = true;
  modalConfirm.textContent = "Procesando...";

  try {
    const { action, device } = pendingAction;

    if (action === "rename") {
      await apiRequest("/api/devices/alias", {
        method: "POST",
        body: JSON.stringify({ mac: device.mac, alias: aliasInput.value }),
      });
      successMessage = "Nombre guardado correctamente.";
    } else {
      const path = device.blocked ? "/api/devices/unblock" : "/api/devices/block";
      await apiRequest(path, {
        method: "POST",
        body: JSON.stringify({ mac: device.mac }),
      });
      successMessage = device.blocked ? "Dispositivo desbloqueado." : "Dispositivo bloqueado.";
    }

    closeActionModal();
    await loadDevices();
    setNotice(successMessage, "success");
  } catch (error) {
    modalCopy.textContent = error.message;
  } finally {
    modalConfirm.disabled = false;
    if (!modal.hidden) {
      modalConfirm.textContent = originalConfirmText;
    }
  }
}

// Enlaces de navegacion lateral y accesos rapidos entre vistas.
navButtons.forEach((button) => {
  button.addEventListener("click", () => showView(button.dataset.view));
});

quickLinks.forEach((button) => {
  button.addEventListener("click", () => showView(button.dataset.viewLink));
});

// Delegacion global de clics para botones creados dinamicamente.
document.addEventListener("click", (event) => {
  const siteActionButton = event.target.closest("[data-site-action]");

  if (siteActionButton) {
    applySiteAction(siteActionButton.dataset.profileId, siteActionButton.dataset.siteAction);
    return;
  }

  const actionButton = event.target.closest("[data-action]");

  if (actionButton) {
    openActionModal(actionButton);
    return;
  }

  const viewLink = event.target.closest("[data-view-link]");

  if (viewLink) {
    showView(viewLink.dataset.viewLink);
  }
});

// Eventos directos de formularios y botones persistentes.
deviceSearch.addEventListener("input", renderDevices);
deviceTypeFilter.addEventListener("change", renderDevices);
refreshDevices.addEventListener("click", loadDevices);
saveGuest.addEventListener("click", updateGuestConfig);
startScan.addEventListener("click", runScan);
refreshParentalSites.addEventListener("click", loadSiteProfiles);

siteScopeMac.addEventListener("change", () => {
  parentalLoaded = false;
  loadSiteProfiles();
});

document.getElementById("scanNow").addEventListener("click", () => {
  showView("scan");
});

// Cierre de modal por botones, clic fuera del cuadro y tecla Escape.
closeModalButtons.forEach((button) => {
  button.addEventListener("click", closeActionModal);
});

modalConfirm.addEventListener("click", confirmAction);

modal.addEventListener("click", (event) => {
  if (event.target === modal) {
    closeActionModal();
  }
});

document.addEventListener("keydown", (event) => {
  if (event.key === "Escape" && !modal.hidden) {
    closeActionModal();
  }
});
