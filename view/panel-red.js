/**
 * Controlador del panel web de administracion de red.
 *
 * Este script coordina navegacion entre vistas, renderizado de dispositivos,
 * consumo de la API local, configuracion de redes WiFi, escaneo Nmap y acciones
 * modales para renombrar, bloquear, desbloquear u olvidar equipos.
 */

// Referencias DOM usadas por las vistas principales del panel.
const navButtons = document.querySelectorAll("[data-view]");
const quickLinks = document.querySelectorAll("[data-view-link]");
const views = document.querySelectorAll(".view");
const deviceGrid = document.getElementById("deviceGrid");
const deviceNotice = document.getElementById("deviceNotice");
const deviceSearch = document.getElementById("deviceSearch");
const deviceTypeFilter = document.getElementById("deviceTypeFilter");
const deviceStatusFilter = document.getElementById("deviceStatusFilter");
const refreshDevices = document.getElementById("refreshDevices");
const reloadPanel = document.getElementById("reloadPanel");
const autoRefreshDevices = document.getElementById("autoRefreshDevices");
const deviceFreshness = document.getElementById("deviceFreshness");
const dashboardFreshness = document.getElementById("dashboardFreshness");
const metricConnected = document.getElementById("metricConnected");
const metricNewToday = document.getElementById("metricNewToday");
const metricBlocked = document.getElementById("metricBlocked");
const metricBlockedDetail = document.getElementById("metricBlockedDetail");
const metricGuestState = document.getElementById("metricGuestState");
const metricGuestSsid = document.getElementById("metricGuestSsid");
const metricSignal = document.getElementById("metricSignal");
const metricSignalDetail = document.getElementById("metricSignalDetail");
const activityList = document.getElementById("activityList");
const deviceHistory = document.getElementById("deviceHistory");
const clearDeviceHistory = document.getElementById("clearDeviceHistory");
const routerStatusCard = document.getElementById("routerStatusCard");
const routerStatusDot = document.getElementById("routerStatusDot");
const routerStatusText = document.getElementById("routerStatusText");
const routerStatusAddress = document.getElementById("routerStatusAddress");
const accessNotice = document.getElementById("accessNotice");
const accessDeviceSelect = document.getElementById("accessDeviceSelect");
const accessDeviceHelp = document.getElementById("accessDeviceHelp");
const blockSelectedUser = document.getElementById("blockSelectedUser");
const blockedUsersCount = document.getElementById("blockedUsersCount");
const blockedUsersList = document.getElementById("blockedUsersList");
const primaryNotice = document.getElementById("primaryNotice");
const primarySaveButtons = document.querySelectorAll("[data-primary-save]");
const guestNotice = document.getElementById("guestNotice");
const guestSaveButtons = document.querySelectorAll("[data-guest-save]");
const scanNotice = document.getElementById("scanNotice");
const startScan = document.getElementById("startScan");
const networkRadar = document.getElementById("networkRadar");
const radarPoints = document.getElementById("radarPoints");
const radarStatus = document.getElementById("radarStatus");
const radarCount = document.getElementById("radarCount");
const scanRange = document.getElementById("scanRange");
const scanState = document.getElementById("scanState");
const scanDeviceCount = document.getElementById("scanDeviceCount");
const scanProgress = document.getElementById("scanProgress");
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

// Estado de cliente mantenido en memoria durante la sesion del navegador.
let devices = [];
let deviceHistoryItems = [];
let blockedMacs = [];
let siteProfiles = [];
let guestConfigs = {};
let pendingAction = null;
let primaryLoaded = false;
let guestLoaded = false;
let parentalLoaded = false;
let devicesLoading = false;
let autoRefreshEnabled = true;
let deviceRefreshTimer = null;
let lastDevicePayload = null;
let hasBlockedSnapshot = false;
let radarRevealTimer = null;
let accessStateOverrides = new Map();

const DEVICE_REFRESH_INTERVAL_MS = 10000;
const ACCESS_OVERRIDE_TTL_MS = 30000;
const WIFI_BANDS = [
  { value: "2.4", label: "2.4 GHz", shortLabel: "2.4" },
  { value: "5", label: "5 GHz", shortLabel: "5" },
];

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

  if (viewId === "access") {
    renderAccessControls();
  }

  if (viewId === "wifi" && !primaryLoaded) {
    loadPrimaryConfigs();
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
 * Convierte fechas ISO de la API a una lectura corta local.
 *
 * @param {string} value Fecha ISO.
 * @returns {string} Fecha visible o texto de respaldo.
 */
function formatTimestamp(value) {
  if (!value) {
    return "sin registro";
  }

  const date = new Date(value);

  if (Number.isNaN(date.getTime())) {
    return value;
  }

  return new Intl.DateTimeFormat("es-NI", {
    dateStyle: "short",
    timeStyle: "short",
  }).format(date);
}

/**
 * Indica si una fecha ISO pertenece al dia local actual.
 *
 * @param {string} value Fecha ISO.
 * @returns {boolean} Verdadero si ocurre hoy.
 */
function isToday(value) {
  if (!value) {
    return false;
  }

  const date = new Date(value);
  const now = new Date();

  return (
    !Number.isNaN(date.getTime())
    && date.getFullYear() === now.getFullYear()
    && date.getMonth() === now.getMonth()
    && date.getDate() === now.getDate()
  );
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
    phone: "Celular",
    pc: "Computadora",
    tv: "Televisor",
    camera: "Camara WiFi",
    printer: "Impresora",
    unknown: "Dispositivo",
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

  if (device.source && device.source.includes("+ping")) {
    return "Activo por ping";
  }

  if (device.source === "database") {
    return device.connected ? "Escaneo local + ping" : "Historial local";
  }

  if (device.source === "history") {
    return "Historial";
  }

  if (device.source === "router+nmap") {
    return `${network || "Router"} + escaneo`;
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

  if (device.connected && device.source && device.source.includes("+ping")) {
    return "Activo por ping local";
  }

  if (device.connected && device.source === "database") {
    return "Activo por escaneo/ping";
  }

  if (device.connected && device.source === "router+nmap") {
    return "Conectado y detectado por el escaneo";
  }

  if (device.connected) {
    return `Conectado${device.network ? ` en ${device.network}` : ""}`;
  }

  return `Desconectado. Ultima vez: ${formatTimestamp(device.last_seen)}`;
}

/**
 * Convierte el RSSI del router en un estado comprensible sin mostrar decibeles.
 *
 * @param {object} device Dispositivo recibido desde la API.
 * @returns {{key: string, label: string, level: number, measured: boolean}}
 */
function deviceSignal(device) {
  if (!device.connected) {
    return { key: "offline", label: "Sin conexion", level: 0, measured: false };
  }

  const rawRssi = String(device.rssi ?? "").replace(",", ".");
  const rssi = Number.parseFloat(rawRssi);

  if (!Number.isFinite(rssi) || rssi >= 0) {
    return { key: "unknown", label: "Sin medicion", level: 0, measured: false };
  }

  if (rssi >= -55) {
    return { key: "very-good", label: "Muy buena", level: 4, measured: true };
  }

  if (rssi >= -67) {
    return { key: "good", label: "Buena", level: 3, measured: true };
  }

  if (rssi >= -75) {
    return { key: "low", label: "Baja", level: 2, measured: true };
  }

  return { key: "very-low", label: "Muy mala", level: 1, measured: true };
}

/**
 * Dibuja un icono WiFi cuyas ondas activas dependen del nivel recibido.
 *
 * @param {{key: string, label: string, level: number}} signal Estado cualitativo.
 * @returns {string} Marcado controlado por la aplicacion.
 */
function wifiSignalIcon(signal) {
  return `
    <svg class="wifi-signal-icon level-${signal.level} ${signal.key}" viewBox="0 0 24 24" aria-hidden="true">
      <path class="wifi-wave wave-4" d="M2 8.8a15.4 15.4 0 0 1 20 0"></path>
      <path class="wifi-wave wave-3" d="M5.2 12.1a10.5 10.5 0 0 1 13.6 0"></path>
      <path class="wifi-wave wave-2" d="M8.4 15.4a5.6 5.6 0 0 1 7.2 0"></path>
      <circle class="wifi-wave wave-1" cx="12" cy="19" r="1.25"></circle>
    </svg>
  `;
}

/**
 * Devuelve la senal medida mas baja entre los dispositivos conectados.
 *
 * @returns {{key: string, label: string, level: number, measured: boolean}}
 */
function dashboardSignal() {
  const measured = devices
    .filter((device) => device.connected)
    .map(deviceSignal)
    .filter((signal) => signal.measured)
    .sort((left, right) => left.level - right.level);

  if (measured.length > 0) {
    return measured[0];
  }

  return {
    key: "unknown",
    label: "Sin medicion",
    level: 0,
    measured: false,
  };
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

  if (action === "forget") {
    return "Borra el nombre guardado y el historial local de este equipo. Si sigue conectado, volvera a aparecer.";
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
  const status = deviceStatusFilter.value;

  return devices.filter((device) => {
    const haystack = `${device.name} ${device.hostname} ${device.ip} ${device.mac} ${device.network}`.toLowerCase();
    const matchesQuery = !query || haystack.includes(query);
    const matchesType = type === "Todos" || !type || device.type === type;
    const deviceStatus = device.blocked ? "blocked" : device.connected ? "connected" : "offline";
    const matchesStatus = status === "all" || !status || deviceStatus === status;
    return matchesQuery && matchesType && matchesStatus;
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
        <p>Pruebe actualizar, limpiar el buscador o escanear su red.</p>
      </article>
    `;
    return;
  }

  const cards = visibleDevices.map((device) => {
    const blockLabel = device.blocked ? "Desbloquear" : "Bloquear";
    const blockClass = device.blocked ? "unblock" : "block";
    const signal = deviceSignal(device);
    const statusText = deviceStatusText(device);
    const cardState = `${device.blocked ? "is-blocked" : ""} ${!device.connected ? "is-offline" : ""}`.trim();

    return `
      <article class="device-card ${cardState}">
        <div class="device-signal ${signal.key}" title="Senal WiFi: ${escapeHtml(signal.label)}">
          ${wifiSignalIcon(signal)}
          <span>${escapeHtml(signal.label)}</span>
        </div>
        <div class="device-avatar ${escapeHtml(device.type)}">
          ${deviceIcon(device.type)}
        </div>
        <h3>${escapeHtml(device.name)}</h3>
        <p>${escapeHtml(deviceTypeLabel(device.type))}</p>
        <span class="device-status-line ${device.connected ? "online" : "offline"}">${escapeHtml(statusText)}</span>
        <div class="device-meta-row">
          <span class="device-meta">${escapeHtml(device.ip || "IP no disponible")}</span>
          <span class="device-meta source">${escapeHtml(deviceSourceLabel(device))}</span>
          <span class="device-meta seen">Visto: ${escapeHtml(formatTimestamp(device.last_seen))}</span>
        </div>
        <div class="device-actions">
          <button class="action-button ${blockClass}" type="button" data-action="block" data-mac="${escapeHtml(device.mac)}" data-action-copy="${escapeHtml(actionCopy("block", device))}">
            ${blockLabel}
          </button>
          <button class="action-button rename" type="button" data-action="rename" data-mac="${escapeHtml(device.mac)}" data-action-copy="${escapeHtml(actionCopy("rename", device))}">
            Cambiar nombre
          </button>
          <button class="action-button forget" type="button" data-action="forget" data-mac="${escapeHtml(device.mac)}" data-device-name="${escapeHtml(device.name)}" data-action-copy="${escapeHtml(actionCopy("forget", device))}">
            Olvidar
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
      <button class="button primary" type="button" data-view-link="scan">Escanear red</button>
    </article>
  `);

  deviceGrid.innerHTML = cards.join("");
}

/**
 * Devuelve un nombre breve para la vista de bloqueo.
 * Solo usa la IP cuando el router no entrego un nombre reconocible.
 *
 * @param {object} device Dispositivo conocido.
 * @returns {string} Nombre o IP de respaldo.
 */
function accessDeviceName(device) {
  const hostname = String(device.hostname || "").trim();
  const hasHostname = hostname && hostname.toLowerCase() !== "desconocido";

  if (device.alias) {
    return device.alias;
  }

  if (hasHostname) {
    return hostname;
  }

  return device.ip || "Dispositivo desconocido";
}

/**
 * Renderiza la seleccion y la lista real de usuarios bloqueados.
 */
function renderAccessControls() {
  if (!accessDeviceSelect || !blockedUsersList) {
    return;
  }

  const previousSelection = accessDeviceSelect.value;
  const blockedSet = new Set(blockedMacs.map(canonicalMac));
  const selectable = devices
    .filter((device) => device.mac && !blockedSet.has(canonicalMac(device.mac)))
    .sort((left, right) => (
      Number(right.connected) - Number(left.connected)
      || String(left.name || left.mac).localeCompare(String(right.name || right.mac))
    ));

  if (selectable.length === 0) {
    accessDeviceSelect.innerHTML = `<option value="">No hay usuarios disponibles</option>`;
    accessDeviceSelect.disabled = true;
    blockSelectedUser.disabled = true;
    accessDeviceHelp.textContent = devices.length === 0
      ? "Todavia no hay datos reales de dispositivos."
      : "Todos los usuarios conocidos ya estan bloqueados.";
  } else {
    accessDeviceSelect.disabled = false;
    blockSelectedUser.disabled = false;
    accessDeviceSelect.innerHTML = selectable.map((device) => {
      return `<option value="${escapeHtml(device.mac)}">${escapeHtml(accessDeviceName(device))}</option>`;
    }).join("");

    if (selectable.some((device) => device.mac === previousSelection)) {
      accessDeviceSelect.value = previousSelection;
    }

    accessDeviceHelp.textContent = "El bloqueo se aplica a las redes WiFi administradas por el router.";
  }

  const blockedDevices = [...blockedSet].map((mac) => {
    const known = getDeviceByMac(mac);
    return known || {
      mac,
      name: "Dispositivo desconocido",
      blocked: true,
    };
  });

  blockedUsersCount.textContent = `${blockedDevices.length} ${blockedDevices.length === 1 ? "bloqueado" : "bloqueados"}`;

  if (blockedDevices.length === 0) {
    blockedUsersList.innerHTML = `<li class="blocked-empty">No hay usuarios bloqueados.</li>`;
    return;
  }

  blockedUsersList.innerHTML = blockedDevices.map((device) => `
    <li>
      <div class="blocked-user">
        <strong>${escapeHtml(accessDeviceName(device))}</strong>
      </div>
      <button type="button" data-action="unblock" data-mac="${escapeHtml(device.mac)}" data-device-name="${escapeHtml(accessDeviceName(device))}">
        Desbloquear
      </button>
    </li>
  `).join("");
}

/**
 * Abre la confirmacion para el usuario seleccionado en la vista de bloqueo.
 */
function blockSelectedAccessUser() {
  const mac = accessDeviceSelect.value;

  if (!mac) {
    setBoxNotice(accessNotice, "Seleccione un usuario para bloquear.", "warning");
    return;
  }

  setBoxNotice(accessNotice, "");
  openActionModal({
    dataset: {
      action: "block",
      mac,
      deviceName: accessDeviceName(getDeviceByMac(mac) || {}),
    },
  });
}

/**
 * Devuelve una MAC en una forma estable para comparar listas del router y UI.
 *
 * @param {string} mac Direccion MAC recibida.
 * @returns {string} MAC normalizada para comparacion.
 */
function canonicalMac(mac) {
  return String(mac || "").trim().toUpperCase();
}

/**
 * Sincroniza el ultimo snapshot de dispositivos con la lista bloqueada local.
 */
function syncBlockedSnapshot() {
  if (lastDevicePayload) {
    lastDevicePayload = {
      ...lastDevicePayload,
      blocked_macs: [...blockedMacs],
      blocked_macs_available: true,
    };
  }

  hasBlockedSnapshot = true;
}

/**
 * Cambia el estado local de bloqueo de una MAC sin esperar otra lectura.
 *
 * @param {string} mac Direccion MAC a actualizar.
 * @param {boolean} blocked Estado deseado.
 */
function setBlockedMacInState(mac, blocked) {
  const normalizedMac = canonicalMac(mac);

  if (!normalizedMac) {
    return;
  }

  const remaining = blockedMacs.filter((blockedMac) => (
    canonicalMac(blockedMac) !== normalizedMac
  ));
  blockedMacs = blocked ? [...remaining, normalizedMac] : remaining;
  devices = devices.map((device) => (
    canonicalMac(device.mac) === normalizedMac
      ? { ...device, blocked }
      : device
  ));

  syncBlockedSnapshot();
}

/**
 * Elimina confirmaciones locales vencidas para no ocultar errores permanentes.
 */
function pruneAccessOverrides() {
  const now = Date.now();

  accessStateOverrides.forEach((override, mac) => {
    if (override.expiresAt <= now) {
      accessStateOverrides.delete(mac);
    }
  });
}

/**
 * Reaplica cambios confirmados localmente sobre lecturas del router que llegan tarde.
 */
function applyAccessOverridesToState() {
  pruneAccessOverrides();

  accessStateOverrides.forEach((override, mac) => {
    setBlockedMacInState(mac, override.blocked);
  });
}

/**
 * Pinta inmediatamente un bloqueo o desbloqueo confirmado por la API.
 *
 * @param {string} mac Direccion MAC devuelta por el servidor.
 * @param {boolean} blocked Estado final esperado.
 */
function setLocalAccessState(mac, blocked) {
  const normalizedMac = canonicalMac(mac);

  if (!normalizedMac) {
    return;
  }

  accessStateOverrides.set(normalizedMac, {
    blocked,
    expiresAt: Date.now() + ACCESS_OVERRIDE_TTL_MS,
  });
  setBlockedMacInState(normalizedMac, blocked);
  renderDevices();
  updateDashboard(lastDevicePayload || {});
}

/**
 * Genera una semilla estable para ubicar cada usuario dentro del radar.
 *
 * @param {string} value Identificador del dispositivo.
 * @returns {number} Entero positivo estable.
 */
function radarHash(value) {
  return Array.from(String(value || "device")).reduce(
    (hash, character) => ((hash * 31) + character.charCodeAt(0)) >>> 0,
    7,
  );
}

/**
 * Calcula una posicion dentro del circulo del radar.
 *
 * @param {object} device Dispositivo visible.
 * @param {number} index Posicion en la lista.
 * @returns {{x: number, y: number, delay: number}}
 */
function radarPosition(device, index) {
  const seed = radarHash(device.mac || device.ip || device.name || index);
  const angle = ((seed % 360) * Math.PI) / 180;
  const radius = 16 + ((seed >>> 8) % 20);

  return {
    x: 50 + (Math.cos(angle) * radius),
    y: 50 + (Math.sin(angle) * radius),
    delay: Math.min(index * 90, 900),
  };
}

/**
 * Pinta puntos reales para los dispositivos encontrados.
 *
 * @param {Array<object>} sourceDevices Dispositivos a representar.
 */
function renderRadarDots(sourceDevices) {
  if (!radarPoints) {
    return;
  }

  const unique = [];
  const seen = new Set();

  sourceDevices.forEach((device) => {
    const key = device.mac || device.ip;

    if (!key || seen.has(key)) {
      return;
    }

    seen.add(key);
    unique.push(device);
  });

  radarPoints.innerHTML = unique.slice(0, 36).map((device, index) => {
    const position = radarPosition(device, index);
    const label = accessDeviceName(device);
    const state = device.connected === false ? "is-offline" : "";

    return `
      <button
        type="button"
        class="radar-point ${state}"
        style="--radar-x: ${position.x.toFixed(2)}%; --radar-y: ${position.y.toFixed(2)}%; --radar-delay: ${position.delay}ms"
        aria-label="${escapeHtml(label)}"
        aria-pressed="false"
      >
        <span class="radar-tooltip">${escapeHtml(label)}</span>
      </button>
    `;
  }).join("");
}

/**
 * Sincroniza el radar en reposo con la ultima lectura real.
 *
 * @param {object} data Respuesta mas reciente de dispositivos.
 */
function syncRadar(data = {}) {
  if (!networkRadar || networkRadar.classList.contains("is-scanning")) {
    return;
  }

  const activeDevices = devices.filter((device) => device.connected);
  renderRadarDots(activeDevices);
  scanRange.textContent = data.subnet || lastDevicePayload?.subnet || "Red local";
  scanDeviceCount.textContent = activeDevices.length;
  scanState.textContent = "Lectura activa";
  radarStatus.textContent = activeDevices.length > 0
    ? "Dispositivos visibles en la red"
    : "Listo para buscar dispositivos";
  radarCount.textContent = activeDevices.length === 1
    ? "1 usuario visible."
    : `${activeDevices.length} usuarios visibles.`;
}

/**
 * Inicia el barrido y revela gradualmente los usuarios ya visibles.
 */
function startRadarScan() {
  window.clearInterval(radarRevealTimer);
  networkRadar.classList.add("is-scanning");
  scanProgress.hidden = false;
  scanState.textContent = "Escaneando";
  scanDeviceCount.textContent = "0";
  radarStatus.textContent = "Buscando dispositivos en la red";
  radarCount.textContent = "Cada punto representa un usuario detectado.";
  radarPoints.innerHTML = "";

  const visibleQueue = devices.filter((device) => device.connected);
  let revealed = 0;

  radarRevealTimer = window.setInterval(() => {
    if (revealed >= visibleQueue.length) {
      return;
    }

    revealed += 1;
    renderRadarDots(visibleQueue.slice(0, revealed));
    scanDeviceCount.textContent = revealed;
  }, 650);
}

/**
 * Detiene el barrido y deja visibles los resultados reales del escaneo.
 *
 * @param {object} data Respuesta de la API.
 */
function finishRadarScan(data) {
  window.clearInterval(radarRevealTimer);
  networkRadar.classList.remove("is-scanning");
  scanProgress.hidden = true;

  const scannedDevices = Array.isArray(data.scan_devices) && data.scan_devices.length > 0
    ? data.scan_devices
    : (data.devices || []).filter((device) => device.connected);

  renderRadarDots(scannedDevices);
  scanRange.textContent = data.subnet || "Red local";
  scanState.textContent = "Completado";
  scanDeviceCount.textContent = scannedDevices.length;
  radarStatus.textContent = "Busqueda completada";
  radarCount.textContent = scannedDevices.length === 1
    ? "1 usuario encontrado."
    : `${scannedDevices.length} usuarios encontrados.`;
}

/**
 * Detiene la animacion cuando el escaneo no logra completarse.
 */
function failRadarScan() {
  window.clearInterval(radarRevealTimer);
  networkRadar.classList.remove("is-scanning");
  scanProgress.hidden = true;
  scanState.textContent = "No completado";
  radarStatus.textContent = "No se pudo terminar la busqueda";
  radarCount.textContent = "Los puntos conservan la ultima lectura real.";
}

/**
 * Traduce eventos de presencia a texto visible.
 *
 * @param {string} event Tipo de evento guardado.
 * @returns {string} Etiqueta para historial.
 */
function eventLabel(event) {
  const labels = {
    connected: "Se conecto",
    disconnected: "Se desconecto",
    moved: "Cambio de red",
  };

  return labels[event] || "Actividad";
}

/**
 * Devuelve clase visual para un evento de presencia.
 *
 * @param {string} event Tipo de evento guardado.
 * @returns {string} Clase CSS corta.
 */
function eventClass(event) {
  if (event === "connected") {
    return "success";
  }

  if (event === "disconnected") {
    return "danger";
  }

  return "";
}

/**
 * Obtiene el nombre visible de un evento historico.
 *
 * @param {object} item Evento recibido desde la API.
 * @returns {string} Nombre para mostrar.
 */
function historyDeviceName(item) {
  return item.alias || item.hostname || item.mac || "Dispositivo";
}

/**
 * Renderiza la lista de eventos recientes debajo de los dispositivos.
 */
function renderDeviceHistory() {
  if (!deviceHistory) {
    return;
  }

  if (deviceHistoryItems.length === 0) {
    deviceHistory.innerHTML = `<li class="history-empty">Sin eventos recientes.</li>`;
    return;
  }

  deviceHistory.innerHTML = deviceHistoryItems.map((item) => {
    const name = historyDeviceName(item);
    const detail = item.detail || item.network || item.ip || item.mac;

    return `
      <li>
        <span class="history-dot ${eventClass(item.event)}" aria-hidden="true"></span>
        <div>
          <strong>${escapeHtml(eventLabel(item.event))}: ${escapeHtml(name)}</strong>
          <p>${escapeHtml(detail || "Sin detalle")} - ${escapeHtml(formatTimestamp(item.created_at))}</p>
        </div>
        <button class="history-forget" type="button" data-action="forget" data-mac="${escapeHtml(item.mac)}" data-device-name="${escapeHtml(name)}">
          Olvidar
        </button>
      </li>
    `;
  }).join("");
}

/**
 * Pinta actividad reciente en el dashboard con los mismos eventos historicos.
 */
function renderDashboardActivity() {
  if (!activityList) {
    return;
  }

  const recent = deviceHistoryItems.slice(0, 5);

  if (recent.length === 0) {
    activityList.innerHTML = `
      <li>
        <span class="activity-dot"></span>
        <div>
          <strong>Sin actividad reciente</strong>
          <p>La siguiente lectura registrara conexiones o desconexiones.</p>
        </div>
      </li>
    `;
    return;
  }

  activityList.innerHTML = recent.map((item) => `
    <li>
      <span class="activity-dot ${eventClass(item.event)}"></span>
      <div>
        <strong>${escapeHtml(eventLabel(item.event))}: ${escapeHtml(historyDeviceName(item))}</strong>
        <p>${escapeHtml(item.network || item.ip || item.mac)} - ${escapeHtml(formatTimestamp(item.created_at))}</p>
      </div>
    </li>
  `).join("");
}

/**
 * Actualiza las metricas superiores a partir de dispositivos e historial.
 *
 * @param {object} data Respuesta de `/api/devices`.
 */
function updateDashboard(data = {}) {
  const currentData = Object.keys(data).length > 0 ? data : lastDevicePayload || {};
  const activeCount = Number(currentData.active_count ?? devices.filter((device) => device.connected).length);
  const blockedCount = blockedMacs.length;
  const signal = dashboardSignal();
  const newToday = new Set(deviceHistoryItems.filter((item) => (
    item.event === "connected" && isToday(item.created_at)
  )).map((item) => item.mac)).size;
  const nowText = `Ultima lectura: ${formatTimestamp(new Date().toISOString())}`;
  const routerReachable = currentData.router_reachable === true;

  if (metricConnected) {
    metricConnected.textContent = activeCount;
  }

  if (metricNewToday) {
    metricNewToday.textContent = `${newToday} nuevos hoy`;
  }

  if (metricBlocked) {
    metricBlocked.textContent = hasBlockedSnapshot ? blockedCount : "--";
  }

  if (metricBlockedDetail) {
    metricBlockedDetail.textContent = !hasBlockedSnapshot
      ? "Router no disponible"
      : currentData.blocked_macs_available === false
        ? "Ultima lista confirmada"
        : blockedCount === 0
          ? "Ningun bloqueo activo"
          : "Lista actual del router";
  }

  if (metricSignal) {
    metricSignal.className = `signal-summary ${signal.key}`;
    metricSignal.innerHTML = `${wifiSignalIcon(signal)}<span>${escapeHtml(signal.label)}</span>`;
  }

  if (metricSignalDetail) {
    metricSignalDetail.textContent = signal.measured
      ? "Estado mas bajo entre los equipos activos"
      : activeCount > 0
        ? "El router no reporto intensidad"
        : "No hay equipos WiFi activos";
  }

  if (dashboardFreshness) {
    dashboardFreshness.textContent = nowText;
  }

  if (deviceFreshness) {
    deviceFreshness.textContent = `${nowText} - auto ${autoRefreshEnabled ? "activo" : "pausado"}`;
  }

  if (routerStatusText && routerStatusAddress) {
    routerStatusText.textContent = routerReachable ? "Router conectado" : "Router sin respuesta";
    routerStatusAddress.textContent = routerReachable
      ? currentData.warning ? "Lectura parcial disponible" : "Lectura en vivo"
      : "Datos locales disponibles";
    routerStatusCard.classList.toggle("is-offline", !routerReachable);
    routerStatusDot.classList.toggle("is-offline", !routerReachable);
  }

  renderDashboardActivity();
  renderAccessControls();
  syncRadar(currentData);
}

/**
 * Programa la siguiente lectura automatica de dispositivos.
 */
function scheduleDeviceRefresh() {
  window.clearTimeout(deviceRefreshTimer);

  if (!autoRefreshEnabled) {
    return;
  }

  deviceRefreshTimer = window.setTimeout(() => {
    if (document.hidden) {
      scheduleDeviceRefresh();
      return;
    }

    loadDevices({ silent: true });
  }, DEVICE_REFRESH_INTERVAL_MS);
}

/**
 * Activa o pausa la actualizacion periodica del panel.
 */
function toggleAutoRefresh() {
  autoRefreshEnabled = !autoRefreshEnabled;
  autoRefreshDevices.textContent = autoRefreshEnabled ? "Auto: activo" : "Auto: pausado";
  updateDashboard();
  scheduleDeviceRefresh();
}

/**
 * Recarga el panel local desde un boton visible tambien en pantallas tactiles.
 */
function reloadPanelPage() {
  if (reloadPanel) {
    reloadPanel.disabled = true;
    reloadPanel.textContent = "Reiniciando...";
  }

  window.location.reload();
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
async function loadDevices(options = {}) {
  const silent = Boolean(options.silent);

  if (devicesLoading) {
    return;
  }

  devicesLoading = true;

  if (!silent) {
    deviceGrid.innerHTML = `
      <article class="device-card skeleton">
        <div class="device-avatar"></div>
        <h3>Cargando dispositivos</h3>
        <p>Consultando WiFi 2.4/5 GHz, escaneo local y ping.</p>
      </article>
    `;
  }

  try {
    const data = await apiRequest("/api/devices");
    devices = data.devices || [];
    deviceHistoryItems = data.history || [];

    if (data.blocked_macs_available !== false) {
      blockedMacs = data.blocked_macs || [];
      hasBlockedSnapshot = true;
    }

    lastDevicePayload = data;
    applyAccessOverridesToState();

    if (!data.router_reachable) {
      setNotice("No se pudo leer el router ahora mismo. Estoy mostrando historial local y equipos que respondan ping.", "warning");
    } else if (data.warning) {
      setNotice(`Lectura parcial: ${data.warning}`, "warning");
    } else if (Number(data.scanned_count || 0) > 0) {
      setNotice("Datos reales actualizados: redes 2.4/5 GHz, invitados, ping local e historial de red.", "success");
    } else {
      setNotice("");
    }

    renderDevices();
    renderDeviceHistory();
    updateDashboard(data);
  } catch (error) {
    setNotice(`No se pudo actualizar: ${error.message}. Se conservan los ultimos datos reales disponibles.`, "warning");

    if (devices.length === 0) {
      deviceGrid.innerHTML = `
        <article class="empty-state">
          <h3>No hay una lectura real disponible</h3>
          <p>Revise que el servidor local este activo y vuelva a actualizar.</p>
        </article>
      `;
      metricConnected.textContent = "--";
      metricBlocked.textContent = "--";
      metricNewToday.textContent = "Sin datos recientes";
      metricSignal.className = "signal-summary unknown";
      metricSignal.innerHTML = `${wifiSignalIcon({ key: "unknown", level: 0 })}<span>Sin medicion</span>`;
      metricSignalDetail.textContent = "No se pudo consultar la red";
    }

    dashboardFreshness.textContent = "Ultima lectura: fallo la actualizacion";
    deviceFreshness.textContent = `Actualizacion fallida - auto ${autoRefreshEnabled ? "activo" : "pausado"}`;
    routerStatusText.textContent = "Router sin confirmar";
    routerStatusAddress.textContent = "Sin lectura reciente";
    routerStatusCard.classList.add("is-offline");
    routerStatusDot.classList.add("is-offline");
    renderAccessControls();
  } finally {
    devicesLoading = false;
    scheduleDeviceRefresh();
  }
}

/**
 * Limpia los eventos historicos sin borrar dispositivos conocidos.
 */
async function clearHistory() {
  clearDeviceHistory.disabled = true;
  clearDeviceHistory.textContent = "Borrando...";

  try {
    const data = await apiRequest("/api/devices/history/clear", { method: "POST" });
    deviceHistoryItems = [];
    renderDeviceHistory();
    updateDashboard();
    setNotice(data.message || "Historial borrado.", "success");
  } catch (error) {
    setNotice(error.message, "warning");
  } finally {
    clearDeviceHistory.disabled = false;
    clearDeviceHistory.textContent = "Limpiar historial";
  }
}

/**
 * Devuelve los metadatos visibles de una banda WiFi.
 *
 * @param {string} band Banda tecnica recibida por API.
 * @returns {{value: string, label: string, shortLabel: string}}
 */
function wifiBandMeta(band) {
  return WIFI_BANDS.find((item) => item.value === String(band)) || {
    value: String(band),
    label: `${band} GHz`,
    shortLabel: String(band),
  };
}

/**
 * Obtiene los controles asociados a una tarjeta de red por banda.
 *
 * @param {string} kind Tipo de tarjeta: `primary` o `guest`.
 * @param {string} band Banda WiFi.
 * @returns {object} Referencias DOM de la tarjeta.
 */
function wifiBandControls(kind, band) {
  const panel = document.querySelector(`[data-${kind}-band="${band}"]`);

  if (!panel) {
    return {};
  }

  return {
    panel,
    enabled: panel.querySelector(`[data-${kind}-field="enabled"]`),
    hidden: panel.querySelector(`[data-${kind}-field="hidden"]`),
    maxClients: panel.querySelector(`[data-${kind}-field="maxClients"]`),
    ssid: panel.querySelector(`[data-${kind}-field="ssid"]`),
    password: panel.querySelector(`[data-${kind}-field="password"]`),
    save: panel.querySelector(`[data-${kind}-save]`),
    state: panel.querySelector(`[data-${kind}-state]`),
  };
}

/**
 * Cambia el texto y bloqueo temporal de un boton de guardado.
 *
 * @param {HTMLButtonElement} button Boton a actualizar.
 * @param {boolean} saving Verdadero mientras hay una solicitud en curso.
 * @param {string} savingText Texto temporal.
 */
function setSavingButton(button, saving, savingText = "Guardando...") {
  if (!button) {
    return;
  }

  if (!button.dataset.defaultText) {
    button.dataset.defaultText = button.textContent;
  }

  button.disabled = saving;
  button.textContent = saving ? savingText : button.dataset.defaultText;
}

/**
 * Devuelve el limite de clientes listo para enviar, o `null` si no aplica.
 *
 * @param {HTMLInputElement} input Campo numerico de limite.
 * @returns {number|null} Valor normalizado.
 */
function normalizedClientLimit(input) {
  if (!input || input.disabled || input.value === "") {
    return null;
  }

  const min = Number(input.min || 0);
  const max = Number(input.max || 20);
  const value = Math.trunc(Number(input.value));

  if (!Number.isFinite(value)) {
    return null;
  }

  const normalized = Math.min(max, Math.max(min, value));
  input.value = normalized;
  return normalized;
}

/**
 * Sincroniza un control de limite de usuarios con soporte reportado por API.
 *
 * @param {HTMLInputElement} input Campo numerico.
 * @param {object} config Configuracion recibida desde el router.
 */
function populateClientLimit(input, config = {}) {
  if (!input) {
    return;
  }

  const supported = config.limite_clientes_soportado !== false;
  const max = Number(config.limite_clientes_max || input.max || 20);
  input.min = "0";
  input.max = String(max);
  input.disabled = !supported;
  input.value = config.limite_clientes === null || config.limite_clientes === undefined
    ? ""
    : String(config.limite_clientes);
  input.closest("label")?.classList.toggle("is-disabled", !supported);
}

/**
 * Muestra u oculta el contenido de un campo de contrasena.
 *
 * @param {HTMLButtonElement} button Boton de ojo.
 */
function togglePasswordVisibility(button) {
  const input = button.closest(".password-field")?.querySelector("input");

  if (!input) {
    return;
  }

  const visible = input.type === "password";
  input.type = visible ? "text" : "password";
  button.classList.toggle("is-visible", visible);
  button.setAttribute("aria-label", visible ? "Ocultar contrasena" : "Mostrar contrasena");
  button.title = visible ? "Ocultar contrasena" : "Mostrar contrasena";
}

/**
 * Pinta el estado de una red primaria en su tarjeta.
 *
 * @param {HTMLElement} badge Indicador visual.
 * @param {object} config Configuracion recibida desde el router.
 */
function updatePrimaryBadge(badge, config = {}) {
  if (!badge) {
    return;
  }

  if (config.habilitada === true) {
    badge.textContent = "Activa";
    badge.className = "badge success";
    return;
  }

  if (config.habilitada === false) {
    badge.textContent = "Inactiva";
    badge.className = "badge warning";
    return;
  }

  badge.textContent = "Sin estado";
  badge.className = "badge warning";
}

/**
 * Copia los valores del router a una tarjeta de red primaria.
 *
 * @param {string} band Banda WiFi.
 * @param {object} primary Configuracion de red primaria.
 */
function populatePrimaryControls(band, primary = {}) {
  const controls = wifiBandControls("primary", band);

  if (controls.ssid) {
    controls.ssid.value = primary.ssid || "";
  }

  if (controls.password) {
    controls.password.value = primary.password || "";
  }

  if (controls.hidden) {
    const supported = primary.oculto !== null && primary.oculto !== undefined;
    controls.hidden.checked = Boolean(primary.oculto);
    controls.hidden.disabled = !supported;
    controls.hidden.closest("label")?.classList.toggle("is-disabled", !supported);
  }

  populateClientLimit(controls.maxClients, primary);
  updatePrimaryBadge(controls.state, primary);
}

/**
 * Copia los valores del router a una tarjeta de red de invitados.
 *
 * @param {string} band Banda WiFi.
 * @param {object} guest Configuracion de red de invitados.
 */
function populateGuestControls(band, guest = {}) {
  const controls = wifiBandControls("guest", band);

  if (controls.enabled) {
    controls.enabled.checked = Boolean(guest.habilitada);
  }

  if (controls.ssid) {
    controls.ssid.value = guest.ssid || "";
  }

  if (controls.password) {
    controls.password.value = guest.password || "";
  }

  if (controls.hidden) {
    const supported = guest.oculto !== null && guest.oculto !== undefined;
    controls.hidden.checked = Boolean(guest.oculto);
    controls.hidden.disabled = !supported;
    controls.hidden.closest("label")?.classList.toggle("is-disabled", !supported);
  }

  populateClientLimit(controls.maxClients, guest);
}

/**
 * Actualiza la metrica de invitados del dashboard para 2.4 y 5 GHz.
 */
function updateGuestMetric() {
  const stateText = WIFI_BANDS
    .map((band) => {
      const config = guestConfigs[band.value];
      const state = config
        ? config.habilitada ? "activa" : "inactiva"
        : "sin lectura";
      return `${band.shortLabel}: ${state}`;
    })
    .join(" / ");
  const ssidText = WIFI_BANDS
    .map((band) => {
      const ssid = guestConfigs[band.value]?.ssid;
      return ssid ? `${band.shortLabel}: ${ssid}` : "";
    })
    .filter(Boolean)
    .join(" / ");

  if (metricGuestState) {
    metricGuestState.textContent = stateText || "Sin lectura";
  }

  if (metricGuestSsid) {
    metricGuestSsid.textContent = ssidText || "SSID sin leer";
  }
}

/**
 * Lee el estado actual de las redes primarias 2.4 y 5 GHz.
 */
async function loadPrimaryConfigs() {
  setBoxNotice(primaryNotice, "Leyendo configuracion de las redes principales...");

  const failures = [];

  await Promise.all(WIFI_BANDS.map(async (band) => {
    try {
      const data = await apiRequest(`/api/primary?band=${encodeURIComponent(band.value)}`);
      populatePrimaryControls(band.value, data.primary || {});
    } catch (error) {
      failures.push(`${band.label}: ${error.message}`);
      updatePrimaryBadge(wifiBandControls("primary", band.value).state, {});
    }
  }));

  primaryLoaded = failures.length === 0;

  if (failures.length > 0) {
    setBoxNotice(primaryNotice, `No se pudo leer el router: ${failures.join("; ")}`, "warning");
    return;
  }

  setBoxNotice(primaryNotice, "");
}

/**
 * Envia al servidor la configuracion visible de una red primaria.
 *
 * @param {string} band Banda WiFi.
 */
async function updatePrimaryConfig(band) {
  const controls = wifiBandControls("primary", band);
  const meta = wifiBandMeta(band);

  setSavingButton(controls.save, true);
  setBoxNotice(primaryNotice, `Enviando cambios de la red primaria ${meta.label}...`);

  try {
    const body = {
      band,
      ssid: controls.ssid?.value || "",
      password: controls.password?.value || "",
    };
    const maxClients = normalizedClientLimit(controls.maxClients);

    if (controls.hidden && !controls.hidden.disabled) {
      body.hidden = Boolean(controls.hidden.checked);
    }

    if (maxClients !== null) {
      body.max_clients = maxClients;
    }

    const data = await apiRequest("/api/primary", {
      method: "POST",
      body: JSON.stringify(body),
    });
    primaryLoaded = false;
    await loadPrimaryConfigs();

    if (primaryLoaded) {
      setBoxNotice(primaryNotice, data.message || "Cambios guardados.", "success");
    }
  } catch (error) {
    setBoxNotice(primaryNotice, error.message, "warning");
  } finally {
    setSavingButton(controls.save, false);
  }
}

/**
 * Lee el estado actual de las redes de invitados 2.4 y 5 GHz.
 */
async function loadGuestConfig() {
  setBoxNotice(guestNotice, "Leyendo configuracion de las redes de invitados...");

  const failures = [];

  await Promise.all(WIFI_BANDS.map(async (band) => {
    try {
      const data = await apiRequest(`/api/guest?band=${encodeURIComponent(band.value)}`);
      guestConfigs[band.value] = data.guest || {};
      populateGuestControls(band.value, guestConfigs[band.value]);
    } catch (error) {
      delete guestConfigs[band.value];
      failures.push(`${band.label}: ${error.message}`);
    }
  }));

  updateGuestMetric();
  guestLoaded = failures.length === 0;

  if (failures.length > 0) {
    setBoxNotice(guestNotice, `No se pudo leer el router: ${failures.join("; ")}`, "warning");
    return;
  }

  setBoxNotice(guestNotice, "");
}

/**
 * Envia al servidor la configuracion visible de una red de invitados.
 *
 * @param {string} band Banda WiFi.
 */
async function updateGuestConfig(band) {
  const controls = wifiBandControls("guest", band);
  const meta = wifiBandMeta(band);

  setSavingButton(controls.save, true);
  setBoxNotice(guestNotice, `Enviando cambios de invitados ${meta.label}...`);

  try {
    const body = {
      band,
      enabled: Boolean(controls.enabled?.checked),
      ssid: controls.ssid?.value || "",
      password: controls.password?.value || "",
    };
    const maxClients = normalizedClientLimit(controls.maxClients);

    if (controls.hidden && !controls.hidden.disabled) {
      body.hidden = Boolean(controls.hidden.checked);
    }

    if (maxClients !== null) {
      body.max_clients = maxClients;
    }

    const data = await apiRequest("/api/guest", {
      method: "POST",
      body: JSON.stringify(body),
    });
    guestLoaded = false;
    await loadGuestConfig();

    if (guestLoaded) {
      setBoxNotice(guestNotice, data.message || "Cambios guardados.", "success");
    }
  } catch (error) {
    setBoxNotice(guestNotice, error.message, "warning");
  } finally {
    setSavingButton(controls.save, false);
  }
}

/**
 * Busca dispositivos en la subred local y actualiza la vista.
 */
async function runScan() {
  startScan.disabled = true;
  startScan.textContent = "Buscando...";
  setBoxNotice(scanNotice, "");
  startRadarScan();

  try {
    const data = await apiRequest("/api/scan", { method: "POST" });
    devices = data.devices || [];
    deviceHistoryItems = data.history || deviceHistoryItems;

    if (data.blocked_macs_available !== false && Array.isArray(data.blocked_macs)) {
      blockedMacs = data.blocked_macs;
      hasBlockedSnapshot = true;
    }

    lastDevicePayload = data;
    applyAccessOverridesToState();
    setBoxNotice(scanNotice, "Busqueda terminada. Los usuarios encontrados ya estan disponibles en el panel.", "success");
    renderDevices();
    renderDeviceHistory();
    updateDashboard(data);
    finishRadarScan(data);
  } catch (error) {
    setBoxNotice(scanNotice, error.message, "warning");
    failRadarScan();
  } finally {
    startScan.disabled = false;
    startScan.textContent = "Escanear ahora";
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
  const normalizedMac = canonicalMac(mac);
  return devices.find((device) => canonicalMac(device.mac) === normalizedMac);
}

/**
 * Abre el modal de confirmacion para renombrar, bloquear o desbloquear.
 *
 * @param {HTMLElement} button Boton que contiene `data-action` y `data-mac`.
 */
function openActionModal(button) {
  const mac = button.dataset.mac;
  const action = button.dataset.action;
  const knownDevice = getDeviceByMac(mac);
  const isBlocked = action === "unblock" || blockedMacs.some((blockedMac) => (
    canonicalMac(blockedMac) === canonicalMac(mac)
  ));
  const device = knownDevice ? {
    ...knownDevice,
    blocked: Boolean(knownDevice.blocked || isBlocked),
  } : {
    mac,
    name: button.dataset.deviceName || mac,
    blocked: isBlocked,
  };

  if (!device.mac) {
    return;
  }

  pendingAction = { action, device };
  renameField.hidden = action !== "rename";
  aliasInput.value = device.alias || device.name || "";

  if (action === "rename") {
    modalTitle.textContent = "Cambiar nombre";
    modalCopy.textContent = "Escriba un nombre sencillo para reconocer este equipo. Se guardara en la base de datos por su direccion MAC.";
    modalConfirm.textContent = "Guardar nombre";
  } else if (action === "forget") {
    modalTitle.textContent = "Olvidar dispositivo";
    modalCopy.textContent = "Se borrara el alias, el historial local y el registro guardado para este equipo. Si todavia esta conectado, reaparecera en la siguiente lectura.";
    modalConfirm.textContent = "Olvidar";
  } else if (action === "unblock" || device.blocked) {
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
  let refreshImmediately = true;

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
    } else if (action === "forget") {
      await apiRequest("/api/devices/forget", {
        method: "POST",
        body: JSON.stringify({ mac: device.mac }),
      });
      successMessage = "Dispositivo eliminado del historial local.";
    } else {
      const shouldUnblock = action === "unblock" || device.blocked;
      const path = shouldUnblock ? "/api/devices/unblock" : "/api/devices/block";
      const data = await apiRequest(path, {
        method: "POST",
        body: JSON.stringify({ mac: device.mac }),
      });
      setLocalAccessState(data.mac || device.mac, !shouldUnblock);
      successMessage = data.message || (
        shouldUnblock ? "Usuario desbloqueado." : "Usuario bloqueado."
      );
      refreshImmediately = false;
      window.setTimeout(() => loadDevices({ silent: true }), 4000);
    }

    closeActionModal();
    if (refreshImmediately) {
      await loadDevices();
    }
    setNotice(successMessage, "success");
    setBoxNotice(accessNotice, successMessage, "success");
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
  const passwordToggle = event.target.closest("[data-password-toggle]");

  if (passwordToggle) {
    togglePasswordVisibility(passwordToggle);
    return;
  }

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

radarPoints.addEventListener("click", (event) => {
  const selectedPoint = event.target.closest(".radar-point");

  if (!selectedPoint) {
    return;
  }

  const willSelect = !selectedPoint.classList.contains("is-selected");

  radarPoints.querySelectorAll(".radar-point").forEach((point) => {
    point.classList.remove("is-selected");
    point.setAttribute("aria-pressed", "false");
  });

  selectedPoint.classList.toggle("is-selected", willSelect);
  selectedPoint.setAttribute("aria-pressed", String(willSelect));
});

document.addEventListener("click", (event) => {
  if (event.target.closest(".radar-point")) {
    return;
  }

  radarPoints.querySelectorAll(".radar-point.is-selected").forEach((point) => {
    point.classList.remove("is-selected");
    point.setAttribute("aria-pressed", "false");
  });
});

// Eventos directos de formularios y botones persistentes.
deviceSearch.addEventListener("input", renderDevices);
deviceTypeFilter.addEventListener("change", renderDevices);
deviceStatusFilter.addEventListener("change", renderDevices);
refreshDevices.addEventListener("click", () => loadDevices());
reloadPanel?.addEventListener("click", reloadPanelPage);
autoRefreshDevices.addEventListener("click", toggleAutoRefresh);
clearDeviceHistory.addEventListener("click", clearHistory);
blockSelectedUser.addEventListener("click", blockSelectedAccessUser);
primarySaveButtons.forEach((button) => {
  button.addEventListener("click", () => updatePrimaryConfig(button.dataset.primarySave));
});
guestSaveButtons.forEach((button) => {
  button.addEventListener("click", () => updateGuestConfig(button.dataset.guestSave));
});
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

document.addEventListener("visibilitychange", () => {
  if (!document.hidden && autoRefreshEnabled) {
    loadDevices({ silent: true });
  }
});

loadDevices({ silent: true });
loadGuestConfig();
