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
const modal = document.getElementById("actionModal");
const modalTitle = document.getElementById("modalTitle");
const modalCopy = document.getElementById("modalCopy");
const renameField = document.getElementById("renameField");
const aliasInput = document.getElementById("aliasInput");
const modalConfirm = document.getElementById("modalConfirm");
const closeModalButtons = document.querySelectorAll(".modal-close, .modal-cancel");

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

let devices = [];
let pendingAction = null;
let guestLoaded = false;

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
}

function escapeHtml(value) {
  return String(value || "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

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

function actionCopy(action, device) {
  if (action === "rename") {
    return "Este boton solo cambia el nombre que usted ve en este panel. No cambia el nombre real del equipo.";
  }

  if (device.blocked) {
    return "Este boton permite que el dispositivo vuelva a conectarse al WiFi.";
  }

  return "Este boton evita que este dispositivo vuelva a conectarse al WiFi. Uselo solo si no lo reconoce.";
}

function filteredDevices() {
  const query = deviceSearch.value.trim().toLowerCase();
  const type = deviceTypeFilter.value;

  return devices.filter((device) => {
    const matchesQuery = !query || `${device.name} ${device.hostname} ${device.ip}`.toLowerCase().includes(query);
    const matchesType = type === "Todos" || !type || device.type === type;
    return matchesQuery && matchesType;
  });
}

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
    const signalClass = Number.parseInt(device.rssi, 10) <= -75 ? "weak" : "";
    const statusText = device.blocked ? "Bloqueado" : "Conectado";

    return `
      <article class="device-card ${device.blocked ? "is-blocked" : ""}">
        <span class="connection-dot ${signalClass}" title="${statusText}"></span>
        <div class="device-avatar ${escapeHtml(device.type)}">
          ${deviceIcon(device.type)}
        </div>
        <h3>${escapeHtml(device.name)}</h3>
        <p>${escapeHtml(deviceTypeLabel(device.type))}</p>
        <span class="device-meta">${escapeHtml(device.ip || "IP no disponible")}</span>
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

async function loadDevices() {
  deviceGrid.innerHTML = `
    <article class="device-card skeleton">
      <div class="device-avatar"></div>
      <h3>Cargando dispositivos</h3>
      <p>Consultando el router y la base de datos.</p>
    </article>
  `;

  try {
    const data = await apiRequest("/api/devices");
    devices = data.devices || [];

    if (data.source === "database") {
      setNotice("No se pudo leer el router ahora mismo. Estoy mostrando lo guardado en la base de datos.", "warning");
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

async function runScan() {
  startScan.disabled = true;
  startScan.textContent = "Escaneando...";
  setBoxNotice(scanNotice, "Escaneando la red local. Esto puede tardar un poco.");

  try {
    const data = await apiRequest("/api/scan", { method: "POST" });
    devices = data.devices || [];
    setBoxNotice(scanNotice, "Escaneo terminado. Los dispositivos fueron guardados en la base de datos.", "success");
    showView("devices");
    renderDevices();
  } catch (error) {
    setBoxNotice(scanNotice, error.message, "warning");
  } finally {
    startScan.disabled = false;
    startScan.textContent = "Iniciar escaneo";
  }
}

function getDeviceByMac(mac) {
  return devices.find((device) => device.mac === mac);
}

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

function closeActionModal() {
  modal.hidden = true;
  pendingAction = null;
}

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

navButtons.forEach((button) => {
  button.addEventListener("click", () => showView(button.dataset.view));
});

quickLinks.forEach((button) => {
  button.addEventListener("click", () => showView(button.dataset.viewLink));
});

document.addEventListener("click", (event) => {
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

deviceSearch.addEventListener("input", renderDevices);
deviceTypeFilter.addEventListener("change", renderDevices);
refreshDevices.addEventListener("click", loadDevices);
saveGuest.addEventListener("click", updateGuestConfig);
startScan.addEventListener("click", runScan);

document.getElementById("scanNow").addEventListener("click", () => {
  showView("scan");
});

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
