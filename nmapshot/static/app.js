const $ = (id) => document.getElementById(id);
const systemTheme = window.matchMedia("(prefers-color-scheme: dark)");
let savedTheme = null;
try {
  savedTheme = localStorage.getItem("dedalo-theme");
  if (!["light", "dark"].includes(savedTheme)) {
    savedTheme = localStorage.getItem("prometheus-theme");
    if (["light", "dark"].includes(savedTheme)) localStorage.setItem("dedalo-theme", savedTheme);
  }
} catch {}
if (!["light", "dark"].includes(savedTheme)) savedTheme = null;
function applyTheme(theme) {
  document.documentElement.dataset.theme = theme;
  const dark = theme === "dark";
  $("theme-toggle").setAttribute("aria-pressed", String(dark));
  $("theme-toggle").title = dark ? "Cambiar a modo claro" : "Cambiar a modo oscuro";
  $("theme-toggle").querySelector("span").textContent = dark ? "Modo claro" : "Modo oscuro";
}
applyTheme(savedTheme || (systemTheme.matches ? "dark" : "light"));
$("theme-toggle").addEventListener("click", () => {
  savedTheme = document.documentElement.dataset.theme === "dark" ? "light" : "dark";
  applyTheme(savedTheme);
  try { localStorage.setItem("dedalo-theme", savedTheme); } catch {}
});
systemTheme.addEventListener("change", event => {
  if (!savedTheme) applyTheme(event.matches ? "dark" : "light");
});
const escapeHtml = (value) => String(value ?? "").replace(/[&<>"']/g, (char) => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[char]));
const labels = {preparada:"Preparada",en_cola:"En cola",en_curso:"Capturando",deteniendo:"Deteniendo",completa:"Completada",parcial:"Con incidencias",error:"Error",cancelada:"Cancelada",interrumpida:"Interrumpida",pendiente:"Pendiente",capturada:"Capturada",sin_captura:"Sin captura",completo:"Completada"};
const activeStates = new Set(["en_cola","en_curso","deteniendo"]);
let token = "", currentId = "", current = null, activeTab = "gallery", files = [], shown = 60, engine = {};
let renderKey = "", polling = false, mutating = false;
let viewVersion = 0, deletionTarget = null;
let inventory = null, inventoryError = "";
const dateText = (value) => new Date(value).toLocaleString("es-ES", {day:"2-digit",month:"short",hour:"2-digit",minute:"2-digit"});
const rangeText = (value) => value === "fuera_de_rango" ? "Fuera de rango" : value;
const badgeClass = (state) => state === "completa" || state === "capturada" ? "complete" : activeStates.has(state) ? "running" : ["error","parcial","sin_captura","interrumpida"].includes(state) ? "error" : "";

function notice(message) {
  $("notice").textContent = message;
  $("notice").hidden = !message;
}
async function request(path, body) {
  const response = await fetch(path, body === undefined ? {} : {method:"POST", headers:{"Content-Type":"application/json","X-Nmapshot-Token":token},body:JSON.stringify(body)});
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || "No se pudo completar la operación");
  return data;
}
function updateJobs(jobs) {
  $("job-count").textContent = jobs.length;
  const html = jobs.map(job => `<button class="job-link ${job.id === currentId ? "active" : ""}" data-id="${job.id}" ${job.id === currentId ? 'aria-current="true"' : ""} title="${escapeHtml(job.nombre)}"><strong>${escapeHtml(job.nombre)}</strong><small><span>${dateText(job.fecha)}</span><span class="job-result ${badgeClass(job.estado)}">${labels[job.estado] || job.estado}</span></small></button>`).join("");
  if ($("jobs").innerHTML !== html) $("jobs").innerHTML = html;
}
async function selectJob(id) {
  const version = ++viewVersion;
  currentId = id;
  inventory = null; inventoryError = "";
  location.hash = id;
  shown = 60;
  renderKey = "";
  $("range-filter").value = $("subnet-filter").value = $("status-filter").value = $("service-filter").value = $("search").value = "";
  const detail = await request("/api/jobs/" + id);
  if (id !== currentId || version !== viewVersion) return;
  current = detail;
  activeTab = !detail.total ? "inventory" : detail.estado === "preparada" ? "targets" : "gallery";
  render();
  await loadInventory(id, version);
  await poll();
}
async function loadInventory(id, version) {
  try {
    const data = await request("/api/jobs/" + id + "/inventory");
    if (id !== currentId || version !== viewVersion) return;
    inventory = data; inventoryError = "";
  } catch (error) {
    if (id !== currentId || version !== viewVersion) return;
    inventoryError = error.message;
  }
  render();
}
function selectOptions(element, values, placeholder, display = (v) => v) {
  const selected = element.value;
  const html = `<option value="">${placeholder}</option>` + [...new Set(values)].map(value => `<option value="${escapeHtml(value)}">${escapeHtml(display(value))}</option>`).join("");
  if (element.innerHTML !== html) {
    element.innerHTML = html;
    element.value = [...element.options].some(option => option.value === selected) ? selected : "";
  }
}
function inventoryAssets() {
  // Con -Pn Nmap da por activas IP que no responden; ocultarlas quita ruido.
  const assets = inventory?.activos || [];
  return $("hide-empty").checked ? assets.filter(asset => asset.servicios.length) : assets;
}
function updateFilters() {
  const groups = activeTab === "inventory" ? inventoryAssets() : current.grupos;
  selectOptions($("range-filter"), groups.map(g => g.rango), "Todos los rangos", rangeText);
  selectOptions($("subnet-filter"), groups.filter(g => !$("range-filter").value || g.rango === $("range-filter").value).map(g => g.subred), "Todas las subredes");
  if (activeTab === "inventory") selectOptions($("service-filter"), (inventory?.activos || []).flatMap(a => a.servicios.map(s => s.servicio || "Sin identificar")).sort(), "Todos los servicios");
}
function rows() {
  if (!current) return [];
  const query = $("search").value.toLowerCase().trim(), range = $("range-filter").value, subnet = $("subnet-filter").value, status = $("status-filter").value;
  return current.grupos.flatMap((group, gi) => group.objetivos.map((target, ti) => ({...target,range:group.rango,subnet:group.subred,key:gi+"-"+ti})))
    .filter(row => (!range || row.range === range) && (!subnet || row.subnet === subnet) && (!status || (status === "pendiente" ? ["pendiente","en_curso"].includes(row.estado) : row.estado === status)) && (!query || [row.ip,row.url,row.titulo,row.subnet].join(" ").toLowerCase().includes(query)));
}
function render() {
  if (!current) {
    $("workspace").hidden = true;
    $("empty-state").hidden = false;
    $("page-title").textContent = "Capturas web";
    $("page-description").textContent = "Inspecciona los servicios web encontrados por Nmap.";
    $("job-state").hidden = true;
    for (const id of ["stat-assets", "stat-services", "stat-targets", "stat-shots", "stat-subnets", "stat-failures"]) $(id).textContent = "0";
    $("results").innerHTML = "";
    $("logs").textContent = "";
    renderKey = "";
    return;
  }
  $("workspace").hidden = false;
  $("empty-state").hidden = true;
  $("page-title").textContent = current.nombre;
  $("page-description").textContent = dateText(current.fecha) + " / " + current.archivos.length + " archivo(s) de Nmap";
  $("job-state").hidden = false;
  $("job-state").className = "badge " + badgeClass(current.estado);
  $("job-state").textContent = labels[current.estado] || current.estado;
  $("stat-targets").textContent = current.total.toLocaleString("es-ES");
  $("stat-assets").textContent = inventory ? inventory.activos_total.toLocaleString("es-ES") : "—";
  $("stat-services").textContent = inventory ? inventory.servicios_total.toLocaleString("es-ES") : "—";
  $("stat-shots").textContent = current.capturas.toLocaleString("es-ES");
  $("stat-subnets").textContent = current.subredes;
  $("stat-failures").textContent = current.sin_captura;
  const running = activeStates.has(current.estado);
  $("delete-job").disabled = mutating || running;
  $("delete-job").title = running ? "Detén la ejecución y espera a que termine antes de borrarla" : "Borrar esta ejecución y sus archivos";
  $("start-job").hidden = current.estado !== "preparada";
  $("start-job").disabled = mutating || !current.total || !engine.ready;
  $("start-job").title = !engine.ready ? "El motor de capturas no está disponible: " + engine.error
    : !current.total ? "No hay puertos web que capturar en estos archivos (80/443 u otros configurados en las opciones)" : "";
  $("cancel-job").hidden = !running;
  $("cancel-job").disabled = mutating || current.estado === "deteniendo";
  $("cancel-job").textContent = current.estado === "en_cola" ? "Cancelar trabajo" : current.estado === "deteniendo" ? "Parada solicitada…" : "Detener tras esta subred";
  for (const type of ["csv","json"]) {
    $(type + "-download").hidden = !current.csv;
    $(type + "-download").href = "/api/jobs/" + currentId + "/download/" + type;
  }
  $("progress").hidden = !running;
  $("progress").value = current.total ? Math.round(current.procesadas / current.total * 100) : 0;
  const activeGroup = current.grupos.find(g => g.estado === "en_curso");
  let title = "Captura finalizada";
  let description = `${current.capturas} imágenes disponibles. ${current.sin_captura} objetivos sin captura.`;
  if (current.estado === "preparada") {
    title = current.total ? "Objetivos listos para revisar" : "No se han encontrado servicios web";
    description = current.total ? "Se capturarán únicamente las IP y puertos seleccionados de tus archivos." : "Puedes consultar los activos y sus servicios en la pestaña Activos. No hay objetivos web que capturar con estas opciones.";
  } else if (current.estado === "en_cola") {
    title = "En cola";
    description = "La captura comenzará cuando termine el trabajo anterior.";
  } else if (current.estado === "en_curso") {
    title = activeGroup ? "Capturando " + activeGroup.subred : "Preparando el navegador…";
    description = `${current.procesadas} de ${current.total} objetivos en subredes completadas. Puedes seguir usando el portal.`;
  } else if (current.estado === "deteniendo") {
    title = "Terminando la subred actual";
    description = "Se conservarán las capturas obtenidas; no se iniciarán más subredes.";
  } else if (current.estado === "interrumpida" || current.estado === "cancelada") {
    title = "Ejecución detenida";
    description = "Los resultados obtenidos se conservan. Los objetivos no intentados aparecen pendientes.";
  } else if (current.estado === "error") {
    title = "La ejecución necesita revisión";
    description = current.error;
  }
  $("run-title").textContent = title;
  $("run-description").textContent = description;
  updateFilters();
  document.querySelectorAll("[data-tab]").forEach(button => button.setAttribute("aria-selected", String(button.dataset.tab === activeTab)));
  $("filters").hidden = activeTab === "logs";
  $("results").hidden = activeTab === "logs";
  $("logs").hidden = activeTab !== "logs";
  $("inventory-tools").hidden = activeTab !== "inventory";
  $("status-filter-label").hidden = activeTab === "inventory";
  $("service-filter-label").hidden = activeTab !== "inventory";
  $("search").placeholder = activeTab === "inventory" ? "IP, nombre, puerto o producto" : "IP, URL o título";
  $("search").setAttribute("aria-label", activeTab === "inventory" ? "Buscar IP, nombre, puerto o producto" : "Buscar IP, URL o título");
  for (const type of ["csv", "json"]) {
    $("inventory-" + type).href = "/api/jobs/" + currentId + "/download/inventory-" + type;
    $("inventory-" + type).hidden = !inventory;
  }
  renderResults();
}
function networkActions(items) {
  // El ZIP incluye todas las capturas de la subred, no solo las filtradas.
  const gi = Number(items[0].key.split("-")[0]), total = current.grupos[gi].capturas;
  const zip = total ? `<a class="secondary" href="/api/jobs/${currentId}/download/captures/${gi}" download>Descargar capturas (${total})</a>` : "";
  return `<div class="network-actions"><span class="network-count">${items.length} objetivos mostrados</span>${zip}</div>`;
}
function renderResults() {
  if (!current || activeTab === "logs") { $("more").hidden = true; return; }
  if (activeTab === "inventory") { renderInventory(); return; }
  const filtered = rows(), visible = filtered.slice(0, shown);
  $("result-count").textContent = filtered.length + " objetivo(s)";
  $("more").hidden = filtered.length <= shown;
  $("more").textContent = "Mostrar más (" + Math.max(0, filtered.length - shown) + " restantes)";
  const key = JSON.stringify([activeTab,visible,currentId]);
  if (key === renderKey) return;
  renderKey = key;
  if (!filtered.length) {
    $("results").innerHTML = '<div class="empty-results">No hay objetivos que coincidan con estos filtros.</div>';
    return;
  }
  if (activeTab === "targets") {
    $("results").innerHTML = '<div class="table-wrap"><table><thead><tr><th>IP / Puerto</th><th>Protocolo</th><th>Rango</th><th>Subred</th><th>Estado</th><th>HTTP</th></tr></thead><tbody>' +
    visible.map(row => `<tr><td>${escapeHtml(row.ip)}:${row.puerto}</td><td>${row.url.startsWith("https:") ? "HTTPS" : "HTTP"}</td><td>${escapeHtml(rangeText(row.range))}</td><td>${escapeHtml(row.subnet)}</td><td><span class="badge ${badgeClass(row.estado)}">${labels[row.estado] || row.estado}</span></td><td>${row.codigo || "—"}</td></tr>`).join("") + "</tbody></table></div>";
    return;
  }
  const grouped = new Map();
  for (const row of visible) {
    const key = row.range + "|" + row.subnet;
    if (!grouped.has(key)) grouped.set(key, []);
    grouped.get(key).push(row);
  }
  $("results").innerHTML = [...grouped.values()].map(items => `<section class="network-section"><header class="network-heading"><div><h3>Subred <span>${escapeHtml(items[0].subnet)}</span></h3><p>${items[0].range === "fuera_de_rango" ? "Sin rango asignado" : "Rango " + escapeHtml(items[0].range)}</p></div>${networkActions(items)}</header><div class="card-grid">${items.map(row => `<article class="capture-card">
    <div class="card-top"><strong>${escapeHtml(row.ip)}</strong><span class="protocol">${row.url.startsWith("https:") ? "HTTPS" : "HTTP"} :${row.puerto}</span></div>
    ${row.imagen ? `<button class="shot-button" data-image="${row.key}" aria-label="Ampliar captura de ${escapeHtml(row.ip)} puerto ${row.puerto}"><img src="${row.imagen}" alt="Captura de ${escapeHtml(row.url)}" loading="lazy"><span class="shot-hint">Ampliar captura</span></button>` : `<div class="shot-placeholder"><span>${labels[row.estado] || row.estado}</span>${row.error ? `<p class="capture-error">${escapeHtml(row.error)}</p>` : ""}</div>`}
    <div class="card-info"><p class="card-title" title="${escapeHtml(row.titulo)}">${escapeHtml(row.titulo || (row.imagen ? "Página sin título" : row.estado === "sin_captura" ? "No se pudo obtener la imagen" : "Pendiente de captura"))}</p><div class="card-bottom"><p class="card-url">${escapeHtml(row.url)}</p>${row.codigo ? `<span class="response-code">HTTP ${row.codigo}</span>` : ""}</div></div>
    </article>`).join("")}</div></section>`).join("");
}
function renderInventory() {
  if (!inventory) {
    $("more").hidden = true;
    $("result-count").textContent = "";
    $("results").innerHTML = `<div class="empty-results">${escapeHtml(inventoryError || "Cargando inventario…")}${inventoryError ? '<p><button class="secondary" data-retry-inventory>Reintentar</button></p>' : ""}</div>`;
    renderKey = "";
    return;
  }
  const query = $("search").value.toLowerCase().trim(), range = $("range-filter").value, subnet = $("subnet-filter").value, service = $("service-filter").value;
  const captures = new Map(current.grupos.flatMap((g, gi) => g.objetivos.map((t, ti) => [t.ip + ":" + t.puerto, {...t, key:gi+"-"+ti}])));
  const empty = inventory.activos.filter(asset => !asset.servicios.length).length;
  $("empty-count").textContent = empty ? ` (${empty})` : "";
  const filtered = inventoryAssets().flatMap(asset => (asset.servicios.length ? asset.servicios : [null]).map(port => ({asset, port})))
    .filter(({asset, port}) => (!range || asset.rango === range) && (!subnet || asset.subred === subnet) && (!service || (port && (port.servicio || "Sin identificar") === service)) &&
      (!query || [asset.ip, ...asset.nombres, asset.subred, port?.puerto, port?.protocolo, port?.servicio, port?.producto, port?.version, port?.detalle, ...(port?.cpe || [])].join(" ").toLowerCase().includes(query)));
  const visible = filtered.slice(0, shown);
  $("result-count").textContent = `${new Set(filtered.map(row => row.asset.ip)).size} activos / ${filtered.filter(row => row.port).length} servicios`;
  $("more").hidden = filtered.length <= shown;
  $("more").textContent = "Mostrar más (" + Math.max(0, filtered.length - shown) + " restantes)";
  const key = JSON.stringify(["inventory", visible, currentId, [...captures.values()].map(t => [t.key, t.imagen, t.estado])]);
  if (key === renderKey) return;
  renderKey = key;
  if (!filtered.length) {
    $("results").innerHTML = '<div class="empty-results">No hay activos o servicios que coincidan con estos filtros.</div>';
    return;
  }
  const grouped = new Map();
  for (const row of visible) {
    const groupKey = row.asset.rango + "|" + row.asset.subred;
    if (!grouped.has(groupKey)) grouped.set(groupKey, []);
    grouped.get(groupKey).push(row);
  }
  $("results").innerHTML = [...grouped.values()].map(items => `<section class="network-section"><header class="network-heading"><div><h3>Subred <span>${escapeHtml(items[0].asset.subred)}</span></h3><p>${escapeHtml(rangeText(items[0].asset.rango))}</p></div></header><div class="table-wrap"><table class="inventory-table"><thead><tr><th>IP / Nombre</th><th>Puerto</th><th>Servicio</th><th>Producto / Versión</th><th>Captura web</th></tr></thead><tbody>${items.map(({asset, port}) => {
    const capture = port?.protocolo === "tcp" ? captures.get(asset.ip + ":" + port.puerto) : null;
    const scripts = [...asset.scripts, ...(port?.scripts || [])];
    const details = [port?.detalle, ...(port?.cpe || []), ...scripts.map(s => s.id + ": " + s.output)].filter(Boolean).join("\n\n");
    return `<tr><td>${escapeHtml(asset.ip)}${asset.nombres.length ? `<small>${escapeHtml(asset.nombres.join(", "))}</small>` : ""}</td><td>${port ? port.puerto + "/" + escapeHtml(port.protocolo.toUpperCase()) : "—"}</td><td>${port ? escapeHtml((port.tunel ? port.tunel + "/" : "") + (port.servicio || "Sin identificar")) : "Sin puertos abiertos"}</td><td class="service-data">${escapeHtml([port?.producto, port?.version].filter(Boolean).join(" ") || "—")}${details ? `<details><summary>Datos Nmap</summary><pre>${escapeHtml(details)}</pre></details>` : ""}</td><td>${capture?.imagen ? `<button class="secondary" data-image="${capture.key}">Ver captura</button>` : capture ? escapeHtml(labels[capture.estado] || capture.estado) : "—"}</td></tr>`;
  }).join("")}</tbody></table></div></section>`).join("");
}
async function loadLogs() {
  const id = currentId;
  const result = await request("/api/jobs/" + id + "/logs");
  if (id === currentId) $("logs").textContent = result.text;
}
async function poll() {
  if (polling || mutating) return;
  polling = true;
  const version = viewVersion;
  try {
    const jobs = await request("/api/jobs");
    if (version !== viewVersion || mutating) return;
    updateJobs(jobs);
    if (currentId && !jobs.some(job => job.id === currentId)) {
      currentId = ""; current = null;
      history.replaceState(null, "", location.pathname);
      render();
    }
    if (!currentId && jobs.length) {
      const hash = location.hash.slice(1);
      const id = jobs.some(j => j.id === hash) ? hash : jobs[0].id;
      polling = false;
      await selectJob(id);
      return;
    }
    if (currentId) {
      const id = currentId;
      const detail = await request("/api/jobs/" + id);
      if (id === currentId && version === viewVersion && !mutating) {
        current = detail; render();
        if (activeTab === "logs") await loadLogs();
      }
    }
  } catch (error) { notice("No se pudo actualizar el portal: " + error.message); }
  finally { polling = false; }
}
function fileList() {
  $("file-list").innerHTML = files.map((file,index) => `<li><span>${escapeHtml(file.name)} · ${Math.ceil(file.size / 1024)} KB</span><button type="button" data-remove="${index}" aria-label="Quitar ${escapeHtml(file.name)}">×</button></li>`).join("");
}
function addFiles(incoming) {
  for (const file of incoming) {
    if (!files.some(f => f.name === file.name && f.size === file.size && f.lastModified === file.lastModified)) files.push(file);
  }
  fileList();
  if (!$("job-name").value && files.length) $("job-name").value = files[0].name.replace(/\.[^.]+$/, "");
}
function openUpload() {
  $("upload-form").reset();
  files = [];
  fileList();
  $("upload-error").hidden = true;
  $("upload-dialog").showModal();
  $("job-name").focus();
}
document.querySelectorAll(".new-job").forEach(button => button.addEventListener("click", openUpload));
document.querySelector(".close-upload").addEventListener("click", () => $("upload-dialog").close());
$("nmap-files").addEventListener("change", (event) => addFiles(event.target.files));
$("file-list").addEventListener("click", event => { const button = event.target.closest("[data-remove]"); if (button) { files.splice(Number(button.dataset.remove),1); fileList(); } });
$("range-file").addEventListener("change", async (event) => {
  try { const file = event.target.files[0]; if (file) { if (file.size > 256000) throw new Error("El fichero de rangos es demasiado grande"); $("ranges").value = await file.text(); } }
  catch (error) { $("upload-error").hidden = false; $("upload-error").textContent = error.message; }
});
for (const type of ["dragenter","dragover"]) $("dropzone").addEventListener(type, event => { event.preventDefault(); $("dropzone").classList.add("dragging"); });
for (const type of ["dragleave","drop"]) $("dropzone").addEventListener(type, event => { event.preventDefault(); $("dropzone").classList.remove("dragging"); if (type === "drop") addFiles(event.dataTransfer.files); });
$("upload-form").addEventListener("submit", async event => {
  event.preventDefault();
  $("upload-error").hidden = true;
  const button = $("prepare-job");
  button.disabled = true; button.textContent = "Analizando archivos…";
  try {
    if (!files.length || files.length > 20) throw new Error("Selecciona entre 1 y 20 archivos de nmap.");
    if (files.some(f => f.size > 10 * 1024 * 1024) || files.reduce((s,f)=>s+f.size,0) > 24 * 1024 * 1024) throw new Error("Máximo 10 MB por archivo y 24 MB en total.");
    const payload = {nombre:$("job-name").value,rangos:$("ranges").value,archivos:await Promise.all(files.map(async file => ({nombre:file.name,contenido:await file.text()}))),
      opciones:{hilos:Number($("threads").value),timeout:Number($("timeout").value),delay:Number($("delay").value),formato:$("format").value,puertos:$("ports").value,por_servicio:$("by-service").checked,pagina_completa:$("fullpage").checked}};
    const result = await request("/api/jobs", payload);
    $("upload-dialog").close();
    notice("");
    await selectJob(result.id);
  } catch (error) { $("upload-error").hidden = false; $("upload-error").textContent = error.message; }
  finally { button.disabled = false; button.textContent = "Revisar objetivos"; }
});
$("jobs").addEventListener("click", event => { const button = event.target.closest("[data-id]"); if (button) selectJob(button.dataset.id).catch(error => notice(error.message)); });
for (const id of ["range-filter","subnet-filter","status-filter","service-filter","hide-empty","search"]) $(id).addEventListener(id === "search" ? "input" : "change", () => { shown=60; updateFilters(); renderResults(); });
document.querySelectorAll("[data-tab]").forEach(button => button.addEventListener("click", () => { activeTab=button.dataset.tab; shown=60; render(); if (activeTab === "logs") loadLogs().catch(error=>notice(error.message)); }));
$("more").addEventListener("click", () => { shown += 60; renderResults(); });
async function action(type) {
  if (mutating) return;
  const id = currentId;
  mutating = true; render(); notice("");
  try { const result = await request("/api/jobs/" + id + "/" + type, {}); if (id === currentId) { current=result; if (type === "start") activeTab="gallery"; render(); } await poll(); }
  catch (error) { notice(error.message); }
  finally { mutating=false; render(); }
}
$("start-job").addEventListener("click", () => action("start"));
$("cancel-job").addEventListener("click", () => action("cancel"));
$("delete-job").addEventListener("click", () => {
  if (!current || mutating || activeStates.has(current.estado)) return;
  deletionTarget = {id: current.id, nombre: current.nombre};
  $("delete-name").textContent = current.nombre;
  $("delete-error").hidden = true;
  $("delete-dialog").showModal();
  $("cancel-delete").focus();
});
$("cancel-delete").addEventListener("click", () => $("delete-dialog").close());
$("delete-dialog").addEventListener("cancel", event => { if (mutating) event.preventDefault(); });
$("confirm-delete").addEventListener("click", async () => {
  if (!deletionTarget || mutating) return;
  const target = deletionTarget;
  mutating = true; ++viewVersion; render(); notice("");
  $("delete-error").hidden = true;
  $("confirm-delete").disabled = $("cancel-delete").disabled = true;
  $("confirm-delete").textContent = "Borrando…";
  let deleted = false;
  try {
    await request("/api/jobs/" + target.id + "/delete", {});
    deleted = true;
    if (currentId === target.id) {
      currentId = ""; current = null;
      history.replaceState(null, "", location.pathname);
    }
    $("delete-dialog").close();
    deletionTarget = null;
    notice("Ejecución borrada: " + target.nombre);
  } catch (error) {
    $("delete-error").textContent = error.message;
    $("delete-error").hidden = false;
  } finally {
    mutating = false; render();
    $("confirm-delete").disabled = $("cancel-delete").disabled = false;
    $("confirm-delete").textContent = "Borrar definitivamente";
  }
  if (deleted) {
    await poll();
    document.querySelector(".new-job").focus();
  }
});
$("results").addEventListener("click", event => {
  if (event.target.closest("[data-retry-inventory]")) { loadInventory(currentId, viewVersion); return; }
  const button = event.target.closest("[data-image]");
  if (!button) return;
  const [gi,ti] = button.dataset.image.split("-").map(Number), group=current.grupos[gi], target=group.objetivos[ti];
  $("image-title").textContent = target.titulo || target.ip;
  $("image-url").textContent = target.url;
  $("image-meta").textContent = "Subred " + group.subred + " / " + rangeText(group.rango) + " / HTTP " + target.codigo;
  $("full-image").src = target.imagen; $("full-image").alt = "Captura de " + target.url;
  $("image-download").href = target.imagen;
  $("image-dialog").showModal();
});
$("close-image").addEventListener("click", () => $("image-dialog").close());
async function boot() {
  try {
    const bootstrap = await request("/api/bootstrap");
    token=bootstrap.token; engine=bootstrap.engine;
    $("engine-status").textContent = engine.ready ? "Motor preparado" : "Motor no disponible";
    $("engine-dot").classList.toggle("error", !engine.ready);
    if (!engine.ready) notice(engine.error);
    await poll();
  } catch (error) { notice("No se pudo conectar: " + error.message); }
  setInterval(poll, 2000);
}
boot();
