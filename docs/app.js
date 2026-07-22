"use strict";

const session = requireSession();
if (session) document.querySelector("#session-user").textContent = session.user;

document.querySelector("#logout").addEventListener("click", () => {
  clearSession();
  window.location.replace("./login.html");
});

const state = { osint: null, audit: null };
const $ = (selector) => document.querySelector(selector);

document.querySelectorAll(".tab").forEach((button) => {
  button.addEventListener("click", () => {
    const selected = button.dataset.panel;
    document.querySelectorAll(".tab").forEach((tab) => {
      const active = tab === button;
      tab.classList.toggle("active", active);
      tab.setAttribute("aria-selected", String(active));
    });
    $("#osint-panel").hidden = selected !== "osint";
    $("#audit-panel").hidden = selected !== "audit";
  });
});

function cleanInput(value) {
  const clean = value.trim();
  if (!clean) throw new Error("Saisissez une cible.");
  if (clean.length > 254 || /[\u0000-\u001f\u007f]/.test(clean)) throw new Error("La cible contient des caractères invalides.");
  return clean;
}

function detectType(value) {
  if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value)) return "email";
  if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(value) || /^[0-9a-f:]{2,}$/i.test(value) && value.includes(":")) return "ip";
  const digits = value.replace(/\D/g, "");
  if (/^\+?[\d\s().-]+$/.test(value) && digits.length >= 7 && digits.length <= 15) return "phone";
  if (/^https?:\/\//i.test(value) || (!value.includes(" ") && value.includes("."))) return "domain";
  if (/\s/.test(value)) return "name";
  return "username";
}

function encoded(value) { return encodeURIComponent(value); }
function link(label, value, url, note) { return { label, value, url, note }; }

function osintLinks(target, type) {
  const q = encoded(target);
  const links = [link("Recherche exacte", "Google", `https://www.google.com/search?q=${encoded(`"${target}"`)}`, "Recouper avant toute attribution.")];
  if (type === "email") {
    const [local, domain] = target.split("@");
    links.push(
      link("Fuites connues", "Have I Been Pwned", `https://haveibeenpwned.com/account/${q}`, "Vérification manuelle."),
      link("Domaine email", domain, `https://lookup.icann.org/en/lookup?name=${encoded(domain)}`, "Données d’enregistrement publiques."),
      link("Pseudo dérivé", local, `https://github.com/${encoded(local)}`, "Une correspondance ne prouve pas l’identité.")
    );
  } else if (type === "username") {
    links.push(
      link("GitHub", target, `https://github.com/${q}`, "Contrôler le login exact."),
      link("GitLab", target, `https://gitlab.com/${q}`, "Contrôler le profil exact."),
      link("Reddit", target, `https://www.reddit.com/user/${q}`, "Profil public."),
      link("Keybase", target, `https://keybase.io/${q}`, "Identités éventuellement vérifiées.")
    );
  } else if (type === "domain") {
    const host = normalizeHost(target);
    links.push(
      link("Enregistrement", "ICANN Lookup", `https://lookup.icann.org/en/lookup?name=${encoded(host)}`, "Source publique."),
      link("Certificats", "crt.sh", `https://crt.sh/?q=${encoded(`%.${host}`)}`, "Peut révéler des sous-domaines historiques."),
      link("DNS", "Google Admin Toolbox", `https://toolbox.googleapps.com/apps/dig/#ANY/${encoded(host)}`, "Enregistrements DNS publics."),
      link("Archive", "Wayback Machine", `https://web.archive.org/web/*/${encoded(host)}`, "Versions historiques publiques.")
    );
  } else if (type === "ip") {
    links.push(
      link("Allocation", "RIPEstat", `https://stat.ripe.net/${q}`, "Allocation et routage publics."),
      link("Réputation", "VirusTotal", `https://www.virustotal.com/gui/ip-address/${q}`, "Un signal doit être contextualisé."),
      link("Vue Internet", "Shodan", `https://www.shodan.io/host/${q}`, "Données issues de scans tiers.")
    );
  } else if (type === "phone") {
    links.push(link("Recherche exacte", "Résultats publics", `https://www.google.com/search?q=${encoded(`"${target}"`)}`, "Un numéro valide n’est pas une identité confirmée."));
  } else {
    links.push(
      link("Profils professionnels", "LinkedIn via Google", `https://www.google.com/search?q=${encoded(`site:linkedin.com/in "${target}"`)}`, "Vérifier avec plusieurs attributs."),
      link("Presse et publications", "Google News", `https://news.google.com/search?q=${q}`, "Homonymes possibles.")
    );
  }
  return links;
}

function normalizeHost(value) {
  try {
    const url = new URL(/^https?:\/\//i.test(value) ? value : `https://${value}`);
    if (!url.hostname || !url.hostname.includes(".")) throw new Error();
    return url.hostname.toLowerCase();
  } catch (_) {
    throw new Error("Saisissez un domaine complet ou une URL HTTP(S) valide.");
  }
}

function safeUrl(value) {
  try {
    const url = new URL(value);
    return url.protocol === "https:" ? url.href : "";
  } catch (_) { return ""; }
}

function renderCards(container, rows) {
  container.replaceChildren();
  rows.forEach((row) => {
    const card = document.createElement("article");
    card.className = "card";
    const title = document.createElement("h2");
    title.textContent = row.label;
    const value = document.createElement(row.url ? "a" : "p");
    value.textContent = row.value;
    if (row.url) {
      value.href = safeUrl(row.url);
      value.target = "_blank";
      value.rel = "noopener noreferrer";
    }
    const note = document.createElement("p");
    note.className = "muted small";
    note.textContent = row.note || "";
    card.append(title, value, note);
    container.append(card);
  });
}

function setupExports(kind, target, rows) {
  const box = $(`#${kind}-actions`);
  box.replaceChildren();
  [["Exporter JSON", "json"], ["Exporter CSV", "csv"], ["Exporter Markdown", "md"]].forEach(([label, format]) => {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "secondary";
    button.textContent = label;
    button.addEventListener("click", () => downloadReport(kind, target, rows, format));
    box.append(button);
  });
  box.hidden = false;
}

function downloadReport(kind, target, rows, format) {
  let content;
  let mime;
  if (format === "json") {
    content = JSON.stringify({ mode: kind, target, generatedAt: new Date().toISOString(), results: rows }, null, 2);
    mime = "application/json";
  } else if (format === "csv") {
    const quote = (value) => `"${String(value || "").replaceAll('"', '""')}"`;
    content = "\ufeff" + [["label", "value", "note", "url"], ...rows.map((row) => [row.label, row.value, row.note, row.url])]
      .map((line) => line.map(quote).join(",")).join("\n");
    mime = "text/csv";
  } else {
    content = [`# Rapport Nexus`, "", `Cible : ${target}`, `Généré : ${new Date().toISOString()}`, "", ...rows.flatMap((row) => [`## ${row.label}`, row.value, row.note || "", row.url || "", ""])].join("\n");
    mime = "text/markdown";
  }
  const url = URL.createObjectURL(new Blob([content], { type: mime }));
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = `nexus-${kind}.${format}`;
  anchor.click();
  setTimeout(() => URL.revokeObjectURL(url), 0);
}

function runOsint() {
  try {
    const target = cleanInput($("#target").value);
    const type = detectType(target);
    const rows = osintLinks(target, type);
    state.osint = { target, type, rows };
    $("#osint-status").textContent = `Type détecté : ${type} · ${rows.length} pivots disponibles`;
    renderCards($("#osint-results"), rows);
    setupExports("osint", target, rows);
  } catch (error) {
    $("#osint-status").textContent = error.message;
    $("#osint-results").replaceChildren();
    $("#osint-actions").hidden = true;
  }
}

function auditChecklist(target) {
  const host = normalizeHost(target);
  return [
    link("TLS et HTTPS", "Vérifier avec SSL Labs", `https://www.ssllabs.com/ssltest/analyze.html?d=${encoded(host)}`, "Contrôler certificat, protocoles et suites cryptographiques."),
    link("En-têtes HTTP", "Vérifier avec Security Headers", `https://securityheaders.com/?q=${encoded(host)}&followRedirects=on`, "Examiner CSP, HSTS, frame-ancestors et nosniff."),
    link("Observatory", "Mozilla HTTP Observatory", `https://developer.mozilla.org/en-US/observatory/analyze?host=${encoded(host)}`, "Analyse externe déclenchée uniquement après clic."),
    link("DNS et email", "Internet.nl", `https://internet.nl/site/${encoded(host)}/`, "Contrôler DNSSEC, IPv6, TLS et politiques email."),
    link("Fichiers publics", "Checklist manuelle", "", "Vérifier /.well-known/security.txt, /robots.txt et les sitemaps sans contourner d’accès."),
    link("Contrôles applicatifs", "À réaliser manuellement", "", "Authentification, autorisations objet, logique métier et erreurs nécessitent un contexte fonctionnel."),
    link("Condition d’arrêt", "Aucune exploitation automatique", "", "Arrêter dès qu’un impact est démontré ou que le périmètre autorisé est atteint.")
  ];
}

function runAudit() {
  if (!$("#authorized").checked) {
    $("#audit-status").textContent = "Confirmez votre autorisation explicite avant de continuer.";
    return;
  }
  try {
    const target = cleanInput($("#audit-target").value);
    const rows = auditChecklist(target);
    state.audit = { target, rows };
    $("#audit-status").textContent = `${rows.length} contrôles guidés · aucune requête automatique envoyée`;
    renderCards($("#audit-results"), rows);
    setupExports("audit", target, rows);
  } catch (error) {
    $("#audit-status").textContent = error.message;
    $("#audit-results").replaceChildren();
    $("#audit-actions").hidden = true;
  }
}

$("#analyse").addEventListener("click", runOsint);
$("#target").addEventListener("keydown", (event) => { if (event.key === "Enter") runOsint(); });
$("#audit").addEventListener("click", runAudit);
$("#audit-target").addEventListener("keydown", (event) => { if (event.key === "Enter") runAudit(); });
