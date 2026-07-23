"use strict";

const session = requireSession();
if (session) document.querySelector("#session-user").textContent = session.user;
document.querySelector("#logout").addEventListener("click", () => { clearSession(); location.replace("./login.html"); });

const $ = (selector) => document.querySelector(selector);
const state = { category: "osint", module: "auto", report: null };
const HISTORY_KEY = "nexus_lab_history_v1";

const MODULES = {
  osint: [
    ["auto", "◈", "Auto", "Détection et pivots adaptés"],
    ["email", "@", "Email", "Exposition et identité publique"],
    ["username", "#", "Pseudo", "Présence sur les plateformes"],
    ["domain", "◎", "Domaine", "DNS, certificats et archives"],
    ["ip", "▦", "Adresse IP", "Allocation et réputation"],
    ["phone", "☎", "Téléphone", "Format et recherche publique"],
    ["social", "⌘", "Social", "Profils et moteurs spécialisés"],
    ["breach", "△", "Fuites", "Sources de compromission"],
    ["github", "◐", "GitHub", "Profil et activité publique"],
    ["image", "▧", "Image", "Recherche inversée et forensic"],
    ["crypto", "₿", "Crypto", "Explorateurs de blockchain"],
    ["people", "◇", "Personne", "Recherche exacte et corrélation"]
  ],
  recon: [
    ["overview", "◈", "Vue d’ensemble", "Plan de reconnaissance"],
    ["headers", "H", "HTTP Headers", "Posture des en-têtes"],
    ["tls", "⌁", "TLS / SSL", "Certificat et protocoles"],
    ["dns", "D", "DNS / Email", "DNSSEC, SPF et DMARC"],
    ["technology", "T", "Technologies", "Stack et empreintes"],
    ["archive", "A", "Archives", "Historique et URLs publiques"],
    ["exposure", "!", "Expositions", "Checklist non destructive"],
    ["external", "↗", "Outils externes", "Validateurs spécialisés"]
  ],
  discord: [
    ["discord-username", "@", "Username checker", "Vérifie si un username est déjà pris"]
  ]
};

const DETAILS = {
  auto: ["OSINT · AUTO", "Investigation automatique", "Détecte la cible et prépare les pivots publics pertinents."],
  email: ["OSINT · EMAIL", "Analyse d’adresse email", "Présence publique, réputation et sources de fuites."],
  username: ["OSINT · USERNAME", "Recherche de pseudonyme", "Profils publics et moteurs de présence multi-plateformes."],
  domain: ["OSINT · DOMAIN", "Intelligence domaine", "Enregistrement, DNS, certificats, réputation et archives."],
  ip: ["OSINT · IP", "Intelligence réseau", "Allocation, routage, réputation et exposition observée par des tiers."],
  phone: ["OSINT · PHONE", "Recherche téléphonique", "Normalisation locale et moteurs de recherche publics."],
  social: ["OSINT · SOCIAL", "Empreinte sociale", "Pivots adaptés au pseudo, au nom ou à l’adresse email."],
  breach: ["OSINT · BREACH", "Exposition dans les fuites", "Services publics et vérifications manuelles de compromission."],
  github: ["OSINT · GITHUB", "Intelligence GitHub", "Profil, dépôts, activité, clés et recherche de commits publics."],
  "discord-username": ["DISCORD · USERNAME", "Discord username checker", "Interroge Discord pour vérifier si un username est actuellement pris ou disponible."],
  image: ["OSINT · IMAGE", "Recherche visuelle", "Moteurs de recherche inversée et outils de métadonnées."],
  crypto: ["OSINT · CRYPTO", "Analyse de wallet", "Explorateurs publics Bitcoin et Ethereum."],
  people: ["OSINT · PEOPLE", "Recherche de personne", "Requêtes exactes, profils professionnels et publications."],
  overview: ["RECON · PLAN", "Plan de reconnaissance", "Checklist structurée pour une cible explicitement autorisée."],
  headers: ["RECON · HTTP", "Sécurité des en-têtes", "CSP, HSTS, framing, MIME et politiques navigateur."],
  tls: ["RECON · TLS", "Posture TLS", "Certificat, chaîne de confiance, protocoles et suites."],
  dns: ["RECON · DNS", "Sécurité DNS et email", "DNSSEC, CAA, SPF, DMARC, MTA-STS et TLS-RPT."],
  technology: ["RECON · STACK", "Empreinte technologique", "CMS, frameworks, CDN et composants exposés."],
  archive: ["RECON · ARCHIVE", "Surface historique", "URLs indexées, anciennes versions et certificats publics."],
  exposure: ["RECON · EXPOSURE", "Expositions à vérifier", "Contrôles manuels limités et non destructifs."],
  external: ["RECON · EXTERNAL", "Validateurs externes", "Services spécialisés déclenchés uniquement au clic."]
};

function escapeCsv(value) {
  let text = String(value ?? "");
  if (/^[=+\-@]/.test(text)) text = `'${text}`;
  return `"${text.replaceAll('"', '""')}"`;
}
function encode(value) { return encodeURIComponent(value); }
function finding(group, label, value, url = "", note = "", confidence = "manual") { return { group, label, value, url, note, confidence }; }
function httpsUrl(value) { try { const url = new URL(value); return url.protocol === "https:" ? url.href : ""; } catch (_) { return ""; } }

function cleanTarget(value) {
  const clean = value.trim();
  if (!clean) throw new Error("Saisissez une cible.");
  if (clean.length > 500 || /[\u0000-\u001f\u007f]/.test(clean)) throw new Error("La cible contient des caractères invalides.");
  return clean;
}

function detectType(value) {
  if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value)) return "email";
  if (/^0x[a-f0-9]{40}$/i.test(value)) return "crypto-eth";
  if (/^(?:bc1|[13])[a-zA-HJ-NP-Z0-9]{25,62}$/.test(value)) return "crypto-btc";
  if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(value)) {
    if (value.split(".").every(part => Number(part) <= 255)) return "ip";
    return "unknown";
  }
  if (value.includes(":") && /^[0-9a-f:]+$/i.test(value)) return "ip";
  const digits = value.replace(/\D/g, "");
  if (/^\+?[\d\s()./-]+$/.test(value) && digits.length >= 7 && digits.length <= 15) return "phone";
  if (/^https?:\/\//i.test(value)) return /\.(?:png|jpe?g|gif|webp|bmp)(?:\?|$)/i.test(value) ? "image" : "url";
  if (!value.includes(" ") && /^[a-z0-9.-]+\.[a-z]{2,}$/i.test(value)) return "domain";
  if (/\s/.test(value)) return "name";
  return "username";
}

async function fetchJson(url, timeout = 8000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);
  try {
    const response = await fetch(url, { headers: { Accept: "application/json" }, signal: controller.signal });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    return await response.json();
  } finally { clearTimeout(timer); }
}

async function backendOsint(target, detected, module) {
  let selected = module === "auto" ? detected : module;
  const aliases = {
    "crypto-btc": "crypto",
    "crypto-eth": "crypto",
    name: "social",
    people: "social"
  };
  selected = aliases[selected] || selected;
  if (selected === "url" || selected === "web") {
    return [finding("Backend Nexus", "Module indisponible", "Les URLs arbitraires sont bloquées sur l’API Web pour éviter le SSRF.", "", "Utilisez les pivots locaux ou un domaine explicite.", "low")];
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 65000);
  try {
    const response = await fetch("./api/osint/scan", {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target, module: selected, timeout: 30 }),
      signal: controller.signal
    });
    if (response.status === 401) {
      location.replace("./login.html");
      throw new Error("Session expirée");
    }
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(data.detail || `API Nexus HTTP ${response.status}`);
    const rows = (data.findings || []).map(item => finding(
      `Backend · ${item.source}`,
      item.label,
      typeof item.value === "string" ? item.value : JSON.stringify(item.value),
      item.url || "",
      "Résultat produit par le moteur Python Nexus.",
      item.severity === "found" ? "live" : item.severity === "warn" ? "low" : "high"
    ));
    for (const message of data.errors || []) {
      rows.push(finding("Backend · erreurs", "Source indisponible", message, "", "Le scan continue avec les autres sources.", "low"));
    }
    return rows.length ? rows : [finding("Backend Nexus", "Aucun résultat", "Le module n’a retourné aucune observation.", "", "", "low")];
  } catch (error) {
    if (error.name === "AbortError") throw new Error("Le backend Nexus a dépassé le délai autorisé.");
    throw error;
  } finally {
    clearTimeout(timer);
  }
}

async function liveDns(host) {
  const types = ["A", "AAAA", "MX", "TXT"];
  const settled = await Promise.allSettled(types.map(type => fetchJson(`https://dns.google/resolve?name=${encode(host)}&type=${type}`)));
  const rows = [];
  settled.forEach((result, index) => {
    if (result.status !== "fulfilled") return;
    const answers = (result.value.Answer || []).map(answer => String(answer.data)).slice(0, 6);
    if (answers.length) rows.push(finding("Données en direct", `DNS ${types[index]}`, answers.join(" · ").slice(0, 700), "", "Réponse Google Public DNS reçue maintenant.", "live"));
  });
  return rows;
}

async function liveGithub(target) {
  const user = target.replace(/^@/, "");
  const data = await fetchJson(`https://api.github.com/users/${encode(user)}`);
  return [
    finding("Données en direct", "Profil GitHub", data.login || user, data.html_url || `https://github.com/${encode(user)}`, "Correspondance exacte via l’API GitHub.", "live"),
    finding("Données en direct", "Nom déclaré", data.name || "non renseigné", "", "Champ public du profil.", "live"),
    finding("Données en direct", "Dépôts / abonnés", `${data.public_repos || 0} dépôts · ${data.followers || 0} abonnés`, "", "Compteurs publics actuels.", "live")
  ];
}

async function liveIp(target) {
  const data = await fetchJson(`https://ipwho.is/${encode(target)}`);
  if (data.success === false) throw new Error(data.message || "IP indisponible");
  return [finding("Données en direct", "Réseau", `${data.connection?.isp || "inconnu"} · ASN ${data.connection?.asn || "?"}`, "", "Géolocalisation approximative fournie par un tiers.", "live"),
    finding("Données en direct", "Zone approximative", [data.city, data.region, data.country].filter(Boolean).join(", ") || "inconnue", "", "Ne permet pas de localiser une personne.", "live")];
}

async function liveBitcoin(target) {
  const data = await fetchJson(`https://mempool.space/api/address/${encode(target)}`);
  const funded = Number(data.chain_stats?.funded_txo_sum || 0), spent = Number(data.chain_stats?.spent_txo_sum || 0);
  return [finding("Données en direct", "Solde confirmé", `${((funded - spent) / 100000000).toFixed(8)} BTC`, `https://mempool.space/address/${encode(target)}`, "Calculé depuis les statistiques publiques de la chaîne.", "live"),
    finding("Données en direct", "Transactions financées", String(data.chain_stats?.funded_txo_count || 0), "", "Donnée on-chain publique.", "live")];
}

async function liveEnrichment(target, detected, module) {
  try {
    if (BACKEND_AUTH) return await backendOsint(target, detected, module);
    if (detected === "ip" && !target.includes(":")) return await liveIp(target);
    if (detected === "crypto-btc") return await liveBitcoin(target);
    if (module === "github" || detected === "username") return await liveGithub(target);
    if (["domain", "url", "email"].includes(detected)) {
      const host = detected === "email" ? target.split("@")[1] : hostOf(target);
      return await liveDns(host);
    }
    return [finding("Données en direct", "Information", "Aucun collecteur passif compatible avec ce type", "", "Les pivots manuels restent disponibles.", "low")];
  } catch (error) {
    return [finding("Données en direct", "Source indisponible", error.name === "AbortError" ? "délai dépassé" : error.message, "", "Une limitation CORS, réseau ou de quota peut être temporaire.", "low")];
  }
}

function hostOf(value) {
  try {
    const url = new URL(/^https?:\/\//i.test(value) ? value : `https://${value}`);
    if (!url.hostname.includes(".")) throw new Error();
    return url.hostname.toLowerCase();
  } catch (_) { throw new Error("Ce module attend un domaine ou une URL HTTP(S) valide."); }
}

function commonSearch(target) {
  return [finding("Recherche", "Recherche exacte", "Google", `https://www.google.com/search?q=${encode(`"${target}"`)}`, "Recouper les résultats avant toute attribution.")];
}

function emailFindings(target) {
  const [local, domain] = target.split("@");
  return [...commonSearch(target),
    finding("Fuites", "Have I Been Pwned", "Vérifier l’exposition", `https://haveibeenpwned.com/account/${encode(target)}`, "Ne révèle pas les mots de passe."),
    finding("Identité", "Epieos", "Recherche email", `https://epieos.com/?q=${encode(target)}`, "Service tiers, conditions propres."),
    finding("Archives", "IntelX", "Recherche publique", `https://intelx.io/?s=${encode(target)}`),
    finding("Domaine", "ICANN Lookup", domain, `https://lookup.icann.org/en/lookup?name=${encode(domain)}`),
    finding("Pivot", "Pseudo probable", local, `https://github.com/${encode(local)}`, "Une correspondance ne prouve pas l’identité.", "low")];
}

function usernameFindings(target) {
  const q = encode(target);
  return [...commonSearch(target),
    finding("Profils", "GitHub", target, `https://github.com/${q}`), finding("Profils", "GitLab", target, `https://gitlab.com/${q}`),
    finding("Profils", "Reddit", target, `https://www.reddit.com/user/${q}`), finding("Profils", "Keybase", target, `https://keybase.io/${q}`),
    finding("Profils", "Medium", target, `https://medium.com/@${q}`), finding("Profils", "Dev.to", target, `https://dev.to/${q}`),
    finding("Moteurs", "WhatsMyName", "Vérification multi-sites", "https://whatsmyname.app/"),
    finding("Moteurs", "IDCrawl", target, `https://www.idcrawl.com/u/${q}`), finding("Moteurs", "Namechk", target, `https://namechk.com/`)
  ];
}

async function checkDiscordUsername(target, timeout = 8000) {
  const username = target.trim().replace(/^@/, "").toLowerCase();
  if (!/^[a-z0-9._]{2,32}$/.test(username) || username.includes("..")) {
    throw new Error("Username invalide : utilisez 2 à 32 caractères minuscules, chiffres, points ou underscores.");
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);
  try {
    const response = await fetch("https://discord.com/api/v9/unique-username/username-attempt-unauthed", {
      method: "POST",
      credentials: "include",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username }),
      signal: controller.signal
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok || typeof data.taken !== "boolean") {
      const detail = data.errors?.username?._errors?.[0]?.message || data.message || `HTTP ${response.status}`;
      throw new Error(`Discord a refusé la vérification : ${detail}`);
    }
    return [
      finding("Discord", "Username vérifié", `@${username}`, "", "Requête envoyée directement à Discord.", "live"),
      finding(
        "Disponibilité",
        data.taken ? "Déjà pris" : "Disponible",
        data.taken ? `@${username} est actuellement utilisé` : `@${username} est actuellement disponible`,
        "",
        "Le statut peut changer à tout moment et Discord reste l’autorité finale.",
        data.taken ? "low" : "live"
      )
    ];
  } catch (error) {
    if (error.name === "AbortError") throw new Error("Discord n’a pas répondu dans le délai prévu.");
    throw error;
  } finally {
    clearTimeout(timer);
  }
}

function domainFindings(target) {
  const host = hostOf(target), q = encode(host);
  return [
    finding("Registre", "ICANN Lookup", host, `https://lookup.icann.org/en/lookup?name=${q}`),
    finding("DNS", "Google Dig", "Enregistrements publics", `https://toolbox.googleapps.com/apps/dig/#ANY/${q}`),
    finding("Certificats", "crt.sh", "Sous-domaines historiques", `https://crt.sh/?q=${encode(`%.${host}`)}`),
    finding("Archives", "Wayback Machine", "Historique du site", `https://web.archive.org/web/*/${q}`),
    finding("URLs", "urlscan.io", "Recherches publiques", `https://urlscan.io/search/#domain:${q}`),
    finding("Réputation", "VirusTotal", host, `https://www.virustotal.com/gui/domain/${q}`),
    finding("Threat intel", "AlienVault OTX", host, `https://otx.alienvault.com/indicator/domain/${q}`),
    finding("Technologies", "BuiltWith", host, `https://builtwith.com/${q}`),
    finding("Historique", "SecurityTrails", host, `https://securitytrails.com/domain/${q}/history/a`)
  ];
}

function ipFindings(target) {
  const q = encode(target);
  return [finding("Allocation", "RIPEstat", target, `https://stat.ripe.net/${q}`),
    finding("Routage", "BGP Toolkit", target, `https://bgp.he.net/ip/${q}`), finding("Contexte", "IPinfo", target, `https://ipinfo.io/${q}`),
    finding("Réputation", "VirusTotal", target, `https://www.virustotal.com/gui/ip-address/${q}`),
    finding("Réputation", "AbuseIPDB", target, `https://www.abuseipdb.com/check/${q}`),
    finding("Services observés", "Shodan", target, `https://www.shodan.io/host/${q}`, "Résultats de scans tiers ; un port ouvert n’est pas une faille."),
    finding("Threat intel", "AlienVault OTX", target, `https://otx.alienvault.com/indicator/ip/${q}`)];
}

function phoneFindings(target) {
  const digits = target.replace(/\D/g, "");
  return [finding("Normalisation", "Chiffres détectés", digits, "", "Le plan peut être ambigu sans indicatif pays.", "low"), ...commonSearch(target),
    finding("Recherche", "Tellows", target, `https://www.tellows.com/num/${encode(digits)}`),
    finding("Recherche", "Truecaller", "Recherche manuelle", "https://www.truecaller.com/"),
    finding("Recherche", "Sync.me", "Recherche manuelle", "https://sync.me/"),
    finding("Prudence", "Attribution", "Numéro valide ≠ numéro actif ni identité confirmée", "", "La portabilité rend aussi l’opérateur d’origine peu fiable.", "low")];
}

function peopleFindings(target) {
  return [...commonSearch(target),
    finding("Professionnel", "LinkedIn via Google", target, `https://www.google.com/search?q=${encode(`site:linkedin.com/in "${target}"`)}`),
    finding("Code", "GitHub users", target, `https://github.com/search?q=${encode(target)}&type=users`),
    finding("Publications", "Google Scholar", target, `https://scholar.google.com/scholar?q=${encode(`"${target}"`)}`),
    finding("Actualité", "Google News", target, `https://news.google.com/search?q=${encode(target)}`),
    finding("Entreprises", "OpenCorporates", target, `https://opencorporates.com/officers?q=${encode(target)}`),
    finding("Prudence", "Homonymie", "Comparer plusieurs attributs indépendants", "", "Nom seul insuffisant pour attribuer une identité.", "low")];
}

function cryptoFindings(target, type) {
  const q = encode(target);
  if (type === "crypto-eth") return [
    finding("Ethereum", "Etherscan", target, `https://etherscan.io/address/${q}`), finding("Multi-chain", "Blockchair", target, `https://blockchair.com/ethereum/address/${q}`),
    finding("Tokens", "Ethplorer", target, `https://ethplorer.io/address/${q}`), finding("Analyse", "Arkham", "Recherche manuelle", "https://platform.arkhamintelligence.com/")];
  return [finding("Bitcoin", "mempool.space", target, `https://mempool.space/address/${q}`),
    finding("Bitcoin", "Blockchain.com", target, `https://www.blockchain.com/explorer/addresses/btc/${q}`),
    finding("Multi-chain", "Blockchair", target, `https://blockchair.com/bitcoin/address/${q}`),
    finding("Analyse", "WalletExplorer", target, `https://www.walletexplorer.com/address/${q}`),
    finding("Prudence", "Attribution", "Une adresse publique ne prouve pas l’identité de son détenteur", "", "Les heuristiques on-chain restent probabilistes.", "low")];
}

function imageFindings(target) {
  const q = encode(target);
  return [finding("Recherche inversée", "Google Lens", "Ouvrir l’image", `https://lens.google.com/uploadbyurl?url=${q}`),
    finding("Recherche inversée", "Yandex Images", "Recherche par URL", `https://yandex.com/images/search?rpt=imageview&url=${q}`),
    finding("Recherche inversée", "TinEye", "Recherche par URL", `https://tineye.com/search?url=${q}`),
    finding("Forensic", "FotoForensics", "Téléversement manuel", "https://fotoforensics.com/"),
    finding("Métadonnées", "Metadata2Go", "Téléversement manuel", "https://www.metadata2go.com/"),
    finding("Vie privée", "Attention", "Téléverser une image la transmet au service choisi", "", "Vérifier les conditions avant tout envoi.", "low")];
}

function githubFindings(target) {
  const user = target.replace(/^@/, ""), q = encode(user);
  return [finding("Profil", "GitHub", user, `https://github.com/${q}`),
    finding("Dépôts", "Repositories", user, `https://github.com/${q}?tab=repositories`),
    finding("Activité", "Public events", user, `https://github.com/${q}?tab=overview`),
    finding("Gists", "Public gists", user, `https://gist.github.com/${q}`),
    finding("Clés", "SSH keys", user, `https://github.com/${q}.keys`),
    finding("Recherche", "Commits publics", user, `https://github.com/search?q=${encode(`author:${user}`)}&type=commits`)];
}

function breachFindings(target) {
  const q = encode(target);
  return [finding("Vérification", "Have I Been Pwned", target, `https://haveibeenpwned.com/account/${q}`),
    finding("Recherche", "IntelX", target, `https://intelx.io/?s=${q}`), finding("Recherche", "DeHashed", target, `https://www.dehashed.com/search?query=${q}`),
    finding("Recherche", "LeakCheck", target, `https://leakcheck.io/?query=${q}`),
    finding("Sécurité", "Consigne", "Ne jamais réutiliser ni afficher un secret trouvé", "", "Changer les identifiants compromis et activer la MFA.")];
}

function socialFindings(target, type) {
  if (type === "email") return emailFindings(target).filter(row => ["Identité", "Pivot", "Recherche"].includes(row.group));
  if (type === "name") return peopleFindings(target);
  return usernameFindings(target);
}

function reconFindings(target, module) {
  const host = hostOf(target), q = encode(host);
  const catalog = {
    headers: [finding("HTTP", "Security Headers", host, `https://securityheaders.com/?q=${q}&followRedirects=on`, "Contrôler CSP, HSTS, framing et MIME."), finding("HTTP", "Mozilla Observatory", host, `https://developer.mozilla.org/en-US/observatory/analyze?host=${q}`)],
    tls: [finding("TLS", "SSL Labs", host, `https://www.ssllabs.com/ssltest/analyze.html?d=${q}`), finding("TLS", "Hardenize", host, `https://www.hardenize.com/report/${q}`)],
    dns: [finding("DNS", "Internet.nl", host, `https://internet.nl/site/${q}/`), finding("DNS", "Google Dig", host, `https://toolbox.googleapps.com/apps/dig/#ANY/${q}`), finding("Email", "MXToolbox", host, `https://mxtoolbox.com/SuperTool.aspx?action=mx%3a${q}`)],
    technology: [finding("Stack", "BuiltWith", host, `https://builtwith.com/${q}`), finding("Stack", "Wappalyzer", "Extension ou lookup", `https://www.wappalyzer.com/lookup/${q}/`), finding("Scan public", "urlscan.io", host, `https://urlscan.io/search/#domain:${q}`)],
    archive: [finding("Archive", "Wayback Machine", host, `https://web.archive.org/web/*/${q}`), finding("URLs", "urlscan.io", host, `https://urlscan.io/search/#domain:${q}`), finding("Certificats", "crt.sh", host, `https://crt.sh/?q=${encode(`%.${host}`)}`)],
    exposure: [finding("Manuel", "security.txt", `https://${host}/.well-known/security.txt`, `https://${host}/.well-known/security.txt`, "Arrêter si la route exige une authentification."), finding("Manuel", "robots.txt", `https://${host}/robots.txt`, `https://${host}/robots.txt`), finding("Checklist", "Fichiers sensibles", ".env, .git, sauvegardes, OpenAPI, source maps", "", "Ne pas contourner une restriction et ne conserver aucun secret."), finding("Checklist", "Contrôles authentifiés", "Autorisations objet, sessions et logique métier", "", "Nécessitent plusieurs comptes de test et un contexte métier.")],
    external: [finding("Validation", "SSL Labs", host, `https://www.ssllabs.com/ssltest/analyze.html?d=${q}`), finding("Validation", "Internet.nl", host, `https://internet.nl/site/${q}/`), finding("Réputation", "VirusTotal", host, `https://www.virustotal.com/gui/domain/${q}`), finding("Observation tierce", "Shodan", host, `https://www.shodan.io/search?query=hostname%3A${q}`)]
  };
  if (module !== "overview") return catalog[module] || [];
  return Object.entries(catalog).flatMap(([name, rows]) => rows.slice(0, 1).map(row => ({ ...row, group: DETAILS[name][1] })));
}

function osintFindings(target, module, detected) {
  const chosen = module === "auto" ? detected : module;
  if (chosen === "email") return emailFindings(target);
  if (chosen === "username") return usernameFindings(target);
  if (chosen === "domain" || chosen === "url") return domainFindings(target);
  if (chosen === "ip") return ipFindings(target);
  if (chosen === "phone") return phoneFindings(target);
  if (chosen === "name" || chosen === "people") return peopleFindings(target);
  if (chosen === "crypto" || chosen.startsWith("crypto-")) return cryptoFindings(target, detected.startsWith("crypto-") ? detected : "crypto-btc");
  if (chosen === "image") return imageFindings(target);
  if (chosen === "github") return githubFindings(target);
  if (chosen === "breach") return breachFindings(target);
  if (chosen === "social") return socialFindings(target, detected);
  throw new Error("Type de cible non reconnu pour ce module.");
}

function renderModules() {
  const list = $("#module-list"); list.replaceChildren();
  MODULES[state.category].forEach(([id, icon, label, description], index) => {
    const button = document.createElement("button"); button.type = "button"; button.className = `module-button${id === state.module ? " active" : ""}`;
    button.innerHTML = `<span>${icon}</span><div><b>${label}</b><small>${description}</small></div>`;
    button.addEventListener("click", () => selectModule(id)); list.append(button);
    if (index === 0 && !MODULES[state.category].some(row => row[0] === state.module)) selectModule(id);
  });
}

function selectModule(id) {
  state.module = id;
  document.querySelectorAll(".module-button").forEach((button, index) => button.classList.toggle("active", MODULES[state.category][index]?.[0] === id));
  const [kicker, title, description] = DETAILS[id]; $("#module-kicker").textContent = kicker; $("#module-title").textContent = title; $("#module-description").textContent = description;
  $("#authorization-wrap").hidden = state.category !== "recon";
  $("#live-wrap").hidden = state.category !== "osint";
  $("#privacy-note").textContent = state.category === "recon"
    ? "Planification locale · les outils externes s’ouvrent uniquement au clic"
    : state.category === "discord"
      ? "Vérification en direct · le username est transmis à Discord"
      : ($("#live-passive").checked ? "Mode passif · la cible sera transmise aux API publiques nécessaires" : "Mode local · aucune cible transmise automatiquement");
}

function renderResults(rows) {
  const container = $("#results"); container.replaceChildren();
  const groups = new Map();
  rows.forEach(row => groups.set(row.group, [...(groups.get(row.group) || []), row]));
  for (const [group, items] of groups) {
    const section = document.createElement("section"); section.className = "result-group";
    const heading = document.createElement("div"); heading.className = "result-heading"; heading.innerHTML = `<h2>${group}</h2><span>${items.length} résultat${items.length > 1 ? "s" : ""}</span>`; section.append(heading);
    items.forEach(item => {
      const row = document.createElement("article"); row.className = "result-item";
      const marker = document.createElement("span"); marker.className = `result-marker ${item.confidence}`; marker.textContent = item.url ? "↗" : "·";
      const content = document.createElement("div"); const title = document.createElement("b"); title.textContent = item.label;
      if (item.confidence === "live") { const badge = document.createElement("span"); badge.className = "live-badge"; badge.textContent = "LIVE"; title.append(" ", badge); }
      const value = item.url ? document.createElement("a") : document.createElement("p"); value.textContent = item.value;
      if (item.url) { value.href = httpsUrl(item.url); value.target = "_blank"; value.rel = "noopener noreferrer"; }
      content.append(title, value); if (item.note) { const note = document.createElement("small"); note.textContent = item.note; content.append(note); }
      row.append(marker, content); section.append(row);
    });
    container.append(section);
  }
}

function readHistory() {
  try { const rows = JSON.parse(localStorage.getItem(HISTORY_KEY) || "[]"); return Array.isArray(rows) ? rows.slice(0, 12) : []; }
  catch (_) { return []; }
}

function saveHistory(report) {
  const entry = { target: report.target, category: report.category, module: report.module, detected: report.detected, date: report.generatedAt };
  const rows = [entry, ...readHistory().filter(row => !(row.target === entry.target && row.module === entry.module))].slice(0, 12);
  localStorage.setItem(HISTORY_KEY, JSON.stringify(rows)); renderHistory();
}

function renderHistory() {
  const container = $("#history-list"), rows = readHistory(); container.replaceChildren();
  if (!rows.length) { const empty = document.createElement("p"); empty.className = "history-empty"; empty.textContent = "Aucune analyse récente"; container.append(empty); return; }
  rows.forEach(row => {
    const button = document.createElement("button"); button.type = "button";
    const name = document.createElement("b"); name.textContent = row.target;
    const meta = document.createElement("small"); meta.textContent = `${row.category} · ${row.module}`;
    button.append(name, meta); button.addEventListener("click", () => {
      state.category = row.category; state.module = row.module;
      document.querySelectorAll(".category-button").forEach(item => item.classList.toggle("active", item.dataset.category === state.category));
      renderModules(); selectModule(state.module); $("#target").value = row.target;
    }); container.append(button);
  });
}

async function run() {
  try {
    const target = cleanTarget($("#target").value), detected = detectType(target);
    if (detected === "unknown") throw new Error("Le format de la cible n’est pas valide.");
    if (state.category === "recon" && !$("#authorized").checked) throw new Error("Confirmez votre autorisation explicite avant de préparer la reconnaissance.");
    const button = $("#run"); button.disabled = true; button.classList.add("running"); button.firstChild.textContent = "Analyse… ";
    let findings;
    if (state.category === "recon") findings = reconFindings(target, state.module);
    else if (state.category === "discord") findings = await checkDiscordUsername(target);
    else findings = osintFindings(target, state.module, detected);
    if ($("#live-passive").checked && state.category === "osint") findings = [...await liveEnrichment(target, detected, state.module), ...findings];
    state.report = { target, detected, category: state.category, module: state.module, generatedAt: new Date().toISOString(), findings };
    saveHistory(state.report);
    $("#empty-state").hidden = true; $("#run-summary").hidden = false;
    $("#summary-title").textContent = `${findings.length} pivot${findings.length > 1 ? "s" : ""} préparé${findings.length > 1 ? "s" : ""}`;
    $("#summary-meta").textContent = state.category === "discord"
      ? "Discord · vérification en direct"
      : `Type ${detected} · ${$("#live-passive").checked ? "enrichissement passif demandé" : "mode local"}`;
    renderResults(findings);
  } catch (error) {
    $("#empty-state").hidden = false; $("#empty-state h2").textContent = "Impossible de préparer l’analyse"; $("#empty-state p").textContent = error.message;
    $("#results").replaceChildren(); $("#run-summary").hidden = true;
  } finally {
    const button = $("#run"); button.disabled = false; button.classList.remove("running"); button.firstChild.textContent = "Lancer ";
  }
}

function download(format) {
  if (!state.report) return;
  const { target, findings } = state.report; let content, mime;
  if (format === "json") { content = JSON.stringify(state.report, null, 2); mime = "application/json"; }
  else if (format === "csv") { content = "\ufeff" + [["group", "label", "value", "note", "url"], ...findings.map(row => [row.group, row.label, row.value, row.note, row.url])].map(line => line.map(escapeCsv).join(",")).join("\n"); mime = "text/csv"; }
  else { content = [`# Rapport Nexus`, "", `Cible : ${target}`, `Module : ${state.report.module}`, `Généré : ${state.report.generatedAt}`, "", ...findings.flatMap(row => [`## ${row.group} · ${row.label}`, row.value, row.note || "", row.url || "", ""])].join("\n"); mime = "text/markdown"; }
  const url = URL.createObjectURL(new Blob([content], { type: mime })); const a = document.createElement("a"); a.href = url; a.download = `nexus-${state.report.module}.${format === "md" ? "md" : format}`; a.click(); setTimeout(() => URL.revokeObjectURL(url), 0);
}

document.querySelectorAll(".category-button").forEach(button => button.addEventListener("click", () => {
  state.category = button.dataset.category; state.module = MODULES[state.category][0][0];
  document.querySelectorAll(".category-button").forEach(item => item.classList.toggle("active", item === button)); renderModules(); selectModule(state.module);
}));
$("#run").addEventListener("click", run); $("#target").addEventListener("keydown", event => { if (event.key === "Enter") run(); });
document.querySelectorAll(".quick-targets button").forEach(button => button.addEventListener("click", () => { $("#target").value = button.dataset.value; run(); }));
document.querySelectorAll(".export").forEach(button => button.addEventListener("click", () => download(button.dataset.format)));
$("#copy-report").addEventListener("click", async () => {
  if (!state.report) return;
  const text = state.report.findings.map(row => `[${row.group}] ${row.label}: ${row.value}${row.url ? ` — ${row.url}` : ""}`).join("\n");
  try { await navigator.clipboard.writeText(text); $("#copy-report").textContent = "Copié ✓"; setTimeout(() => $("#copy-report").textContent = "Copier", 1400); }
  catch (_) { $("#copy-report").textContent = "Échec"; }
});
$("#clear-history").addEventListener("click", () => { localStorage.removeItem(HISTORY_KEY); renderHistory(); });
$("#live-passive").addEventListener("change", event => { $("#privacy-note").textContent = event.target.checked ? "Mode passif · la cible sera transmise aux API publiques nécessaires" : "Mode local · aucune cible transmise automatiquement"; });
if (BACKEND_AUTH) {
  $("#live-passive").checked = true;
  $("#privacy-note").textContent = "Backend Nexus · enrichissement Python activé";
}
renderModules(); selectModule("auto"); renderHistory();
