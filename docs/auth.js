"use strict";

const SESSION_KEY = "nexus_static_session";
const SESSION_VERSION = 3;
const BACKEND_AUTH = location.protocol !== "file:" && !location.hostname.endsWith("github.io");
const AUTHORIZED_PROOFS = new Set([
  "67a855fcab8897aaebed6a1ceda44d926d281ed627b997c333192676ec2786de",
  "f778e280e889cc81cee59e1eac6de7856dc73bd96fda1311f1bf93558a61f50e",
  "a490517d9bcd44c8aa207ea359278804d2f60348966fbf13c7aa659e4b7e348f"
]);

function readSession() {
  if (BACKEND_AUTH) return { user: "session", backend: true };
  try {
    const session = JSON.parse(localStorage.getItem(SESSION_KEY) || "null");
    if (!session || session.version !== SESSION_VERSION ||
        typeof session.user !== "string" ||
        typeof session.proof !== "string" || !AUTHORIZED_PROOFS.has(session.proof)) {
      localStorage.removeItem(SESSION_KEY);
      return null;
    }
    return session;
  } catch (_) {
    localStorage.removeItem(SESSION_KEY);
    return null;
  }
}

function createSession(user, proof) {
  if (!AUTHORIZED_PROOFS.has(proof)) throw new Error("Utilisateur non autorisé.");
  const session = {
    user,
    proof,
    version: SESSION_VERSION,
    createdAt: new Date().toISOString()
  };
  localStorage.setItem(SESSION_KEY, JSON.stringify(session));
  return session;
}

function clearSession() {
  if (BACKEND_AUTH) {
    fetch("./api/auth/logout", {
      method: "POST",
      credentials: "same-origin",
      keepalive: true
    }).catch(() => {});
  }
  localStorage.removeItem(SESSION_KEY);
}

function requireSession() {
  if (BACKEND_AUTH) {
    fetch("./api/auth/session", { credentials: "same-origin" })
      .then(async response => {
        if (!response.ok) throw new Error("Session invalide");
        const session = await response.json();
        const label = document.querySelector("#session-user");
        if (label) label.textContent = session.user;
      })
      .catch(() => window.location.replace("./login.html"));
    return { user: "session", backend: true };
  }
  const session = readSession();
  if (!session) {
    window.location.replace("./login.html");
    return null;
  }
  return session;
}
