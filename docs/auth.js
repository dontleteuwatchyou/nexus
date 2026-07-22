"use strict";

const SESSION_KEY = "nexus_static_session";
const SESSION_VERSION = 2;
const AUTHORIZED_USERS = new Set(["4wmk", "Codex", "sam"]);

function readSession() {
  try {
    const session = JSON.parse(localStorage.getItem(SESSION_KEY) || "null");
    if (!session || session.version !== SESSION_VERSION ||
        typeof session.user !== "string" || !AUTHORIZED_USERS.has(session.user)) {
      localStorage.removeItem(SESSION_KEY);
      return null;
    }
    return session;
  } catch (_) {
    localStorage.removeItem(SESSION_KEY);
    return null;
  }
}

function createSession(user) {
  if (!AUTHORIZED_USERS.has(user)) throw new Error("Utilisateur non autorisé.");
  const session = {
    user,
    version: SESSION_VERSION,
    createdAt: new Date().toISOString()
  };
  localStorage.setItem(SESSION_KEY, JSON.stringify(session));
  return session;
}

function clearSession() {
  localStorage.removeItem(SESSION_KEY);
}

function requireSession() {
  const session = readSession();
  if (!session) {
    window.location.replace("./login.html");
    return null;
  }
  return session;
}
