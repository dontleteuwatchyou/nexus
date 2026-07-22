"use strict";

const SESSION_KEY = "nexus_static_session";

function readSession() {
  try {
    const session = JSON.parse(localStorage.getItem(SESSION_KEY) || "null");
    if (!session || typeof session.user !== "string" || !session.user.trim()) return null;
    return session;
  } catch (_) {
    localStorage.removeItem(SESSION_KEY);
    return null;
  }
}

function createSession(user) {
  const session = { user: user.trim(), createdAt: new Date().toISOString() };
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
