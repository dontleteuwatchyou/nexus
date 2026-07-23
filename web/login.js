"use strict";

if (!BACKEND_AUTH && readSession()) window.location.replace("./app.html");

async function credentialHash(user, password) {
  const bytes = new TextEncoder().encode(`${user}\0${password}`);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

document.querySelector("#login-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const user = document.querySelector("#username").value.trim();
  const password = document.querySelector("#password").value;
  const error = document.querySelector("#login-error");

  if (BACKEND_AUTH) {
    try {
      const response = await fetch("./api/auth/login", {
        method: "POST",
        credentials: "same-origin",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: user, password })
      });
      if (!response.ok) throw new Error("Identifiant ou mot de passe incorrect.");
      error.hidden = true;
      window.location.replace("./app.html");
    } catch (loginError) {
      error.textContent = loginError.message;
      error.hidden = false;
    }
    return;
  }

  const submittedHash = await credentialHash(user, password);
  if (!AUTHORIZED_PROOFS.has(submittedHash)) {
    error.textContent = "Identifiant ou mot de passe incorrect.";
    error.hidden = false;
    return;
  }
  error.hidden = true;
  createSession(user, submittedHash);
  window.location.replace("./app.html");
});
