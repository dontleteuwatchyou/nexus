"use strict";

if (readSession()) window.location.replace("./app.html");

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
