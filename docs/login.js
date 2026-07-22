"use strict";

if (readSession()) window.location.replace("./app.html");

const AUTHORIZED_ACCOUNTS = new Map([
  ["4wmk", "67a855fcab8897aaebed6a1ceda44d926d281ed627b997c333192676ec2786de"],
  ["Codex", "f778e280e889cc81cee59e1eac6de7856dc73bd96fda1311f1bf93558a61f50e"],
  ["sam", "a490517d9bcd44c8aa207ea359278804d2f60348966fbf13c7aa659e4b7e348f"]
]);

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

  const expectedHash = AUTHORIZED_ACCOUNTS.get(user);
  const submittedHash = await credentialHash(user, password);
  if (!expectedHash || submittedHash !== expectedHash) {
    error.textContent = "Identifiant ou mot de passe incorrect.";
    error.hidden = false;
    return;
  }
  error.hidden = true;
  createSession(user);
  window.location.replace("./app.html");
});
