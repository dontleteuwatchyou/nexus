"use strict";

if (readSession()) window.location.replace("./app.html");

document.querySelector("#login-form").addEventListener("submit", (event) => {
  event.preventDefault();
  const user = document.querySelector("#username").value.trim();
  const password = document.querySelector("#password").value;
  const error = document.querySelector("#login-error");

  if (!user || password.length < 4) {
    error.textContent = "Saisissez un identifiant et un mot de passe d’au moins 4 caractères.";
    error.hidden = false;
    return;
  }
  createSession(user);
  window.location.replace("./app.html");
});
