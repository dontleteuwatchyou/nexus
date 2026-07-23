# Breach and infostealer interpretation

Pour interpréter 1 000 entrées de fuite associées à un pseudo, décrire
exactement 1 000 correspondances de la chaîne dans l'index du fournisseur.
Elles sont non attribuées : elles ne prouvent pas qu'une personne possède les
comptes concernés ni qu'elle est victime de toutes les fuites.

Breach search results are index matches, not automatic identity attribution.
For a username query, the same string may represent many unrelated people.
Counts from a provider describe matching records or computers in that
provider's index; they do not prove that one person owns every record.

Use precise language:

- Say “the provider returned three infostealer records matching the queried
  username”, not “the subject has three infected computers”.
- Say “1,000 indexed entries match the identifier”, not “the subject exposed
  1,000 credentials”.
- Treat a provider summary as a lead until a stable attribute such as an exact
  authorised email, domain, account identifier or verified cross-link
  correlates it.
- A manual-search link is not a positive result.
- A `Clean`, `None found`, error or timeout is not proof that no exposure
  exists.

Do not reveal passwords, tokens, session cookies, personal records or raw
breach data. Prefer notification, password rotation, unique passwords, MFA,
session revocation, endpoint malware checks and monitoring. Clearly separate
provider observation, analyst inference, confidence, limitations and
defensive next steps.
