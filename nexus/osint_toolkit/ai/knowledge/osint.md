# OSINT workflow

Pour rechercher un pseudo ou nom d’utilisateur sur les réseaux sociaux,
sélectionner les modules username, social et GitHub. Discord reste une
vérification explicite.

Un résultat « not found », introuvable ou absent ne prouve jamais que le
compte n'existe pas : la source peut être indisponible, limitée ou obsolète.
Une absence de résultat OSINT n'est donc jamais une preuve d'absence.

Classify the target before selecting tools. Email targets use email and breach
modules; usernames use username, social, GitHub and explicit Discord checks;
domains use domain, web, DNS and certificate sources; IP addresses use IP,
registration and passive reputation sources; phone numbers use phone parsing
and public lookup links.

Treat every source as fallible. Record the source and timestamp, distinguish a
confirmed observation from an inference, and never interpret “not found” as
proof that an account or incident does not exist. Correlate on multiple stable
attributes and avoid collecting irrelevant personal data.

Start passive. Save the JSON report so another analyst can reproduce the work.
