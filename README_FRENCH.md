# Check-Security

🇬🇧 [English version](README.md)

Un audit de sécurité complet et non invasif pour Windows 11 — 27 sections couvrant tout, du statut Windows Update aux suites de chiffrement TLS et à l'exposition de l'accès distant, noté selon un modèle pondéré par catégorie, suivi dans le temps, et rendu sous forme de tableau de bord HTML avec recherche. Lecture seule : chaque vérification inspecte l'état du système, aucune ne le modifie.

> Rien n'est vérifié sur la base d'un nom. Les certificats racine de confiance sont validés par empreinte SHA-1/SHA-256 par rapport à une liste blanche vérifiée manuellement — jamais par leur nom (Subject CN), que n'importe quel certificat auto-signé malveillant pourrait copier. Le modèle de score lui-même a déjà été entièrement reconstruit une fois, après que la version originale ait produit un score de 1/100 sur une machine pourtant bien durcie.

**À partir de la v5.1.0, le script lui-même (console, rapports HTML/TXT/JSON/CSV, noms de catégories, valeurs de `-Category`) est entièrement en anglais** — ce README reste en français, mais les libellés réellement affichés par le script (ex. "Critical points", "BitLocker") sont ceux en anglais. Quelques contrôles dont l'*entrée* est Windows lui-même — `auditpol`, `wbadmin` — savent lire les formulations anglaises ET françaises que ces commandes peuvent renvoyer, donc le script continue de fonctionner correctement sur un Windows en français, pas seulement en anglais. Les shadow copies ne dépendent plus du tout de l'analyse de texte : depuis la **v5.4.2** elles sont lues via CIM (`Win32_ShadowCopy` / `Win32_ShadowStorage`), indépendant de la langue — `vssadmin` n'est conservé qu'en secours.

---

## Sommaire

- [Présentation](#présentation)
- [Captures d'écran](#captures-décran)
- [Comment fonctionne le score](#comment-fonctionne-le-score)
- [Les 27 sections](#les-27-sections)
- [Historique et détection de régression](#historique-et-détection-de-régression)
- [Utiliser le filtre `-Category`](#utiliser-le-filtre--category)
- [Prérequis](#prérequis)
- [Premier lancement](#premier-lancement-pas-à-pas)
- [Paramètres en ligne de commande](#paramètres-en-ligne-de-commande)
- [Rapports générés](#rapports-générés)
- [Déploiement multi-machines](#déploiement-multi-machines)
- [Dépannage](#dépannage)

---

## Présentation

`Check-Security.ps1` exécute un audit en une passe de la posture de sécurité d'une machine Windows 11 : statut Windows Update, pare-feu, Defender, politique de comptes/mots de passe, BitLocker, exposition des protocoles réseau, tâches planifiées, programmes au démarrage, VBS/Credential Guard/HVCI, configuration TLS/chiffrement, magasin de confiance des certificats, résilience anti-ransomware (Shadow Copy/VSS), résolution de noms héritée et tunnels IPv6, protections Defender, PowerShell 2.0, services d'accès distant, identifiants stockés, et plus encore — 27 sections au total.

Il est entièrement **en lecture seule**. Aucune vérification ne modifie un paramètre, n'arrête un service, ni n'écrit dans le registre en dehors de ses propres fichiers de rapport/historique — il ne fait que lire et rapporter.

Depuis la v5.5.0, les constats des contrôles les plus récents se terminent par un indice qui nomme la commande correspondante du lanceur séparé **Toolbox-SystemCommands** (par exemple *Fix with Toolbox-SystemCommands > Quick security > 'Disable PowerShell 2.0'*). Check-Security lui-même ne corrige toujours rien : il détecte, la Toolbox corrige. Les indices se désactivent avec `$ShowToolboxHints`.

Chaque constat est enregistré avec une catégorie, un statut (`OK` / `WARN` / `FAIL` / `INFO`), et un détail en langage clair. L'ensemble se résume en un **score pondéré sur 100**, et chaque run est comparé au précédent pour faire ressortir ce qui a changé.

---

## Captures d'écran

<p align="center">
  <img src="https://raw.githubusercontent.com/NephVx2/Check-Security/main/screenshots/01-banner-sysinfo.png" width="49%">
  <img src="https://raw.githubusercontent.com/NephVx2/Check-Security/main/screenshots/06-html-report.png" width="49%">
</p>

Davantage dans [`screenshots/`](screenshots/) — sortie console section par section, et le rapport HTML complet.

---

## Comment fonctionne le score

Le modèle de scoring a connu une refonte documentée (v4.1) après que l'approche originale "100 − somme des pénalités" ait produit un score de 1/100 sur une machine qui avait pourtant HVCI, LSA Protection, Secure Boot et 18 règles ASR actives — les pénalités s'accumulaient sans limite à mesure que de nouveaux contrôles étaient ajoutés, indépendamment de la posture globale.

Le modèle actuel est un **taux de réussite pondéré par catégorie** :

```
Pour chaque catégorie C :
    OK / INFO → 1.0   (réussi complètement)
    WARN      → 0.5   (demi-crédit)
    FAIL      → 0.0   (en échec)
    taux(C) = moyenne des valeurs ci-dessus sur tous les contrôles de cette catégorie

Score = Σ(poids(C) × taux(C)) / Σ(poids(C)) × 100
```

Ceci est invariant au nombre de contrôles présent dans chaque catégorie, et un seul `FAIL` dans une petite catégorie ne peut plus faire couler tout le score comme c'était le cas avec l'ancien modèle.

**Poids par catégorie** (les catégories non listées ont un poids par défaut de 1.0) :

| Catégorie (valeur réelle, en anglais) | Poids | Catégorie (valeur réelle, en anglais) | Poids |
|---|---|---|---|
| Antivirus | 1.6 | Certificates | 1.3 |
| BitLocker | 1.6 | Firewall | 1.4 |
| VBS | 1.5 | Network | 1.4 |
| Backup | 1.5 | TLS/SCHANNEL | 1.4 |
| Password Policy | 1.3 | Hardening | 1.4 |
| Accounts | 1.2 | Defender | 1.1 |
| Services | 0.8 | Startup | 0.7 |
| Software | 0.5 | | |

L'intention : un `FAIL` sur BitLocker ou l'antivirus doit peser plus lourd qu'un `FAIL` sur "logiciels installés" — les poids codent ce jugement explicitement plutôt que de laisser chaque contrôle avoir la même importance par accident.

---

## Les 27 sections

<details>
<summary><strong>1–5 · Système, Windows Update, Pare-feu, Defender, Comptes</strong></summary>

Infos système + signature Authenticode du script lui-même ; ancienneté du dernier patch (WARN >30 jours, FAIL >60) ; statut du pare-feu par profil et classification des règles par éditeur (signé Microsoft → INFO, tiers/non signé → WARN) ; protection en temps réel Defender, ancienneté du dernier scan (WARN >7 jours, FAIL >30), historique des détections de menaces sur 30 jours ; comptes locaux, politique de mot de passe, et le compte Administrator intégré (RID-500) spécifiquement.
</details>

### Politique de mot de passe, en détail

**Ce contrôle vérifie la politique locale que Windows imposerait lors d'un *futur* changement de mot de passe — pas ton mot de passe actuel.** `Minimum length required by local policy: 0 characters` (la valeur par défaut Windows à l'installation) ne veut pas dire que ton mot de passe actuel fait 0 caractère, ni qu'il a un problème — ça veut dire que si le mot de passe de ce compte était changé demain, Windows n'imposerait aucun minimum. Tu peux très bien avoir un mot de passe long et solide en place actuellement malgré une politique permissive ici ; le script le précise explicitement dans le détail de chaque résultat.

| Contrôle | Ce qu'il rapporte |
|---|---|
| **Longueur minimale** | `WARN` en dessous de 12 caractères — voir ci-dessous pourquoi |
| **Âge maximal / minimal du mot de passe** | Informatif — à quelle fréquence Windows forcerait un changement, et le délai minimal avant de pouvoir en rechanger |
| **Seuil de verrouillage** | `WARN` si désactivé (`0` tentative) — aucun verrouillage automatique après des échecs de connexion répétés |
| **Durée de verrouillage** | `WARN` si configurée à moins de 5 minutes — trop court pour freiner efficacement des salves rapides de force brute |

**Pourquoi 12 caractères précisément ?** C'est la recommandation actuelle la plus répandue (NIST SP 800-63B, CISA, ANSSI) — l'ancien standard "8 caractères" date d'une époque où le craquage hors-ligne était bien plus lent. Sur du matériel GPU moderne, un hash NTLM à 8 caractères — complexe ou non — peut tomber en force brute en quelques heures ; chaque caractère supplémentaire multiplie l'espace de recherche par environ 95 (la plage ASCII imprimable). 12 est à peu près le point où même une attaque hors-ligne soutenue cesse d'être rentable, d'où le glissement général (NIST inclus) de la "complexité obligatoire" vers la "longueur d'abord".

Pour relever le seuil : `net accounts /minpwlen:12` (ajuste le chiffre à ta convenance). C'est un réglage de politique, pas la correction de quelque chose d'activement cassé — traite un `WARN` ici comme une recommandation, pas comme une erreur.

**Comptes locaux et drapeaux de mot de passe.** Chaque ligne de compte local se termine par `Pwd expires: …`. `Never` signifie que le compte a un mot de passe qui n'expire jamais (`WARN`, une recommandation de durcissement : les recommandations actuelles comme NIST SP 800-63B ne demandent plus de rotation forcée, c'est donc un choix que tu peux assumer en connaissance de cause) ; `Yes` qu'il expire ; `n/a (no password set)` désigne un compte intégré qui n'a jamais eu de mot de passe (Administrateur, Invité, DefaultAccount) ; `Managed online` un compte lié à un compte Microsoft ou Entra ID, dont le mot de passe est géré en ligne. Par ailleurs, un compte local activé dont le drapeau SAM indique *mot de passe non requis* reçoit un `WARN` : le drapeau ne prouve pas que le mot de passe est vide, il signifie que Windows en *autoriserait* un vide, et le script ne peut pas le tester sans provoquer une connexion échouée (qui compterait dans ton seuil de verrouillage). Si le compte a bien un mot de passe, retire le drapeau avec `net user <nom> /passwordreq:yes` (définis d'abord un mot de passe s'il n'en a pas, sinon tu ne pourrais plus te connecter).

<details>
<summary><strong>6–10 · UAC, BitLocker, Réseau, Services, Journaux d'audit</strong></summary>

Niveau UAC ; BitLocker (lecteur système `C:` → FAIL si désactivé, autres volumes → WARN) ; ports en écoute classés par exposition (RDP sur `0.0.0.0` → FAIL, WinRM → WARN fort, RPC 135/SMB 445 sur interfaces système → INFO car comportement Windows normal), connexions TCP établies vers des IP publiques enrichies avec le nom du processus, exposition pare-feu IPv6, profil réseau actif par interface ; services auto-démarrés non-système avec chemins suspects ; configuration de la politique d'audit et événements de sécurité récents (4648 connexions avec identifiants explicites, 4720/4726 création/suppression de compte).
</details>

<details>
<summary><strong>11–15 · Tâches planifiées, Secure Boot/TPM, PowerShell, Logiciels, Démarrage</strong></summary>

Tâches planifiées suspectes (une tâche est reconnue comme la tienne quand son script est dans un dossier de confiance, porte une signature Authenticode valide d'un éditeur présent dans le magasin Éditeurs approuvés, ou a été créée par Winhance avec un script que seuls les administrateurs peuvent modifier) ; statut Secure Boot et TPM ; politique d'exécution PowerShell, Script Block Logging/Transcription (rétrogradés en INFO sur un poste personnel — ce sont des outils forensiques d'entreprise qui ajoutent du bruit sans SOC pour surveiller les journaux), Smart App Control (sensible à la compatibilité CPU : "non disponible" sur du matériel non compatible est INFO, pas un avertissement) ; inventaire des logiciels installés ; programmes au démarrage depuis à la fois les autoruns registre et les dossiers Démarrage, contrôles de persistance par détournement IFEO et `AppInit_DLLs`.
</details>

<details>
<summary><strong>16–19 · Exclusions Defender, Windows Hello, VBS, Certificats</strong></summary>

Exclusions de chemin/extension/processus Defender (signalées si trop larges) ; enrôlement PIN/biométrique Windows Hello ; VBS, Credential Guard, Memory Integrity (HVCI), et LSA Protection (RunAsPPL) ; certificats racine de confiance hors liste Microsoft, validés par **empreinte par rapport à une liste blanche vérifiée manuellement** (voir ci-dessous) — une vraie autorité non vérifiée est un `WARN`, un certificat end-entity non vérifié n'est qu'un `INFO` — et certificats expirés dans le magasin personnel.
</details>

<details>
<summary><strong>20–22 · Suites TLS/chiffrement, Pilotes vulnérables, Shadow Copy/VSS</strong></summary>

**TLS/SCHANNEL** — cinq contrôles indépendants, détaillés juste après le tableau : état des protocoles (TLS 1.0/1.1 désactivés, TLS 1.2/1.3 activés), une politique GPO forçant l'ordre des suites de chiffrement si elle existe, les chiffrements legacy individuels (RC4/DES/RC2/3DES/NULL) désactivés au niveau registre, les algorithmes de hachage faibles (MD5/SHA-1), la longueur minimale de clé Diffie-Hellman, et le Strong Crypto .NET Framework sur chaque installation .NET réellement présente. **Pilotes** vérifiés contre la liste de blocage HVCI de Microsoft et pilotes récemment installés (un service en mode utilisateur avec une signature valide, typiquement un programme de mise à jour d'application, est `INFO` ; les pilotes noyau et les exécutables non signés restent en `WARN`, avec la raison indiquée). **Shadow Copy/VSS** — service Volume Shadow Copy, snapshots locaux de `C:`, espace réservé aux snapshots sur chaque volume, et sauvegardes d'image système (`wbadmin`) — tout est pertinent pour la récupération après ransomware, détaillé [plus bas](#shadow-copyvss-en-détail).
</details>

<details>
<summary><strong>23–27 · Résolution de noms et tunnels IPv6, Protections Defender, PowerShell 2.0, Services d'accès distant, Identifiants stockés</strong></summary>

Ajoutées en v5.5.0. **Résolution de noms héritée et tunnels IPv6** — LLMNR (stratégie `EnableMulticast`), mDNS (`EnableMDNS`) et NetBIOS sur TCP/IP sur chaque carte active, plus les tunnels de transition Teredo, 6to4 et ISATAP, lus via les cmdlets NetworkTransition (pour Teredo, le type effectif rapporté par `netsh` compte aussi, car le désactiver avec `netsh` laisse le type configuré sur `Default`). **Protections Defender** — Tamper Protection, protection PUA, Network Protection et protection cloud. **PowerShell 2.0** — l'ancien moteur qui contourne AMSI et la journalisation des scripts (supprimé de Windows 11 à partir de la 24H2). **Services d'accès distant** — Remote Registry, WebClient, sshd / SSDP / UPnP / Routage et accès distant, les fonctionnalités client Telnet et TFTP, l'Assistance à distance. **Identifiants stockés** — ouverture automatique de session Winlogon et `DefaultPassword` en clair. Chacune de ces sections réutilise une catégorie existante (`Network`, `Defender`, `PowerShell`, `Services`, `Accounts`), donc aucun poids n'a changé. Détaillées [ci-dessous](#sections-23-à-27-en-détail).
</details>

### TLS/SCHANNEL, en détail

SCHANNEL est le composant Windows bas niveau par lequel passe toute connexion TLS/SSL sur la machine — RDP, LDAPS, IIS, la plupart des applications .NET, et beaucoup de logiciels tiers qui n'embarquent pas leur propre pile TLS. La Section 20 lit son état sur cinq surfaces de registre indépendantes :

| Contrôle | Ce que ça signifie si c'est faible |
|---|---|
| **Protocoles** (TLS 1.0/1.1/1.2/1.3) | TLS 1.0/1.1 sont obsolètes et vulnérables à **POODLE**/**BEAST** — ils doivent être désactivés, côté client comme côté serveur |
| **Ordre des suites de chiffrement (GPO)** | Une Group Policy de domaine ou locale peut forcer une liste de suites précise ; si elle existe, elle ne doit pas contenir RC4, 3DES, DES, NULL ou EXPORT |
| **Chiffrements legacy individuels** | RC4, DES, RC2, Triple DES 168 et NULL peuvent chacun être désactivés indépendamment au niveau registre — le mécanisme réellement utilisé hors domaine, distinct du contrôle GPO ci-dessus |
| **Algorithmes de hachage faibles** | MD5 et SHA-1 sont encore acceptés par SCHANNEL sauf désactivation explicite |
| **Longueur minimale de clé Diffie-Hellman** | En dessous de 2048 bits, une connexion est vulnérable à une dégradation type **Logjam** |
| **Strong Crypto .NET Framework** | Sans ça, une application .NET peut contourner tous les réglages ci-dessus et négocier le TLS via sa propre pile obsolète |

<p align="center"><img src="screenshots/03-tls-schannel.png" alt="Sortie console de la section TLS/SCHANNEL" width="700"></p>

POODLE, BEAST et Logjam ne sont pas des menaces théoriques — ce sont des attaques nommées et pratiques contre exactement les réglages par défaut que Windows continue d'expédier tant que personne ne les désactive explicitement. Une machine jamais touchée affichera la plupart de cette section en `WARN` ou en `INFO` ("valeur par défaut Windows") — c'est attendu, pas un bug de l'audit.

**Check-Security se contente de lire cet état — il n'écrit jamais dans le registre.** Si la Section 20 remonte des `WARN`, c'est un constat, pas une correction. Pour durcir réellement TLS/SCHANNEL sur la machine, lance le script complémentaire **[Harden-TLS](https://github.com/NephVx2/Harden-TLS)** (même auteur, même suite), puis relance Check-Security ensuite pour confirmer que le changement a bien pris effet.

**Validation de confiance des certificats, en détail :** la liste blanche des certificats racine "connus comme sains" est indexée par **empreinte SHA-1/SHA-256**, pas par Subject CN — un choix de conception délibéré expliqué directement dans le script : le nom affiché d'un certificat n'est qu'une chaîne de caractères, et n'importe quel certificat auto-signé pourrait définir son CN sur `"DigiCert Trusted Root G4"`. Une correspondance par nom serait trivialement contournable ; une correspondance par empreinte signifie qu'une entrée ne peut être légitime que si quelqu'un a réellement vérifié ce certificat précis.

### Shadow Copy/VSS, en détail

La section 22 répond à une seule question : *si un ransomware chiffrait cette machine cette nuit, que pourrais-tu récupérer ?* Les ransomwares suppriment couramment les shadow copies locales en premier, donc la réponse dépend de plusieurs éléments.

| Contrôle | Ce qu'il rapporte |
|---|---|
| **Service VSS** | Type de démarrage du service Volume Shadow Copy. `Manual` est normal — il démarre à la demande pour les opérations de snapshot et de sauvegarde |
| **Shadow copies on C:** | Nombre et ancienneté des snapshots VSS locaux du lecteur système, lus via CIM (`Win32_ShadowCopy`, filtré sur le volume système). `OK` si le dernier a 7 jours ou moins, `WARN` s'il est plus ancien, `FAIL` s'il n'y a ni snapshot ni point de restauration. Les snapshots stockés pour *d'autres* volumes ne sont pas comptés ici |
| **VSS shadow storage** | Espace réservé aux snapshots sur chaque volume (`Win32_ShadowStorage`). Une limite utilisée à 80 % ou plus n'est un `WARN` que si le volume garde **moins de 3 snapshots** (ou si le nombre est illisible), car une limite bornée finit toujours pleine et Windows supprime alors lui-même les plus anciens snapshots : ce qui compte, c'est l'historique qui reste, pas le pourcentage. Avec 3 snapshots ou plus, c'est un `INFO`. `WARN` aussi quand un volume n'a **aucune limite** et que ses snapshots occupent déjà 20 % ou plus du disque qui les héberge ; `INFO` en dessous. La commande `vssadmin resize shadowstorage` pour ajuster est donnée dans le détail |
| **System image backup / scheduling** | Versions de sauvegarde `wbadmin`, ancienneté de la dernière, et tâche planifiée Windows Backup |

Trois choses à savoir :

- **Moins de snapshots que prévu est généralement une limite de stockage, pas un problème de détection** — voir [Dépannage](#dépannage).
- La fenêtre Restauration du système de Windows (`rstrui`, avec *Afficher d'autres points de restauration* coché) liste les vrais points de restauration **et** les sauvegardes d'image système `wbadmin` stockées sur d'autres disques, donc cette liste est normalement plus longue que le compte de "Shadow copies on C:". Les deux sont justes ; ils mesurent des choses différentes.
- Des sauvegardes d'image système conservées sur un disque toujours connecté peuvent être chiffrées par le même ransomware que celui qui touche `C:`. Check-Security ne peut pas savoir si ton disque de sauvegarde est déconnecté entre deux runs — une copie hors ligne reste la protection la plus solide.

### Sections 23 à 27, en détail

Ces cinq sections (v5.5.0, 17 contrôles) comblent des lacunes laissées par les 22 premières. Comme tout le reste du script, elles sont en **lecture seule**, et elles sont rattachées à des catégories existantes plutôt qu'à de nouvelles, donc les poids du tableau plus haut sont inchangés.

| Contrôle | Catégorie | Résultat |
|---|---|---|
| **LLMNR** | Network | `OK` désactivé par stratégie · `WARN` activé (valeur par défaut de Windows) |
| **mDNS** | Network | `OK` désactivé · `INFO` activé |
| **NetBIOS sur TCP/IP** | Network | `OK` désactivé sur chaque carte active · `WARN` activé ou laissé par défaut sur au moins une |
| **Tunnels Teredo / 6to4 / ISATAP** | Network | `OK` désactivé (configuré, ou type effectif rapporté par `netsh`) · `INFO` laissé sur `Default` · `WARN` explicitement activé (6to4, ISATAP) ou Teredo réellement actif |
| **Tamper Protection** | Defender | `OK` activée · `FAIL` désactivée · `INFO` Defender passif ou illisible |
| **Protection PUA, Network Protection** | Defender | `OK` activée (blocage) · `INFO` mode audit ou désactivée |
| **Protection cloud (MAPS)** | Defender | `OK` basique ou avancée · `INFO` désactivée |
| **PowerShell 2.0** | PowerShell | `OK` supprimé de cette version ou désactivé · `WARN` activé |
| **Service Remote Registry** | Services | `OK` arrêté · `FAIL` en cours d'exécution |
| **Service WebClient (WebDAV)** | Services | `OK` arrêté · `WARN` en cours d'exécution |
| **Autres services d'accès distant** | Services | `OK` aucun en cours · `INFO` sshd, SSDP ou UPnP en cours · `WARN` Routage et accès distant en cours |
| **Fonctionnalités client Telnet / TFTP** | Services | `OK` non activées · `WARN` activées |
| **Assistance à distance** | Services | `OK` non autorisée · `INFO` autorisée (valeur par défaut de Windows) |
| **Ouverture automatique de session (Winlogon)** | Accounts | `OK` désactivée · `WARN` activée · `FAIL` un mot de passe en clair est stocké |

**Résolution de noms.** Quand le DNS ne sait pas résoudre un nom, Windows se rabat sur LLMNR, mDNS et le service de noms NetBIOS : ils interrogent tout le réseau local, sans aucune authentification. N'importe quel appareil du même réseau — un invité sur ton Wi-Fi, un objet connecté compromis — peut répondre « c'est moi » et faire envoyer à Windows le hash NTLM de l'utilisateur (attaques de type Responder). Ils sont activés par défaut sur presque toutes les machines Windows, donc LLMNR et NetBIOS sont en `WARN` plutôt qu'en `FAIL` : l'exposition réelle dépend des réseaux que la machine rejoint. mDNS présente moins de risque et reste en `INFO`.

**Tunnels IPv6.** Teredo, 6to4 et ISATAP font passer de l'IPv6 dans de l'IPv4. Avec de l'IPv6 natif, ou sans besoin d'IPv6, ils n'ajoutent que de la surface d'attaque : le trafic encapsulé peut contourner un pare-feu ou un filtre DNS, et Teredo permet à des connexions entrantes de traverser le NAT de la box. Leur état est lu via `Get-NetTeredoConfiguration`, `Get-Net6to4Configuration` et `Get-NetIsatapConfiguration` plutôt qu'en analysant le texte de `netsh`, qui est localisé — le même piège que celui du faux positif `vssadmin` de la v5.4.2. Un tunnel laissé sur `Default` est en `INFO` : Windows décide, et en pratique il reste inactif derrière une box domestique.

**Defender.** La section 16 audite ce que Defender a pour consigne de *ne pas* analyser ; la section 24 audite les protections qui l'entourent. Tamper Protection est la plus importante : sans elle, un malware ou un script exécuté en administrateur peut désactiver Defender. Elle ne se modifie pas par script — seulement depuis l'application Sécurité Windows. Si Defender n'est pas l'antivirus actif (mode passif ou EDR block), ces contrôles sont remplacés par un seul `INFO`. PUA, Network Protection et la protection cloud sont des couches optionnelles, donc « désactivée » est en `INFO`, et le rapport HTML affiche un lien d'aide qui explique comment les activer. L'ancienne ligne de la section 4 intitulée « Network protection » indiquait en réalité la protection IOAV de Defender (analyse des téléchargements et des pièces jointes) ; elle s'appelle désormais **Download/attachment scanning (IOAV)** pour éviter toute confusion.

**PowerShell 2.0.** L'ancien moteur est antérieur à AMSI (analyse antimalware des scripts) et à la journalisation des scripts : un attaquant qui peut lancer `powershell -Version 2` contourne les deux. Microsoft l'a supprimé de Windows 11 à partir de la 24H2, donc « Removed from this Windows build » est un résultat normal et bon.

**Services d'accès distant.** WinRM est déjà couvert par la section 8 ; cette section ajoute les autres portes. Remote Registry est désactivé par défaut sur les Windows clients, donc un service en cours d'exécution signifie que quelqu'un l'a activé (`FAIL`). L'Assistance à distance est *activée* par défaut et chaque session exige quand même une invitation, donc elle n'est jamais pire qu'`INFO`.

**Identifiants stockés.** L'ouverture automatique de session configurée à la manière classique stocke le mot de passe du compte en clair sous Winlogon, où d'autres logiciels du PC peuvent le lire. Le contrôle teste seulement si cette valeur **existe** — le mot de passe lui-même n'est jamais lu dans un rapport. Des outils comme Sysinternals Autologon le conservent plutôt comme secret LSA, ce qui est invisible d'ici : `AutoAdminLogon = 1` seul est donc un `WARN`. Le Gestionnaire d'identifiants (`cmdkey /list`) n'est volontairement **pas** audité : sa sortie est un texte localisé.

**Indices « Fix with ».** Les constats de ces contrôles se terminent par une phrase qui nomme la commande correspondante du lanceur séparé **Toolbox-SystemCommands**, par exemple *Fix with Toolbox-SystemCommands > Quick security > 'Disable PowerShell 2.0'*. Check-Security lui-même ne modifie toujours rien : **il détecte, la Toolbox corrige.** L'indice est du texte simple, n'apparaît que lorsque le contrôle n'est pas `OK`, et pour les réglages qui ne se corrigent pas par script (Tamper Protection) il renvoie vers une commande en lecture seule (*Details in …*). Les libellés sont réunis dans une seule table (`$ToolboxLabels`) et correspondent au catalogue anglais de la Toolbox. Un enchaînement naturel : corriger avec la Toolbox, puis relancer uniquement cette catégorie (`-Category "Network"`) pour voir la ligne passer à `OK`. Les indices se désactivent avec `$ShowToolboxHints = $false`.

**Autres changements de la v5.5.0.**
- La ligne **Local Administrators members** de la section 5 annote désormais chaque membre — `ORDINATEUR\Administrateur (built-in, disabled), ORDINATEUR\utilisateur` — et ne compte que les membres qui peuvent réellement ouvrir une session pour son seuil de `WARN`. Le compte administrateur intégré est toujours dans ce groupe, même désactivé, donc la liste brute donnait l'impression de deux comptes pour une seule personne.
- `-SelfTest` ne laisse plus de `Check-Security_<date>.txt` parasite dans le dossier de rapports : son journal est redirigé vers un fichier temporaire, et le dossier n'est plus créé dans ce mode.
- **Section 19, certificats.** Un certificat racine non vérifié n'est un `WARN` que s'il s'agit d'une vraie autorité de certification (`CA:TRUE`), la seule capable de signer d'autres certificats. Un certificat *end-entity* non vérifié dans le magasin Root ne peut rien signer ni intercepter de TLS : il est en `INFO` avec le crédit de score complet et n'a besoin d'aucune entrée dans la liste blanche. La liste blanche ne garde que trois racines universelles (DigiCert Trusted Root G4, Thawte Timestamping CA, VeriSign Time Stamping Service Root). Le détail d'un certificat non vérifié suggère `certutil -store Root <empreinte>` pour retrouver son origine, et les liens du rapport sont désormais une recherche web sur l'empreinte, la liste des participants au programme racine de Microsoft, et crt.sh (certificats d'autorité uniquement, car il n'indexe que les journaux publics de Certificate Transparency).
- **Section 11, tâches planifiées.** Une tâche est reconnue comme la tienne quand son script est dans un dossier de confiance, quand elle porte une signature Authenticode valide d'un éditeur présent dans le magasin Éditeurs approuvés (aucun réglage à modifier), ou quand elle a été créée par Winhance (dossier `\Winhance\`, script sous `%ProgramData%\Winhance\Scripts`) **et** que ni le script ni son dossier ne sont modifiables par un non-administrateur. `$TrustedTaskNames` est vide par défaut : une reconnaissance par le nom seul ignorerait aussi une tâche malveillante portant le même nom.
- **Section 21, pilotes récemment installés.** Un service en mode utilisateur (`.exe`) avec une signature valide hors des chemins Windows, typiquement un programme de mise à jour comme Edge Update, est en `INFO` avec son signataire. Les pilotes noyau et les exécutables non signés ou invalides restent en `WARN`, annotés `[file not found on disk]` ou `[signature: <état>]`.
- **Section 23, Teredo.** Teredo désactivé avec `netsh` est désormais reconnu : `Get-NetTeredoConfiguration` continue d'indiquer le type configuré (`Default`) alors que `netsh` indique le type effectif `disabled`.
- **Section 5, comptes.** `Pwd expires` est désormais lu correctement (`Get-LocalUser` n'a pas de propriété `PasswordNeverExpires`, donc chaque compte affichait `Yes`), et le `WARN` *mot de passe non requis* donne maintenant la correction ; voir *Comptes locaux et drapeaux de mot de passe* ci-dessus.
- **Section 22, VSS shadow storage.** Une limite bornée utilisée à 80 % ou plus n'est désormais un `WARN` que si le volume garde moins de 3 snapshots ; avec 3 snapshots ou plus, c'est un `INFO`, car VSS remplit la limite puis recycle les plus anciens snapshots.
- **Section 3, règles entrantes ouvertes.** Le détail regroupe désormais les règles par application avec leurs protocoles (une application a en général une règle TCP et une règle UDP portant le même nom, ce qui ressemblait à des doublons), affiche les éditeurs par leur seul CN, et indique combien d'entrées distinctes composent le total.
- **Corrections.** Sous Windows PowerShell 5.1, un décompte d'un seul résultat pouvait rester vide (par exemple `Established TCP connections (outbound)` sans nombre), et la ligne des exclusions Defender affichait `1:` pour une liste vide. Le rapport HTML échappe désormais les noms, valeurs et détails des contrôles : le texte entre chevrons, comme le `<larger size>` de la commande de correction VSS, disparaissait.

---

## Historique et détection de régression

Chaque run écrit son score dans un fichier d'historique glissant (20 derniers runs) et se compare au run immédiatement précédent :

- **Deltas par contrôle** — tout ce qui a changé de statut (ex : `OK → WARN`) depuis la dernière fois est signalé spécifiquement, pas seulement le score global. Les contrôles qui n'existaient pas lors de l'exécution précédente — par exemple après une mise à jour du script — sont listés comme `New check` plutôt que comme un changement de statut ; la première exécution après la v5.5.0 affiche ainsi ses 17 nouveaux contrôles.
- **Alerte de régression** — si le score chute de plus de `$ScoreRegressionThreshold` (par défaut : **5 points**) depuis le dernier run, une bannière rouge apparaît en console et dans le rapport HTML. Une variation de 1 à 2 points est un bruit normal ; une chute de 5+ points signale un changement réel.
- **Sparkline de tendance** — un petit graphique SVG des 20 derniers scores, rendu directement dans le rapport HTML.
- **Résumé exécutif** — un bloc "Points critiques" tout en haut du rapport HTML liste chaque `FAIL` actuel (puis les `WARN`, jusqu'à 10 au total) avant même de défiler dans le détail complet des 27 sections.

---

## Utiliser le filtre `-Category`

`-Category` ne relance que les sections correspondantes, au lieu de l'audit complet d'environ 3 minutes — pratique juste après un correctif ciblé (BitLocker activé, Harden-TLS exécuté, un service désactivé) quand on veut juste confirmer qu'un point précis a changé.

```powershell
.\Check-Security.ps1 -Category "BitLocker"
.\Check-Security.ps1 -Category "BitLocker","TLS/SCHANNEL"
```

C'est un `[string[]]`, donc on peut passer une ou plusieurs valeurs, séparées par des virgules. Une section s'exécute si *au moins une* de ses propres catégories correspond partiellement à *au moins une* des valeurs passées (`-like` dans les deux sens), donc `-Category "TLS"` matche aussi la catégorie `TLS/SCHANNEL`. Les valeurs acceptées sont celles du tableau de poids par catégorie plus haut, plus quelques catégories de contrôles sans poids personnalisé (`System`, `Updates`, `UAC`, `Audit`, `Scheduled Tasks`, `UEFI Security`, `Windows Hello`, `Defender`) — voir l'aide intégrée du script (`Get-Help .\Check-Security.ps1 -Full`) pour la liste exacte sous `-Category`.

Depuis la v5.5.0, les cinq sections les plus récentes réutilisent des catégories existantes, donc `-Category "Network"` exécute aussi la section 23, `"Defender"` la section 24, `"PowerShell"` la section 25, `"Services"` la section 26 et `"Accounts"` la section 27 — pratique juste après une commande de la Toolbox, pour confirmer que le constat est passé à `OK`.

Deux états ($OS/$CS/$BIOS/$CPU, et la détection Windows Hello) sont partagés entre des sections qui ne tournent pas forcément ensemble, donc ils sont toujours calculés quel que soit le `-Category` passé — le filtre ne laisse jamais l'en-tête du rapport HTML ou le contrôle Windows Hello sans données.

<p align="center"><img src="screenshots/04-run-category.png" alt="Sortie console d'un run filtré par -Category" width="700"></p>

---

## Prérequis

- Windows 11 (le script vérifie le numéro de build et rapporte `FAIL` s'il est exécuté sur un OS plus ancien — il continue de s'exécuter, mais se signale lui-même comme hors de son périmètre prévu).
- PowerShell 5.1 (intégré à Windows) ou PowerShell 7+.
- Droits administrateur (le script s'auto-élève via une invite UAC s'il est lancé depuis une session non élevée).
- Si le script est signé numériquement (recommandé en environnement `-ExecutionPolicy AllSigned`/`RemoteSigned`) : le certificat de signature doit être approuvé sur la machine cible.

---

## Premier lancement (pas à pas)

1. Copier `Check-Security.ps1` sur la machine cible.

2. Ouvrir PowerShell (l'élévation n'est pas nécessaire pour le lancer — le script s'auto-élève lui-même via une invite UAC).

   Puis se placer dans le dossier qui contient le script (adapter le chemin ; garder les guillemets s'il contient des espaces) :

   ```powershell
   cd "$HOME\Downloads"
   ```

3. **Débloquer le script** s'il a été téléchargé depuis Internet. Windows marque les fichiers téléchargés, et la politique d'exécution de PowerShell (`RemoteSigned`, par exemple) refuse de lancer un script marqué. Dans cette même fenêtre Administrateur, depuis le dossier du script :

   ```powershell
   Unblock-File .\Check-Security.ps1
   ```

   Si PowerShell indique plutôt que l'exécution de scripts est désactivée sur ce système (la politique par défaut de Windows est `Restricted`), autoriser d'abord les scripts pour le compte courant (la modification ne s'applique qu'à ce compte, pas à toute la machine) :

   ```powershell
   Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
   ```

   Toujours bloqué ? Voir le [guide pas à pas](https://github.com/NephVx2/Script-blocked-Look-at-this/blob/main/README_POWERSHELL_FRENCH.md).

4. Lancer d'abord le self-test — aucun fichier écrit, aucune modification système :

   ```powershell
   .\Check-Security.ps1 -SelfTest
   ```
   
   Exécute 64 assertions internes (fonction d'échappement HTML, rendu des badges de statut, table des poids par catégorie, la fonction ShouldRunSection elle-même, cohérence du seuil de régression du score, l'assistant d'indices vers la Toolbox, et plus). Code de sortie 0 = tout passe, 1 = au moins un échec.

5. Lancer l'audit complet :

   ```powershell
   .\Check-Security.ps1
   ```

   Prend environ quelques minutes selon la machine (les requêtes de journaux d'événements et l'énumération des certificats sont généralement les étapes les plus lentes). Suivre en console le flux en direct `[OK]`/`[WARN]`/`[FAIL]`/`[INFO]` à mesure que chaque section se termine.

6. À la fin, la console affiche une bannière finale avec le score pondéré, suivie de jusqu'à 5 constats `FAIL` et 5 `WARN` pour une lecture immédiate sans ouvrir le rapport HTML.

7. Ouvrir le rapport HTML généré (le script propose de le faire automatiquement sauf si `-Silent` est utilisé) — commencer par le bloc "Points critiques" en haut, puis utiliser la barre de recherche pour sauter vers un contrôle spécifique.

8. Sur les **deuxième run et suivants**, la console et le rapport HTML afficheront en plus ce qui a changé depuis la dernière fois, et une bannière de régression si le score a chuté de plus de 5 points.

9. Si un `FAIL` spécifique nécessite une réponse vérifiée à la source (ex : "ce certificat racine est-il légitime ?"), ne pas se fier uniquement au rapport — vérifier l'empreinte du certificat par rapport à la liste publiée par Microsoft ou l'éditeur lui-même avant de l'ajouter à la liste blanche dans le script.

---

## Paramètres en ligne de commande

| Paramètre | Description |
|---|---|
| `-Silent` | Supprime la sortie console, le prompt "ouvrir dans le navigateur", et la pause ENTRÉE finale — pour un usage via tâche planifiée. Les rapports (HTML/TXT/JSON/CSV) sont toujours générés normalement. |
| `-SelfTest` | Exécute la batterie de tests internes à 64 assertions puis quitte. Passe par la même auto-élévation UAC qu'un lancement normal, aucun rapport généré, rien de modifié. Code de sortie `0`/`1`. |
| `-Category <nom(s)>` | Ne relance que les sections correspondantes — voir [Utiliser le filtre -Category](#utiliser-le-filtre--category) ci-dessus. |

**Exemples :**

```powershell
.\Check-Security.ps1 -SelfTest
.\Check-Security.ps1
.\Check-Security.ps1 -Silent
```

---

## Rapports générés

Chaque run réel (hors `-SelfTest`) écrit dans :

```
%USERPROFILE%\Desktop\Maintenance_Reports\Check-Security\
```

| Fichier | Contenu |
|---|---|
| `Check-Security_<horodatage>.html` | Tableau de bord complet : résumé exécutif ("Points critiques"), score pondéré, tableau de répartition par catégorie, sparkline de tendance, bannière de régression le cas échéant, détail complet des 27 sections avec recherche/filtre et ancres |
| `Check-Security_<horodatage>.txt` | Équivalent texte brut de l'ensemble des constats |
| `Check-Security_<horodatage>.json` | Export complet machine-readable de chaque constat |
| `Check-Security_<horodatage>.csv` | Export tabulaire de chaque constat |
| `_last_audit_baseline.json` | Instantané du dernier run uniquement, écrasé à chaque run — utilisé pour calculer les deltas par contrôle |
| `_score_history.json` | Historique glissant des 20 derniers couples (date, score) — utilisé pour la sparkline de tendance |

---

## Déploiement multi-machines

1. **Distribuer** le fichier `.ps1` vers chaque machine cible.

2. **Approuver le certificat de signature** si une politique d'exécution stricte est en place (`-ExecutionPolicy AllSigned`/`RemoteSigned`).

3. **Exécuter `-SelfTest` en premier** sur chaque machine pour confirmer que le script lui-même est intact avant de se fier à un audit complet.

4. **Planifier via le Planificateur de tâches Windows** avec `-Silent` et la case **Exécuter avec les autorisations maximales** cochée. Une tâche planifiée s'exécute sans session interactive, donc l'invite UAC d'auto-élévation du script n'a nulle part où s'afficher — la tâche elle-même doit déjà être configurée pour s'exécuter élevée :

   | Champ | Valeur |
   |---|---|
   | Programme/script | `pwsh.exe` (ou `powershell.exe`) |
   | Arguments | `-NoProfile -ExecutionPolicy Bypass -File "C:\Scripts\Security\Check-Security.ps1" -Silent` |
   | Exécuter avec les autorisations maximales | Oui |

5. **Consulter d'abord le résumé "Critical points"** (le rapport est entièrement en anglais depuis la v5.1.0) sur le rapport HTML de chaque machine plutôt que de lire les 27 sections complètes à chaque fois — c'est exactement à ça qu'il sert.

6. Les rapports, la baseline et l'historique sont **propres à chaque machine** — aucune donnée n'est centralisée automatiquement. Pour une vue consolidée sur un parc, une étape de collecte séparée (partage réseau, remontée de logs) devrait être ajoutée par-dessus ce script.

7. **Liste blanche de certificats et racines non reconnues.** Le `$TrustedRootThumbprintAllowlist` est livré avec seulement trois racines universelles (DigiCert Trusted Root G4, Thawte Timestamping CA, VeriSign Time Stamping Service Root). Sur une autre machine, un certificat racine hors liste Microsoft est jugé selon ce qu'il peut faire : une vraie autorité de certification est un `WARN` à examiner (antivirus avec inspection HTTPS, proxy ou VPN d'entreprise et outils de développement comme mkcert ou Fiddler en sont des sources légitimes courantes), alors qu'un certificat end-entity est un `INFO` qui ne coûte aucun point. Pour faire taire une autorité que tu as vérifiée, ajoute son empreinte à la liste blanche . Revoir par machine (ou par image de parc connue) plutôt que de supposer qu'une seule liste blanche convient à toutes les cibles de déploiement.

---

## Dépannage

<details>
<summary><strong>Le script ne démarre pas du tout</strong></summary>

Depuis la v5.4.1 le script s'auto-élève : une invite UAC doit apparaître automatiquement s'il est lancé depuis une session non élevée. Si rien ne se passe, l'invite a probablement été refusée — relancer et l'accepter. Dans un contexte non interactif (tâche planifiée, session distante sans bureau), l'invite UAC n'a nulle part où s'afficher ; vérifier que la tâche/session elle-même est déjà configurée pour s'exécuter élevée (voir l'entrée Planificateur de tâches ci-dessus).
</details>

<details>
<summary><strong>Un certificat racine tout nouveau apparaît comme non reconnu</strong></summary>

Une vraie autorité de certification est signalée `WARN` ; un certificat end-entity est `INFO` et ne coûte rien. Aucun des deux n'est un bug : le script ne peut pas savoir si un certificat est légitime (voir [Déploiement multi-machines](#déploiement-multi-machines)). Retrouver d'abord son origine avec `certutil -store Root <empreinte>` (date de création, fournisseur de clé, présence d'une clé privée sur cette machine), en s'aidant de la recherche sur l'empreinte et de la liste des participants au programme racine de Microsoft indiquées dans le rapport. Les sources légitimes courantes sont l'antivirus avec inspection HTTPS, un proxy ou VPN d'entreprise et les outils de développement (mkcert, Fiddler, mitmproxy). N'ajouter l'empreinte à `$TrustedRootThumbprintAllowlist` qu'après l'avoir vérifiée de manière indépendante, jamais simplement parce que le rapport l'a signalée : cela va à l'encontre du but de la liste blanche.
</details>

<details>
<summary><strong>Le score a chuté et je ne sais pas pourquoi</strong></summary>

Consulter la bannière de régression du rapport HTML (affichée uniquement si la chute dépasse `$ScoreRegressionThreshold`, 5 points par défaut) et la liste des deltas par contrôle — les deux sont calculés automatiquement par comparaison avec `_last_audit_baseline.json`. Une variation de 1 à 2 points entre deux runs peut être un bruit normal dans une catégorie ne comptant que quelques contrôles.
</details>

<details>
<summary><strong>"Shadow copies on C:" affiche moins de snapshots que prévu</strong></summary>

Généralement une limite de stockage, pas un problème de détection : quand l'espace réservé aux snapshots sur `C:` est plein, Windows supprime silencieusement le plus ancien pour faire de la place à chaque nouveau, donc le compte reste bloqué autour du même nombre. Vérifier avec `vssadmin list shadowstorage` — la ligne "VSS shadow storage" du rapport le signale aussi à partir de 80 % de la limite. Pour conserver plus d'historique, relever la limite : `vssadmin resize shadowstorage /for=C: /on=C: /maxsize=<taille>`.

Seuls les snapshots de `C:` sont comptés sur cette ligne. Les snapshots des volumes de sauvegarde (`E:`, `F:`…) apparaissent dans les lignes "VSS shadow storage" et `wbadmin`, et la fenêtre Restauration du système de Windows mélange les deux types dans une liste plus longue (voir [Shadow Copy/VSS, en détail](#shadow-copyvss-en-détail)).
</details>

<details>
<summary><strong>Les sections 25 et 26 affichent « Unable to read » pour les fonctionnalités facultatives</strong></summary>

Les deux sections lisent la liste des fonctionnalités facultatives de Windows une seule fois par exécution (`Get-WindowsOptionalFeature -Online`, un appel DISM qui prend quelques secondes). S'il échoue — la pile de maintenance est occupée, ou le magasin de composants est endommagé — les lignes PowerShell 2.0 et Telnet/TFTP affichent `Unable to read` en `INFO` au lieu de deviner. Lance `Get-WindowsOptionalFeature -Online` dans une console administrateur pour voir la vraie erreur, et `DISM /Online /Cleanup-Image /CheckHealth` si elle pointe le magasin de composants. Rien d'autre dans l'audit n'est affecté.
</details>

<details>
<summary><strong>Je ne veux pas des indices « Fix with Toolbox-SystemCommands »</strong></summary>

Mets `$ShowToolboxHints = $false` en haut du script, à côté de `$ScoreRegressionThreshold`. Les indices sont du texte simple ajouté au détail d'un constat : ils n'exécutent rien, et n'apparaissent que lorsqu'un contrôle n'est pas `OK`. Ils nomment des commandes du lanceur séparé Toolbox-SystemCommands, donc si tu ne l'utilises pas, les masquer ne fait rien perdre.
</details>

<details>
<summary><strong>-SelfTest signale un FAIL</strong></summary>

Lire directement le nom de l'assertion — il pointe vers une fonction utilitaire spécifique en échec (échappement HTML, rendu des badges de statut, un poids de catégorie manquant, etc.), pas vers la posture de sécurité réelle de la machine. C'est une auto-vérification du script, sans rapport avec ce qu'un audit complet rapporterait.
</details>

---

<sub>Check-Security — 27 sections, lecture seule, scoring pondéré par catégorie, confiance des certificats basée sur l'empreinte, self-test à 64 assertions.</sub>
