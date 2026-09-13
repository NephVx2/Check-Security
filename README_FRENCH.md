# Check-Security

🇬🇧 [English version](README.md)

Un audit de securite complet et non invasif pour Windows 11 — 22 sections couvrant tout, du statut Windows Update aux suites de chiffrement TLS, note selon un modele pondere par categorie, suivi dans le temps, et rendu sous forme de tableau de bord HTML avec recherche. Lecture seule : chaque verification inspecte l'etat du systeme, aucune ne le modifie.

> Rien n'est verifie sur la base d'un nom. Les certificats racine de confiance sont valides par empreinte SHA-1/SHA-256 par rapport a une liste blanche verifiee manuellement — jamais par leur nom (Subject CN), que n'importe quel certificat auto-signe malveillant pourrait copier. Le modele de score lui-meme a deja ete entierement reconstruit une fois, apres que la version originale ait produit un score de 1/100 sur une machine pourtant bien durcie.

**A partir de la v5.1.0, le script lui-meme (console, rapports HTML/TXT/JSON/CSV, noms de categories, valeurs de `-Category`) est entierement en anglais** — ce README reste en francais, mais les libelles reellement affiches par le script (ex. "Critical points", "BitLocker") sont ceux en anglais. Quelques controles dont l'*entree* est Windows lui-meme — `auditpol`, `vssadmin`, `wbadmin` — savent lire les formulations anglaises ET francaises que ces commandes peuvent renvoyer, donc le script continue de fonctionner correctement sur un Windows en francais, pas seulement en anglais.

---

## Sommaire

- [Presentation](#presentation)
- [Comment fonctionne le score](#comment-fonctionne-le-score)
- [Les 22 sections](#les-22-sections)
- [Historique et detection de regression](#historique-et-detection-de-regression)
- [Utiliser le filtre `-Category`](#utiliser-le-filtre--category)
- [Prerequis](#prerequis)
- [Premier lancement](#premier-lancement-pas-a-pas)
- [Parametres en ligne de commande](#parametres-en-ligne-de-commande)
- [Rapports generes](#rapports-generes)
- [Deploiement multi-machines](#deploiement-multi-machines)
- [Depannage](#depannage)

---

## Presentation

`Check-Security.ps1` execute un audit en une passe de la posture de securite d'une machine Windows 11 : statut Windows Update, pare-feu, Defender, politique de comptes/mots de passe, BitLocker, exposition des protocoles reseau, taches planifiees, programmes au demarrage, VBS/Credential Guard/HVCI, configuration TLS/chiffrement, magasin de confiance des certificats, resilience anti-ransomware (Shadow Copy/VSS), et plus encore — 22 sections au total.

Il est entierement **en lecture seule**. Aucune verification ne modifie un parametre, n'arrete un service, ni n'ecrit dans le registre en dehors de ses propres fichiers de rapport/historique — il ne fait que lire et rapporter.

Chaque constat est enregistre avec une categorie, un statut (`OK` / `WARN` / `FAIL` / `INFO`), et un detail en langage clair. L'ensemble se resume en un **score pondere sur 100**, et chaque run est compare au precedent pour faire ressortir ce qui a change.

---

## Comment fonctionne le score

Le modele de scoring a connu une refonte documentee (v4.1) apres que l'approche originale "100 − somme des penalites" ait produit un score de 1/100 sur une machine qui avait pourtant HVCI, LSA Protection, Secure Boot et 18 regles ASR actives — les penalites s'accumulaient sans limite a mesure que de nouveaux controles etaient ajoutes, independamment de la posture globale.

Le modele actuel est un **taux de reussite pondere par categorie** :

```
Pour chaque categorie C :
    OK / INFO → 1.0   (reussi completement)
    WARN      → 0.5   (demi-credit)
    FAIL      → 0.0   (en echec)
    taux(C) = moyenne des valeurs ci-dessus sur tous les controles de cette categorie

Score = Σ(poids(C) × taux(C)) / Σ(poids(C)) × 100
```

Ceci est invariant au nombre de controles present dans chaque categorie, et un seul `FAIL` dans une petite categorie ne peut plus faire couler tout le score comme c'etait le cas avec l'ancien modele.

**Poids par categorie** (les categories non listees ont un poids par defaut de 1.0) :

| Categorie (valeur reelle, en anglais) | Poids | Categorie (valeur reelle, en anglais) | Poids |
|---|---|---|---|
| Antivirus | 1.6 | Certificates | 1.3 |
| BitLocker | 1.6 | Firewall | 1.4 |
| VBS | 1.5 | Network | 1.4 |
| Backup | 1.5 | TLS/SCHANNEL | 1.4 |
| Password Policy | 1.3 | Hardening | 1.4 |
| Accounts | 1.2 | Defender | 1.1 |
| Services | 0.8 | Startup | 0.7 |
| Software | 0.5 | | |

L'intention : un `FAIL` sur BitLocker ou l'antivirus doit peser plus lourd qu'un `FAIL` sur "logiciels installes" — les poids codent ce jugement explicitement plutot que de laisser chaque controle avoir la meme importance par accident.

---

## Les 22 sections

<details>
<summary><strong>1–5 · Systeme, Windows Update, Pare-feu, Defender, Comptes</strong></summary>

Infos systeme + signature Authenticode du script lui-meme ; anciennete du dernier patch (WARN >30 jours, FAIL >60) ; statut du pare-feu par profil et classification des regles par editeur (signe Microsoft → INFO, tiers/non signe → WARN) ; protection en temps reel Defender, anciennete du dernier scan (WARN >7 jours, FAIL >30), historique des detections de menaces sur 30 jours ; comptes locaux, politique de mot de passe, et le compte Administrator integre (RID-500) specifiquement.
</details>

<details>
<summary><strong>6–10 · UAC, BitLocker, Reseau, Services, Journaux d'audit</strong></summary>

Niveau UAC ; BitLocker (lecteur systeme `C:` → FAIL si desactive, autres volumes → WARN) ; ports en ecoute classes par exposition (RDP sur `0.0.0.0` → FAIL, WinRM → WARN fort, RPC 135/SMB 445 sur interfaces systeme → INFO car comportement Windows normal), connexions TCP etablies vers des IP publiques enrichies avec le nom du processus, exposition pare-feu IPv6, profil reseau actif par interface ; services auto-demarres non-systeme avec chemins suspects ; configuration de la politique d'audit et evenements de securite recents (4648 connexions avec identifiants explicites, 4720/4726 creation/suppression de compte).
</details>

<details>
<summary><strong>11–15 · Taches planifiees, Secure Boot/TPM, PowerShell, Logiciels, Demarrage</strong></summary>

Taches planifiees suspectes ; statut Secure Boot et TPM ; politique d'execution PowerShell, Script Block Logging/Transcription (retrogrades en INFO sur un poste personnel — ce sont des outils forensiques d'entreprise qui ajoutent du bruit sans SOC pour surveiller les journaux), Smart App Control (sensible a la compatibilite CPU : "non disponible" sur du materiel non compatible est INFO, pas un avertissement) ; inventaire des logiciels installes ; programmes au demarrage depuis a la fois les autoruns registre et les dossiers Demarrage, controles de persistance par detournement IFEO et `AppInit_DLLs`.
</details>

<details>
<summary><strong>16–19 · Exclusions Defender, Windows Hello, VBS, Certificats</strong></summary>

Exclusions de chemin/extension/processus Defender (signalees si trop larges) ; enrolement PIN/biometrique Windows Hello ; VBS, Credential Guard, Memory Integrity (HVCI), et LSA Protection (RunAsPPL) ; certificats racine de confiance valides par **empreinte par rapport a une liste blanche verifiee manuellement** (voir ci-dessous) et certificats expires dans le magasin personnel.
</details>

<details>
<summary><strong>20–22 · Suites TLS/chiffrement, Pilotes vulnerables, Shadow Copy/VSS</strong></summary>

**TLS/SCHANNEL** — cinq controles independants, detailles juste apres le tableau : etat des protocoles (TLS 1.0/1.1 desactives, TLS 1.2/1.3 actives), une politique GPO forcant l'ordre des suites de chiffrement si elle existe, les chiffrements legacy individuels (RC4/DES/RC2/3DES/NULL) desactives au niveau registre, les algorithmes de hachage faibles (MD5/SHA-1), la longueur minimale de cle Diffie-Hellman, et le Strong Crypto .NET Framework sur chaque installation .NET reellement presente. **Pilotes** verifies contre la liste de blocage HVCI de Microsoft et pilotes recemment installes. **Shadow Copy/VSS** — service Volume Shadow Copy et points de restauration existants (pertinent pour la recuperation apres ransomware).
</details>

### TLS/SCHANNEL, en detail

SCHANNEL est le composant Windows bas niveau par lequel passe toute connexion TLS/SSL sur la machine — RDP, LDAPS, IIS, la plupart des applications .NET, et beaucoup de logiciels tiers qui n'embarquent pas leur propre pile TLS. La Section 20 lit son etat sur cinq surfaces de registre independantes :

| Controle | Ce que ca signifie si c'est faible |
|---|---|
| **Protocoles** (TLS 1.0/1.1/1.2/1.3) | TLS 1.0/1.1 sont obsoletes et vulnerables a **POODLE**/**BEAST** — ils doivent etre desactives, cote client comme cote serveur |
| **Ordre des suites de chiffrement (GPO)** | Une Group Policy de domaine ou locale peut forcer une liste de suites precise ; si elle existe, elle ne doit pas contenir RC4, 3DES, DES, NULL ou EXPORT |
| **Chiffrements legacy individuels** | RC4, DES, RC2, Triple DES 168 et NULL peuvent chacun etre desactives independamment au niveau registre — le mecanisme reellement utilise hors domaine, distinct du controle GPO ci-dessus |
| **Algorithmes de hachage faibles** | MD5 et SHA-1 sont encore acceptes par SCHANNEL sauf desactivation explicite |
| **Longueur minimale de cle Diffie-Hellman** | En dessous de 2048 bits, une connexion est vulnerable a une degradation type **Logjam** |
| **Strong Crypto .NET Framework** | Sans ca, une application .NET peut contourner tous les reglages ci-dessus et negocier le TLS via sa propre pile obsolete |

POODLE, BEAST et Logjam ne sont pas des menaces theoriques — ce sont des attaques nommees et pratiques contre exactement les reglages par defaut que Windows continue d'expedier tant que personne ne les desactive explicitement. Une machine jamais touchee affichera la plupart de cette section en `WARN` ou en `INFO` ("valeur par defaut Windows") — c'est attendu, pas un bug de l'audit.

**Check-Security se contente de lire cet etat — il n'ecrit jamais dans le registre.** Si la Section 20 remonte des `WARN`, c'est un constat, pas une correction. Pour durcir reellement TLS/SCHANNEL sur la machine, lance le script complementaire **[Harden-TLS](https://github.com/NephVx2/Harden-TLS)** (meme auteur, meme suite), puis relance Check-Security ensuite pour confirmer que le changement a bien pris effet.

**Validation de confiance des certificats, en detail :** la liste blanche des certificats racine "connus comme sains" est indexee par **empreinte SHA-1/SHA-256**, pas par Subject CN — un choix de conception delibere explique directement dans le script : le nom affiche d'un certificat n'est qu'une chaine de caracteres, et n'importe quel certificat auto-signe pourrait definir son CN sur `"DigiCert Trusted Root G4"`. Une correspondance par nom serait trivialement contournable ; une correspondance par empreinte signifie qu'une entree ne peut etre legitime que si quelqu'un a reellement verifie ce certificat precis.

---

## Historique et detection de regression

Chaque run ecrit son score dans un fichier d'historique glissant (20 derniers runs) et se compare au run immediatement precedent :

- **Deltas par controle** — tout ce qui a change de statut (ex : `OK → WARN`) depuis la derniere fois est signale specifiquement, pas seulement le score global.
- **Alerte de regression** — si le score chute de plus de `$ScoreRegressionThreshold` (par defaut : **5 points**) depuis le dernier run, une banniere rouge apparait en console et dans le rapport HTML. Une variation de 1 a 2 points est un bruit normal ; une chute de 5+ points signale un changement reel.
- **Sparkline de tendance** — un petit graphique SVG des 20 derniers scores, rendu directement dans le rapport HTML.
- **Resume executif** — un bloc "Points critiques" tout en haut du rapport HTML liste chaque `FAIL` actuel (puis les `WARN`, jusqu'a 10 au total) avant meme de defiler dans le detail complet des 22 sections.

---

## Utiliser le filtre `-Category`

`-Category` ne relance que les sections correspondantes, au lieu de l'audit complet d'environ 3 minutes — pratique juste apres un correctif cible (BitLocker active, Harden-TLS execute, un service desactive) quand on veut juste confirmer qu'un point precis a change.

```powershell
.\Check-Security.ps1 -Category "BitLocker"
.\Check-Security.ps1 -Category "BitLocker","TLS/SCHANNEL"
```

C'est un `[string[]]`, donc on peut passer une ou plusieurs valeurs, separees par des virgules. Une section s'execute si *au moins une* de ses propres categories correspond partiellement a *au moins une* des valeurs passees (`-like` dans les deux sens), donc `-Category "TLS"` matche aussi la categorie `TLS/SCHANNEL`. Les valeurs acceptees sont celles du tableau de poids par categorie plus haut, plus quelques categories de controles sans poids personnalise (`System`, `Updates`, `UAC`, `Audit`, `Scheduled Tasks`, `UEFI Security`, `Windows Hello`, `Defender`) — voir l'aide integree du script (`Get-Help .\Check-Security.ps1 -Full`) pour la liste exacte sous `-Category`.

Deux etats ($OS/$CS/$BIOS/$CPU, et la detection Windows Hello) sont partages entre des sections qui ne tournent pas forcement ensemble, donc ils sont toujours calcules quel que soit le `-Category` passe — le filtre ne laisse jamais l'en-tete du rapport HTML ou le controle Windows Hello sans donnees.

---

## Prerequis

- Windows 11 (le script verifie le numero de build et rapporte `FAIL` s'il est execute sur un OS plus ancien — il continue de s'executer, mais se signale lui-meme comme hors de son perimetre prevu).
- PowerShell 5.1 (integre a Windows) ou PowerShell 7+.
- Droits administrateur (`#Requires -RunAsAdministrator` — le script refusera de demarrer sans, il n'y a pas de logique d'auto-elevation, contrairement a d'autres scripts de cette suite).
- Si le script est signe numeriquement (recommande en environnement `-ExecutionPolicy AllSigned`/`RemoteSigned`) : le certificat de signature doit etre approuve sur la machine cible.

---

## Premier lancement (pas a pas)

1. Copier `Check-Security.ps1` sur la machine cible.

2. Ouvrir PowerShell **en tant qu'Administrateur** manuellement — le script exige l'elevation des le depart et ne s'auto-eleve pas.

3. Lancer d'abord le self-test — aucun rapport ecrit, aucune requete registre/WMI, rien de modifie :

   ```powershell
   .\Check-Security.ps1 -SelfTest
   ```

   Execute 48 assertions internes (fonction d'echappement HTML, rendu des badges de statut, table des poids par categorie, la fonction `ShouldRunSection` elle-meme, coherence du seuil de regression du score, et plus). Code de sortie `0` = tout passe, `1` = au moins un echec.

4. Lancer l'audit complet :

   ```powershell
   .\Check-Security.ps1
   ```

   Prend environ quelques minutes selon la machine (les requetes de journaux d'evenements et l'enumeration des certificats sont generalement les etapes les plus lentes). Suivre en console le flux en direct `[OK]`/`[WARN]`/`[FAIL]`/`[INFO]` a mesure que chaque section se termine.

5. A la fin, la console affiche une banniere finale avec le score pondere, suivie de jusqu'a 5 constats `FAIL` et 5 `WARN` pour une lecture immediate sans ouvrir le rapport HTML.

6. Ouvrir le rapport HTML genere (le script propose de le faire automatiquement sauf si `-Silent` est utilise) — commencer par le bloc "Points critiques" en haut, puis utiliser la barre de recherche pour sauter vers un controle specifique.

7. Sur les **deuxieme run et suivants**, la console et le rapport HTML afficheront en plus ce qui a change depuis la derniere fois, et une banniere de regression si le score a chute de plus de 5 points.

8. Si un `FAIL` specifique necessite une reponse verifiee a la source (ex : "ce certificat racine est-il legitime ?"), ne pas se fier uniquement au rapport — verifier l'empreinte du certificat par rapport a la liste publiee par Microsoft ou l'editeur lui-meme avant de l'ajouter a la liste blanche dans le script.

---

## Parametres en ligne de commande

| Parametre | Description |
|---|---|
| `-Silent` | Supprime la sortie console, le prompt "ouvrir dans le navigateur", et la pause ENTREE finale — pour un usage via tache planifiee. Les rapports (HTML/TXT/JSON/CSV) sont toujours generes normalement. |
| `-SelfTest` | Execute la batterie de tests internes a 48 assertions puis quitte. Aucun droit admin requis au-dela du `#Requires` global du script, aucun rapport genere, rien de modifie. Code de sortie `0`/`1`. |
| `-Category <nom(s)>` | Ne relance que les sections correspondantes — voir [Utiliser le filtre -Category](#utiliser-le-filtre--category) ci-dessus. |

**Exemples :**

```powershell
.\Check-Security.ps1 -SelfTest
.\Check-Security.ps1
.\Check-Security.ps1 -Silent
```

---

## Rapports generes

Chaque run reel (hors `-SelfTest`) ecrit dans :

```
%USERPROFILE%\Desktop\Rapports_Maintenance\Check-Security\
```

| Fichier | Contenu |
|---|---|
| `Check-Security_<horodatage>.html` | Tableau de bord complet : resume executif ("Points critiques"), score pondere, tableau de repartition par categorie, sparkline de tendance, banniere de regression le cas echeant, detail complet des 22 sections avec recherche/filtre et ancres |
| `Check-Security_<horodatage>.txt` | Equivalent texte brut de l'ensemble des constats |
| `Check-Security_<horodatage>.json` | Export complet machine-readable de chaque constat |
| `Check-Security_<horodatage>.csv` | Export tabulaire de chaque constat |
| `_last_audit_baseline.json` | Instantane du dernier run uniquement, ecrase a chaque run — utilise pour calculer les deltas par controle |
| `_score_history.json` | Historique glissant des 20 derniers couples (date, score) — utilise pour la sparkline de tendance |

---

## Deploiement multi-machines

1. **Distribuer** le fichier `.ps1` vers chaque machine cible.

2. **Approuver le certificat de signature** si une politique d'execution stricte est en place (`-ExecutionPolicy AllSigned`/`RemoteSigned`).

3. **Executer `-SelfTest` en premier** sur chaque machine pour confirmer que le script lui-meme est intact avant de se fier a un audit complet.

4. **Planifier via le Planificateur de taches Windows** avec `-Silent`, en s'executant en tant qu'Administrateur (obligatoire — le script n'a pas d'auto-elevation, donc la tache elle-meme doit deja s'executer elevee) :

   | Champ | Valeur |
   |---|---|
   | Programme/script | `pwsh.exe` (ou `powershell.exe`) |
   | Arguments | `-NoProfile -ExecutionPolicy Bypass -File "C:\Scripts\Security\Check-Security.ps1" -Silent` |
   | Executer avec les autorisations maximales | Oui |

5. **Consulter d'abord le resume "Critical points"** (le rapport est entierement en anglais depuis la v5.1.0) sur le rapport HTML de chaque machine plutot que de lire les 22 sections completes a chaque fois — c'est exactement a ca qu'il sert.

6. Les rapports, la baseline et l'historique sont **propres a chaque machine** — aucune donnee n'est centralisee automatiquement. Pour une vue consolidee sur un parc, une etape de collecte separee (partage reseau, remontee de logs) devrait etre ajoutee par-dessus ce script.

7. **La liste blanche de certificats est specifique a la machine par conception.** Le `$TrustedRootThumbprintAllowlist` du script a ete rempli en verifiant manuellement des certificats specifiques trouves sur une machine particuliere (NEPH-DESKTOP). Deployer ce script tel quel sur une autre machine signifie que ses propres certificats racine legitimes mais differents apparaitront comme non reconnus — c'est le script qui fonctionne correctement, pas un bug. Revoir et etendre la liste blanche par machine (ou par image de parc connue) plutot que de supposer qu'une seule liste blanche convient a toutes les cibles de deploiement.

---

## Depannage

<details>
<summary><strong>Le script ne demarre pas du tout</strong></summary>

Il exige les droits Administrateur des le depart (`#Requires -RunAsAdministrator`) et ne s'auto-eleve pas — faire un clic droit sur PowerShell et choisir "Executer en tant qu'administrateur" avant de le lancer, ou lancer depuis un terminal deja eleve.
</details>

<details>
<summary><strong>Un certificat racine tout nouveau apparait comme non reconnu</strong></summary>

Attendu sur toute machine autre que celle pour laquelle la liste blanche a ete construite (voir [Deploiement multi-machines](#deploiement-multi-machines)). Verifier l'empreinte du certificat de maniere independante (liste racine publiee par Microsoft, documentation de l'editeur, ou `certutil`) avant de l'ajouter a `$TrustedRootThumbprintAllowlist` — ne jamais ajouter une empreinte simplement parce que le rapport l'a signalee, cela va a l'encontre du but de la liste blanche.
</details>

<details>
<summary><strong>Le score a chute et je ne sais pas pourquoi</strong></summary>

Consulter la banniere de regression du rapport HTML (affichee uniquement si la chute depasse `$ScoreRegressionThreshold`, 5 points par defaut) et la liste des deltas par controle — les deux sont calcules automatiquement par comparaison avec `_last_audit_baseline.json`. Une variation de 1 a 2 points entre deux runs peut etre un bruit normal dans une categorie ne comptant que quelques controles.
</details>

<details>
<summary><strong>-SelfTest signale un FAIL</strong></summary>

Lire directement le nom de l'assertion — il pointe vers une fonction utilitaire specifique en echec (echappement HTML, rendu des badges de statut, un poids de categorie manquant, etc.), pas vers la posture de securite reelle de la machine. C'est une auto-verification du script, sans rapport avec ce qu'un audit complet rapporterait.
</details>

---

<sub>Check-Security — 22 sections, lecture seule, scoring pondere par categorie, confiance des certificats basee sur l'empreinte, self-test a 48 assertions.</sub>
