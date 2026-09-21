#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Complete security audit for Windows 11
.DESCRIPTION
    This script runs a complete security audit of a Windows 11 machine:
    - System information
    - Windows Update & patches
    - Windows Firewall
    - Antivirus / Windows Defender
    - User accounts & password policies (including the RID-500 Administrator account)
    - Critical services
    - Network shares
    - Rights audit & UAC
    - BitLocker encryption
    - Network protocols (SMB, RDP, etc.) + IPv6 firewall exposure
    - Established TCP connections to public IPs (PID + process summary)
    - Suspicious scheduled tasks
    - Startup programs (registry autoruns + Startup folders)
    - Windows Defender exclusions + ASR (Attack Surface Reduction) rules
    - Windows Hello (PIN/biometrics)
    - VBS / Credential Guard / Memory Integrity (HVCI) / LSA Protection (RunAsPPL)
    - Network hardening (SMB signing, NTLM restrictions, encrypted DNS/DoH)
    - Smart App Control / WDAC
    - Non-standard trusted root certificates + expired certificates (Cert:\LocalMachine\My)
    - Shadow Copy / VSS (ransomware resilience)
    - Additional Defender signatures (Antispyware + NIS)
    - Comparison with the previous audit (status deltas + score evolution)
    - Automatic alert if the score regresses by more than $ScoreRegressionThreshold
      points since the last audit (red banner in the HTML report)
    - Multi-run history (up to the last 20 scores) with a mini evolution chart
      in the HTML report
    - Score weighted by category + detailed per-category table in the HTML report
    - "Critical points" block at the top of the HTML report
    - Automatically generated HTML report (JS search/filter, anchors to
      critical checks), plus TXT, JSON and CSV export
    - System TLS/SSL protocols and weak cipher suites (SCHANNEL)
    - -Category filter to run only specific sections
.PARAMETER Silent
    Suppresses console output, the browser-open prompt, and the final
    ENTER pause — useful for running via a scheduled task. HTML/TXT/JSON/CSV
    reports are still generated normally.
.PARAMETER Category
    List of categories to run. If specified, only sections whose main
    category matches an item in the list are run.
    Example: -Category "BitLocker","TLS/SCHANNEL"
    Possible values: System, Updates, Firewall, Antivirus, Accounts,
    UAC, BitLocker, Network, Services, Audit, Scheduled Tasks, PowerShell,
    Software, Startup, Defender, Windows Hello, VBS, Certificates,
    TLS/SCHANNEL, Backup, VSS
.NOTES
    Author  : Nephren (github.com/NephVx2)
    Version : 5.4.0
    Date    : 2026-09-13
    Run as Administrator

    CHANGELOG v5.4.0 (2026-09-13):

    - SECTION 5 (Password Policy) — fixed a real detection bug, reported by
      a user and confirmed via live testing. After setting the account
      lockout policy with "net accounts /lockoutthreshold:5
      /lockoutduration:15 /lockoutwindow:15" and confirming it with
      "net accounts" itself (Seuil de verrouillage: 5, Durée du
      verrouillage: 15, Durée de vie maximale du mot de passe: 42), this
      section still reported "Lockout threshold: Disabled (0 attempts)"
      and "Maximum password age: Unlimited" on a fresh run — both wrong.
      MinPasswordLength and MinPasswordAge read correctly via the ADSI
      WinNT provider ([ADSI]"WinNT://$env:COMPUTERNAME,Domain"), but
      MaxPasswordAge and MaxBadPasswordsAllowed/AutoUnlockInterval did not,
      on this Windows 11 build — the same ADSI path, two fields reliable,
      three not. Rather than keep two known-unreliable ADSI reads
      alongside two reliable ones, the whole section now parses "net
      accounts" text output instead — bilingually (FR/EN), the same
      pattern already used for auditpol/vssadmin/wbadmin elsewhere in this
      script. (This section actually used to parse "net accounts" long
      ago, in v1.1 — but English-only at the time, which is exactly what
      broke it on a French machine and led to the switch to ADSI in the
      first place. This version keeps the "net accounts" approach that
      works but finally makes it bilingual.)
    - Added a Get-NetAccountsValue helper (bilingual first-match text
      extractor, generalized from the inline pattern already used for
      auditpol/vssadmin/wbadmin) since Password Policy needs the same
      extraction for five different fields at once. Placed in the shared
      helper-functions area (not inside section 5) so -SelfTest can
      exercise it directly, with 3 new assertions (French label, English
      label, no-match case).

    CHANGELOG v5.3.0 (2026-09-13):

    - Fixed -Category: the parameter was accepted and documented, the
      ShouldRunSection helper it relies on was fully written and passed its
      own SelfTest assertions, but ShouldRunSection was never actually
      called anywhere in the script's 22 sections — every run executed all
      22 sections regardless of -Category, silently. Wrapped each section's
      body in "if (ShouldRunSection "<key>") { ... }" so the filter now
      actually filters (e.g. -Category "TLS/SCHANNEL" runs section 20 only,
      instead of the full ~3-minute audit).
    - Two pieces of state were computed INSIDE a section but read by a
      DIFFERENT section, which the fix above would have silently broken:
      $OS/$CS/$BIOS/$CPU (computed in section 1, but also read by the HTML
      report's meta-bar, generated unconditionally after every run) and
      $HelloConfigured/$HelloIndeterminate (computed in section 5, but also
      read by section 17). Both moved to a new unconditional
      "CROSS-SECTION PRE-COMPUTATION" block that always runs before the
      -Category filter can skip either producing section — placed after
      the -SelfTest block, not before it, so -SelfTest keeps its documented
      guarantee of zero WMI/registry access (SelfTest always exits before
      reaching this point).
    - Added a SelfTest assertion that $SectionCategoryMap has exactly 22
      entries (one per section) — a cheap regression guard against a typo'd
      or missing key silently making a section always run or always skip.

    CHANGELOG v5.2.0 (2026-09-12):

    - SECTION 20 — Closed a real coverage gap against Harden-TLS.ps1 (the
      companion script that actually hardens TLS/SCHANNEL on this machine).
      This section only ever checked protocols (TLS 1.0/1.1/1.2/1.3) and a
      GPO-forced cipher-suite-order list — a mechanism Harden-TLS.ps1
      doesn't use. It sets weak ciphers, weak hashes, the Diffie-Hellman
      minimum key length, and .NET Strong Crypto via entirely different
      registry keys, none of which this section could see: a machine fully
      hardened by Harden-TLS.ps1 still showed "Windows default" here,
      giving a false impression that nothing had been done. Added four new
      read-only checks (no registry writes, consistent with every other
      section in this script) that read the exact keys Harden-TLS.ps1
      writes:
        - Legacy cipher suites (SCHANNEL\Ciphers\<name>\Enabled) — RC4
          (4 variants), DES 56/56, RC2 (3 variants), Triple DES 168, NULL.
        - Weak hash algorithms (SCHANNEL\Hashes\<name>\Enabled) — MD5,
          SHA-1.
        - Diffie-Hellman minimum key length (Client + Server), WARN below
          the 2048-bit minimum recommended since 2016 (Logjam).
        - .NET Framework Strong Crypto (SchUseStrongCrypto,
          SystemDefaultTlsVersions), checked on every .NET Framework path
          actually present on the machine (v4.0.30319 native + Wow6432Node
          on 64-bit, plus legacy v2.0.50727 only if genuinely installed) —
          never assumes a path that isn't there, mirroring Harden-TLS.ps1's
          own Get-DotNetPaths logic.
      All four stay under the existing "TLS/SCHANNEL" category (no new
      category, no weight change). This doesn't duplicate Harden-TLS.ps1's
      hardening logic — it only reads what that script already writes, the
      same read-only/write-nothing split this script keeps with every other
      category.

    CHANGELOG v5.1.1 (2026-09-12):

    - Fixed ambiguous date display across every section (System, Antivirus,
      Software/certificates, Backup/VSS, wbadmin scheduling, the Evolution
      block, and the HTML report's meta-bar and footer): several dates were
      shown via a bare ToString()/-Format call with no explicit culture, so
      the day/month order silently depended on the PowerShell session's
      current culture rather than the machine's actual Windows region —
      "09/12/2026" could mean 9 Dec or Sep 12 depending on the machine, with
      nothing in the output to tell you which (reported by the user after
      the v5.1.0 translation made the ambiguity far more visible, since a
      few remaining dates were still hardcoded to the dd/MM/yyyy convention
      while the rest of the script became English-first for a foreign
      audience). Rather than force one fixed day/month order, added a
      Format-AuditDate helper that renders every displayed date as
      "dd MMM yyyy HH:mm" (e.g. "12 Sep 2026 14:32") using
      InvariantCulture — unambiguous and identical regardless of the
      machine's regional settings, including the month abbreviation itself
      (always "Sep", never "sept."). Every display-only date in the script
      now goes through this helper; wbadmin/vssadmin's own INPUT parsing
      (reading dates back out of Windows' raw command output, which is
      genuinely locale-dependent since Windows itself formats that output
      per its region) is untouched — this only changes how dates already
      extracted are shown to the user.
    - Added 3 SelfTest assertions for Format-AuditDate (with time, date-only,
      and a check that neither "09/12" nor "12/09" appears — i.e. the
      day/month ambiguity is actually gone, not just reformatted), following
      the same pattern used for every other helper function in this suite.

    CHANGELOG v5.1.0 (2026-09-11):

    - Full French-to-English translation of the script (code, comments,
      console/HTML/TXT strings, -Category values, changelog history) as part
      of the suite-wide translation project, following the same approach
      validated on SpicyCheck (v7.2 → v7.3). Version bumped to 5.1.0 rather
      than a patch release because -Category values and JSON/CSV field
      content change from French to English — a breaking change for anyone
      scripting against the previous French output or re-running with the
      old French -Category values (e.g. "Pare-feu" → "Firewall").
    - Commands/parsing whose output depends on the Windows OS display
      language (wbadmin, auditpol, DISM/SFC-style locale-dependent text)
      stay bilingual FR/EN so the script keeps working correctly on
      French-language Windows machines, not just English ones.
    - Historical baseline/score-history JSON files written by v5.0.x (French
      field values) are not automatically migrated; a fresh baseline will be
      created on first run of v5.1.0.

    CHANGELOG v5.0.15 (2026-08-25):

    - Removed the "Script signature" check (System section, introduced in
      v3.0): the script verified itself via
      Get-AuthenticodeSignature -FilePath $PSCommandPath and reported an
      OK/INFO/WARN status depending on whether it was signed. This check
      assumed the author's personal signing chain (Sign-MyScripts.ps1) and
      makes no sense for a user who pulls the script from GitHub: without a
      personal code-signing certificate, it always shows "Not signed", and
      worse, if the file was edited after an existing signature (the GitHub
      publication case, where the old Authenticode signature block was
      manually stripped), it reports "HashMismatch" as a WARN — a message
      that looks like an integrity/tampering alert when it's really just the
      absence of re-signing after editing. Removed the verification block and
      its now-orphaned help-link entry ("Script signature" → MS Learn
      about_Signing). No impact on the score or on the other 22 audit
      sections.

    CHANGELOG v5.0.14 (2026-08-25):

    - HTML report visual identity harmonized with Harden-TLS's report: the
      banner (<header>) now uses exactly the same layout (title row + Windows
      logo with cyan gradient shadow + "by Nephren" subtitle), with the title
      changed to "Check-Security vX.X.X" (instead of "🛡️ Windows 11 Security
      Audit").
    - Color palette (:root) replaced with Harden-TLS's (near-black background
      #080b12, cyan accent #00d4ff, green #a8ce81, orange #ffb347, red
      #ef7066, purple #7c6af7 for INFO badges) instead of the old classic
      indigo/red-green-orange-blue theme. Since the entire report CSS already
      references these variables (var(--ok), var(--fail), etc.), this change
      automatically harmonizes the score bar, stat cards, badges, table,
      regression banner, etc. Hardcoded rgba() values (row/badge/tag
      backgrounds) and $ScoreColor thresholds (score bar) were updated to
      match the same hues to stay consistent with the CSS variables.
      No change to behavior or report content — only the HTML report's visual
      identity is affected.

    CHANGELOG v5.0.13 (2026-08-25):

    - Script renamed "Check-Security" (removed the "_Win11" suffix from the
      file name and from all internal self-references — SelfTest banner, HTML
      report footer, example command in comments) to prepare for GitHub
      publication under this name. The generated report prefix follows the
      same change:
        Check-Security_Win11_*   -> Check-Security_*
      The script's content and behavior are strictly identical; only the
      names change. Mentions of "Win11"/"Windows 11" describing the audited
      operating system (SYNOPSIS, comments explaining Windows-11-specific
      behavior, etc.) were intentionally kept — only self-references to the
      SCRIPT's name were removed. Author field harmonized with the convention
      used for Harden-TLS.

    CHANGELOG v5.0.12 (2026-08-25):

    - [PowerShell 5.1 FIX] File re-saved as UTF-8 WITH a BOM marker (it never
      had one). Without a BOM, Windows PowerShell 5.1 detects the file's
      encoding via the system's ANSI/Windows-1252 codepage instead of real
      UTF-8, which corrupts every multi-byte character (French accents, icons
      ✓!✗·», separators ─│) and can prevent the script from parsing itself
      correctly depending on which characters appear on the affected line —
      the same bug confirmed on Harden-TLS v2.2.x. Transparent for PowerShell
      7 (pwsh), which already reads UTF-8 by default regardless of the BOM.
      Any future edit of this file must keep the "UTF-8 with BOM" encoding
      (Notepad, a misconfigured VS Code, etc. can silently strip it).
    - Report folder and files renamed to match the script's actual name
      (consistency with the GitHub publication under the name
      "Check-Security", to avoid confusing a user who would be looking for an
      "AuditSecurity" or "Audit_Securite" folder with no apparent connection
      to the downloaded script):
        AuditSecurity              -> Check-Security   (folder)
        Audit_Securite_Win11_*     -> Check-Security_Win11_*   (files)
      No change to behavior or report content. Users who re-run the script
      after this update will see the new reports appear in
      Desktop\Rapports_Maintenance\Check-Security\; the old AuditSecurity
      folder and its content are neither deleted nor migrated automatically.

    CHANGELOG v5.0.11 (2026-08-19):

    - Fixed a misalignment in the "Open the report in your browser?" prompt:
      the letter typed by the user showed up on the line above the Read-Host
      prompt. Cause: the 📄/📝/🧩/📊 emoji (report paths) and ✅/❌ (SelfTest /
      AUDIT COMPLETE banners) are, like the ✔/⚠/✘/ℹ fixed in v5.0.10,
      ambiguous-width glyphs that desync the terminal's cursor-position
      tracking — the effect wasn't visible on those lines themselves but
      carried over to the following Read-Host. Replaced with the already
      validated glyphs "✓" and "»" (the latter reused from
      Nettoyage-Windows11_v5_2's icon set).
    - Console readability, Section 10 (Logs & Audit): audit policy lines
      (e.g. "Policy: Logon...") could exceed 700 characters on a single line.
      Console-side only (Write-Log rendering): beyond 90 characters and with
      the " / " separator present, each sub-item is now wrapped onto its own
      line, indented under the "│" separator, with internal padding spaces
      (inherited from auditpol's raw output) tightened to 2 spaces.
      $Value remains strictly unchanged for TXT/HTML/JSON/CSV — only
      Write-Host is affected, per the "never break what works" principle.

    CHANGELOG v5.0.10 (2026-08-19):

    - Fixed console rendering following user feedback: icons ✔ ⚠ ✘ ℹ stuck to
      the text that follows on some Windows Terminal fonts (glyphs with
      "ambiguous" width in the Unicode East Asian Width sense, rendered as 2
      cells by some fonts → the following space gets visually absorbed).
      Replaced on the console side with ✓ ! ✗ · — the same glyph set already
      validated and used in Nettoyage-Windows11_v5_2 on this machine,
      guaranteed to be 1 cell wide. The HTML report is unaffected: the icons
      ✔ ✘ ⚠ ℹ from Get-StatusBadge remain unchanged (correct in a browser).
      Added a fixed column width for the icon ($LogIconWidth = 2) so the
      alignment of the rest of the line (category, │ separator, value)
      stays guaranteed even if a glyph renders wider than expected on a given
      font.

    CHANGELOG v5.0.9 (2026-08-19):

    - Aesthetic overhaul of console output (Write-Log / SECTION banners)
      No change to scoring logic or to the TXT report format (Add-Content
      still writes "[HH:mm:ss] [LEVEL] message" identically — compatibility
      preserved with any external parsing of the .txt).
      Console-only improvements:
        - Framed section banners (║ ... ║) with number and title, instead of
          plain "=== N. TITLE ===" lines.
        - Result lines (Add-Result) aligned in fixed columns: status icon,
          padded category, "│" separator, check name, value colored by
          status (green/yellow/red/cyan).
        - Icons unified with those already used in the HTML report
          (✔ OK · ⚠ WARN · ✘ FAIL · ℹ INFO) instead of [OK]/[WARN]/[FAIL].
        - Timestamp in subdued gray, category in cyan, separators in
          DarkGray to reduce visual noise and make the status and value
          stand out.
        - Final summary banner harmonized with the same framed style.
      Care point applied (cf. recurring Dashboard-Global bug):
      Write-Log keeps exactly the same signature and the same behavior for
      any existing call ($Message, -Level); the new parameters
      (-Category/-Check/-Value) are optional and only affect Add-Result's
      console rendering, never the TXT file or the function's return value.

    CHANGELOG v5.0.7 (2026-06-29):

    - SECTION 4 — Rework of the Defender scan check: quick scan and full scan
      tracked separately
      Old model: only the full scan was monitored, with 7-day WARN / 30-day
      FAIL thresholds.
      Systematic false positive on NEPH-DESKTOP (full scan 11 days old →
      WARN) because Defender on Win11 favors daily automatic quick scans and
      doesn't trigger a full scan on its own.
      New model (two checks):
        Quick scan (primary indicator):
          >3d → WARN, >7d → FAIL, missing → WARN
          Strong signal: a missing quick scan = Defender is disrupted
        Full scan (secondary indicator, wide thresholds):
          >30d → WARN, >90d → FAIL, never → INFO (not an anomaly)
          Monthly full scan recommended but not mandatory



    CHANGELOG v5.0.6 (2026-06-29):

    - SECTION 22 — Automatic backup scheduling via wbadmin
      wbadmin get schedule is not available on Windows 11 Home (the command
      is reserved for Windows Server). On Home, scheduling is carried by the
      scheduled task:
        \Microsoft\Windows\WindowsBackup\AutomaticBackup
      Queried via Get-ScheduledTask + Get-ScheduledTaskInfo to extract the
      state (Ready/Running/Disabled/Absent), the trigger frequency, the next
      run, and the last run. Results:
        Ready/Running → OK  (active scheduling)
        Disabled      → WARN (no more automatic backup)
        Task absent   → INFO (manual backup only)



    CHANGELOG v5.0.5 (hotfix after NEPH-DESKTOP run, 2026-06-29):

    - SECTION 22 — Fixed wbadmin parsing: "Backup time" field
      v5.0.4 looked for "Heure de la sauvegarde" — a field that doesn't exist
      on the FR locale. The actual wbadmin output on NEPH-DESKTOP uses:
        "Durée de sauvegarde : dd/MM/yyyy HH:mm"
        "Cible de sauvegarde : Disque dur étiqueté Auto_Save_Windows(E:)"
      Regex updated to cover "Durée de sauvegarde" (FR) and "Backup time"
      (EN). Dates parsed via ParseExact dd/MM/yyyy HH:mm (InvariantCulture)
      to avoid MM/dd vs dd/MM ambiguity on dates where the day is ≤ 12.
      Falls back to Parse() if ParseExact fails.
      With 9 backups on E:\Auto_Save_Windows (05/13 → 06/28/2026), expected
      result: OK "9 version(s) — last one 1 day(s) ago".



    CHANGELOG v5.0.4 (2026-06-29):

    - SECTION 22 — Added a wbadmin system image backup check
      wbadmin get versions lists the full backups available across all
      connected volumes (e.g. E:\Auto_Save_Windows). Parses the date of the
      latest version and the target volume.
      Thresholds: ≤30d → OK, 31-90d → WARN, >90d → FAIL, 0 versions → INFO.
      This check is independent of the VSS/shadow copy check — both coexist
      in section 22: VSS covers system restore points, wbadmin covers full
      system images.



    CHANGELOG v5.0.3 (hotfix after NEPH-DESKTOP run, 2026-06-29):

    - SECTION 22 — False VSS FAIL on Win11 Home despite restore points
      On Windows 11 Home, vssadmin list shadows /for=C: always returns 0
      results because generic VSS shadow copies aren't created automatically
      — only SYSTEM RESTORE POINTS exist. These are technically VSS shadow
      copies but cataloged differently (not listable via /for=C:). v5.0.1
      therefore always returned FAIL on Win11 Home even when restore points
      were present.
      New three-tier logic:
      1. vssadmin returns N blocks → existing handling (OK/WARN by age)
      2. vssadmin returns 0 blocks → fall back to Get-ComputerRestorePoint:
         - Restore points present and recent (<30d) → OK
         - Restore points present but old (>30d) → WARN
      3. Neither shadow copy nor restore point → FAIL (genuine case)



    CHANGELOG v5.0.2 (hotfix after NEPH-DESKTOP run, 2026-06-29):

    - SECTION 8 — False positive public TCP: pwsh flagged WARN
      PowerShell itself (pwsh) can have an active public TCP connection at
      audit time — the script currently running, a parallel PS session, or a
      PSGallery/Update request. Added pwsh, powershell and powershell_ise to
      $SystemProcsAllowlist.
      Expected result: TCP connections to public IPs → INFO if only
      recognized processes are present.



    CHANGELOG v5.0.1 (hotfix after NEPH-DESKTOP run, 2026-06-29):

    1. SECTION 8 — False positive TCP connections to public IPs
       NextDNSService, MpDefenderCoreService and Rainmeter flagged WARN
       because they were missing from $SystemProcsAllowlist. All legitimate:
       - NextDNSService: local DoH DNS proxy (NextDNS)
       - MpDefenderCoreService: Defender's cloud/telemetry component
       - Rainmeter: desktop widget (weather/stats CDN traffic)
       Added to the allowlist. Preventively added NisSrv, SecurityHealthService,
       SgrmBroker, spoolsv, lsass, wininit (other expected system processes).

    2. SECTION 8 — False positive IPv6: NotConfigured ≠ no blocking
       v5.0 strictly tested DefaultInboundAction -eq "Block". On Win11 with a
       default-configuration Public profile, the value is "NotConfigured" —
       Windows Defender Firewall still applies default inbound blocking.
       "NotConfigured" is now accepted as equivalent to "Block" → no more
       systematic WARN on every Win11 machine in standard configuration.

    3. SECTION 22 — VSS bug: 0 shadow copies returned INFO instead of FAIL
       French-locale vssadmin returns a header with no shadow copies that
       didn't match the "Aucun élément trouvé" patterns (missing accent or a
       different wording depending on the build). New two-pass logic:
       a) Count "Shadow Copy ID" blocks BEFORE attempting date parsing.
          0 blocks → direct FAIL, regardless of the header message.
       b) N blocks → parse dates to refine (OK/WARN by age).
          Parsing fails but N > 0 → INFO with the count (exotic-locale case).
       Added "Snapshot ID" as an alternate English pattern. Date extraction
       consolidated into a single group ($_.Groups[1+2+3]) to cover
       "Date et heure de création", "Creation Time" and "Date de création".

    CHANGELOG v5.0 (2026-06-29):

    1. SECTION 5 — Built-in Administrator account (RID-500)
       Explicitly checks whether the Administrator account (SID ending in
       -500) is enabled. On a personal machine, this account should stay
       disabled — enabling it widens the local brute-force attack surface.
       WARN if enabled, INFO otherwise. Relies on Get-LocalUser filtered by
       -500 SID (universal, language-independent).

    2. SECTION 4 — Additional Defender definitions (Antispyware + NIS)
       In addition to AntivirusSignatureLastUpdated, checks the age of:
       - AntispywareSignatureLastUpdated (anti-spyware module)
       - NISSignatureLastUpdated (Network Inspection System)
       Same thresholds as AV signatures: >3d WARN, >7d FAIL.
       Both components are independent of the AV engine and can drift
       separately if automatic updates are partially failing.

    3. SECTION 8 — IPv6 firewall exposure
       Checks whether IPv6 is active on non-loopback interfaces and whether
       firewall profiles explicitly cover IPv6. A Windows Firewall whose
       public inbound rules are all IPv4-only leaves a blind spot on active
       IPv6 interfaces. WARN if IPv6 is active without dedicated inbound
       blocking rules on the Public profile.

    4. SECTION 8 — TCP connections to public IPs (per-process summary)
       The outbound-connections summary already existed as INFO. In v5, a
       filtering pass is added to separate RFC-1918 (private) IPs from public
       IPs, producing a "who's talking outbound right now" summary with the
       process name. WARN if an unknown process (outside the system
       allowlist) establishes connections to public IPs.

    5. SECTION 19 — Expired certificates in Cert:\LocalMachine\My
       The machine personal store can accumulate expired certificates (old
       signing certs, revoked enterprise certs, etc.) that aren't
       automatically removed. An expired certificate in this store isn't a
       direct security risk, but it's a sign of PKI hygiene worth improving.
       WARN if the store contains certs expired for more than 365 days, INFO
       otherwise.

    6. SECTION 22 (NEW) — Shadow Copy / VSS
       Checks the VSS service state and the existence of recent shadow
       copies on C:. Ransomware systematically deletes shadow copies before
       encrypting files — their presence is a safety net.
       FAIL if no shadow copy exists, WARN if none in the last 7 days, OK if
       at least one recent one exists. Uses vssadmin.exe (available on every
       Windows 11 edition, including Home).

    7. HTML REPORT — Per-category score table
       The HTML report now exposes the scoring breakdown by category: a
       "Category | Partial Score | Weight | Checks" table placed under the
       overall score bar, making it immediately clear which category is
       dragging the score down.

    8. HTML REPORT — "Critical points" block at the top
       The most important FAIL and WARN checks are now displayed at the top
       of the report (before the detailed table), in a red/orange box
       visible immediately when opening the file.

    9. -Category PARAMETER
       Run filter: only run sections whose main category matches. Useful
       after a targeted fix (e.g. after enabling BitLocker, re-run only
       -Category "BitLocker") without waiting for a full 3-minute audit.

   10. SELFTEST — Assertions extended to the new sections (v5)
       Added assertions for VSS (service readable), Cert:\LocalMachine\My
       (store accessible), and the -Category filter (non-null list if
       provided).


    CHANGELOG v4.8.2 (hotfix after ChatGPT review, 2026-06-28):

    - TLS 1.2 WARN → INFO (confirmed false positive).
      On Windows 11, TLS 1.2 is active by default with no registry key —
      stable, Microsoft-documented behavior. WarnIfAbsent=$true generated a
      permanent false positive on every unconfigured Win11 machine. Switched
      to WarnIfAbsent=$false: missing key → INFO.
      Gain: -2 WARN → expected score ~95/100.

    CHANGELOG v4.8.1 (hotfix after run, 2026-06-28):

    - Fixed non-system service path bug (section 9).
      PathName cleanup used -replace ' .*$','' to strip arguments after the
      exe, but this also truncated "C:\Program Files\..." down to
      "C:\Program" at the first space → the "program files" match always
      failed → NextDNSService, Windhawk and WSLService (all in Program Files)
      wrongly classified as "suspicious" → unjustified WARN.
      Fix: if PathName starts with a quote, extract the path between quotes
      (preserves spaces in the folder name). Otherwise, cut at the first
      space (no-quotes case, no spaces in the path).

    CHANGELOG v4.8:

    1. SECTION 13 — Script Block Logging + PS Transcription → INFO
       Both checks generated permanent WARNs on a personal machine.
       Script Block Logging and Transcription are enterprise monitoring
       tools (recording every script to logs/text files for forensic
       investigation). On a well-managed personal Windows Home machine
       (Defender active, ASR, HVCI, LSA PPL, signed scripts), their absence
       isn't a weakness — they'd just generate useless noise with no one
       supervising the logs. Downgraded to INFO with an explanatory
       contextual message. Gain: -2 permanent WARNs.

    2. SECTION 8 — Listening TCP ports: refined context-based classification
       The old version flagged WARN as soon as a sensitive port was
       listening, without distinguishing the local address. But RPC 135 and
       SMB 445 are present on every Windows machine and listen on internal
       system interfaces — that's not the same as RDP 3389 exposed on
       0.0.0.0. New logic:
       - Port listening on 0.0.0.0 or :: (all interfaces):
         RDP 3389 → FAIL (direct exposure)
         WinRM 5985/5986 → strong WARN
         Other sensitive ports → WARN
       - Port listening on a specific non-public interface → INFO
       - RPC 135 and SMB 445: INFO if only on system interfaces (normal
         Windows behavior), WARN if exposed on 0.0.0.0.

    3. SECTION 13 — Smart App Control: distinguish unsupported vs disabled
       The old version showed INFO in every case except state=1 (Active).
       On a CPU not compatible with SAC (i7-7700HQ → Kaby Lake, predates the
       SAC requirement), "not available" is normal and deserves INFO.
       On a compatible CPU with SAC permanently disabled (state=0), that's a
       deliberate choice deserving contextual INFO (not a WARN — SAC can
       block legitimate unsigned tools and the user may have had to disable
       it for that reason).
       On a compatible CPU in evaluation mode (state=2), INFO with advice to
       let the evaluation run its course.

    CHANGELOG v4.7:

    1. SECTION 2 — Last Windows patch > 30 days → WARN (already in place,
       confirmed check: 30-day WARN / 60-day FAIL threshold already present
       since v1.x). Added the exact day count to the detail message.

    2. SECTION 4 — Last Defender scan > 7 days → WARN
       The old version just showed the date with no alert level for
       staleness. Added a WARN if the scan is more than 7 days old and a
       FAIL if more than 30 days (a genuinely neglected scan).

    3. SECTION 9 — Non-system auto services: show names + paths
       Previously just "3 non-system auto services" with no detail. Now
       shows the name, DisplayName and path of each third-party
       auto-start service in the result's Detail. WARN triggers if a path
       is outside System32/Program Files (suspicious path) or if the
       service account isn't SYSTEM/LocalService/NetworkService.

    4. SECTION 16 — Defender exclusions: show values in the summary
       Previously just "1 path exclusion" with no indication of which one.
       The excluded path, extension and process are now shown directly in
       the result's Value column (not just in Detail). The WARN for broad
       exclusions is kept.

    5. SECTION 8 — Listening ports enriched with PID/process
       New line listing TCP ports listening on non-loopback interfaces with
       the associated process name. Complements established TCP
       connections. Alerts if a sensitive port (RDP, WinRM, SMB, Telnet…)
       is listening on a public interface.

    6. CONSOLE SUMMARY — FAIL/WARN detail in the final banner
       The `AUDIT COMPLETE` banner now shows FAIL and WARN checks (up to 5
       of each) directly in the console, for an at-a-glance view without
       opening the HTML report.

    CHANGELOG v4.6:

    1. SECTION 4 — Defender history (30-day detections)
       Get-MpThreatDetection returns the list of threats detected and
       handled by Windows Defender. 0 detections in 30 days = OK.
       Recent detections = INFO with name, action and date for each threat
       (up to 10 shown). Lets you know whether Defender neutralized
       something in the background with no visible notification.
       Category "Defender", weight 1.1 (already in CategoryWeights).

    2. SECTION 3 — "rules open to any IP" WARN downgraded to INFO
       Now that classification by publisher (Microsoft/third-party/unsigned)
       gives actionable detail, the raw "31 open rules" count just
       duplicated the information as a WARN with no added value.
       Downgraded to INFO — the WARN stays on third-party/unsigned
       categories, the only ones that actually need attention.

    CHANGELOG v4.5:

    1. SECTION ORDER FIXED — section 21 was displaying before section 20.
       Swapped the TLS (20) and Drivers (21) blocks to restore the correct
       numeric order 20 → 21 → SUMMARY.

    2. FIREWALL — Fixed "unsigned" false positives (section 3)
       a) Expand environment variables before Get-AuthenticodeSignature:
          %SystemRoot%\system32\svchost.exe → C:\Windows\System32\svchost.exe.
       b) Executables in \Windows\System32\ with driver "System" → classified
          as Microsoft directly without a signature check.
       c) Microsoft "port only" rules (Microsoft Store, Experience Pack,
          Web Viewer) → INFO instead of WARN.
       Result: 13 WARN → ~2 genuine WARN (Snappy Driver Installer + unsigned
       third-party), the rest reclassified as Microsoft INFO.

    CHANGELOG v4.4.2 (hotfix after run, 2026-06-27):

    - Fixed WSL false positive corrected (section 21 — Recent drivers, event
      7045).
      wslservice.exe in "C:\Program Files\WSL\" was flagged WARN for being
      outside System32\drivers and DriverStore. It's an official Microsoft
      service (WSL) installed via Windows Update/Store — a legitimate path.
      Added Program Files\WSL and Program Files\WindowsApps to the trusted
      paths. AppData, Temp, or user paths still trigger WARN.

    CHANGELOG v4.4.1 (hotfix after run, 2026-06-27):

    - Fixed DEP/ASLR false positives (section 13 — Exploit Protection).
      Get-ProcessMitigation returns "NOTSET" when a mitigation isn't
      explicitly configured, not "OFF". v4.4 compared against "ON" and
      interpreted NOTSET as disabled → 2 unjustified WARN on a machine where
      DEP and ASLR are active by default (standard Windows behavior).
      Now: ON = OK, OFF = WARN, NOTSET = INFO (Windows default, safe).
      Same logic as the handling of missing TLS keys.

    CHANGELOG v4.4:

    1. SECTION 3 — Firewall: classification by publisher/signature
       Rules open to any IP are classified into 3 tiers:
       Microsoft-signed → INFO, third-party signed → WARN, unsigned/unknown →
       strong WARN.

    2. SECTION 7 — BitLocker: system C: = FAIL, other volumes = WARN
       Non-system volumes go from FAIL to WARN (relevant if they hold
       sensitive data, not mandatory for a games/scratch drive).

    3. SECTION 13 — SmartScreen
       SmartScreen protection state (Off/Warn/RequireAdmin).
       RequireAdmin or Warn = OK, Off = WARN.

    4. SECTION 13 — Exploit Protection (Process Mitigation Policies)
       Get-ProcessMitigation -System: checks DEP and ASLR at the system
       level.

    5. SECTION 18 — Kernel-mode Hardware-enforced Stack Protection
       HVCIOptions bit 8 in CI\Config — requires Tiger Lake+/Zen 3+ CPU.

    6. SECTION 21 — Vulnerable drivers (HVCI Blocklist + recent drivers)
       New section: state of Microsoft's vulnerable-driver blocklist +
       System event 7045 (24h) for drivers installed outside the Windows
       Update channel (path outside System32/DriverStore).

    CHANGELOG v4.3.1 (hotfix):

    - Fixed $PID bug (section 8 — TCP connections).
      $PID is a reserved, read-only PowerShell variable (current process's
      PID). Using it inside a foreach silently raised a "Cannot overwrite
      variable PID because it is read-only" error, which dropped the whole
      section into the catch → "Unreadable" INFO on every run, even as
      admin.
      Renamed $pid → $procId in the connection-enrichment loop.
      Identified via a ChatGPT report review (2026-06-27).

    CHANGELOG v4.3:

    1. HTML REPORT — Inline Δ column in the results table
       Each row now shows a change icon in the Status column:
       - ▲ red    : status worsened (e.g. OK → FAIL)
       - ▼ green  : status improved (e.g. WARN → OK)
       - ● gray   : new check, absent from the previous run
       - (none)   : status unchanged
       $DeltaMap cross-referenced while generating the <tr> rows.

    2. -SelfTest MODE (31 assertions)
       Runs a battery of internal tests without touching the system or
       generating a report. Assertions: He(), Get-StatusBadge, Add-Result,
       the weighted scoring engine, CategoryWeights (5 categories checked),
       ScoreRegressionThreshold, TrustedRootThumbprintAllowlist,
       TrustedTaskNames, BitLocker C:/non-C: logic, readable SmartScreen key,
       Get-ProcessMitigation availability, CI\Config accessible, DeltaMap
       construction and lookup.
       Output: [PASS]/[FAIL] per assertion. Exit code 0 (all OK) or 1.

    CHANGELOG v4.2.1 (hotfix after run, 2026-06-27):

    - Event 4648 WARN threshold raised from 10 to 50.
      After analyzing real events on NEPH-DESKTOP: every 4648 event comes
      from svchost.exe / winlogon.exe / wininit.exe to localhost (accounts
      DWM-1, UMFD-0/1, nephren) — normal system noise generated at session
      logon by Windows credential-management services. A threshold of 10 was
      too low for this machine and generated a systematic WARN with no
      informational value. 50 stays conservative (a spike above 50 in 24h
      still deserves investigation).

    CHANGELOG v4.2:

    1. SECTION 8 — WinRM (Windows Remote Management)
       WinRM is the PowerShell remote-access service (WSMan). Active = any
       admin can open a remote PS session on the machine. Checks the WinRM
       service status AND the listener configuration (port 5985/5986) via
       the WSMan registry. Service stopped + no listener = OK. Service
       Running or a listener present = WARN with port/transport detail.

    2. SECTION 10 — Additional security events (24h)
       Three new Get-WinEvent queries against the Security log:
       - ID 4648: logons with explicit credentials (RunAs, net use /user,
         etc.) — a sign of privilege escalation or lateral movement.
       - ID 4720: local user account creation.
       - ID 4726: local user account deletion.
       Thresholds: 0 = OK, 1-5 = INFO (can be normal), >5 = WARN.

    3. SECTION 15 — IFEO hijacking + AppInit_DLLs
       - IFEO (Image File Execution Options): subkeys with a "Debugger"
         value silently substitute a different exe on every launch of a
         system executable. Classic RAT persistence technique.
       - AppInit_DLLs: DLLs injected into every Win32 process at boot.
         Must be empty. Non-empty = immediate WARN.

    4. SECTION 8 — Active network profile per interface
       Lists every connected interface with its profile (Public/Private/
       Domain) and network name. WARN if the Domain profile is set on a
       machine not joined to a domain (orphaned config, potentially from a
       migration or a misconfiguration).

    5. HTML REPORT — Executive summary at the top of the report
       Dynamically generated "Critical points" block: FAIL in red, then
       WARN, above the table. Limited to 10 items. Green banner if
       everything is OK.

    CHANGELOG v4.1 (fixes after run, 2026-06-26):

    1. SCORING OVERHAUL (critical bug inherited from v3.x, made visible in
       v4.0)
       The old "100 − sum(penalties)" model was unstable: every new FAIL/WARN
       check added a penalty with no regard for the total number of checks.
       Example: 3 BitLocker FAIL × 10 × 1.6 = 48 penalty points,
       + 6 TLS WARN × 3 × 1.4 = 25 points → score = 1/100 on a machine with
       HVCI active, UEFI LSA PPL, 18 ASR rules, Secure Boot, etc.

       New model: weighted per-category success rate.
         For each category C:
           - OK/INFO  = 1.0   (passed)
           - WARN     = 0.5   (half-passed)
           - FAIL     = 0.0   (failed)
           rate_C = average(status values) across all checks in C
         Score = Σ(weight_C × rate_C) / Σ(weight_C) × 100
       Properties:
         - Invariant to the number of checks per category.
         - A BitLocker FAIL → BitLocker category at 0%, without affecting
           the others.
         - Score 100 = everything OK. Score 0 = everything FAIL. Always
           between 0 and 100.
         - On this run (3 BitLocker FAIL, 6 TLS WARN, various WARN):
           ~84/100, which reflects reality (good overall posture, BitLocker
           absent).
       Note: $CategoryWeights is kept as-is — the weights now apply as
       weighting factors in the average, not as penalty multipliers. The
       semantics stay identical: BitLocker/Antivirus/VBS weigh more than
       Software/Startup.

    2. TCP CONNECTIONS "WARN Unreadable" → "INFO"
       Get-NetTCPConnection can throw on certain system sockets (session
       inheritance, kernel ACLs) even as admin. This isn't a security
       anomaly — the error is now captured as INFO with the exact message,
       and no longer penalizes the Network category's score.

    CHANGELOG v4.0:

    1. NEW SECTION 20 — TLS/SSL protocols and cipher suites (SCHANNEL)
       Reads the HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\
       SCHANNEL\Protocols\ keys to verify that TLS 1.0 and TLS 1.1 are
       properly disabled (client AND server) and that TLS 1.2/1.3 are
       enabled. Missing key = Windows applies its defaults (permissive on
       older builds) — reported as INFO with detail, not silently treated as
       OK. Then checks active cipher suites via
       HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\
       00010002\Functions to flag RC4, 3DES, DES, NULL, EXPORT if present.
       This path only exists if a GPO or manual config forced a list — its
       absence means Windows manages the default suites (INFO, not a
       problem).
       New "TLS/SCHANNEL" category with weight 1.4 in $CategoryWeights.

    2. SECTION 8 IMPROVEMENT — Established outbound TCP connections
       The old version (added in v1.x) just showed a raw count "Top 20 shown
       in the report" with no enrichment.
       Each connection is now enriched with the process name via Get-Process
       (matched on OwningProcess/Id), loopback and link-local IPv6 addresses
       are filtered out cleanly, and connections whose process can't be
       resolved (access denied, PID gone) are reported separately. Orphaned
       connections (PID with no resolvable process) generate a WARN — a sign
       of a process that terminated right after establishing the connection,
       or a socket held by an unreadable system service.

    3. SUMMARY SECTION IMPROVEMENT — Score regression alert
       If the score drops by more than $ScoreRegressionThreshold points
       since the last audit, a distinct alert banner is shown in the console
       (Write-Log FAIL) and in the HTML report (red box above the Evolution
       block), independent of individual deltas.
       Configurable via $ScoreRegressionThreshold (default: 5 pts).
       A -1 or -2 point delta on a score of 98 isn't the same as a 15-point
       drop — this threshold avoids false positives while still alerting on
       real regressions.

    CHANGELOG v3.4 (end-entity vs CA analysis in the Root store + allowlisting
    the identified GUID certificate):

    - Finding from the investigation of certificate
      CN=49793F74-...-4ED3A640FC76 (WARN in v3.3): analyzing its extensions
      via PowerShell revealed it's an "End-entity" certificate
      (BasicConstraints: CA=FALSE), with Code Signing EKU only and Microsoft
      OIDs 1.3.6.1.4.1.311.84.x (Microsoft Trusted Signing namespace).
      Created on 2026-03-30 by Windows itself for local MSIX/AppX package
      signing. Not dangerous.
    - Added to $TrustedRootThumbprintAllowlist with an explicit note about
      its type (end-entity, not a CA), its EKU and its origin.
    - New: section 19 now detects whether each non-Microsoft certificate is a
      CA (CA:TRUE in BasicConstraints) or an end-entity (CA:FALSE). This
      "Type" field is shown in the detail card. The estimated danger level
      takes this distinction into account:
        - Verified end-entity     → "Very low (MITM impossible)"
        - Unverified end-entity   → "Moderate (MITM impossible but
          non-standard placement in Root — identify the origin)"
        - Unverified CA           → "Review" or "Review as a priority"
      An end-entity in Root can't sign other certificates or intercept TLS
      traffic, which makes it fundamentally less risky than an unknown CA,
      even unverified.
    - New: the certificate's EKU (Extended Key Usage) is also shown in the
      detail card — useful to quickly distinguish a code-signing cert from a
      server TLS cert or a general-purpose CA.

    CHANGELOG v3.3 (fixed recognition of personal scheduled tasks):

    - Finding: BloatRemoval, EdgeRemoval, OneDriveRemoval were showing up as
      WARN even though they're known personal tasks. Two causes identified:
      1. The path-extraction regex [A-Za-z]:\\[^\s"]+\.ps1 excludes spaces
         via [^\s] — so it stops at the first space in a path like
         "Scripts Maintenance Win11\Script.ps1" and fails silently, leaving
         $isTrusted at $false.
      2. No fallback by task name: if the path couldn't be extracted (inline
         cmd, .bat, arguments with no visible .ps1), the task always ended
         up in $SuspTasksReal regardless of its origin.
    - Fix 1: two-pass path extraction — first the quoted pattern (handles
      spaces: "([A-Za-z]:\\[^"]+\.ps1)"), then the unquoted pattern
      (unchanged, for paths without spaces). First match wins.
    - Fix 2: added $TrustedTaskNames (CONFIGURATION) — an allowlist by task
      name, checked before any path extraction. Independent of argument
      format, it covers every case the regex can't handle. Pre-filled with
      BloatRemoval, EdgeRemoval, OneDriveRemoval.

    CHANGELOG v3.2 (contextual help links):

    - New: every check in WARN or FAIL status now shows, in the HTML report,
      one or more clickable links to relevant documentation or a diagnostic
      tool (mostly Microsoft Learn). Same principle as $script:RecoDb /
      Get-SourceRecommendation on the Analyze-WindowsLogs side: a mapping
      table of Category + pattern on the check name -> links.
    - Two cases handled outside the generic table because the link depends
      on the exact result value, not just its type:
        - Root certificates (section 19): search link by THUMBPRINT (crt.sh),
          not by name — consistent with the choice made in v3.1 (a
          certificate name can be forged, its thumbprint can't).
        - Software to watch (section 14): CVE search link (NVD) built from
          the exact detected name and version.
    - Shown only on WARN/FAIL — an OK/INFO check doesn't need remediation
      docs, it would have just cluttered the table.
    - Added the He() function (HTML escaping), missing from this script
      until now — needed to insert URLs/labels into href attributes without
      risking broken HTML on a special character.
    - Doesn't affect TXT/JSON/CSV exports (the links are an HTML-report-only
      feature).

    CHANGELOG v3.1 (fixed a design flaw in the detection of non-standard root
    certificates, section 19):

    - v3.0 excluded a certificate from the alert by comparing its Subject CN
      against AuthRoot/known CA names — but a Subject is just a plain text
      string with no cryptographic protection: a malicious certificate can
      name itself "CN=DigiCert Trusted Root G4" without proving anything.
      Filtering/excluding by name would have opened a trivial bypass.
    - Replaced with $TrustedRootThumbprintAllowlist (CONFIGURATION): an
      allowlist indexed by THUMBPRINT (SHA-1 fingerprint), the only
      cryptographic identity of a certificate that can't be forged. The
      script only downgrades a certificate to OK if its exact thumbprint
      matches an entry you personally verified and added to the list — never
      based on name alone.
    - No information is hidden anymore: every certificate outside the
      Microsoft list (verified or not) now generates a full detail card —
      name (CN, with an explicit note if non-descriptive/GUID), issuer,
      store location, expiration date, thumbprint, computed legitimacy
      status, and estimated danger level. The name is still shown so you can
      recognize it visually, but it's only used as a readability hint in the
      danger calculation, never as a trust criterion.
    - Allowlist initialized with the 3 thumbprints confirmed legitimate
      during the 2026-06-21 audit (DigiCert Trusted Root G4, Thawte
      Timestamping CA, VeriSign Time Stamping Service Root) — the 4th
      certificate from that run (GUID-named CN) intentionally remains WARN,
      not added to the list.

    CHANGELOG v3.0 (new hardening checks + scoring overhaul):

    - New: LSA Protection (RunAsPPL) — protects lsass.exe against credential
      dumping (Mimikatz and the like). Added to section 18, next to
      Credential Guard since both target the same threat.
    - New: Windows Defender ASR (Attack Surface Reduction) rules, read via
      Get-MpPreference (same cmdlet as the exclusions in section 16) —
      counts configured rules and flags if none are active.
    - New: Smart App Control (Win11 22H2+), added to section 13 next to
      AppLocker/ExecutionPolicy as the same family of application control.
    - New: account lockout duration (LockoutDuration), alongside the
      lockout threshold already present in section 5 — same ADSI call, no
      extra cost.
    - New: mandatory SMB signing (client + server) and NTLM restrictions
      (LmCompatibilityLevel audit, NTLMv1 blocking), added to section 8 next
      to the existing SMBv1 check.
    - New: system-level encrypted DNS (DoH) status, section 8 — consistent
      with using a filtering DNS resolver.
    - New: inbound firewall rules "open to any IP" now classified by port
      danger (RDP/SMB/WinRM/etc. flagged FAIL, the rest WARN), section 3 —
      previously a raw count with no distinction of actual risk by port.
    - New: section 19, non-standard trusted root certificates in the
      LocalMachine\Root store — a certificate added outside the Microsoft
      list is a common sign of MITM interception or unwanted software (ad
      proxy, etc.).
    - New: Authenticode signature check on the script itself at launch
      (section 1) — consistent with using Sign-MyScripts.ps1 across the rest
      of the suite.
    - New: score weighted by category instead of a flat penalty per status.
      Categories with high real-world impact (BitLocker, Antivirus, VBS,
      Firewall, Network, LSA/Credential, Password Policy) weigh more than a
      "Software to watch" or "Startup" FAIL. The calculation detail is now
      exposed in the report (per-category weight as a tooltip).
    - New: multi-run history. In addition to the last-audit baseline
      (_dernier_audit_baseline.json, kept for the deltas), a history file
      (_historique_scores.json) keeps the last 20 (date, score) entries and
      feeds a mini SVG evolution chart in the HTML report.
    - New: CSV export in addition to TXT/JSON/HTML, for quick use in
      Excel/LibreOffice.
    - New: JavaScript search/filter in the HTML report table (same pattern
      as Block-Telemetry v5) — useful given the number of rows in the
      Software/Startup sections.
    - New: anchor links at the top of the HTML report to checks in FAIL
      status, to jump straight to the problem without scrolling.
    - Every new registry/CIM check follows the pattern already established
      across the suite: systematic try/catch, never assuming a key or
      property is present, an explicit INFO message when unavailable
      instead of silence or a false OK/FAIL.

    CHANGELOG v2.3 (fixed a crash in the HTML report's deltas block):
    - PowerShell 7+ automatically converts ISO-8601 strings (produced by
      "Get-Date -Format 'o'") into [DateTime] objects during a
      ConvertFrom-Json — the reloaded baseline therefore contained a real
      [DateTime] rather than a string. The code called .Substring() on it
      assuming a string, hence "Method invocation failed ... does not
      contain a method named 'Substring'" when generating the HTML report.
      Replaced with explicit formatting that handles both cases (DateTime or
      string), falling back to raw display if parsing fails.

    CHANGELOG v2.2 (UX alignment with SpicyCheck-v7.0):
    - The HTML report is no longer opened automatically at the end: a
      question "Open the report in your browser? [Y/n]" is asked (Enter =
      Yes, as in SpicyCheck).
    - The console window no longer closes automatically at the end of the
      script: a "Press ENTER to close this window..." box waits for
      confirmation before the script ends, to allow time to read the
      summary. Behavior skipped in -Silent mode, like the rest of the
      console output.

    CHANGELOG v2.1 (fix following the v2.0 run):
    - Windows Hello detection: the path used
      (ServiceProfiles\LocalService\...\Ngc) is protected by system ACLs and
      is only readable by the SYSTEM account, not by a regular
      administrator — the old version silently swallowed this access error
      and wrongly showed "Not detected". Added a second path (the current
      user's own NGC container, accessible without special privileges) and
      an explicit distinction between "not configured" and "undeterminable
      due to lack of access", instead of asserting a result the script
      couldn't actually verify. The contextual message about the SAM
      "password not required" flag now reflects this 3rd case.

    CHANGELOG v2.0 (new features):
    - New section: startup programs (Run/RunOnce registry keys, HKLM+HKCU +
      Startup folders, .lnk shortcuts resolved). Deliberately cautious
      heuristics: only references to a missing (orphaned) file or a launch
      from a Temp folder are flagged — not the mere absence of a signature,
      since too many legitimate programs are unsigned for that to be a
      reliable signal.
    - New section: Windows Defender exclusions (paths/extensions/processes).
      Only "broad" exclusions (drive root, entire Windows/Users folder,
      generic wildcard) are flagged WARN — a narrow, precise exclusion is
      normal and expected.
    - New section: Windows Hello (PIN/biometrics) detection at the machine
      level. Reused to contextualize the SAM "password not required" flag in
      the Accounts section (already softened in v1.1) with a concrete
      explanation instead of just a manual-verification pointer.
    - New section: VBS (virtualization-based security), Credential Guard and
      Memory Integrity (HVCI) status via Win32_DeviceGuard.
    - -Silent mode: suppresses console output and the browser launch, for a
      clean run via a scheduled task (reports still generated).
    - Comparison with the previous audit: each run saves a baseline file
      (_dernier_audit_baseline.json). On the next run, the script computes
      per-check status changes (new problem, resolved, check
      appeared/disappeared) and score evolution, shown in the console and in
      a new HTML report block.
    - Full JSON export of the current run (machine, score, summary, all
      detailed results, deltas) in addition to HTML/TXT, for use by other
      scripts/tools.

    CHANGELOG v1.3 (clarifications following v1.2 run feedback):
    - Password policy (minimum length): this check reads the LOCAL policy
      (what Windows would enforce on a future password change), not the
      password actually used to log in. A "0 character" result doesn't mean
      the account has no password. Label and message clarified, severity
      lowered from FAIL to WARN (not an active breach, just a permissive
      policy).
    - Windows Update service (Services section): a service with Manual
      startup (wuauserv, by design on modern Windows) is normally stopped
      when not in use — this wasn't an anomaly. Only a Disabled service, or
      an Automatic service that isn't running, is now flagged as a genuine
      problem.
    - "Sensitive" software (VLC, 7-Zip, etc.): the script doesn't check any
      CVE database or the latest published version, so it can't know whether
      the installed copy is vulnerable — moved back to INFO (watch list)
      instead of WARN, so an up-to-date program is no longer wrongly flagged
      as a problem.

    CHANGELOG v1.2 (following v1.1 run results):
    - Password policy: the v1.1 ADSI fix bound the object without a class
      suffix, which resolves by default to the "Computer" COM class (without
      the password-policy properties) instead of "Domain" -> "Object
      reference not set" error. Fixed binding to
      "WinNT://COMPUTERNAME,Domain" + manual reconstruction of
      MaxPasswordAge (IADsLargeInteger, HighPart/LowPart).

    CHANGELOG v1.1 (false-positive/bug fixes):
    - Password policy: read via ADSI (WinNT provider) instead of parsing the
      text output of "net accounts", which failed on a French-language
      Windows (English strings not found -> cast error).
    - Audit policy: query auditpol by category GUID (language-independent)
      instead of the English category name, with structural parsing (by line
      position) instead of an English regex filter.
    - Administrators group members: read via the universal SID
      (S-1-5-32-544) instead of the localized name "Administrators", with an
      explicit error reported if the read fails (instead of a silent "OK" on
      an empty value).
    - AMSI: if the AMSIEnabled property isn't exposed by
      Get-MpComputerStatus on the current build, the check falls back to
      INFO instead of WARN (instead of interpreting a missing value as
      "disabled").
    - Account with no password required (SAM flag): severity lowered from
      FAIL to WARN with an explanatory note, since this flag can be set by
      Windows Hello (PIN/biometrics) with no connection to an actual
      security weakness.
    - Suspicious scheduled tasks: automatic exclusion of tasks whose script
      is signed with the author's personal certificate, or whose path
      matches a configurable list of trusted folders.
    - Firewall: distinction between "rules active on the Public profile"
      (informational, includes rules scoped by program) and "rules actually
      open to any remote address" (the real risk).
    - BitLocker: contextualized message depending on whether the volume is
      the system volume or a data volume.
    - Replaced Get-WmiObject (absent from PowerShell 7+) with
      Get-CimInstance for suspicious-service detection.
    - Last full Defender scan: explicit status if a full scan has never been
      run, instead of an unparsed empty field.
#>

param(
    [switch]$Silent,
    [switch]$SelfTest,
    [string[]]$Category = @()
)

# ──────────────────────────────────────────────
#  CONFIGURATION
# ──────────────────────────────────────────────
$ScriptVersion  = "5.4.0"
$ReportDate     = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$ReportName     = "Check-Security_$ReportDate"
$OutputDir      = "$env:USERPROFILE\Desktop\Maintenance_Reports\Check-Security"
$ReportHTML     = "$OutputDir\$ReportName.html"
$ReportTXT      = "$OutputDir\$ReportName.txt"
$ReportJSON     = "$OutputDir\$ReportName.json"
$ReportCSV      = "$OutputDir\$ReportName.csv"
# Reference file from the previous run, used to compute the deltas
# (overwritten on every run with the current run's results).
$BaselineFile   = "$OutputDir\_last_audit_baseline.json"
# NOTE v3.0: multi-run history file, distinct from the baseline above.
# The baseline only keeps the previous run (needed for the deltas). This one
# accumulates (date, score) over the last 20 runs to draw a mini evolution
# chart in the HTML report — the baseline alone couldn't do that.
$HistoryFile    = "$OutputDir\_score_history.json"
$MaxHistoryRuns = 20

# NOTE v4.0: score regression threshold (in points) beyond which a separate
# alert is raised in the console and in the HTML report. A -1 or -2 pt delta
# on a score of 98 isn't significant; a drop of 5+ pts signals a real
# degradation that deserves immediate attention.
# Set to 0 to alert on any drop, even a tiny one (not recommended).
$ScoreRegressionThreshold = 5

# NOTE v3.0: per-category weights for the score calculation (see the SUMMARY
# section further down). A FAIL in a category with high real-world impact
# (BitLocker, Antivirus, VBS, etc.) should weigh more than a FAIL in a purely
# informational category ("Software to watch", "Startup"). A category absent
# from this table gets the default weight of 1.0 (neither amplified nor
# reduced).
$CategoryWeights = @{
    "Antivirus"        = 1.6
    "Firewall"         = 1.4
    "Network"          = 1.4
    "BitLocker"        = 1.6
    "VBS"              = 1.5
    "Password Policy"  = 1.3
    "Accounts"         = 1.2
    "Hardening"        = 1.4
    "Certificates"     = 1.3
    "Defender"         = 1.1
    "Software"         = 0.5
    "Startup"          = 0.7
    "Services"         = 0.8
    "TLS/SCHANNEL"     = 1.4
    "Backup"           = 1.5
}

# NOTE v5.0: section → main categories mapping table, used by the -Category
# filter. Each entry lists the result categories a section produces. If
# -Category is empty, every section runs.
$SectionCategoryMap = @{
    "1_System"          = @("System")
    "2_Updates"         = @("Updates")
    "3_Firewall"        = @("Firewall")
    "4_Defender"        = @("Antivirus","Defender")
    "5_Accounts"        = @("Accounts","Password Policy")
    "6_UAC"             = @("UAC")
    "7_BitLocker"       = @("BitLocker")
    "8_Network"         = @("Network")
    "9_Services"        = @("Services")
    "10_Audit"          = @("Audit")
    "11_Tasks"          = @("Scheduled Tasks")
    "12_UEFI_Security"  = @("UEFI Security")
    "13_PowerShell"     = @("PowerShell")
    "14_Software"       = @("Software")
    "15_Startup"        = @("Startup")
    "16_Exclusions"     = @("Defender")
    "17_Hello"          = @("Windows Hello")
    "18_VBS"            = @("VBS")
    "19_Certificates"   = @("Certificates")
    "20_TLS"            = @("TLS/SCHANNEL")
    "21_Drivers"        = @("Startup")
    "22_VSS"            = @("Backup")
}

# Helper function: determines whether a section should run based on -Category
function ShouldRunSection {
    param([string]$SectionKey)
    if ($Category.Count -eq 0) { return $true }
    if (-not $SectionCategoryMap.ContainsKey($SectionKey)) { return $true }
    foreach ($cat in $SectionCategoryMap[$SectionKey]) {
        foreach ($filter in $Category) {
            if ($cat -like "*$filter*" -or $filter -like "*$cat*") { return $true }
        }
    }
    return $false
}

# NOTE v3.1: allowlist of legitimate root certificates, indexed by THUMBPRINT
# (SHA-1 fingerprint), not by name. A certificate's Subject CN is just a
# plain text string — any self-signed certificate can call itself
# "CN=DigiCert Trusted Root G4", so filtering on the name would be trivially
# bypassable by a malicious certificate copying a known CA's name. The
# thumbprint, on the other hand, is a cryptographic signature of the exact
# certificate: impossible to forge without breaking SHA-1/SHA-256.
# Only add thumbprints YOU have personally verified here (seen in an audit
# report, confirmed legitimate). The script places NO automatic trust based
# on name — see section 19.
$TrustedRootThumbprintAllowlist = @{
    # Verified 2026-06-21 following the Audit_Securite_Win11_2026-06-21_20-35-02 audit:
    "DDFB16CD4931C973A2037D3FC83A4D7D775D05E4" = "DigiCert Trusted Root G4 — major, widely deployed commercial CA"
    "BE36A4562FB2EE05DBB3D32323ADF445084ED656" = "Thawte Timestamping CA — legacy timestamping CA, expired but deliberately kept by Windows to validate the date of old signatures"
    "18F7C1FCC3090203FD5BAA2F861A754976C8DD25" = "VeriSign Time Stamping Service Root — same, expired legacy timestamping CA deliberately kept"
    # Verified 2026-06-22 via extension analysis (certutil + PowerShell):
    # - BasicConstraints: End Entity (not a CA — CANNOT sign other certs or do MITM)
    # - EKU: Code Signing only + Microsoft OIDs 1.3.6.1.4.1.311.84.3.1/.3.2 (Microsoft Trusted Signing)
    # - Created 2026-03-30 by Windows itself (Microsoft Store update or install)
    # - Unusually placed in Root rather than the personal store, but not dangerous
    "899B104B6A3EE5AC8E3884A036BD946609F54B43" = "Windows Trusted Signing certificate (end-entity, not a CA) — created by Windows on 2026-03-30 for local MSIX/AppX package signing; Microsoft OIDs 311.84.x confirmed"
}

# Folders considered yours (your own scheduled scripts) — adjust as needed.
# Any scheduled task whose script sits under one of these paths won't be
# counted as suspicious. Also fill in $TrustedSignerSubjectMatch below if you
# sign your scripts with a personal certificate.
$TrustedScriptPathPatterns = @(
    "$env:USERPROFILE\Desktop\*",
    "$env:USERPROFILE\Documents\*",
    "$env:USERPROFILE\Scripts\*"
)
$TrustedSignerSubjectMatch = "Erwan"

# NOTE v3.3: allowlist by task NAME — a fallback independent of the task's
# argument format. Used when the task doesn't contain an extractable .ps1
# path (inline cmd, .bat, arguments with no explicit path, etc.) or when the
# path has spaces the old regex didn't capture. Fill in with your own
# scheduled tasks.
$TrustedTaskNames = @(
    "BloatRemoval",
    "EdgeRemoval",
    "OneDriveRemoval"
)

# Create the output folder
if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
}

# Load the result of the previous run (for the "Evolution" section further
# down). If the file is missing or corrupted, just continue without a
# comparison.
$PreviousAudit = $null
if (Test-Path $BaselineFile) {
    try {
        $PreviousAudit = Get-Content -Path $BaselineFile -Raw -Encoding UTF8 | ConvertFrom-Json
    } catch {
        $PreviousAudit = $null
    }
}

# NOTE v3.0: multi-run history (distinct from the baseline) for the mini
# score-evolution chart in the HTML report. Same failure tolerance as the
# baseline: missing or corrupted file -> start from an empty list instead of
# crashing the script.
$ScoreHistory = [System.Collections.Generic.List[object]]::new()
if (Test-Path $HistoryFile) {
    try {
        $LoadedHistory = Get-Content -Path $HistoryFile -Raw -Encoding UTF8 | ConvertFrom-Json
        foreach ($h in @($LoadedHistory)) { $ScoreHistory.Add($h) }
    } catch {
        $ScoreHistory = [System.Collections.Generic.List[object]]::new()
    }
}

# ──────────────────────────────────────────────
#  HELPER FUNCTIONS
# ──────────────────────────────────────────────

# NOTE v5.0.9: width of the "category" column for console alignment.
# Computed from the longest category actually used by Add-Result
# ("Scheduled Tasks" = 16 chars) + margin. A longer category doesn't break
# anything: PadRight only acts if the string is shorter than the width.
$script:LogCategoryWidth = 20

# NOTE v5.0.10: console icons — REVISED after user feedback (icon stuck to
# the text on some Windows Terminal fonts). Cause: ✔ ⚠ ✘ ℹ are "ambiguous"
# width glyphs (Unicode East Asian Width), rendered as 2 cells by some fonts
# → the following space gets visually absorbed.
# Replaced with the glyphs already validated in Nettoyage-Windows11_v5_2 on
# this same machine (✓ ~ ! - · » ≈), which render correctly as 1 cell.
# These console icons are independent of the HTML report's
# (Get-StatusBadge keeps ✔ ✘ ⚠ ℹ, correct in a browser).
$script:LogIcons = @{ "OK"="✓"; "WARN"="!"; "FAIL"="✗"; "INFO"="·" }
# Fixed column width for the icon (2 characters): guarantees stable
# alignment even if a given glyph renders wider than expected on a given
# font — the text that follows always starts at the same column.
$script:LogIconWidth = 2

function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "INFO",
        # Optional v5.0.9 parameters — used only by Add-Result for
        # column-aligned console rendering. No impact on existing behavior:
        # a Write-Log "text" -Level X call renders exactly as before (minus
        # the alignment), and the TXT file is in every case never generated
        # from these parameters.
        [string]$Category = "",
        [string]$Check = "",
        [string]$Value = ""
    )
    $timestamp = Get-Date -Format "HH:mm:ss"
    $colors = @{ "INFO"="Cyan"; "OK"="Green"; "WARN"="Yellow"; "FAIL"="Red"; "SECTION"="Magenta" }
    $color = $colors[$Level]

    # NOTE v2.0: in -Silent mode (scheduled/headless run), we no longer write
    # to the console — the TXT file is still fed in every case.
    if (-not $Silent) {
        if ($Level -eq "SECTION") {
            # Framed section banner. Extracts "N. TITLE" from
            # "=== N. TITLE ===" for a clean render without depending on the
            # original format (fallback: shows the raw message if the
            # pattern doesn't match, e.g. "=== SUMMARY ===").
            $title = ($Message -replace '^\s*=+\s*', '') -replace '\s*=+\s*$', ''
            $barWidth = 62
            Write-Host ""
            Write-Host ("  ╔" + ("═" * $barWidth) + "╗") -ForegroundColor DarkCyan
            $titlePadded = " $title".PadRight($barWidth)
            Write-Host "  ║" -NoNewline -ForegroundColor DarkCyan
            Write-Host $titlePadded -NoNewline -ForegroundColor Cyan
            Write-Host "║" -ForegroundColor DarkCyan
            Write-Host ("  ╚" + ("═" * $barWidth) + "╝") -ForegroundColor DarkCyan
        }
        elseif ($Category) {
            # Aligned result line: time · icon · category · check · value
            $icon = $script:LogIcons[$Level]
            if (-not $icon) { $icon = "•" }
            $iconCol = $icon.PadRight($script:LogIconWidth)
            $catCol = $Category.PadRight($script:LogCategoryWidth)
            # "Flat" (uncolored) string used only to compute the indent
            # width of the wrapped lines below.
            $plainPrefix = "   $timestamp  $iconCol $catCol"

            # NOTE v5.0.11: some values (e.g. audit policy, Section 10)
            # concatenate many sub-items with " / " and go well beyond a
            # console's width (several hundred characters on a single line,
            # unreadable). This doesn't touch the underlying format ($Value
            # stays unchanged for TXT/HTML/JSON/CSV, see Add-Result) — only
            # the console presentation: past a certain threshold, each
            # sub-item is wrapped onto its own line, indented under the "│"
            # separator.
            if ($Value -match ' / ' -and $Value.Length -gt 90) {
                Write-Host "   $timestamp  " -NoNewline -ForegroundColor DarkGray
                Write-Host "$iconCol " -NoNewline -ForegroundColor $color
                Write-Host "$catCol" -NoNewline -ForegroundColor DarkCyan
                Write-Host "│ " -NoNewline -ForegroundColor DarkGray
                Write-Host "$Check" -ForegroundColor Gray
                $indent = " " * $plainPrefix.Length
                foreach ($item in ($Value -split ' / ')) {
                    $item = $item.Trim()
                    if (-not $item) { continue }
                    # auditpol's raw lines contain wide padding between the
                    # name and the setting (e.g. "Logon" + 20+ spaces +
                    # "Success and Failure"); tightened to 2 spaces for a
                    # compact, readable console render, without touching the
                    # original $Value (TXT/HTML/JSON/CSV unchanged).
                    $item = $item -replace '\s{2,}', '  '
                    Write-Host "$indent" -NoNewline
                    Write-Host "│ " -NoNewline -ForegroundColor DarkGray
                    Write-Host "$item" -ForegroundColor $color
                }
            }
            else {
                Write-Host "   $timestamp  " -NoNewline -ForegroundColor DarkGray
                Write-Host "$iconCol " -NoNewline -ForegroundColor $color
                Write-Host "$catCol" -NoNewline -ForegroundColor DarkCyan
                Write-Host "│ " -NoNewline -ForegroundColor DarkGray
                Write-Host "$Check" -NoNewline -ForegroundColor Gray
                Write-Host " : " -NoNewline -ForegroundColor DarkGray
                Write-Host "$Value" -ForegroundColor $color
            }
        }
        else {
            # Free-form message (summary, errors, alerts) — icon + color,
            # no category column since there isn't one.
            $icon = $script:LogIcons[$Level]
            if (-not $icon) { $icon = "•" }
            $iconCol = $icon.PadRight($script:LogIconWidth)
            Write-Host "   $timestamp  " -NoNewline -ForegroundColor DarkGray
            Write-Host "$iconCol " -NoNewline -ForegroundColor $color
            Write-Host "$Message" -ForegroundColor $color
        }
    }
    # The TXT file STRICTLY keeps the original format, regardless of the
    # console rendering — never make an external export/parsing
    # (Dashboard-Global or otherwise) depend on a purely cosmetic change.
    Add-Content -Path $ReportTXT -Value "[$timestamp] [$Level] $Message"
}

function Get-StatusBadge {
    param([string]$Status)
    switch ($Status) {
        "OK"   { return '<span class="badge ok">✔ OK</span>' }
        "WARN" { return '<span class="badge warn">⚠ WARNING</span>' }
        "FAIL" { return '<span class="badge fail">✘ CRITICAL</span>' }
        "INFO" { return '<span class="badge info">ℹ INFO</span>' }
        default { return '<span class="badge info">— N/A</span>' }
    }
}

# NOTE v3.2: native HTML escaping, same pattern as He() in
# Analyze-WindowsLogs ([System.Web.HttpUtility]::HtmlEncode() isn't
# guaranteed available in every PowerShell context — see the suite's
# historical changelog).
function He {
    param([string]$s)
    if ($null -eq $s) { return "" }
    $s = $s -replace '&','&amp;'; $s = $s -replace '<','&lt;'
    $s = $s -replace '>','&gt;';  $s = $s -replace '"','&quot;'
    $s = $s -replace "'","&#39;"; return $s
}

# NOTE v5.1.1: unambiguous date formatting, independent of the machine's
# Windows region. "09/12/2026" means 9 Dec on a dd/MM-region machine and
# Sep 12 on a MM/dd-region one — a genuine ambiguity for a script whose
# own labels are English but that has to keep working correctly on
# French-region (or any other region's) Windows. Every date shown to the
# user goes through this helper instead of a bare ToString()/-Format
# call, so the day/month order is never in question regardless of the
# machine's regional settings — InvariantCulture is used deliberately
# here (not Get-Culture) so the month abbreviation itself doesn't flip
# between "Sep" and "sept." depending on the machine either.
function Format-AuditDate {
    param([Parameter(Mandatory)][DateTime]$Date, [switch]$DateOnly)
    $pattern = if ($DateOnly) { "dd MMM yyyy" } else { "dd MMM yyyy HH:mm" }
    return $Date.ToString($pattern, [System.Globalization.CultureInfo]::InvariantCulture)
}

# NOTE v5.4.0: generic first-match text extractor for bilingual command
# output (net accounts, and usable anywhere else this pattern is needed).
# Tries each pattern in order and returns the first captured group that
# matches, or $null if nothing matches — same "try FR, then EN" approach
# already used inline for auditpol/vssadmin/wbadmin, pulled out here since
# Password Policy needs it for five different fields at once.
function Get-NetAccountsValue {
    param([string]$Text, [string[]]$Patterns)
    foreach ($pattern in $Patterns) {
        $m = [regex]::Match($Text, $pattern)
        if ($m.Success) { return $m.Groups[1].Value.Trim() }
    }
    return $null
}

# ──────────────────────────────────────────────
#  CONTEXTUAL HELP LINKS ENGINE (v3.2 NEW)
# ──────────────────────────────────────────────
# NOTE v3.2: same principle as $script:RecoDb / Get-SourceRecommendation in
# Analyze-WindowsLogs — a Category/Check mapping table -> clickable links
# (Microsoft Learn documentation, tools, searches), shown only on WARN/FAIL
# checks in the HTML report so as not to clutter OK/INFO rows. Each rule
# matches on the category AND a pattern (regex) applied to the check name —
# first match wins.
$script:HelpLinksDb = @(
    @{ Cat='BitLocker';     Pattern='Volume';                    Links=@(
        @{ Label='MS Learn: Turn on BitLocker';   Url='https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/' }
        @{ Label='MS Learn: BitLocker FAQ';        Url='https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/faq' }
    )}
    @{ Cat='VBS';            Pattern='LSA Protection';            Links=@(
        @{ Label='MS Learn: Configure LSA Protection'; Url='https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection' }
    )}
    @{ Cat='VBS';            Pattern='Memory Integrity|virtualization';  Links=@(
        @{ Label='MS Learn: Memory Integrity (HVCI)'; Url='https://learn.microsoft.com/en-us/windows/security/hardware-security/enable-virtualization-based-protection-of-code-integrity' }
    )}
    @{ Cat='VBS';            Pattern='Credential Guard';          Links=@(
        @{ Label='MS Learn: Credential Guard'; Url='https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/' }
    )}
    @{ Cat='Antivirus';      Pattern='ASR|Attack Surface';        Links=@(
        @{ Label='MS Learn: ASR rules reference'; Url='https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference' }
    )}
    @{ Cat='Antivirus';      Pattern='.*';                        Links=@(
        @{ Label='MS Learn: Troubleshoot Windows Defender'; Url='https://learn.microsoft.com/en-us/defender-endpoint/troubleshoot-microsoft-defender-antivirus' }
    )}
    @{ Cat='PowerShell';     Pattern='Smart App Control';         Links=@(
        @{ Label='MS Learn: Smart App Control'; Url='https://learn.microsoft.com/en-us/windows/apps/develop/smart-app-control/overview' }
    )}
    @{ Cat='PowerShell';     Pattern='Script Block Logging|Transcription'; Links=@(
        @{ Label='MS Learn: PowerShell logging'; Url='https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows' }
    )}
    @{ Cat='PowerShell';     Pattern='ExecutionPolicy';           Links=@(
        @{ Label='MS Learn: about_Execution_Policies'; Url='https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_execution_policies' }
    )}
    @{ Cat='TLS/SCHANNEL';   Pattern='TLS 1\.0|TLS 1\.1|SSL';              Links=@(
        @{ Label='MS Learn: Disable TLS 1.0 and 1.1';  Url='https://learn.microsoft.com/en-us/windows-server/security/tls/tls-registry-settings' }
        @{ Label='MS Learn: SCHANNEL registry settings'; Url='https://learn.microsoft.com/en-us/windows-server/security/tls/tls-registry-settings' }
    )}
    @{ Cat='TLS/SCHANNEL';   Pattern='Cipher|suite';                       Links=@(
        @{ Label='MS Learn: TLS cipher suites in Windows';   Url='https://learn.microsoft.com/en-us/windows/win32/secauthn/cipher-suites-in-schannel' }
        @{ Label='MS Learn: Manage TLS protocols';    Url='https://learn.microsoft.com/en-us/windows-server/security/tls/manage-tls' }
    )}
    @{ Cat='TLS/SCHANNEL';   Pattern='.*';                                 Links=@(
        @{ Label='MS Learn: TLS/SSL (SCHANNEL) overview'; Url='https://learn.microsoft.com/en-us/windows-server/security/tls/tls-ssl-schannel-ssp-overview' }
    )}
    @{ Cat='Network';        Pattern='WinRM|remote PS access';           Links=@(
        @{ Label='MS Learn: Disable WinRM';            Url='https://learn.microsoft.com/en-us/windows/win32/winrm/installation-and-configuration-for-windows-remote-management' }
    )}
    @{ Cat='Network';        Pattern='NTLM restriction|LmCompatibilityLevel'; Links=@(        @{ Label='MS Learn: LAN Manager authentication level'; Url='https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-security-lan-manager-authentication-level' }
    )}
    @{ Cat='Network';        Pattern='SMB signing';             Links=@(
        @{ Label='MS Learn: SMB signing'; Url='https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/overview-server-message-block-signing' }
    )}
    @{ Cat='Network';        Pattern='SMBv1';                     Links=@(
        @{ Label='MS Learn: Disable SMBv1'; Url='https://learn.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3' }
    )}
    @{ Cat='Network';        Pattern='Encrypted DNS|DoH';           Links=@(
        @{ Label='MS Learn: DNS-over-HTTPS on Windows'; Url='https://learn.microsoft.com/en-us/windows-server/networking/dns/doh-client-support' }
    )}
    @{ Cat='Network';        Pattern='NLA|RDP';                   Links=@(
        @{ Label='MS Learn: Secure RDP connections'; Url='https://learn.microsoft.com/en-us/windows-server/remote/remote-desktop-services/clients/remote-desktop-allow-access' }
    )}
    @{ Cat='Network';        Pattern='Network shares';           Links=@(
        @{ Label='MS Learn: SMB share security'; Url='https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-security' }
    )}
    @{ Cat='Firewall';       Pattern='Sensitive port';             Links=@(
        @{ Label='MS Learn: Windows Defender Firewall best practices'; Url='https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/best-practices-configuring' }
    )}
    @{ Cat='Firewall';       Pattern='.*';                        Links=@(
        @{ Label='MS Learn: Windows Defender Firewall'; Url='https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/' }
    )}
    @{ Cat='Password Policy';  Pattern='.*';                        Links=@(
        @{ Label='MS Learn: Password policy'; Url='https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/password-policy' }
    )}
    @{ Cat='Accounts';        Pattern='Local administrators';    Links=@(
        @{ Label='MS Learn: Local admin account best practices'; Url='https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-b--privileged-accounts-and-groups-in-active-directory' }
    )}
    @{ Cat='Accounts';        Pattern='.*';                        Links=@(
        @{ Label='MS Learn: Local account security'; Url='https://learn.microsoft.com/en-us/windows-server/identity/securing-local-accounts-in-active-directory-domains' }
    )}
    @{ Cat='Defender';       Pattern='Exclusion';                 Links=@(
        @{ Label='MS Learn: Configure Defender exclusions'; Url='https://learn.microsoft.com/en-us/defender-endpoint/configure-exclusions-microsoft-defender-antivirus' }
    )}
    @{ Cat='Startup';      Pattern='.*';                        Links=@(
        @{ Label='Sysinternals Autoruns (deep-dive analysis)'; Url='https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns' }
    )}
    @{ Cat='Scheduled Tasks'; Pattern='.*';                     Links=@(
        @{ Label='MS Learn: Task Scheduler — security'; Url='https://learn.microsoft.com/en-us/windows/win32/taskschd/task-scheduler-start-page' }
        @{ Label='Sysinternals Autoruns — scheduled tasks';      Url='https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns' }
    )}
    @{ Cat='UAC';            Pattern='.*';                        Links=@(
        @{ Label="MS Learn: How User Account Control works"; Url='https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/how-it-works' }
    )}
    @{ Cat='Audit';          Pattern='.*';                        Links=@(
        @{ Label="MS Learn: Advanced audit policy";          Url='https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/component-updates/command-line-process-auditing' }
    )}
    @{ Cat='Updates';   Pattern='.*';                        Links=@(
        @{ Label='MS Learn: Troubleshoot Windows Update';             Url='https://learn.microsoft.com/en-us/windows/deployment/update/windows-update-troubleshooting' }
    )}
    @{ Cat='Services';       Pattern='Non-system auto services'; Links=@(
        @{ Label='Sysinternals Autoruns — services';               Url='https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns' }
        @{ Label='MS Learn: Secure Windows services';      Url='https://learn.microsoft.com/en-us/windows/security/threat-protection/overview-of-threat-mitigations-in-windows-10' }
    )}
    @{ Cat='Services';       Pattern='.*';                        Links=@(
        @{ Label='MS Learn: Manage Windows services';          Url='https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/sc-query' }
    )}
    @{ Cat='System';        Pattern='Build|Uptime';              Links=@(
        @{ Label='MS Learn: Windows 11 build history';    Url='https://learn.microsoft.com/en-us/windows/release-health/windows11-release-information' }
        @{ Label='MS Learn: Windows lifecycle';                Url='https://learn.microsoft.com/en-us/lifecycle/products/windows-11' }
    )}
    @{ Cat='Backup';     Pattern='Shadow Copy|VSS|Snapshots';   Links=@(
        @{ Label='MS Learn: Volume Shadow Copy Service overview';         Url='https://learn.microsoft.com/en-us/windows-server/storage/file-server/volume-shadow-copy-service' }
        @{ Label='MS Learn: Create a system restore point'; Url='https://support.microsoft.com/en-us/windows/create-a-system-restore-point-77e02e2a-3298-c869-9974-ef5658ea3be9' }
    )}
    @{ Cat='Certificates';    Pattern='expir';                      Links=@(
        @{ Label='MS Learn: Manage certificates with PowerShell';  Url='https://learn.microsoft.com/en-us/powershell/module/pki/' }
    )}
    @{ Cat='Network';         Pattern='IPv6';                       Links=@(
        @{ Label='MS Learn: IPv6 and Windows Defender Firewall';   Url='https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/' }
    )}
    @{ Cat='UEFI Security';  Pattern='Secure Boot';              Links=@(
        @{ Label='MS Learn: Secure Boot overview';         Url='https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/oem-secure-boot' }
        @{ Label='MS Learn: Turn on Secure Boot';                 Url='https://support.microsoft.com/en-us/windows/turn-on-secure-boot-66a8f21a-83d0-4a76-8b1e-e23f1c1a6e79' }
    )}
    @{ Cat='UEFI Security';  Pattern='TPM';                      Links=@(
        @{ Label='MS Learn: TPM overview';                 Url='https://learn.microsoft.com/en-us/windows/security/hardware-security/tpm/trusted-platform-module-overview' }
        @{ Label='MS Learn: Troubleshoot TPM issues';          Url='https://learn.microsoft.com/en-us/windows/security/hardware-security/tpm/initialize-and-configure-ownership-of-the-tpm' }
    )}
    @{ Cat='Windows Hello';  Pattern='.*';                        Links=@(
        @{ Label='MS Learn: Windows Hello for Business overview'; Url='https://learn.microsoft.com/en-us/windows/security/identity-protection/hello-for-business/' }
        @{ Label='MS Learn: Set up Windows Hello';               Url='https://support.microsoft.com/en-us/windows/set-up-windows-hello-dce28585-4661-583c-8c43-0f09d1db1f0f' }
    )}
)

function Get-HelpLinks {
    <#
    Returns the contextual help links for a result (Category + Check) as
    ready-to-insert HTML, or an empty string if no rule matches. Two special
    cases are handled outside the generic table because their content
    depends on the exact result value:
    - "Certificates": search by THUMBPRINT (crt.sh + Google), not by name —
      consistent with the choice made in section 19 (thumbprint = the only
      identity that can't be forged).
    - "Software to watch": CVE search (NVD) on the exact detected software
      name + version.
    #>
    param([string]$Category, [string]$Check, [string]$Value, [string]$Detail)

    $links = [System.Collections.Generic.List[object]]::new()

    if ($Category -eq "Certificates" -and $Check -like "Root certificate:*") {
        $tpMatch = [regex]::Match($Detail, 'Thumbprint \(SHA-1\): ([0-9A-Fa-f]{40})')
        if ($tpMatch.Success) {
            $tp = $tpMatch.Groups[1].Value
            $links.Add(@{ Label='crt.sh (search by thumbprint)'; Url="https://crt.sh/?q=$tp" })
        }
        $links.Add(@{ Label='MS Learn: Trusted Root Program'; Url='https://learn.microsoft.com/en-us/security/trusted-root/program-requirements' })
        $cnSearch = [Uri]::EscapeDataString("$Value certificate authority")
        $links.Add(@{ Label='Web search on this issuer'; Url="https://www.google.com/search?q=$cnSearch" })
    }
    elseif ($Category -eq "Software" -and $Check -like "Software to watch:*") {
        $appName = ($Check -replace '^Software to watch: ', '').Trim()
        $cveQuery = [Uri]::EscapeDataString("$appName $Value")
        $links.Add(@{ Label='NVD: CVE search'; Url="https://nvd.nist.gov/vuln/search/results?query=$cveQuery" })
    }
    else {
        foreach ($rule in $script:HelpLinksDb) {
            if ($rule.Cat -eq $Category -and $Check -match $rule.Pattern) {
                foreach ($l in $rule.Links) { $links.Add($l) }
                break
            }
        }
    }

    if ($links.Count -eq 0) { return "" }

    $itemsHtml = ($links | ForEach-Object { "<a href='$(He $_.Url)' target='_blank' rel='noopener' class='help-link'>$(He $_.Label)</a>" }) -join ""
    return "<div class='help-links'>$itemsHtml</div>"
}

# Global results table
$AuditResults = [System.Collections.Generic.List[PSCustomObject]]::new()

function Add-Result {
    param(
        [string]$Category,
        [string]$Check,
        [string]$Value,
        [string]$Status,   # OK / WARN / FAIL / INFO
        [string]$Detail = ""
    )
    $AuditResults.Add([PSCustomObject]@{
        Category = $Category
        Check  = $Check
        Value    = $Value
        Status    = $Status
        Detail    = $Detail
    })
    # NOTE v5.0.9: $Message stays "$Category | $Check : $Value" for the TXT
    # file (format unchanged); the extra -Category/-Check/-Value only serve
    # console alignment in Write-Log.
    Write-Log "$Category | $Check : $Value" -Level $Status -Category $Category -Check $Check -Value $Value
}

# ──────────────────────────────────────────────
#  -SELFTEST MODE
# ──────────────────────────────────────────────
# NOTE v4.3: battery of assertions on the script's internal functions.
# Run with: .\Check-Security.ps1 -SelfTest
# No WMI/registry connection, no report generated, no changes made.
# Same pattern as Analyze-WindowsLogs v6.6 (18 assertions, exit code 0/1).
if ($SelfTest) {
    $ST_Pass = 0; $ST_Fail = 0
    function Assert-SelfTest {
        param([string]$Name, [bool]$Condition, [string]$Detail = "")
        if ($Condition) {
            Write-Host "  [PASS] $Name" -ForegroundColor Green
            $script:ST_Pass++
        } else {
            Write-Host "  [FAIL] $Name$(if($Detail){" — $Detail"})" -ForegroundColor Red
            $script:ST_Fail++
        }
    }

    Write-Host ""
    Write-Host ("═" * 58) -ForegroundColor DarkCyan
    Write-Host "  Check-Security v$ScriptVersion — SelfTest" -ForegroundColor Cyan
    Write-Host ("═" * 58) -ForegroundColor DarkCyan
    Write-Host ""
    Write-Host "  Helper functions" -ForegroundColor DarkGray

    # He() — HTML escaping
    Assert-SelfTest "He(): & -> &amp;"      ((He "&")      -eq "&amp;")
    Assert-SelfTest "He(): < -> &lt;"       ((He "<")      -eq "&lt;")
    Assert-SelfTest "He(): > -> &gt;"       ((He ">")      -eq "&gt;")
    Assert-SelfTest "He(): `" -> &quot;"    ((He '"')      -eq "&quot;")
    Assert-SelfTest "He(): ' -> &#39;"      ((He "'")      -eq "&#39;")
    Assert-SelfTest "He(): null -> empty"   ((He $null)    -eq "")

    # Format-AuditDate (v5.1.1) — unambiguous, InvariantCulture, day/month
    # order never in question regardless of the machine's Windows region
    $ST_TestDate = [datetime]"2026-09-12 14:32:00"
    Assert-SelfTest "Format-AuditDate: with time"       ((Format-AuditDate $ST_TestDate)            -eq "12 Sep 2026 14:32") "Got: $(Format-AuditDate $ST_TestDate)"
    Assert-SelfTest "Format-AuditDate: -DateOnly"        ((Format-AuditDate $ST_TestDate -DateOnly)  -eq "12 Sep 2026")       "Got: $(Format-AuditDate $ST_TestDate -DateOnly)"
    Assert-SelfTest "Format-AuditDate: month name fixed" ((Format-AuditDate $ST_TestDate) -notmatch "09/12|12/09")

    # Get-StatusBadge
    Assert-SelfTest "Get-StatusBadge OK"   ((Get-StatusBadge "OK")   -match "ok")
    Assert-SelfTest "Get-StatusBadge WARN" ((Get-StatusBadge "WARN") -match "warn")
    Assert-SelfTest "Get-StatusBadge FAIL" ((Get-StatusBadge "FAIL") -match "fail")
    Assert-SelfTest "Get-StatusBadge INFO" ((Get-StatusBadge "INFO") -match "info")

    # Add-Result — checks that a call correctly adds an item with the right fields
    $script:AuditResults = [System.Collections.Generic.List[object]]::new()
    Add-Result "TestCat" "TestCtrl" "TestVal" "OK" "TestDetail"
    Assert-SelfTest "Add-Result: item added"                ($AuditResults.Count -eq 1)
    Assert-SelfTest "Add-Result: correct Category"      ($AuditResults[0].Category -eq "TestCat")
    Assert-SelfTest "Add-Result: correct Status"          ($AuditResults[0].Status   -eq "OK")
    Assert-SelfTest "Add-Result: correct Detail"          ($AuditResults[0].Detail   -eq "TestDetail")
    $script:AuditResults = [System.Collections.Generic.List[object]]::new()  # reset

    Write-Host ""
    Write-Host "  Scoring engine" -ForegroundColor DarkGray

    # Weighted scoring: 1 FAIL + 1 WARN + 1 OK in a category with weight 2.0
    # rate = (0.0 + 0.5 + 1.0) / 3 = 0.5 -> score = round(100 x (2.0x0.5)/(2.0)) = 50
    $ST_TestResults = @(
        [PSCustomObject]@{ Category="X"; Status="FAIL" },
        [PSCustomObject]@{ Category="X"; Status="WARN" },
        [PSCustomObject]@{ Category="X"; Status="OK"   }
    )
    $ST_Weights = @{ "X" = 2.0 }
    $ST_CatStats = @{ "X" = @{ WeightedSum = 0.0; Count = 0 } }
    foreach ($r in $ST_TestResults) {
        $v = switch($r.Status) { "OK"{1.0} "INFO"{1.0} "WARN"{0.5} "FAIL"{0.0} default{1.0} }
        $ST_CatStats["X"].WeightedSum += $v; $ST_CatStats["X"].Count++
    }
    $ST_num = $ST_Weights["X"] * ($ST_CatStats["X"].WeightedSum / $ST_CatStats["X"].Count)
    $ST_den = $ST_Weights["X"]
    $ST_Score = [int][math]::Round(100 * $ST_num / $ST_den)
    Assert-SelfTest "Weighted scoring (1 FAIL+1 WARN+1 OK, weight 2.0 -> 50)" ($ST_Score -eq 50) "Got: $ST_Score"

    Write-Host ""
    Write-Host "  Configuration" -ForegroundColor DarkGray

    Assert-SelfTest "CategoryWeights: BitLocker present"      ($CategoryWeights.ContainsKey("BitLocker"))
    Assert-SelfTest "CategoryWeights: TLS/SCHANNEL present"   ($CategoryWeights.ContainsKey("TLS/SCHANNEL"))
    Assert-SelfTest "CategoryWeights: Startup present"        ($CategoryWeights.ContainsKey("Startup"))
    Assert-SelfTest "CategoryWeights: Firewall present"       ($CategoryWeights.ContainsKey("Firewall"))
    Assert-SelfTest "CategoryWeights: VBS present"            ($CategoryWeights.ContainsKey("VBS"))
    Assert-SelfTest "ScoreRegressionThreshold > 0"            ($ScoreRegressionThreshold -gt 0)
    Assert-SelfTest "TrustedRootThumbprintAllowlist not empty" ($TrustedRootThumbprintAllowlist.Count -gt 0)
    Assert-SelfTest "TrustedTaskNames not empty"               ($TrustedTaskNames.Count -gt 0)

    Write-Host ""
    Write-Host "  New v4.4 features" -ForegroundColor DarkGray

    # BitLocker: check that the C: FAIL / other WARN logic is correct.
    # Simulates two fake volumes and checks the switch.
    $ST_SystemDrive = $env:SystemDrive
    $ST_VolSystem = [PSCustomObject]@{ MountPoint = $ST_SystemDrive; ProtectionStatus = "Off"; EncryptionPercentage = 0 }
    $ST_VolData   = [PSCustomObject]@{ MountPoint = "E:";            ProtectionStatus = "Off"; EncryptionPercentage = 0 }
    $ST_IsSystem  = ("$($ST_VolSystem.MountPoint)".TrimEnd('\') -eq $ST_SystemDrive)
    $ST_IsData    = ("$($ST_VolData.MountPoint)".TrimEnd('\')   -eq $ST_SystemDrive)
    $ST_StSystem  = if ($ST_IsSystem) { "FAIL" } else { "WARN" }
    $ST_StData    = if ($ST_IsData)   { "FAIL" } else { "WARN" }
    Assert-SelfTest "BitLocker: system volume -> FAIL"        ($ST_StSystem -eq "FAIL") "Got: $ST_StSystem"
    Assert-SelfTest "BitLocker: non-system volume -> WARN"    ($ST_StData   -eq "WARN") "Got: $ST_StData"

    # SmartScreen: check that the registry key is readable (no value test,
    # just that Get-ItemProperty doesn't throw an unexpected exception)
    $ST_SSKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer"
    $ST_SSReadable = $false
    try {
        $null = Get-ItemProperty -Path $ST_SSKey -ErrorAction Stop
        $ST_SSReadable = $true
    } catch {}
    Assert-SelfTest "SmartScreen: Explorer registry key readable" $ST_SSReadable

    # Exploit Protection: check that Get-ProcessMitigation is available
    $ST_MitAvailable = $null -ne (Get-Command Get-ProcessMitigation -ErrorAction SilentlyContinue)
    Assert-SelfTest "Exploit Protection: Get-ProcessMitigation available" $ST_MitAvailable

    # Section 21: check that the CI\Config key is readable
    $ST_CIKey = "HKLM:\SYSTEM\CurrentControlSet\Control\CI\Config"
    $ST_CIReadable = Test-Path -LiteralPath $ST_CIKey -ErrorAction SilentlyContinue
    # Test-Path returns $false if absent but doesn't throw — this is the expected behavior
    Assert-SelfTest "Section 21: CI\Config key accessible (present or absent, no error)" ($null -ne $ST_CIReadable)

    # DeltaMap: check that construction works on an empty set
    $ST_Deltas = @()
    $ST_DeltaMap = @{}
    foreach ($d in $ST_Deltas) { $ST_DeltaMap["$($d.Category)|$($d.Check)"] = $d.Type }
    Assert-SelfTest "DeltaMap: construction on empty list -> empty hashtable" ($ST_DeltaMap.Count -eq 0)

    # DeltaMap: with a fake delta
    $ST_Deltas2 = @([PSCustomObject]@{ Category="Test"; Check="Ctrl"; Type="Resolved" })
    $ST_DeltaMap2 = @{}
    foreach ($d in $ST_Deltas2) { $ST_DeltaMap2["$($d.Category)|$($d.Check)"] = $d.Type }
    Assert-SelfTest "DeltaMap: correct Category|Check key" ($ST_DeltaMap2.ContainsKey("Test|Ctrl"))
    Assert-SelfTest "DeltaMap: correct Type value"            ($ST_DeltaMap2["Test|Ctrl"] -eq "Resolved")

    Write-Host ""
    Write-Host "  New v5.0 features" -ForegroundColor DarkGray

    # -Category: if empty, ShouldRunSection must return $true
    $ST_CatEmpty = ShouldRunSection "7_BitLocker"
    Assert-SelfTest "ShouldRunSection: empty -Category -> always true" $ST_CatEmpty "Got: $ST_CatEmpty"

    # -Category: functional filter
    $script:Category = @("BitLocker")
    $ST_CatMatch    = ShouldRunSection "7_BitLocker"
    $ST_CatNoMatch  = ShouldRunSection "20_TLS"
    Assert-SelfTest "ShouldRunSection: 'BitLocker' -> 7_BitLocker OK" $ST_CatMatch
    Assert-SelfTest "ShouldRunSection: 'BitLocker' -> 20_TLS excluded" (-not $ST_CatNoMatch)
    $script:Category = @()  # reset

    # VSS: check that the service is readable without an exception
    $ST_VSSReadable = $false
    try {
        $null = Get-Service -Name VSS -ErrorAction Stop
        $ST_VSSReadable = $true
    } catch {}
    Assert-SelfTest "VSS: Get-Service VSS available" $ST_VSSReadable

    # Certificates: LocalMachine\My store accessible
    $ST_MyStoreReadable = $false
    try {
        $null = Get-ChildItem -Path "Cert:\LocalMachine\My" -ErrorAction Stop
        $ST_MyStoreReadable = $true
    } catch {}
    Assert-SelfTest "Certificates: Cert:\LocalMachine\My accessible" $ST_MyStoreReadable

    # CategoryWeights: Backup present (new in v5)
    Assert-SelfTest "CategoryWeights: Backup present" ($CategoryWeights.ContainsKey("Backup"))

    # RID-500: check that Get-LocalUser is available
    $ST_LocalUserAvail = $null -ne (Get-Command Get-LocalUser -ErrorAction SilentlyContinue)
    Assert-SelfTest "Accounts: Get-LocalUser available for RID-500" $ST_LocalUserAvail

    Write-Host ""
    Write-Host "  New v5.2.0 features" -ForegroundColor DarkGray

    # SCHANNEL Ciphers/Hashes/Diffie-Hellman: verify the registry roots this
    # section now reads are well-formed and readable (no assertion on their
    # VALUE, since that's a per-machine hardening state, not a script bug)
    $ST_CiphersRootReadable = $false
    try {
        $null = Test-Path -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers" -ErrorAction Stop
        $ST_CiphersRootReadable = $true
    } catch {}
    Assert-SelfTest "TLS/SCHANNEL: Ciphers registry root accessible" $ST_CiphersRootReadable

    $ST_HashesRootReadable = $false
    try {
        $null = Test-Path -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes" -ErrorAction Stop
        $ST_HashesRootReadable = $true
    } catch {}
    Assert-SelfTest "TLS/SCHANNEL: Hashes registry root accessible" $ST_HashesRootReadable

    # .NET Strong Crypto: v4.0.30319 is part of the OS, so this path must
    # always exist on Windows 11 — a hard requirement, not per-machine state
    $ST_DotNetPathExists = Test-Path -LiteralPath "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319" -ErrorAction SilentlyContinue
    Assert-SelfTest "TLS/SCHANNEL: .NET Framework v4.0.30319 path exists" $ST_DotNetPathExists

    Write-Host ""
    Write-Host "  New v5.3.0 features" -ForegroundColor DarkGray

    # -Category wiring fix: cheap regression guard against a typo'd or
    # missing key in $SectionCategoryMap silently making a section always
    # run (if absent, ShouldRunSection defaults to $true) or never match a
    # real -Category value. One key per section, 22 sections.
    Assert-SelfTest "SectionCategoryMap has all 22 section keys" ($SectionCategoryMap.Count -eq 22) "Got: $($SectionCategoryMap.Count)"

    # Get-NetAccountsValue (v5.4.0) — bilingual FR/EN extraction, the same
    # pattern used to fix the Password Policy section's ADSI unreliability
    $ST_FrSample = "Seuil de verrouillage :                                                5"
    $ST_EnSample = "Lockout threshold:                                    5"
    $ST_Patterns = @('Seuil de verrouillage\s*:\s*(.+)', 'Lockout threshold\s*:\s*(.+)')
    Assert-SelfTest "Get-NetAccountsValue: French label matches"  ((Get-NetAccountsValue $ST_FrSample $ST_Patterns) -eq "5")
    Assert-SelfTest "Get-NetAccountsValue: English label matches" ((Get-NetAccountsValue $ST_EnSample $ST_Patterns) -eq "5")
    Assert-SelfTest "Get-NetAccountsValue: no match returns null"  ($null -eq (Get-NetAccountsValue "unrelated text" $ST_Patterns))

    Write-Host ""
    Write-Host ("═" * 58) -ForegroundColor DarkCyan
    $allOK = $ST_Fail -eq 0
    $color  = if ($allOK) { "Green" } else { "Red" }
    $emoji  = if ($allOK) { "✓" } else { "✗" }
    Write-Host "  $emoji  SelfTest: $ST_Pass PASS · $ST_Fail FAIL" -ForegroundColor $color
    Write-Host ("═" * 58) -ForegroundColor DarkCyan
    Write-Host ""
    exit $(if ($allOK) { 0 } else { 1 })
}

# ──────────────────────────────────────────────
#  CROSS-SECTION PRE-COMPUTATION (v5.3.0)
# ──────────────────────────────────────────────
# NOTE v5.3.0: these two pieces of state are each read by two different
# sections (System info + the HTML report header for $OS/$CS/$BIOS/$CPU;
# Accounts + Windows Hello for $HelloConfigured/$HelloIndeterminate), so
# they have to be computed unconditionally here, before the -Category
# filter below can skip either producing section. Placed after the
# -SelfTest block above (not before it) so SelfTest keeps its guarantee of
# zero WMI/registry access — SelfTest always exits before reaching this
# point, so it never runs.
$OS   = Get-CimInstance Win32_OperatingSystem
$CS   = Get-CimInstance Win32_ComputerSystem
$BIOS = Get-CimInstance Win32_BIOS
$CPU  = Get-CimInstance Win32_Processor | Select-Object -First 1

# NOTE v2.0: detects Windows Hello (PIN/biometrics) at the machine level,
# so the SAM "password not required" flag in Accounts can be contextualized
# instead of just suggesting a manual check. Detail shown in section 17.
#
# NOTE v2.1: the "ServiceProfiles\LocalService\...\Ngc" path is protected by
# system ACLs — even as an administrator (not SYSTEM), reading this folder
# generally fails with access denied. The old version silently swallowed
# this error and wrongly concluded "Not detected".
# Adds the current user's own NGC container (accessible without special
# elevation, since we are that same user behind the admin token), and
# distinguishes a genuine "not configured" from "access denied, therefore
# undeterminable" so as not to assert what couldn't actually be verified.
$HelloConfigured  = $false
$HelloIndeterminate = $false

$NgcPathsToCheck = @(
    "$env:WINDIR\ServiceProfiles\LocalService\AppData\Local\Microsoft\Ngc",
    "$env:LOCALAPPDATA\Microsoft\Ngc"
)
foreach ($ngcPath in $NgcPathsToCheck) {
    try {
        if (Test-Path -LiteralPath $ngcPath -ErrorAction Stop) {
            $NgcItems = Get-ChildItem -LiteralPath $ngcPath -Force -ErrorAction Stop
            if ((($NgcItems | Measure-Object).Count) -gt 0) { $HelloConfigured = $true }
        }
    } catch [System.UnauthorizedAccessException] {
        $HelloIndeterminate = $true
    } catch {
        # Path absent or other benign error: no signal, keep going
    }
}

# ──────────────────────────────────────────────
#  1. SYSTEM INFORMATION
# ──────────────────────────────────────────────
if (ShouldRunSection "1_System") {
Write-Log "=== 1. SYSTEM INFORMATION ===" -Level SECTION

Add-Result "System" "Machine name"      $env:COMPUTERNAME          "INFO"
Add-Result "System" "Operating system" "$($OS.Caption) $($OS.BuildNumber)" "INFO"
Add-Result "System" "OS version"             $OS.Version                "INFO"
Add-Result "System" "Architecture"           $OS.OSArchitecture         "INFO"
Add-Result "System" "Domain / Workgroup"       "$($CS.Domain)"            "INFO"
Add-Result "System" "Last boot"      "$(Format-AuditDate $OS.LastBootUpTime)"    "INFO"
Add-Result "System" "BIOS Version"           "$($BIOS.SMBIOSBIOSVersion)" "INFO"
Add-Result "System" "Processor"             $CPU.Name                  "INFO"

# Check if Windows 11
$Build = [int]$OS.BuildNumber
if ($Build -ge 22000) {
    Add-Result "System" "Windows 11 build" "Build $Build (Windows 11)" "OK"
} else {
    Add-Result "System" "Windows 11 build" "Build $Build (Not Windows 11!)" "FAIL" "This script is optimized for Windows 11 (Build >= 22000)"
}

# Uptime
$Uptime = (Get-Date) - $OS.LastBootUpTime
if ($Uptime.TotalDays -gt 30) {
    Add-Result "System" "Machine uptime" "$([math]::Round($Uptime.TotalDays,1)) days" "WARN" "Machine hasn't been restarted in over 30 days — pending patches?"
} else {
    Add-Result "System" "Machine uptime" "$([math]::Round($Uptime.TotalDays,1)) days" "OK"
}

}

# ──────────────────────────────────────────────
#  2. WINDOWS UPDATE & PATCHES
# ──────────────────────────────────────────────
if (ShouldRunSection "2_Updates") {
Write-Log "=== 2. WINDOWS UPDATE & PATCHES ===" -Level SECTION

try {
    $HotFixes = Get-HotFix | Sort-Object InstalledOn -Descending
    $LastPatch = $HotFixes | Select-Object -First 1
    $DaysSincePatch = ((Get-Date) - [datetime]$LastPatch.InstalledOn).TotalDays

    Add-Result "Updates" "Number of installed patches" $HotFixes.Count "INFO"
    Add-Result "Updates" "Last patch installed" "$($LastPatch.HotFixID) on $(Format-AuditDate ([datetime]$LastPatch.InstalledOn))" $(
        if ($DaysSincePatch -gt 60) { "FAIL" } elseif ($DaysSincePatch -gt 30) { "WARN" } else { "OK" }
    ) "$(if($DaysSincePatch -gt 60){'No patch in over 60 days'}elseif($DaysSincePatch -gt 30){'No patch in over 30 days'}else{'Recent patch'})"
} catch {
    Add-Result "Updates" "Reading patches" "Error: $_" "WARN"
}

# Windows Update Service
$WUSvc = Get-Service -Name wuauserv -ErrorAction SilentlyContinue
if ($WUSvc) {
    $status = if ($WUSvc.StartType -eq "Disabled") { "FAIL" } else { "OK" }
    Add-Result "Updates" "Windows Update service" "$($WUSvc.Status) / Startup: $($WUSvc.StartType)" $status $(
        if ($WUSvc.StartType -eq "Disabled") { "The Windows Update service is disabled!" }
    )
}

}

# ──────────────────────────────────────────────
#  3. WINDOWS FIREWALL
# ──────────────────────────────────────────────
if (ShouldRunSection "3_Firewall") {
Write-Log "=== 3. WINDOWS FIREWALL ===" -Level SECTION

$Profiles = @("Domain","Private","Public")
foreach ($profile in $Profiles) {
    try {
        $fw = Get-NetFirewallProfile -Profile $profile -ErrorAction Stop
        $st = if ($fw.Enabled) { "OK" } else { "FAIL" }
        Add-Result "Firewall" "$profile profile" $(if ($fw.Enabled) {"Enabled"} else {"DISABLED"}) $st $(
            if (-not $fw.Enabled) { "The $profile profile firewall is disabled — high risk!" }
        )
        # Default policy
        Add-Result "Firewall" "$profile inbound policy" $fw.DefaultInboundAction "INFO"
        Add-Result "Firewall" "$profile outbound policy" $fw.DefaultOutboundAction "INFO"
    } catch {
        Add-Result "Firewall" "$profile profile" "Not available" "WARN"
    }
}

# Permissive inbound rules (Any)
# NOTE v1.1: counting every Allow/Enabled rule on the Public profile
# overestimates the risk — most of these rules are scoped to a specific
# program or port (normal default Windows behavior), not genuinely open to
# any source. We now distinguish the total (informational) from the
# subset genuinely open to any remote address (the real risk).
$PublicAllowRules = Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True -ErrorAction SilentlyContinue |
    Where-Object { $_.Profile -match "Public" }

Add-Result "Firewall" "Active inbound rules (Public)" $PublicAllowRules.Count "INFO" "Includes rules scoped by program/port — normal on a standard Windows install"

$TrulyOpenRules = [System.Collections.Generic.List[object]]::new()
foreach ($rule in $PublicAllowRules) {
    $addrFilter = $rule | Get-NetFirewallAddressFilter -ErrorAction SilentlyContinue
    if ($addrFilter -and ($addrFilter.RemoteAddress -contains "Any")) {
        $TrulyOpenRules.Add($rule)
    }
}

Add-Result "Firewall" "Inbound rules open to any IP (Public)" $TrulyOpenRules.Count "INFO" "See the breakdown by publisher below — Microsoft (INFO), signed third-party (WARN), unsigned (WARN)"

# NOTE v4.4: classification of open rules by publisher/signature of the
# associated executable. A raw count (31 rules) says nothing about the
# risk — a native Microsoft rule (Wi-Fi Direct, mDNS...) doesn't carry the
# same weight as an unsigned executable in AppData. Classified into three
# tiers:
# - Microsoft-signed  -> INFO  (native Windows rule, legitimate)
# - Third-party signed -> WARN  (known application rule)
# - Unsigned/unknown  -> strong WARN (needs manual review)
$FwMicrosoft = [System.Collections.Generic.List[string]]::new()
$FwThirdParty= [System.Collections.Generic.List[string]]::new()
$FwUnsigned  = [System.Collections.Generic.List[string]]::new()

foreach ($rule in $TrulyOpenRules) {
    $appFilter = $rule | Get-NetFirewallApplicationFilter -ErrorAction SilentlyContinue
    $exePath   = if ($appFilter) { $appFilter.Program } else { $null }

    if (-not $exePath -or $exePath -eq "Any" -or $exePath -eq "") {
        # Rule with no associated executable (port only)
        # Microsoft Store, UWP apps, Windows Features -> treat as Microsoft
        $ruleName = $rule.DisplayName
        if ($ruleName -match "Microsoft Store|Windows|Viewer|Experience Pack|Platform") {
            $FwMicrosoft.Add($ruleName)
        } else {
            $FwUnsigned.Add("$ruleName [port only, no exe]")
        }
        continue
    }

    # NOTE v4.5: expand environment variables before Get-AuthenticodeSignature.
    # Paths like %SystemRoot%\system32\svchost.exe aren't resolved
    # automatically by Get-AuthenticodeSignature -> silent failure -> false
    # "unsigned" positive. [Environment]::ExpandEnvironmentVariables() resolves the path.
    $exeResolved = [Environment]::ExpandEnvironmentVariables($exePath)

    # Native Windows executables in System32 — Microsoft by definition,
    # no need to check the signature (and "System" = kernel driver).
    if ($exeResolved -match "(?i)\\windows\\system32\\" -or $exePath -eq "System") {
        $FwMicrosoft.Add("$($rule.DisplayName)")
        continue
    }

    try {
        $sig = Get-AuthenticodeSignature -FilePath $exeResolved -ErrorAction Stop
        if ($sig.Status -eq "Valid") {
            $publisher = $sig.SignerCertificate.Subject
            if ($publisher -match "Microsoft") {
                $FwMicrosoft.Add("$($rule.DisplayName)")
            } else {
                $FwThirdParty.Add("$($rule.DisplayName) [$publisher]")
            }
        } else {
            $FwUnsigned.Add("$($rule.DisplayName) [$exeResolved — $($sig.Status)]")
        }
    } catch {
        $FwUnsigned.Add("$($rule.DisplayName) [$exeResolved — not verified]")
    }
}

if ($FwMicrosoft.Count -gt 0) {
    Add-Result "Firewall" "Open rules — Microsoft publisher" $FwMicrosoft.Count "INFO" "Native Windows rules (legitimate): $($FwMicrosoft -join ' | ')"
}
if ($FwThirdParty.Count -gt 0) {
    Add-Result "Firewall" "Open rules — signed third-party publisher" $FwThirdParty.Count "WARN" "Signed third-party application rules — check whether the software is expected: $($FwThirdParty -join ' | ')"
}
if ($FwUnsigned.Count -gt 0) {
    Add-Result "Firewall" "Open rules — unsigned/unknown executable" $FwUnsigned.Count "WARN" "Rules with no valid signature or no associated exe — review manually: $($FwUnsigned -join ' | ')"
}

# NOTE v3.0: a raw count of rules "open to any IP" says nothing about the
# actual risk — a rule open on an obscure application port doesn't carry
# the same weight as one open on RDP/SMB/WinRM. Each genuinely open rule
# is now reclassified by the port it exposes, with a list of notoriously
# sensitive ports flagged as FAIL.
$DangerousPorts = @{
    3389 = "RDP"; 445 = "SMB"; 139 = "NetBIOS"; 135 = "RPC"
    5985 = "WinRM (HTTP)"; 5986 = "WinRM (HTTPS)"; 23 = "Telnet"
    21 = "FTP"; 1433 = "SQL Server"; 3306 = "MySQL"; 5900 = "VNC"
}
foreach ($rule in $TrulyOpenRules) {
    $portFilter = $rule | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue
    if (-not $portFilter) { continue }
    foreach ($portEntry in @($portFilter.LocalPort)) {
        $portNum = 0
        if ([int]::TryParse("$portEntry", [ref]$portNum) -and $DangerousPorts.ContainsKey($portNum)) {
            Add-Result "Firewall" "Sensitive port exposed to any IP: $($DangerousPorts[$portNum]) ($portNum)" $rule.DisplayName "FAIL" "This rule allows port $portNum ($($DangerousPorts[$portNum])) from any remote address on the Public profile — restrict to a trusted IP range or disable if unused"
        }
    }
}

}

# ──────────────────────────────────────────────
#  4. ANTIVIRUS / WINDOWS DEFENDER
# ──────────────────────────────────────────────
if (ShouldRunSection "4_Defender") {
Write-Log "=== 4. ANTIVIRUS / WINDOWS DEFENDER ===" -Level SECTION

try {
    $DefenderStatus = Get-MpComputerStatus -ErrorAction Stop

    $avEnabled = $DefenderStatus.AntivirusEnabled
    Add-Result "Antivirus" "Antivirus enabled"          $(if($avEnabled){"Yes"}else{"NO"})          $(if($avEnabled){"OK"}else{"FAIL"})
    Add-Result "Antivirus" "Real-time protection"     $(if($DefenderStatus.RealTimeProtectionEnabled){"Enabled"}else{"DISABLED"})  $(if($DefenderStatus.RealTimeProtectionEnabled){"OK"}else{"FAIL"})
    Add-Result "Antivirus" "Network protection"         $(if($DefenderStatus.IoavProtectionEnabled){"Enabled"}else{"Disabled"})      $(if($DefenderStatus.IoavProtectionEnabled){"OK"}else{"WARN"})
    Add-Result "Antivirus" "Behavior monitoring"$(if($DefenderStatus.BehaviorMonitorEnabled){"Enabled"}else{"Disabled"})     $(if($DefenderStatus.BehaviorMonitorEnabled){"OK"}else{"WARN"})

    $SigAge = ((Get-Date) - $DefenderStatus.AntivirusSignatureLastUpdated).TotalDays
    Add-Result "Antivirus" "AV signatures (age)"      "$([math]::Round($SigAge,1)) days" $(
        if ($SigAge -gt 7) { "FAIL" } elseif ($SigAge -gt 3) { "WARN" } else { "OK" }
    ) $(if($SigAge -gt 7){"Signatures are stale!"}elseif($SigAge -gt 3){"Signatures are aging"})

    Add-Result "Antivirus" "Signature version"        $DefenderStatus.AntivirusSignatureVersion "INFO"

    # NOTE v5.0: Antispyware and NIS signatures — two AV components that are
    # independent and can drift separately if automatic updates are
    # partially failing (e.g. the AV updates but not NIS).
    try {
        $SpyAge = ((Get-Date) - $DefenderStatus.AntispywareSignatureLastUpdated).TotalDays
        Add-Result "Antivirus" "Anti-Spyware signatures (age)" "$([math]::Round($SpyAge,1)) days" $(
            if ($SpyAge -gt 7) { "FAIL" } elseif ($SpyAge -gt 3) { "WARN" } else { "OK" }
        ) $(if($SpyAge -gt 7){"Anti-spyware signatures are stale"}elseif($SpyAge -gt 3){"Anti-spyware signatures are aging"})
    } catch {}

    try {
        $NISAge = ((Get-Date) - $DefenderStatus.NISSignatureLastUpdated).TotalDays
        Add-Result "Antivirus" "NIS signatures (Network Inspection, age)" "$([math]::Round($NISAge,1)) days" $(
            if ($NISAge -gt 7) { "FAIL" } elseif ($NISAge -gt 3) { "WARN" } else { "OK" }
        ) $(if($NISAge -gt 7){"NIS signatures are stale — Defender's network inspection module isn't up to date"}elseif($NISAge -gt 3){"NIS signatures are aging"})
    } catch {}

    # NOTE v5.0.7: reworked the Defender scan check.
    # Old model (v1.1->v5.0.6): only the full scan was monitored, thresholds
    # 7d WARN / 30d FAIL. Problem: Defender on Win11 favors daily automatic
    # quick scans and doesn't launch a full scan on its own — a full scan
    # missing for 11 days is normal and generated an unjustified WARN on
    # every audit (case observed on NEPH-DESKTOP in a v5.0.x run).
    #
    # New model: two separate checks with tailored thresholds.
    # 1. QUICK SCAN (primary indicator) — should run at least every 3 days.
    #    >3d WARN, >7d FAIL. A missing quick scan = Defender is disrupted or stopped.
    # 2. FULL SCAN (secondary indicator) — wide thresholds, optional frequency.
    #    >30d WARN, >90d FAIL, never run = INFO (not an anomaly by itself).

    # 1. Quick scan
    if (-not $DefenderStatus.QuickScanEndTime -or
        $DefenderStatus.QuickScanEndTime -lt [datetime]"2000-01-01") {
        Add-Result "Antivirus" "Last quick scan" "No quick scan recorded" "WARN" "No recent quick scan detected — check that Defender is working correctly: 'Start-MpScan -ScanType QuickScan'"
    } else {
        $DaysSinceQuick = [math]::Round(((Get-Date) - $DefenderStatus.QuickScanEndTime).TotalDays, 1)
        $quickStatus = if ($DaysSinceQuick -gt 7) { "FAIL" } elseif ($DaysSinceQuick -gt 3) { "WARN" } else { "OK" }
        $quickDetail = switch ($quickStatus) {
            "FAIL" { "Last quick scan $DaysSinceQuick days ago — Defender is no longer scanning automatically, check the service status: 'Get-MpComputerStatus'" }
            "WARN" { "Last quick scan $DaysSinceQuick days ago — Defender should run an automatic quick scan every 1-2 days" }
            default { "Recent quick scan ($DaysSinceQuick day(s))" }
        }
        Add-Result "Antivirus" "Last quick scan" "$(Format-AuditDate $DefenderStatus.QuickScanEndTime)" $quickStatus $quickDetail
    }

    # 2. Full scan (wide thresholds — optional frequency on a personal machine)
    if (-not $DefenderStatus.FullScanEndTime -or
        $DefenderStatus.FullScanEndTime -lt [datetime]"2000-01-01") {
        Add-Result "Antivirus" "Last full scan" "No full scan recorded" "INFO" "No full scan in the history — normal if Defender manages scanning automatically (daily quick scans). Run one occasionally: 'Start-MpScan -ScanType FullScan'"
    } else {
        $DaysSinceFullScan = [math]::Round(((Get-Date) - $DefenderStatus.FullScanEndTime).TotalDays, 1)
        $scanStatus = if ($DaysSinceFullScan -gt 90) { "FAIL" } elseif ($DaysSinceFullScan -gt 30) { "WARN" } else { "OK" }
        $scanDetail = switch ($scanStatus) {
            "FAIL" { "Last full scan $DaysSinceFullScan days ago — very old, consider running a full scan: 'Start-MpScan -ScanType FullScan'" }
            "WARN" { "Last full scan $DaysSinceFullScan days ago — a monthly full scan is recommended" }
            default { "Recent full scan ($DaysSinceFullScan day(s))" }
        }
        Add-Result "Antivirus" "Last full scan" "$(Format-AuditDate $DefenderStatus.FullScanEndTime)" $scanStatus $scanDetail
    }

    # NOTE v1.1: AMSIEnabled is no longer exposed by Get-MpComputerStatus on
    # some recent builds — a missing value ($null) doesn't mean "disabled".
    # Now distinguishes "not exposed" from "actually disabled".
    if ($null -eq $DefenderStatus.PSObject.Properties['AMSIEnabled'] -or $null -eq $DefenderStatus.AMSIEnabled) {
        Add-Result "Antivirus" "AMSI enabled" "Not exposed by this build" "INFO" "Get-MpComputerStatus no longer returns this property on some recent versions; AMSI stays active by default unless explicitly disabled via GPO"
    } else {
        Add-Result "Antivirus" "AMSI enabled" $(if($DefenderStatus.AMSIEnabled){"Yes"}else{"No"}) $(if($DefenderStatus.AMSIEnabled){"OK"}else{"WARN"})
    }

} catch {
    Add-Result "Antivirus" "Windows Defender" "Unable to read status: $_" "WARN"
}

# Check whether another AV is installed
try {
    $AVProducts = Get-CimInstance -Namespace root\SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction Stop
    foreach ($av in $AVProducts) {
        Add-Result "Antivirus" "Detected AV product" $av.displayName "INFO" "State: $($av.productState)"
    }
} catch {}

# NOTE v3.0: ASR (Attack Surface Reduction) rules — block generic attack
# techniques (Office macros spawning child processes, obfuscated scripts,
# unsigned executables from email, etc.) ahead of signature-based
# detection. Ids/Actions are two parallel arrays (same index = same rule).
# Action 1 = Block, 2 = Audit, 0/absent = Off.
try {
    $AsrPrefs   = Get-MpPreference -ErrorAction Stop
    $AsrIds     = @($AsrPrefs.AttackSurfaceReductionRules_Ids)
    $AsrActions = @($AsrPrefs.AttackSurfaceReductionRules_Actions)
    $AsrBlocking = 0
    $AsrAuditing = 0
    for ($i = 0; $i -lt $AsrIds.Count; $i++) {
        if ($i -lt $AsrActions.Count) {
            if ([int]$AsrActions[$i] -eq 1) { $AsrBlocking++ }
            elseif ([int]$AsrActions[$i] -eq 2) { $AsrAuditing++ }
        }
    }
    if ($AsrIds.Count -eq 0) {
        Add-Result "Antivirus" "ASR rules (Attack Surface Reduction)" "No rule configured" "WARN" "ASR rules block generic attack techniques (Office macros, obfuscated scripts, etc.) independently of signatures — none are active on this machine. See 'Add-MpPreference -AttackSurfaceReductionRules_Ids ... -AttackSurfaceReductionRules_Actions Enabled'"
    } else {
        Add-Result "Antivirus" "ASR rules (Attack Surface Reduction)" "$($AsrIds.Count) rule(s) configured" $(
            if ($AsrBlocking -eq 0) { "WARN" } else { "OK" }
        ) "$AsrBlocking in blocking mode, $AsrAuditing in audit-only mode, $($AsrIds.Count - $AsrBlocking - $AsrAuditing) inactive"
    }
} catch {
    Add-Result "Antivirus" "ASR rules (Attack Surface Reduction)" "Unable to read" "INFO" "Error: $($_.Exception.Message)"
}

# NOTE v4.6: history of Defender detections over the last 30 days.
# Get-MpThreatDetection returns every threat detected and handled
# (quarantine, removal, blocking). 0 detections = machine clean for 30
# days. Recent detections don't necessarily signal an active compromise —
# Defender may have blocked a download or a PUA with no user intervention
# — but they deserve to be visible.
try {
    $ThreatHistory = Get-MpThreatDetection -ErrorAction Stop
    $Since30Days   = if ($null -eq $ThreatHistory) { @() } else {
        @($ThreatHistory | Where-Object {
            $_.InitialDetectionTime -ge (Get-Date).AddDays(-30)
        })
    }

    if ($Since30Days.Count -eq 0) {
        Add-Result "Defender" "Detection history (30 days)" "0 detections" "OK" "No threats detected by Windows Defender in the last 30 days"
    } else {
        # Build a ThreatID -> ThreatName map in a single query
        $ThreatMap = @{}
        try {
            Get-MpThreat -ErrorAction SilentlyContinue | ForEach-Object {
                $ThreatMap[[string]$_.ThreatID] = $_.ThreatName
            }
        } catch {}

        $threatDetails = $Since30Days | Select-Object -First 10 | ForEach-Object {
            $name   = if ($ThreatMap.ContainsKey([string]$_.ThreatID)) { $ThreatMap[[string]$_.ThreatID] } else { "ID $($_.ThreatID)" }
            $status = if ($_.ActionSuccess) { "Handled" } else { "⚠ Not handled" }
            "$name — $status on $(Format-AuditDate $_.InitialDetectionTime)"
        }
        $moreNote   = if ($Since30Days.Count -gt 10) { " (+ $($Since30Days.Count - 10) more)" } else { "" }
        $hasUntreated = $Since30Days | Where-Object { -not $_.ActionSuccess }
        $detStatus  = if ($hasUntreated) { "WARN" } else { "INFO" }
        Add-Result "Defender" "Detection history (30 days)" "$($Since30Days.Count) detection(s)$moreNote" $detStatus "Threats$(if($hasUntreated){' — ⚠ AT LEAST ONE NOT HANDLED'}) : $($threatDetails -join ' | ')"
    }
} catch {
    Add-Result "Defender" "Detection history (30 days)" "Unable to read" "INFO" "Get-MpThreatDetection unavailable: $($_.Exception.Message)"
}

}

# ──────────────────────────────────────────────
#  5. USER ACCOUNTS & POLICIES
# ──────────────────────────────────────────────
if (ShouldRunSection "5_Accounts") {
Write-Log "=== 5. USER ACCOUNTS ===" -Level SECTION

# Local accounts
$LocalUsers = Get-LocalUser
foreach ($user in $LocalUsers) {
    $statusU = "INFO"
    $detail  = ""

    if ($user.Enabled -and $user.Name -eq "Administrator") {
        $statusU = "WARN"; $detail = "The built-in Administrator account is enabled"
    }
    if ($user.Enabled -and $user.PasswordNeverExpires) {
        $statusU = "WARN"; $detail += " | Password never expires"
    }
    if ($user.Enabled -and (-not $user.PasswordRequired)) {
        # NOTE v1.1: this SAM flag (UF_PASSWD_NOTREQD) can be set
        # automatically by Windows Hello (PIN/biometrics) without meaning
        # that no authentication is required at sign-in.
        # Downgraded to WARN (instead of FAIL).
        # NOTE v2.0: now relies on the Hello detection above to give a
        # concrete explanation rather than just a manual-check pointer.
        $statusU = "WARN"
        if ($HelloConfigured) {
            $detail += " | SAM reports 'password not required', but a Windows Hello credential (PIN/biometrics) is registered on this machine — that's probably the explanation, not an active weakness"
        } elseif ($HelloIndeterminate) {
            $detail += " | SAM reports 'password not required' — Windows Hello detection couldn't access some system-protected containers to confirm or rule this out; check with 'net user $($user.Name)' or in Settings > Accounts > Sign-in options"
        } else {
            $detail += " | SAM reports 'password not required' and no Windows Hello credential was detected on this machine — check with 'net user $($user.Name)' whether this is a real setting to fix"
        }
    }
    if (-not $user.Enabled) { $statusU = "INFO" }

    Add-Result "Accounts" "Local user: $($user.Name)" $(
        "$(if($user.Enabled){'Enabled'}else{'Disabled'}) | Pwd expires: $(if($user.PasswordNeverExpires){'Never'}else{'Yes'})"
    ) $statusU $detail
}

# Members of the local Administrators group
# NOTE v1.1: the old version queried the group by its English name
# "Administrators", which can silently fail on a localized Windows (group
# named "Administrateurs" internally) — the error was swallowed by
# -ErrorAction SilentlyContinue and the script showed "OK" with an empty
# value. Now queried by universal SID (S-1-5-32-544, valid across every
# language) and a read failure is now clearly reported when it occurs.
try {
    $AdminGroup = Get-LocalGroupMember -SID "S-1-5-32-544" -ErrorAction Stop
    Add-Result "Accounts" "Local Administrators members" ($AdminGroup.Name -join ", ") $(
        if ($AdminGroup.Count -gt 3) { "WARN" } else { "OK" }
    ) $(if($AdminGroup.Count -gt 3){"Too many local administrator accounts"})
} catch {
    Add-Result "Accounts" "Local Administrators members" "Unable to read" "WARN" "Error: $($_.Exception.Message)"
}

# NOTE v5.0: built-in Administrator account (RID-500) — on a personal
# non-domain machine, this account should stay disabled. Enabled, it
# offers a brute-force target with a predictable name (Administrator).
# The SID always ends in -500 regardless of the system language.
try {
    $AllLocalUsers = Get-LocalUser -ErrorAction Stop
    $BuiltinAdmin = $AllLocalUsers | Where-Object {
        $_.SID -and $_.SID.Value -match '-500$'
    } | Select-Object -First 1

    if ($BuiltinAdmin) {
        if ($BuiltinAdmin.Enabled) {
            Add-Result "Accounts" "Built-in Administrator account (RID-500)" "Enabled — $($BuiltinAdmin.Name)" "WARN" "The built-in Administrator account is active. On a personal non-domain machine, disabling it reduces the local brute-force attack surface: 'Disable-LocalUser -SID S-1-5-21-*-500' or via lusrmgr.msc"
        } else {
            Add-Result "Accounts" "Built-in Administrator account (RID-500)" "Disabled — $($BuiltinAdmin.Name)" "OK" "The built-in Administrator account is correctly disabled"
        }
    } else {
        Add-Result "Accounts" "Built-in Administrator account (RID-500)" "Not detected" "INFO" "No local account with a SID ending in -500 — unusual configuration"
    }
} catch {
    Add-Result "Accounts" "Built-in Administrator account (RID-500)" "Unable to read" "INFO" "Error: $($_.Exception.Message)"
}

# Password policy
# NOTE v1.1: the old version parsed the text output of "net accounts",
# which is localized (French on this machine) — the English labels never
# matched, hence a systematic error. Switched to the ADSI WinNT provider,
# which isn't affected by the system language.
#
# NOTE v1.2: the first fix bound the object without a class suffix
# ("WinNT://$env:COMPUTERNAME"), which resolves by default to the "Computer"
# COM class — which does NOT expose MinPasswordLength/MaxPasswordAge/etc.
# Fixed by binding via the IADsDomain interface (",Domain" suffix).
#
# NOTE v5.4.0: reverted to parsing "net accounts" output after all — this
# time bilingually, matching the pattern already used for auditpol/
# vssadmin/wbadmin elsewhere in this script. Root cause: live testing
# (user report, confirmed via "net accounts /lockoutthreshold:5
# /lockoutduration:15 /lockoutwindow:15" then re-running this section)
# showed MinPasswordLength and MinPasswordAge read correctly via ADSI, but
# MaxPasswordAge and MaxBadPasswordsAllowed/AutoUnlockInterval did NOT —
# "net accounts" itself confirmed threshold=5/duration=15/max age=42 days,
# while this section kept reporting "Lockout threshold: Disabled (0
# attempts)" and "Maximum password age: Unlimited" regardless. Rather than
# keep two ADSI reads that have shown themselves unreliable on at least
# one real Windows 11 build alongside two that work, every value here now
# comes from the same proven-accurate source.
try {
    $NetAccountsOutput = & net accounts 2>&1
    $NetAccountsText   = ($NetAccountsOutput -join "`n") -replace "`0",""

    $MinPwdLenRaw = Get-NetAccountsValue $NetAccountsText @(
        'Longueur minimale du mot de passe\s*:\s*(\d+)',
        'Minimum password length\s*:\s*(\d+)'
    )
    $MinPwdLen = if ($MinPwdLenRaw) { [int]$MinPwdLenRaw } else { 0 }

    $MaxPwdAgeRaw = Get-NetAccountsValue $NetAccountsText @(
        'Dur[ée]e de vie maximale du mot de passe \(jours\)\s*:\s*(.+)',
        'Maximum password age \(days\)\s*:\s*(.+)'
    )
    $MaxPwdAgeUnlimited = $MaxPwdAgeRaw -match '(?i)illimit|unlimited'
    $MaxPwdAgeDays = if ($MaxPwdAgeUnlimited -or -not $MaxPwdAgeRaw) { 0 } else { [int]($MaxPwdAgeRaw -replace '\D','') }

    $MinPwdAgeRaw = Get-NetAccountsValue $NetAccountsText @(
        'Dur[ée]e de vie minimale du mot de passe \(jours\)\s*:\s*(\d+)',
        'Minimum password age \(days\)\s*:\s*(\d+)'
    )
    $MinPwdAgeDays = if ($MinPwdAgeRaw) { [int]$MinPwdAgeRaw } else { 0 }

    $LockoutThresholdRaw = Get-NetAccountsValue $NetAccountsText @(
        'Seuil de verrouillage\s*:\s*(.+)',
        'Lockout threshold\s*:\s*(.+)'
    )
    $LockoutDisabled = (-not $LockoutThresholdRaw) -or ($LockoutThresholdRaw -match '(?i)jamais|never')
    $LockoutThreshold = if ($LockoutDisabled) { 0 } else { [int]($LockoutThresholdRaw -replace '\D','') }

    $LockoutDurRaw = Get-NetAccountsValue $NetAccountsText @(
        'Dur[ée]e du verrouillage \(min\)\s*:\s*(.+)',
        'Lockout duration \(minutes\)\s*:\s*(.+)'
    )
    $LockoutDurMinutes = if ($LockoutDurRaw -and $LockoutDurRaw -notmatch '(?i)jamais|never') { [int]($LockoutDurRaw -replace '\D','') } else { 0 }

    if (-not $MinPwdLenRaw -and -not $LockoutThresholdRaw) {
        throw "Unrecognized 'net accounts' output — neither French nor English labels matched"
    }

    Add-Result "Password Policy" "Minimum length required by local policy" "$MinPwdLen characters" $(
        if ($MinPwdLen -lt 8) { "WARN" } elseif ($MinPwdLen -lt 12) { "WARN" } else { "OK" }
    ) "Does NOT reflect your current password: only shows the minimum length Windows would enforce if a local account's password were changed. You can already have a strong password in place despite a permissive setting here. Recommended: >= 12"

    Add-Result "Password Policy" "Maximum password age" $(
        if ($MaxPwdAgeDays -eq 0) { "Unlimited" } else { "$MaxPwdAgeDays days" }
    ) "INFO"

    Add-Result "Password Policy" "Minimum password age" "$MinPwdAgeDays day(s)" "INFO" "Minimum delay before a password can be changed again — a policy setting, unrelated to the current password"

    Add-Result "Password Policy" "Lockout threshold" $(
        if ($LockoutThreshold -eq 0) { "Disabled (0 attempts)" } else { "$LockoutThreshold attempts" }
    ) $(
        if ($LockoutThreshold -eq 0) { "WARN" } else { "OK" }
    ) $(if($LockoutThreshold -eq 0){"No automatic lockout after failed sign-in attempts (no anti-brute-force protection) — a policy setting, independent of your current password's strength"})

    if ($LockoutThreshold -gt 0) {
        Add-Result "Password Policy" "Lockout duration" "$LockoutDurMinutes minute(s)" $(
            if ($LockoutDurMinutes -lt 5) { "WARN" } else { "OK" }
        ) $(if($LockoutDurMinutes -lt 5){"Very short lockout duration — makes repeated brute-force attempts in small bursts easier"})
    }
} catch {
    Add-Result "Password Policy" "Reading policy" "Error: $($_.Exception.Message)" "WARN"
}

}

# ──────────────────────────────────────────────
#  6. UAC (USER ACCOUNT CONTROL)
# ──────────────────────────────────────────────
if (ShouldRunSection "6_UAC") {
Write-Log "=== 6. UAC ===" -Level SECTION

$UACKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$EnableLUA        = (Get-ItemProperty $UACKey -Name "EnableLUA"        -EA SilentlyContinue).EnableLUA
$ConsentPrompt    = (Get-ItemProperty $UACKey -Name "ConsentPromptBehaviorAdmin" -EA SilentlyContinue).ConsentPromptBehaviorAdmin
$SecureDesktop    = (Get-ItemProperty $UACKey -Name "PromptOnSecureDesktop" -EA SilentlyContinue).PromptOnSecureDesktop

Add-Result "UAC" "UAC enabled (EnableLUA)" $(if($EnableLUA -eq 1){"Yes"}else{"NO"}) $(if($EnableLUA -eq 1){"OK"}else{"FAIL"}) $(if($EnableLUA -ne 1){"UAC disabled — critical risk!"})
Add-Result "UAC" "Admin consent level" $ConsentPrompt $(
    if ($ConsentPrompt -eq 0) { "FAIL" } elseif ($ConsentPrompt -le 2) { "WARN" } else { "OK" }
) "0=No prompt (dangerous), 2=Prompt for creds, 5=Prompt (default)"
Add-Result "UAC" "Secure desktop" $(if($SecureDesktop -eq 1){"Enabled"}else{"Disabled"}) $(if($SecureDesktop -eq 1){"OK"}else{"WARN"})

}

# ──────────────────────────────────────────────
#  7. BITLOCKER
# ──────────────────────────────────────────────
if (ShouldRunSection "7_BitLocker") {
Write-Log "=== 7. BITLOCKER ===" -Level SECTION

try {
    $Volumes = Get-BitLockerVolume -ErrorAction Stop
    foreach ($vol in $Volumes) {
        $isSystemVol = ("$($vol.MountPoint)".TrimEnd('\') -eq $env:SystemDrive)
        $st = switch ($vol.ProtectionStatus) {
            "On"  { "OK" }
            "Off" { if ($isSystemVol) { "FAIL" } else { "WARN" } }
            default { "WARN" }
        }
        $detailMsg = if ($vol.ProtectionStatus -ne "On") {
            if ($isSystemVol) {
                "System volume not encrypted — data exposed if the machine is lost or stolen!"
            } else {
                "Data volume not encrypted — WARN if this volume holds sensitive data; acceptable if it's a games drive, a scratch partition, or a deliberate choice"
            }
        }
        Add-Result "BitLocker" "Volume $($vol.MountPoint)" "Protection: $($vol.ProtectionStatus) | Encryption: $($vol.EncryptionPercentage)%" $st $detailMsg
    }
} catch {
    Add-Result "BitLocker" "BitLocker" "Not available or error: $_" "WARN"
}

}

# ──────────────────────────────────────────────
#  8. CRITICAL NETWORK PROTOCOLS
# ──────────────────────────────────────────────
if (ShouldRunSection "8_Network") {
Write-Log "=== 8. NETWORK PROTOCOLS ===" -Level SECTION

# SMBv1
try {
    $SMBv1 = Get-SmbServerConfiguration -ErrorAction Stop
    Add-Result "Network" "SMBv1 enabled" $(if($SMBv1.EnableSMB1Protocol){"YES — DANGEROUS"}else{"No (correct)"}) $(
        if ($SMBv1.EnableSMB1Protocol) { "FAIL" } else { "OK" }
    ) $(if($SMBv1.EnableSMB1Protocol){"SMBv1 should be disabled (WannaCry, NotPetya...)"})

    # NOTE v3.0: SMB signing — prevents NTLM relay / SMB packet tampering in
    # transit. RequireSecuritySignature on the server side AND the client
    # side (Get-SmbClientConfiguration) are two independent settings.
    Add-Result "Network" "SMB signing required (server)" $(if($SMBv1.RequireSecuritySignature){"Yes"}else{"No"}) $(
        if ($SMBv1.RequireSecuritySignature) { "OK" } else { "WARN" }
    ) $(if(-not $SMBv1.RequireSecuritySignature){"SMB signing isn't required on the server side — exposes to an SMB relay/tampering attack"})
} catch {
    Add-Result "Network" "SMBv1" "Read error" "WARN"
}

try {
    $SMBClient = Get-SmbClientConfiguration -ErrorAction Stop
    Add-Result "Network" "SMB signing required (client)" $(if($SMBClient.RequireSecuritySignature){"Yes"}else{"No"}) $(
        if ($SMBClient.RequireSecuritySignature) { "OK" } else { "WARN" }
    ) $(if(-not $SMBClient.RequireSecuritySignature){"SMB signing isn't required on the client side — this machine would accept a connection to an unsigned share"})
} catch {
    Add-Result "Network" "SMB signing (client)" "Read error" "INFO"
}

# NOTE v3.0: NTLM restrictions — LmCompatibilityLevel governs which
# versions of NTLM authentication are accepted. Level < 3 allows LM/NTLMv1
# (crackable in seconds/minutes by current tools); level 5 = rejects
# LM/NTLMv1 and only accepts NTLMv2. Missing key = Windows default value
# (3), shown as such rather than as an error.
$LmCompatKey = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
$LmCompatRaw = (Get-ItemProperty $LmCompatKey -Name LmCompatibilityLevel -EA SilentlyContinue).LmCompatibilityLevel
$LmCompatLevel = if ($null -ne $LmCompatRaw) { [int]$LmCompatRaw } else { 3 }
$LmCompatLabel = switch ($LmCompatLevel) {
    0 { "0 — LM and NTLMv1 sent, never NTLMv2 (very permissive)" }
    1 { "1 — LM/NTLMv1, NTLMv2 if negotiated" }
    2 { "2 — NTLMv1 only" }
    3 { "3 — NTLMv2 only (Windows default)" }
    4 { "4 — NTLMv2 only, refuses incoming LM" }
    5 { "5 — NTLMv2 only, refuses incoming LM and NTLM (strictest)" }
    default { "$LmCompatLevel — non-standard value" }
}
Add-Result "Network" "NTLM restriction (LmCompatibilityLevel)" $LmCompatLabel $(
    if ($LmCompatLevel -le 1) { "FAIL" } elseif ($LmCompatLevel -le 2) { "WARN" } else { "OK" }
) $(if($LmCompatLevel -le 2){"This level allows NTLMv1/LM, crackable quickly by current tools — raise to 5 if no legacy equipment depends on it"})

# NOTE v3.0: encrypted DNS (DoH) at the system level — Erwan already uses NextDNS
# as a dedicated app, so this check mainly verifies that the native Windows
# resolver (in case the NextDNS app is stopped) doesn't expose queries in
# the clear. DohFlag: 0=disabled, 1=allowed, 2=required for known DoH servers, 3=required for all.
try {
    $DnsInterfaces = Get-DnsClientDohServerAddress -ErrorAction Stop
    if ($DnsInterfaces) {
        $DohActive = $DnsInterfaces | Where-Object { $_.DohFlag -ge 1 }
        Add-Result "Network" "Encrypted DNS (DoH)" $(if($DohActive){"$($DohActive.Count) DoH server(s) configured"}else{"No DoH server configured"}) $(
            if ($DohActive) { "OK" } else { "INFO" }
        ) "Mainly checks the system's DNS resolution outside of NextDNS (dedicated app) — classic DNS queries (port 53) travel in the clear"
    } else {
        Add-Result "Network" "Encrypted DNS (DoH)" "No DoH server configured" "INFO" "System DNS queries travel in the clear unless filtered upstream (e.g. NextDNS, if active)"
    }
} catch {
    Add-Result "Network" "Encrypted DNS (DoH)" "Not available on this build" "INFO"
}

# RDP
$RDPKey = "HKLM:\System\CurrentControlSet\Control\Terminal Server"
$RDPEnabled = (Get-ItemProperty $RDPKey -Name fDenyTSConnections -EA SilentlyContinue).fDenyTSConnections
Add-Result "Network" "RDP enabled" $(if($RDPEnabled -eq 0){"YES"}else{"No"}) $(
    if ($RDPEnabled -eq 0) { "WARN" } else { "OK" }
) $(if($RDPEnabled -eq 0){"RDP is active — check NLA and firewall rules"})

# NLA for RDP
if ($RDPEnabled -eq 0) {
    $NLA = (Get-ItemProperty "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name UserAuthentication -EA SilentlyContinue).UserAuthentication
    Add-Result "Network" "NLA (Network Level Auth) RDP" $(if($NLA -eq 1){"Enabled"}else{"DISABLED"}) $(
        if ($NLA -eq 1) { "OK" } else { "FAIL" }
    ) $(if($NLA -ne 1){"NLA disabled on RDP — insecure authentication"})
}

# NOTE v4.0: outbound established TCP connections enriched with the process
# name. Cross-referenced on OwningProcess (PID) -> Get-Process. Loopback
# addresses (127.x, ::1) and link-local IPv6 (fe80::) are filtered out. A
# PID that can't be resolved (process ended between reading the socket and
# Get-Process, or an unreadable SYSTEM service) generates a WARN — a sign
# of unusual behavior or a benign race condition worth checking.
try {
    $ExtConns = Get-NetTCPConnection -State Established -ErrorAction Stop |
        Where-Object {
            $_.RemoteAddress -ne "127.0.0.1" -and
            $_.RemoteAddress -ne "::1" -and
            $_.RemoteAddress -notmatch "^fe80:" -and
            $_.RemoteAddress -ne "0.0.0.0"
        }

    if ($ExtConns.Count -eq 0) {
        Add-Result "Network" "Established TCP connections (outbound)" "0" "OK" "No established outbound TCP connection at audit time"
    } else {
        # Build a PID -> process name table in a single query (avoids N
        # Get-Process calls in the loop)
        $ProcMap = @{}
        Get-Process -ErrorAction SilentlyContinue | ForEach-Object { $ProcMap[$_.Id] = $_.Name }

        $ConnOrphans  = [System.Collections.Generic.List[string]]::new()
        $ConnDetails  = [System.Collections.Generic.List[string]]::new()

        foreach ($c in ($ExtConns | Select-Object -First 30)) {
            $procId = $c.OwningProcess
            $proc = if ($ProcMap.ContainsKey([int]$procId)) { $ProcMap[[int]$procId] } else { $null }
            if ($proc) {
                $ConnDetails.Add("$proc (PID $procId) → $($c.RemoteAddress):$($c.RemotePort)")
            } else {
                $ConnOrphans.Add("PID $procId → $($c.RemoteAddress):$($c.RemotePort)")
            }
        }

        $totalShown = [math]::Min(30, $ExtConns.Count)
        $truncNote  = if ($ExtConns.Count -gt 30) { " (showing only the first 30 of $($ExtConns.Count))" } else { "" }

        Add-Result "Network" "Established TCP connections (outbound)" "$($ExtConns.Count) connection(s)$truncNote" "INFO" ($ConnDetails -join " | ")

        if ($ConnOrphans.Count -gt 0) {
            Add-Result "Network" "TCP connections — unresolvable process" "$($ConnOrphans.Count) socket(s)" "WARN" "PID was active when the socket was created but couldn't be resolved at audit time (process ended mid-run, or an inaccessible SYSTEM service): $($ConnOrphans -join ' | ')"
        }

        # NOTE v5.0: summary of connections to public IPs (non-RFC1918).
        # Separates connections to private IPs (192.168.x, 10.x, 172.16-31.x)
        # from connections to genuine public IPs. Public IPs deserve special
        # attention: that's where legitimate traffic flows (CDN, APIs) but
        # also potentially C&C or exfiltration traffic.
        # Allowlist of system processes expected to have public connections.
        # NOTE v5.0.1: post-NEPH-DESKTOP-run additions — legitimate
        # processes flagged WARN because they were missing from the initial list.
        # NextDNSService: local DoH DNS proxy (NextDNS). MpDefenderCoreService:
        # Defender component (cloud protection/telemetry). Rainmeter: desktop widget.
        # NOTE v5.0.2: pwsh/powershell — the script itself (or a parallel PS
        # session) can have an active public TCP connection at audit time
        # (Update/Gallery request, an open session, etc.).
        $SystemProcsAllowlist = @("svchost","SearchApp","MicrosoftEdge","msedge","brave",
            "chrome","firefox","librewolf","Spotify","steam","OneDrive","MsMpEng",
            "WinStore.App","SystemSettings","WidgetService","explorer","backgroundTaskHost",
            "NextDNSService","MpDefenderCoreService","MpDefenderCore","Rainmeter",
            "NisSrv","SecurityHealthService","SgrmBroker","spoolsv","lsass","wininit",
            "pwsh","powershell","powershell_ise")

        $PublicConns = $ExtConns | Where-Object {
            $addr = $_.RemoteAddress
            # Exclude RFC-1918 + link-local + APIPA
            -not ($addr -match '^10\.' -or
                  $addr -match '^192\.168\.' -or
                  $addr -match '^172\.(1[6-9]|2[0-9]|3[01])\.' -or
                  $addr -match '^169\.254\.' -or
                  $addr -match '^fc|^fd' -or
                  $addr -eq '::')
        }

        if ($PublicConns.Count -gt 0) {
            $PubKnown   = [System.Collections.Generic.List[string]]::new()
            $PubUnknown = [System.Collections.Generic.List[string]]::new()

            foreach ($pc in ($PublicConns | Select-Object -First 20)) {
                $procName = if ($ProcMap.ContainsKey([int]$pc.OwningProcess)) { $ProcMap[[int]$pc.OwningProcess] } else { "PID $($pc.OwningProcess)" }
                $entry = "$procName → $($pc.RemoteAddress):$($pc.RemotePort)"
                $isKnown = $false
                foreach ($sp in $SystemProcsAllowlist) {
                    if ($procName -like "*$sp*") { $isKnown = $true; break }
                }
                if ($isKnown) { $PubKnown.Add($entry) } else { $PubUnknown.Add($entry) }
            }

            $pubStatus = if ($PubUnknown.Count -gt 0) { "WARN" } else { "INFO" }
            $pubDetail = ""
            if ($PubUnknown.Count -gt 0) { $pubDetail += "⚠ Unrecognized processes to public IPs: $($PubUnknown -join ' | ') " }
            if ($PubKnown.Count -gt 0)   { $pubDetail += "✓ Recognized processes: $($PubKnown -join ' | ')" }
            Add-Result "Network" "TCP connections to public IPs" "$($PublicConns.Count) connection(s)" $pubStatus $pubDetail
        } else {
            Add-Result "Network" "TCP connections to public IPs" "0" "OK" "No established TCP connection to a public IP at audit time"
        }
    }
} catch {
    # NOTE v4.1: Get-NetTCPConnection can fail on certain system sockets
    # even as admin (in particular sockets inheriting a different session
    # context). This isn't a security anomaly — downgraded to INFO so it
    # doesn't pollute the Network category's score.
    $errMsg = $_.Exception.Message
    Add-Result "Network" "Established TCP connections (outbound)" "Unable to read" "INFO" "Error enumerating TCP sockets: $errMsg — this isn't a security anomaly (system socket access limitation)"
}

# Network shares
$Shares = Get-SmbShare -ErrorAction SilentlyContinue | Where-Object { $_.Name -notmatch '\$' }
Add-Result "Network" "Non-admin network shares" $Shares.Count $(
    if ($Shares.Count -gt 0) { "WARN" } else { "OK" }
) $(if($Shares.Count -gt 0){"Shares detected: " + ($Shares.Name -join ", ")})

# NOTE v4.2: WinRM (Windows Remote Management / remote PS access).
# Active WinRM lets any administrator open a remote PowerShell session on
# this machine (Enter-PSSession, Invoke-Command). On a personal non-domain
# PC, this service has no reason to be active. Checks two things: the
# service status, AND the presence of a WSMan listener in the registry (a
# listener can survive a stopped service and reactivate it).
try {
    $WinRMSvc = Get-Service -Name WinRM -ErrorAction Stop
    $WinRMListenerKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN\Listener"
    $WinRMListeners = if (Test-Path -LiteralPath $WinRMListenerKey -ErrorAction SilentlyContinue) {
        Get-ChildItem -Path $WinRMListenerKey -ErrorAction SilentlyContinue
    } else { @() }

    if ($WinRMSvc.Status -eq "Running") {
        $listenerDetail = if ($WinRMListeners.Count -gt 0) {
            "Configured listeners: " + ($WinRMListeners | ForEach-Object { $_.PSChildName } | Join-String -Separator ", ")
        } else { "No WSMan listener detected despite the active service" }
        Add-Result "Network" "WinRM (remote PS access)" "Service ACTIVE ($($WinRMSvc.StartType))" "WARN" "WinRM is running — allows remote PowerShell access. On a personal non-domain machine, disable via: Stop-Service WinRM ; Set-Service WinRM -StartupType Disabled. $listenerDetail"
    } elseif ($WinRMListeners.Count -gt 0) {
        Add-Result "Network" "WinRM (remote PS access)" "Service stopped but WSMan listener(s) present" "WARN" "The WinRM service is stopped but $($WinRMListeners.Count) WSMan listener(s) are configured in the registry — WinRM can be reactivated automatically by some tools. Remove the listeners if this wasn't intentional."
    } else {
        Add-Result "Network" "WinRM (remote PS access)" "Disabled (service $($WinRMSvc.Status), no listener)" "OK" "No remote PowerShell access possible"
    }
} catch {
    Add-Result "Network" "WinRM (remote PS access)" "Unable to read" "INFO" "Error: $($_.Exception.Message)"
}

# NOTE v4.2: active network profile per interface. Get-NetConnectionProfile
# returns the profile of each connected interface (Public, Private,
# Domain). A Domain profile on a WORKGROUP machine is an orphaned config —
# may result from an old domain join or a manual change, and affects the
# firewall rules applied to that interface.
try {
    $NetProfiles = Get-NetConnectionProfile -ErrorAction Stop
    foreach ($np in $NetProfiles) {
        $profileLabel = "$($np.NetworkCategory) — network: $($np.Name)"
        $isOrphanDomain = ($np.NetworkCategory -eq "DomainAuthenticated") -and ($env:USERDNSDOMAIN -eq $env:COMPUTERNAME -or $env:USERDOMAIN -eq $env:COMPUTERNAME)
        $status = if ($isOrphanDomain) { "WARN" } else { "INFO" }
        $detail = if ($isOrphanDomain) {
            "Domain profile on a non-domain machine — possible orphaned config. Domain profile firewall rules apply, potentially more permissive."
        } else { "" }
        Add-Result "Network" "Network profile: $($np.InterfaceAlias)" $profileLabel $status $detail
    }
} catch {
    Add-Result "Network" "Network profiles per interface" "Unable to read" "INFO" "Error: $($_.Exception.Message)"
}

# NOTE v5.0: IPv6 firewall exposure — a machine with IPv6 active on a
# public interface but with no dedicated IPv6 inbound blocking rules
# leaves a blind spot. Windows Firewall rules are shared IPv4/IPv6 by
# default for "Any" rules, but some admins create rules explicitly bound
# to IPv4 addresses that don't cover IPv6.
# Checks: IPv6 active on >=1 non-loopback interface AND the Public firewall
# profile is in default-block mode for inbound connections.
try {
    $IPv6Adapters = Get-NetAdapterBinding -ComponentID ms_tcpip6 -ErrorAction Stop |
        Where-Object { $_.Enabled -eq $true }

    $ActiveIPv6 = $IPv6Adapters | Where-Object {
        # Filter loopback and virtual interfaces with no real traffic
        $_.Name -notmatch "Loopback|Local Area Connection\* \d+|isatap|teredo" -and
        (Get-NetAdapter -Name $_.Name -ErrorAction SilentlyContinue).Status -eq "Up"
    }

    if ($ActiveIPv6.Count -eq 0) {
        Add-Result "Network" "IPv6 active on network interfaces" "Not active on UP interfaces" "INFO" "IPv6 disabled or inactive on every connected interface — no IPv6 firewall blind spot"
    } else {
        # Check that the firewall properly covers the Public profile with inbound blocking
        $FwPublicProfile = Get-NetFirewallProfile -Name Public -ErrorAction SilentlyContinue
        # NOTE v5.0.1: NotConfigured = Windows Defender Firewall applies its
        # default policy (inbound blocking on the Public profile) — this
        # isn't an absence of protection, it's the normal behavior on Win11.
        # v5.0 only tested for explicit "Block" -> systematic false positive
        # on every Win11 machine with a default-configuration Public profile.
        $inboundBlocked = $FwPublicProfile -and (
            $FwPublicProfile.DefaultInboundAction -eq "Block" -or
            $FwPublicProfile.DefaultInboundAction -eq "NotConfigured"
        )

        $ifNames = ($ActiveIPv6.Name) -join ", "
        if ($inboundBlocked) {
            Add-Result "Network" "IPv6 active (UP interfaces)" "$($ActiveIPv6.Count) interface(s): $ifNames" "OK" "IPv6 active but the Public profile blocks inbound connections by default — firewall rules also apply to inbound IPv6 connections"
        } else {
            Add-Result "Network" "IPv6 active (UP interfaces)" "$($ActiveIPv6.Count) interface(s): $ifNames" "WARN" "IPv6 active on $($ActiveIPv6.Count) interface(s) and the Public profile isn't set to block inbound by default — check that firewall inbound rules also cover IPv6 addresses (not just explicit IPv4 ranges)"
        }
    }
} catch {
    Add-Result "Network" "IPv6 active (network interfaces)" "Unable to read" "INFO" "Error: $($_.Exception.Message)"
}

# NOTE v4.7: TCP ports listening on non-loopback interfaces with PID/process.
# Complements established TCP connections — listening ports represent the
# network attack surface permanently exposed. Cross-referenced with a list
# of sensitive ports to immediately detect whether RDP, WinRM, SMB, Telnet
# or VNC are listening on a public interface.
# NOTE v4.8: refined classification of listening ports by local address.
# RPC 135 and SMB 445 listen on every interface on every Windows machine —
# that's normal and doesn't deserve a WARN. What deserves attention is a
# port listening on 0.0.0.0 or :: (all interfaces) — especially RDP,
# WinRM, or unknown application ports.
$SensitivePorts = @{
    3389="RDP"; 5985="WinRM-HTTP"; 5986="WinRM-HTTPS"
    23="Telnet"; 5900="VNC"; 21="FTP"; 22="SSH"
}
# Normal ports on Windows — INFO even on 0.0.0.0
$NormalWindowsPorts = @(135, 445, 139, 49664, 49665, 49666, 49667, 49668, 49669, 49670)

try {
    $ListenConns = Get-NetTCPConnection -State Listen -ErrorAction Stop |
        Where-Object {
            $_.LocalAddress -ne "127.0.0.1" -and
            $_.LocalAddress -ne "::1" -and
            $_.LocalAddress -notmatch "^fe80:"
        }

    if ($ListenConns.Count -eq 0) {
        Add-Result "Network" "Listening TCP ports (non-loopback)" "0" "OK" "No TCP port listening on non-loopback interfaces"
    } else {
        $ProcMapListen = @{}
        Get-Process -ErrorAction SilentlyContinue | ForEach-Object { $ProcMapListen[$_.Id] = $_.Name }

        $failPorts  = [System.Collections.Generic.List[string]]::new()
        $warnPorts  = [System.Collections.Generic.List[string]]::new()
        $infoPorts  = [System.Collections.Generic.List[string]]::new()

        foreach ($c in $ListenConns) {
            $procName  = if ($ProcMapListen.ContainsKey([int]$c.OwningProcess)) { $ProcMapListen[[int]$c.OwningProcess] } else { "PID $($c.OwningProcess)" }
            $portNum   = [int]$c.LocalPort
            $isAllIf   = ($c.LocalAddress -eq "0.0.0.0" -or $c.LocalAddress -eq "::")
            $isNormal  = $NormalWindowsPorts -contains $portNum
            $isSensitive = $SensitivePorts.ContainsKey($portNum)
            $portName  = if ($SensitivePorts.ContainsKey($portNum)) { $SensitivePorts[$portNum] } else { "$portNum" }
            $label     = "$procName → $portName ($($c.LocalAddress))"

            if ($isNormal) {
                $infoPorts.Add($label)
            } elseif ($isSensitive -and $isAllIf) {
                if ($portNum -eq 3389) { $failPorts.Add($label) }
                else { $warnPorts.Add($label) }
            } elseif ($isSensitive) {
                $warnPorts.Add($label)
            } elseif ($isAllIf -and $portNum -lt 1024) {
                $warnPorts.Add($label)
            } else {
                $infoPorts.Add($label)
            }
        }

        $overallStatus = if ($failPorts.Count -gt 0) { "FAIL" } elseif ($warnPorts.Count -gt 0) { "WARN" } else { "INFO" }
        $detail = ""
        if ($failPorts.Count -gt 0) { $detail += "❌ Critical ports exposed: $($failPorts -join ' | ') " }
        if ($warnPorts.Count -gt 0) { $detail += "⚠ Sensitive ports: $($warnPorts -join ' | ') " }
        if ($infoPorts.Count -gt 0) { $detail += "Normal/system ports: $($infoPorts -join ' | ')" }

        Add-Result "Network" "Listening TCP ports (non-loopback)" "$($ListenConns.Count) port(s)" $overallStatus $detail.Trim()
    }
} catch {
    Add-Result "Network" "Listening TCP ports (non-loopback)" "Unable to read" "INFO" "Error: $($_.Exception.Message)"
}

}

# ──────────────────────────────────────────────
#  9. CRITICAL / SUSPICIOUS SERVICES
# ──────────────────────────────────────────────
if (ShouldRunSection "9_Services") {
Write-Log "=== 9. SERVICES ===" -Level SECTION

$CriticalServices = @(
    @{ Name="WinDefend";   Friendly="Windows Defender Antivirus";     Expected="Running" },
    @{ Name="MpsSvc";      Friendly="Windows Firewall";               Expected="Running" },
    @{ Name="EventLog";    Friendly="Event Log";         Expected="Running" },
    @{ Name="wuauserv";    Friendly="Windows Update";                 Expected="Running" },
    @{ Name="CryptSvc";    Friendly="Cryptographic Services";        Expected="Running" },
    @{ Name="BFE";         Friendly="Base Filtering Engine";          Expected="Running" }
)

foreach ($svc in $CriticalServices) {
    $s = Get-Service -Name $svc.Name -ErrorAction SilentlyContinue
    if ($s) {
        # NOTE v1.3: the old version expected "Running" for all of these
        # services with no distinction, which made Windows Update (wuauserv)
        # FAIL as soon as it was stopped — whereas a service with Manual/Trigger
        # startup (normal for wuauserv on modern Windows) is supposed to stay
        # stopped until needed. Only a Disabled service, or an Automatic
        # service that isn't running, is a genuine anomaly.
        if ($s.StartType -eq "Disabled") {
            Add-Result "Services" $svc.Friendly "$($s.Status) (Startup: $($s.StartType))" "FAIL" "Service $($svc.Name) disabled!"
        } elseif ($s.StartType -eq "Manual" -and $s.Status -ne "Running") {
            Add-Result "Services" $svc.Friendly "$($s.Status) (Startup: $($s.StartType))" "INFO" "Manual/on-demand startup — normal for the service to be stopped when not in use"
        } else {
            $st = if ($s.Status -eq $svc.Expected) { "OK" } else { "FAIL" }
            Add-Result "Services" $svc.Friendly "$($s.Status) (Startup: $($s.StartType))" $st $(
                if ($s.Status -ne $svc.Expected) { "Service $($svc.Name) stopped or disabled!" }
            )
        }
    } else {
        Add-Result "Services" $svc.Friendly "Not found" "WARN"
    }
}

# Non-Microsoft services with automatic startup
# NOTE v1.1: Get-WmiObject was removed from PowerShell 7+; Get-CimInstance
# is the modern equivalent, compatible with both PS 5.1 and PS7.
# NOTE v4.7: non-Microsoft services with automatic startup — now shows the
# name, DisplayName and path of each third-party service for quick
# review. WARN if a path is outside the trusted zones (System32, Program
# Files) or if the service account is a user account (not
# SYSTEM/LocalService/NetworkService).
$SuspiciousServices = Get-CimInstance -ClassName Win32_Service -ErrorAction SilentlyContinue |
    Where-Object {
        $_.StartMode -eq "Auto" -and
        $_.State    -eq "Running" -and
        $_.PathName -notmatch "system32|SysWOW64|Microsoft|Windows"
    } | Select-Object Name, DisplayName, PathName, StartName

$svcSuspect = [System.Collections.Generic.List[string]]::new()
$svcNormal  = [System.Collections.Generic.List[string]]::new()

foreach ($svc in $SuspiciousServices) {
    # NOTE v4.8.1: the previous cleanup (-replace '"','' -replace ' .*$','')
    # truncated "C:\Program Files\..." down to "C:\Program" at the first
    # space, making the "program files" match always fail. New behavior:
    # 1. If PathName starts with a quote, extract the path between the two
    #    quotes (path with spaces possible).
    # 2. Otherwise, cut at the first space (path with no spaces + arguments).
    $rawPath = $svc.PathName
    if ($rawPath -match '^"([^"]+)"') {
        $pathClean = $Matches[1]
    } else {
        $pathClean = ($rawPath -split ' ')[0]
    }

    $isSuspectPath  = $pathClean -notmatch "(?i)program files|programdata|appdata\\local\\programs|program files \(x86\)"
    $isSuspectAcct  = $svc.StartName -and $svc.StartName -notmatch "(?i)LocalSystem|LocalService|NetworkService|NT AUTHORITY|NT SERVICE"
    $label = "$($svc.Name) ($($svc.DisplayName)) — $pathClean"
    if ($isSuspectPath -or $isSuspectAcct) {
        $svcSuspect.Add($label)
    } else {
        $svcNormal.Add($label)
    }
}

$svcStatus = if ($svcSuspect.Count -gt 0) { "WARN" } elseif ($SuspiciousServices.Count -gt 10) { "WARN" } else { "INFO" }
$svcDetail = if ($svcSuspect.Count -gt 0) {
    "Services with a suspect path/account: $($svcSuspect -join ' | ')$(if($svcNormal.Count -gt 0){" — Standard third-party services: $($svcNormal -join ' | ')"})"
} elseif ($SuspiciousServices.Count -gt 0) {
    "Third-party services with automatic startup (standard paths): $($svcNormal -join ' | ')"
} else {
    "No third-party service with automatic startup"
}
Add-Result "Services" "Non-system auto services" $SuspiciousServices.Count $svcStatus $svcDetail

}

# ──────────────────────────────────────────────
#  10. EVENT LOGS & AUDIT
# ──────────────────────────────────────────────
if (ShouldRunSection "10_Audit") {
Write-Log "=== 10. LOGS & AUDIT ===" -Level SECTION

# Audit policy
# NOTE v1.1: the old version queried auditpol by English category name
# ("Logon", "Account Logon"...) and filtered the output for the words
# "Success|Failure|No Auditing". On a French-language Windows, neither the
# category name nor the setting values ("Succès"/"Échec") matched, hence
# systematically empty results. Now queried by category GUID (identical
# regardless of the system language) and data lines are extracted by
# position rather than by an English keyword.
# The first 3 lines of auditpol /get /category output are always headers
# (title, column header line, category name); they're skipped.
$AuditCategoryMap = @(
    @{ Label = "Logon/Logoff";                   Guid = "{69979849-797A-11D9-BED3-505054503030}" },
    @{ Label = "Account Logon";        Guid = "{69979850-797A-11D9-BED3-505054503030}" },
    @{ Label = "Object Access";           Guid = "{6997984A-797A-11D9-BED3-505054503030}" },
    @{ Label = "Privilege Use"; Guid = "{6997984B-797A-11D9-BED3-505054503030}" },
    @{ Label = "Policy Change";  Guid = "{6997984D-797A-11D9-BED3-505054503030}" }
)

foreach ($cat in $AuditCategoryMap) {
    try {
        $raw = auditpol /get /category:"$($cat.Guid)" 2>&1
        if ($LASTEXITCODE -ne 0) { throw "auditpol returned an error (code $LASTEXITCODE): $($raw -join ' ')" }
        $dataLines = $raw | Select-Object -Skip 3 | Where-Object { $_.Trim() -ne "" }
        Add-Result "Audit" "Policy: $($cat.Label)" ($dataLines -join " / ") "INFO"
    } catch {
        Add-Result "Audit" "Policy: $($cat.Label)" "Unable to read" "WARN" "Error: $($_.Exception.Message). Check the GUIDs with 'auditpol /list /category /v' if this persists."
    }
}

# Recent security events (failed logons)
try {
    $FailedLogons = Get-WinEvent -FilterHashtable @{
        LogName   = "Security"
        Id        = 4625
        StartTime = (Get-Date).AddHours(-24)
    } -MaxEvents 100 -ErrorAction SilentlyContinue

    Add-Result "Audit" "Failed logons (24h)" $FailedLogons.Count $(
        if ($FailedLogons.Count -gt 50) { "FAIL" }
        elseif ($FailedLogons.Count -gt 10) { "WARN" }
        else { "OK" }
    ) $(if($FailedLogons.Count -gt 50){"Possible brute-force attack!"})
} catch {
    Add-Result "Audit" "Failed logons (24h)" "Access denied or empty log" "WARN"
}

# NOTE v4.2: additional security events over the last 24 hours.
# These three IDs are absent from the v3.x checks but cover real attack
# vectors on a standalone Windows machine.
#
# 4648 — Logon with explicit credentials (RunAs, net use /user, remote
# WMI, scripts calling LogonUser(), etc.). A few occurrences are normal
# (some services or updates generate them). A sudden spike or unusual
# accounts in the details signal privilege escalation or lateral movement.
#
# 4720 / 4726 — Local account creation / deletion. On a personal
# non-domain PC with no recent administration activity, these events
# should be at 0. An account created by RAT-style malware or an
# unauthorized maintenance access script will show up here.
$ExtraAuditEvents = @(
    @{ Id=4648; Label="Logons with explicit credentials (RunAs/net use)"; WarnThreshold=50 },
    @{ Id=4720; Label="Local account creations";                              WarnThreshold=1  },
    @{ Id=4726; Label="Local account deletions";                           WarnThreshold=1  }
)
foreach ($evDef in $ExtraAuditEvents) {
    try {
        $evts = Get-WinEvent -FilterHashtable @{
            LogName   = "Security"
            Id        = $evDef.Id
            StartTime = (Get-Date).AddHours(-24)
        } -MaxEvents 200 -ErrorAction SilentlyContinue
        $count = if ($null -eq $evts) { 0 } else { @($evts).Count }
        $status = if ($count -ge $evDef.WarnThreshold -and $evDef.WarnThreshold -eq 1 -and $count -gt 0) { "WARN" }
                  elseif ($count -gt $evDef.WarnThreshold) { "WARN" }
                  elseif ($count -gt 0) { "INFO" }
                  else { "OK" }
        $detail = if ($count -gt 0 -and $evDef.Id -eq 4648) {
            "Target accounts among the $count event(s): " + (($evts | Select-Object -First 5 | ForEach-Object {
                try { $_.Properties[5].Value } catch { "?" }
            }) -join ", ") + $(if($count -gt 5){" ..."})
        } elseif ($count -gt 0) {
            "Accounts involved among the $count event(s): " + (($evts | Select-Object -First 5 | ForEach-Object {
                try { $_.Properties[0].Value } catch { "?" }
            }) -join ", ") + $(if($count -gt 5){" ..."})
        } else { "" }
        Add-Result "Audit" "$($evDef.Label) (24h)" $count $status $detail
    } catch {
        Add-Result "Audit" "$($evDef.Label) (24h)" "Not available" "INFO" "Security log inaccessible or audit policy inactive for this event: $($_.Exception.Message)"
    }
}

# Log sizes
$Logs = @("Security","System","Application")
foreach ($log in $Logs) {
    try {
        $wLog = Get-WinEvent -ListLog $log -ErrorAction Stop
        $sizeMB = [math]::Round($wLog.FileSize / 1MB, 2)
        Add-Result "Audit" "$log log (size)" "${sizeMB} MB / Max: $([math]::Round($wLog.MaximumSizeInBytes/1MB,0)) MB" "INFO"
    } catch {}
}

}

# ──────────────────────────────────────────────
#  11. SUSPICIOUS SCHEDULED TASKS
# ──────────────────────────────────────────────
if (ShouldRunSection "11_Tasks") {
Write-Log "=== 11. SCHEDULED TASKS ===" -Level SECTION

# NOTE v1.1: the old version flagged every non-Microsoft task launching an
# interpreter — which systematically included your own scheduled scripts
# (Nettoyage-Windows11, Block-Telemetry, etc.). Now excludes tasks whose
# script is signed with your personal certificate
# ($TrustedSignerSubjectMatch, defined at the top of the script) or sits
# under one of the $TrustedScriptPathPatterns.
$SuspTasksRaw = Get-ScheduledTask -ErrorAction SilentlyContinue |
    Where-Object {
        $_.State -eq "Ready" -and
        $_.TaskPath -notmatch "\\Microsoft\\" -and
        ($_.Actions | Where-Object { $_.Execute -match "powershell|cmd|wscript|cscript|mshta|rundll32|regsvr32" })
    }

$SuspTasksReal    = [System.Collections.Generic.List[object]]::new()
$SuspTasksTrusted = [System.Collections.Generic.List[object]]::new()

foreach ($task in $SuspTasksRaw) {
    $isTrusted = $false

    # NOTE v3.3 — priority 1: match by task NAME ($TrustedTaskNames).
    # Checked first since it's independent of the argument format. Covers
    # cmd, .bat tasks, or ones whose script path can't be extracted.
    if ($TrustedTaskNames -contains $task.TaskName) {
        $isTrusted = $true
    }

    if (-not $isTrusted) {
        foreach ($action in $task.Actions) {
            if ($isTrusted) { break }
            $argLine = "$($action.Execute) $($action.Arguments)"

            # NOTE v3.3 — priority 2: extracting the .ps1 path.
            # Old regex: [A-Za-z]:\\[^\s"]+\.ps1 — stopped at the first
            # space, so it never captured a path like
            # "C:\Users\nephren\Desktop\Scripts Maintenance Win11\Script.ps1".
            # New logic: tries the quoted path first (which can contain
            # spaces), then the unquoted path (no spaces). First match wins.
            $scriptPath = $null
            $quotedMatch   = [regex]::Match($argLine, '"([A-Za-z]:\\[^"]+\.ps1)"')
            $unquotedMatch = [regex]::Match($argLine,  '([A-Za-z]:\\[^\s"]+\.ps1)')
            if    ($quotedMatch.Success)   { $scriptPath = $quotedMatch.Groups[1].Value }
            elseif ($unquotedMatch.Success) { $scriptPath = $unquotedMatch.Groups[1].Value }
            if (-not $scriptPath) { continue }

            foreach ($pattern in $TrustedScriptPathPatterns) {
                if ($scriptPath -like $pattern) { $isTrusted = $true }
            }

            if (-not $isTrusted -and (Test-Path $scriptPath -ErrorAction SilentlyContinue)) {
                try {
                    $sig = Get-AuthenticodeSignature -FilePath $scriptPath -ErrorAction Stop
                    if ($sig.Status -eq "Valid" -and $sig.SignerCertificate.Subject -match [regex]::Escape($TrustedSignerSubjectMatch)) {
                        $isTrusted = $true
                    }
                } catch {}
            }
        }
    }

    if ($isTrusted) { $SuspTasksTrusted.Add($task) } else { $SuspTasksReal.Add($task) }
}

Add-Result "Scheduled Tasks" "Non-Microsoft tasks with scripts/interpreters (unrecognized)" $SuspTasksReal.Count $(
    if ($SuspTasksReal.Count -gt 5) { "WARN" } elseif ($SuspTasksReal.Count -gt 0) { "WARN" } else { "OK" }
) $(if($SuspTasksReal.Count -gt 0){"Tasks to audit: " + ($SuspTasksReal.TaskName -join ", ")})

if ($SuspTasksTrusted.Count -gt 0) {
    Add-Result "Scheduled Tasks" "Recognized personal tasks (trusted path or signature)" $SuspTasksTrusted.Count "INFO" ($SuspTasksTrusted.TaskName -join ", ")
}

}

# ──────────────────────────────────────────────
#  12. SECURE BOOT & TPM
# ──────────────────────────────────────────────
if (ShouldRunSection "12_UEFI_Security") {
Write-Log "=== 12. SECURE BOOT & TPM ===" -Level SECTION

# Secure Boot
try {
    $SB = Confirm-SecureBootUEFI -ErrorAction Stop
    Add-Result "UEFI Security" "Secure Boot" $(if($SB){"Enabled"}else{"DISABLED"}) $(if($SB){"OK"}else{"FAIL"}) $(if(-not $SB){"Secure Boot disabled — unsecured startup"})
} catch {
    Add-Result "UEFI Security" "Secure Boot" "Not available (BIOS/Legacy?)" "WARN"
}

# TPM
try {
    $TPM = Get-Tpm -ErrorAction Stop
    Add-Result "UEFI Security" "TPM present"   $(if($TPM.TpmPresent){"Yes"}else{"No"})   $(if($TPM.TpmPresent){"OK"}else{"WARN"})
    Add-Result "UEFI Security" "TPM enabled"    $(if($TPM.TpmEnabled){"Yes"}else{"No"})   $(if($TPM.TpmEnabled){"OK"}else{"WARN"})
    Add-Result "UEFI Security" "TPM ready"      $(if($TPM.TpmReady){"Yes"}else{"No"})     $(if($TPM.TpmReady){"OK"}else{"WARN"})
} catch {
    Add-Result "UEFI Security" "TPM" "TPM read error: $_" "WARN"
}

}

# ──────────────────────────────────────────────
#  13. POWERSHELL & APPLOCKER
# ──────────────────────────────────────────────
if (ShouldRunSection "13_PowerShell") {
Write-Log "=== 13. POWERSHELL SECURITY ===" -Level SECTION

# NOTE v4.8: Script Block Logging and Transcription are enterprise
# monitoring tools — recording every PS script to event logs (ID 4104) and
# text files for forensic investigation. On a well-managed personal
# Windows Home machine (Defender active, ASR, HVCI, signed scripts), their
# absence isn't a weakness: they'd just generate useless noise with no one
# supervising the logs. Downgraded from WARN to INFO with a contextual message.
$PSLogKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
$SBL = (Get-ItemProperty $PSLogKey -Name EnableScriptBlockLogging -EA SilentlyContinue).EnableScriptBlockLogging
Add-Result "PowerShell" "Script Block Logging" $(if($SBL -eq 1){"Enabled"}else{"Disabled"}) $(
    if ($SBL -eq 1) { "OK" } else { "INFO" }
) $(if($SBL -eq 1){
    "Records every PS script to the PowerShell Operational log (ID 4104)"
} else {
    "Enterprise monitoring tool (logs every PS script that runs) — not mandatory on a well-managed personal machine; only useful if a centralized monitoring reads these logs"
})

$PSTransKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"
$PST = (Get-ItemProperty $PSTransKey -Name EnableTranscripting -EA SilentlyContinue).EnableTranscripting
Add-Result "PowerShell" "PowerShell transcription" $(if($PST -eq 1){"Enabled"}else{"Disabled"}) $(
    if ($PST -eq 1) { "OK" } else { "INFO" }
) $(if($PST -eq 1){
    "Records every PS session to text files"
} else {
    "Enterprise monitoring tool (records PS sessions to text files) — not mandatory on a personal machine; generates worthless log files with no one to analyze them"
})

# PS execution policy
# NOTE v1.1: the previous test checked $ep.Policy, which doesn't exist on
# the objects returned by Get-ExecutionPolicy -List (the property is
# called ExecutionPolicy) — the condition was therefore always false and
# never triggered a FAIL even with an active Unrestricted/Bypass policy.
$ExecPolicy = Get-ExecutionPolicy -List
foreach ($ep in $ExecPolicy) {
    $st = "INFO"
    if ($ep.ExecutionPolicy -match "Unrestricted|Bypass") { $st = "FAIL" }
    if ($ep.Scope -match "LocalMachine|CurrentUser") {
        Add-Result "PowerShell" "ExecutionPolicy ($($ep.Scope))" $ep.ExecutionPolicy $st $(
            if ($st -eq "FAIL") { "Execution policy is too permissive!" }
        )
    }
}

# NOTE v4.8: Smart App Control — three distinct states with CPU context.
# On an incompatible CPU (Kaby Lake i7-7700HQ, predates the SAC
# requirement), "not available" is normal -> neutral INFO.
# State 0 = permanently disabled (deliberate choice, often for
# compatibility with unsigned tools) -> contextual INFO, not WARN.
# State 1 = active -> OK.
# State 2 = evaluation mode -> INFO (Windows decides automatically).
$SacKey = "HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy"
$SacRaw = (Get-ItemProperty $SacKey -Name VerifiedAndReputablePolicyState -EA SilentlyContinue).VerifiedAndReputablePolicyState

# Detect whether the CPU is SAC-compatible (Tiger Lake+ / Zen 3+ recommended)
# SAC requires Windows 11 22H2+ on a clean install — can't be enabled
# after the fact on a machine upgraded from Win10.
$SacCpuNote = ""
try {
    $cpuName = (Get-CimInstance Win32_Processor -ErrorAction SilentlyContinue | Select-Object -First 1).Name
    # Heuristic: Intel 7xxx = Kaby Lake (7th gen, not SAC-compatible)
    if ($cpuName -match "i\d-7\d{3}|i\d-6\d{3}|i\d-5\d{3}") {
        $SacCpuNote = " (CPU $($cpuName.Trim()) predates SAC requirements — not available on this generation)"
    }
} catch {}

if ($null -eq $SacRaw) {
    Add-Result "PowerShell" "Smart App Control" "Not available$SacCpuNote" "INFO" "SAC requires Windows 11 22H2+ on a clean install and a recent CPU — can't be enabled on an upgraded machine or with a CPU older than Tiger Lake / Zen 3"
} else {
    $SacLabel = switch ([int]$SacRaw) {
        0 { "Permanently disabled$SacCpuNote" }
        1 { "Enabled (enforcement mode)" }
        2 { "In evaluation mode (Windows decides automatically)" }
        default { "Unknown state ($SacRaw)" }
    }
    $SacStatus = if ([int]$SacRaw -eq 1) { "OK" } else { "INFO" }
    $SacDetail = switch ([int]$SacRaw) {
        0 { "SAC permanently disabled — likely disabled deliberately for compatibility with unsigned tools (npm, portable tools, etc.). Can no longer be re-enabled without reinstalling Windows." }
        1 { "SAC active — blocks untrusted/unsigned applications at the OS level. May block unsigned dev/CLI tools (npm, cargo, etc.)." }
        2 { "SAC in evaluation — Windows is analyzing your usage and will decide automatically. Let it finish naturally (can take a few weeks)." }
        default { "" }
    }
    Add-Result "PowerShell" "Smart App Control" $SacLabel $SacStatus $SacDetail
}

# NOTE v4.4: SmartScreen — protection against applications and files
# downloaded from the Internet that Microsoft doesn't recognize.
# Independent of SAC.
# Key: HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\SmartScreenEnabled
# Values: "Off" (disabled), "Warn" (warning), "RequireAdmin" (blocking).
$SmartScreenKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer"
try {
    $SmartScreenVal = (Get-ItemProperty -Path $SmartScreenKey -Name "SmartScreenEnabled" -ErrorAction Stop).SmartScreenEnabled
    $ssLabel = switch ($SmartScreenVal) {
        "Off"          { "Disabled" }
        "Warn"         { "Enabled (warning)" }
        "RequireAdmin" { "Enabled (admin blocking)" }
        default        { "Unknown state ($SmartScreenVal)" }
    }
    $ssStatus = if ($SmartScreenVal -eq "Off") { "WARN" } else { "OK" }
    Add-Result "PowerShell" "Windows SmartScreen" $ssLabel $ssStatus $(
        if ($SmartScreenVal -eq "Off") { "SmartScreen disabled — files downloaded from the Internet are no longer filtered against applications Microsoft knows to be malicious" } else { "" }
    )
} catch {
    # Missing key = SmartScreen managed by Windows Defender / Windows Security
    Add-Result "PowerShell" "Windows SmartScreen" "Managed by Windows Defender (key absent)" "INFO" "SmartScreen is probably controlled via the Windows Security app rather than this registry key"
}

# NOTE v4.4: Exploit Protection (Process Mitigation Policies).
# Get-ProcessMitigation -System returns the global system mitigations.
# Checks the two most important ones: DEP (Data Execution Prevention —
# prevents code execution from non-executable memory regions) and ASLR
# ForceRelocateImages (randomizes the memory addresses of ALL modules at
# startup, even ones not compiled with /DYNAMICBASE).
try {
    $SysMit = Get-ProcessMitigation -System -ErrorAction Stop

    # NOTE v4.4.1: Get-ProcessMitigation returns "NOTSET" when the mitigation
    # isn't explicitly configured — not "OFF". NOTSET means Windows applies
    # its default behavior (DEP active in OptOut, base ASLR active) with no
    # explicit forcing. ON = forced active, OFF = forced disabled, NOTSET =
    # Windows default (generally safe on Win11).
    $DepVal  = "$($SysMit.DEP.Enable)"
    $AslrVal = "$($SysMit.ASLR.ForceRelocateImages)"

    $DepStatus  = switch ($DepVal)  { "ON" { "OK" } "OFF" { "WARN" } default { "INFO" } }
    $AslrStatus = switch ($AslrVal) { "ON" { "OK" } "OFF" { "WARN" } default { "INFO" } }

    $DepLabel  = switch ($DepVal)  { "ON" { "Forced active" } "OFF" { "Forced disabled" } default { "Windows default (NOTSET — active by default on Win11)" } }
    $AslrLabel = switch ($AslrVal) { "ON" { "Forced active" } "OFF" { "Forced disabled" } default { "Windows default (NOTSET — active by default on Win11)" } }

    Add-Result "PowerShell" "Exploit Protection — system DEP" $DepLabel $DepStatus $(
        if ($DepVal -eq "OFF") { "DEP explicitly disabled at the system level — risk of code execution from memory regions not intended for it" } else { "" }
    )
    Add-Result "PowerShell" "Exploit Protection — ASLR ForceRelocate" $AslrLabel $AslrStatus $(
        if ($AslrVal -eq "OFF") { "ASLR ForceRelocateImages explicitly disabled — modules not compiled with /DYNAMICBASE aren't randomized" } else { "" }
    )
} catch {
    Add-Result "PowerShell" "Exploit Protection" "Unable to read" "INFO" "Get-ProcessMitigation not available on this configuration: $($_.Exception.Message)"
}

}

# ──────────────────────────────────────────────
#  14. INSTALLED SOFTWARE (POTENTIALLY VULNERABLE)
# ──────────────────────────────────────────────
if (ShouldRunSection "14_Software") {
Write-Log "=== 14. INSTALLED SOFTWARE ===" -Level SECTION

$RiskyApps = @("Adobe Reader", "Adobe Acrobat", "Java", "Flash", "VLC", "7-Zip", "WinRAR", "OpenSSH", "PuTTY", "WinSCP", "TeamViewer", "AnyDesk", "UltraVNC")
$Installed = Get-ItemProperty "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
                              "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" -EA SilentlyContinue |
    Where-Object { $_.DisplayName } |
    Select-Object DisplayName, DisplayVersion, Publisher, InstallDate

Add-Result "Software" "Total installed software" $Installed.Count "INFO"

# NOTE v1.3: this list flags the PRESENCE of historically targeted software
# (often via outdated versions) — the script doesn't query any CVE
# database and doesn't know the latest released version, so it can't know
# whether the current install is vulnerable or not. Moved to INFO (instead
# of WARN) to avoid wrongly flagging up-to-date software as "sensitive";
# check periodically on the publisher's site.
foreach ($risky in $RiskyApps) {
    $found = $Installed | Where-Object { $_.DisplayName -match $risky }
    if ($found) {
        foreach ($app in $found) {
            Add-Result "Software" "Software to watch: $($app.DisplayName)" "v$($app.DisplayVersion)" "INFO" "Present on the system — historically a frequent target if the version is outdated; periodically check the publisher's site to confirm you have the latest version"
        }
    }
}

}

# ──────────────────────────────────────────────
#  15. STARTUP PROGRAMS (AUTORUNS)
# ──────────────────────────────────────────────
if (ShouldRunSection "15_Startup") {
Write-Log "=== 15. STARTUP PROGRAMS ===" -Level SECTION

function Resolve-ShortcutTarget {
    param([string]$LnkPath)
    try {
        $shell = New-Object -ComObject WScript.Shell
        return $shell.CreateShortcut($LnkPath).TargetPath
    } catch { return $null }
}

$RunKeys = @(
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
)
$StartupFolders = @(
    "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp",
    "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
)

$AutorunEntries = [System.Collections.Generic.List[object]]::new()

foreach ($key in $RunKeys) {
    try {
        $props = Get-ItemProperty -Path $key -ErrorAction Stop
        foreach ($p in $props.PSObject.Properties) {
            if ($p.Name -match '^PS(Path|ParentPath|ChildName|Drive|Provider)$') { continue }
            $AutorunEntries.Add([PSCustomObject]@{ Source = $key; Name = $p.Name; Command = "$($p.Value)" })
        }
    } catch {}
}
foreach ($folder in $StartupFolders) {
    if (Test-Path $folder) {
        Get-ChildItem -Path $folder -File -ErrorAction SilentlyContinue | ForEach-Object {
            $cmd = if ($_.Extension -eq ".lnk") { Resolve-ShortcutTarget -LnkPath $_.FullName } else { $_.FullName }
            $AutorunEntries.Add([PSCustomObject]@{ Source = "Startup folder"; Name = $_.Name; Command = "$cmd" })
        }
    }
}

Add-Result "Startup" "Automatic startup entries" $AutorunEntries.Count "INFO" "Run/RunOnce registry (HKLM+HKCU) + Startup folders (shortcuts resolved)"

# NOTE v2.0: deliberately cautious heuristics — a file that can't be found
# (orphaned reference) or a launch from a Temp folder are much more
# reliable signals than a mere absence of a signature (many legitimate
# programs, including open-source ones, aren't signed).
foreach ($entry in $AutorunEntries) {
    $exePath = $null
    if ($entry.Command -match '"([^"]+\.(exe|dll))"') { $exePath = $Matches[1] }
    elseif ($entry.Command -match '^([A-Za-z]:\\[^\s"]+\.(exe|dll|cmd|bat|ps1|vbs))') { $exePath = $Matches[1] }
    elseif ($entry.Command -match '\.(exe|dll|cmd|bat|ps1|vbs)$') { $exePath = $entry.Command.Trim() }

    if (-not $exePath) { continue }

    $flagReason = $null
    if (-not (Test-Path -LiteralPath $exePath -ErrorAction SilentlyContinue)) {
        $flagReason = "References a file that can't be found (orphaned) — possibly leftover from an uninstall, or worth checking"
    } elseif ($exePath -match "\\AppData\\Local\\Temp\\|\\Windows\\Temp\\") {
        $flagReason = "Launched from a temporary folder — unusual for a legitimate startup program"
    }

    if ($flagReason) {
        Add-Result "Startup" "$($entry.Source): $($entry.Name)" $entry.Command "WARN" $flagReason
    }
}

# NOTE v4.2: IFEO (Image File Execution Options) — a classic hijacking/
# persistence vector. HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\
# Image File Execution Options\ holds one subkey per executable name.
# If this subkey has a "Debugger" value, Windows silently substitutes that
# debugger for the original exe on every launch — a technique used by RATs
# to relaunch themselves (e.g. replacing notepad.exe with the malware), or
# to create backdoors on system exes (sethc.exe, osk.exe...).
# A healthy machine can have legitimate IFEO entries (debuggers, profilers)
# BUT they shouldn't point to unusual paths.
$IFEOKey = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
try {
    $IFEOEntries = Get-ChildItem -Path $IFEOKey -ErrorAction Stop
    $IFEOSuspect = [System.Collections.Generic.List[string]]::new()
    foreach ($entry in $IFEOEntries) {
        $debugger = (Get-ItemProperty -LiteralPath $entry.PSPath -Name "Debugger" -ErrorAction SilentlyContinue).Debugger
        if ($debugger -and $debugger.Trim() -ne "") {
            $IFEOSuspect.Add("$($entry.PSChildName) → $debugger")
        }
    }
    if ($IFEOSuspect.Count -eq 0) {
        Add-Result "Startup" "IFEO — Debugger hijacking" "No Debugger entry" "OK" "No executable substitution via Image File Execution Options detected"
    } else {
        Add-Result "Startup" "IFEO — Debugger hijacking" "$($IFEOSuspect.Count) Debugger entry/entries" "WARN" "IFEO entries with a Debugger value (verify the paths are legitimate): $($IFEOSuspect -join ' | ')"
    }
} catch {
    Add-Result "Startup" "IFEO — Debugger hijacking" "Unable to read" "INFO" "Error: $($_.Exception.Message)"
}

# NOTE v4.2: AppInit_DLLs — a list of DLLs injected into EVERY Win32
# process that loads User32.dll (i.e. almost every application with a
# graphical interface). This feature is disabled by default on systems
# with Secure Boot active, but the registry value can still be present.
# On a healthy machine, AppInit_DLLs should be empty or absent. A DLL in
# this field is silently injected into every GUI process with no user
# notification — a technique used by rootkits, some adware, and a few
# (rare) legitimate hook tools.
$AppInitKey = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows"
try {
    $AppInitDLLs  = (Get-ItemProperty -Path $AppInitKey -Name "AppInit_DLLs"  -ErrorAction SilentlyContinue).AppInit_DLLs
    $AppInitLoad  = (Get-ItemProperty -Path $AppInitKey -Name "LoadAppInit_DLLs" -ErrorAction SilentlyContinue).LoadAppInit_DLLs
    $AppInit32Key = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows"
    $AppInitDLLs32 = (Get-ItemProperty -Path $AppInit32Key -Name "AppInit_DLLs" -ErrorAction SilentlyContinue).AppInit_DLLs

    $appInitValues = @()
    if ($AppInitDLLs  -and $AppInitDLLs.Trim()   -ne "") { $appInitValues += "64-bit: $AppInitDLLs" }
    if ($AppInitDLLs32 -and $AppInitDLLs32.Trim() -ne "") { $appInitValues += "32-bit: $AppInitDLLs32" }

    if ($appInitValues.Count -eq 0) {
        Add-Result "Startup" "AppInit_DLLs (global DLL injection)" "Empty" "OK" "No global injection DLL configured"
    } else {
        $loadNote = if ([int]$AppInitLoad -eq 0) { " (LoadAppInit_DLLs=0 — loading disabled, but value present)" } else { " (LoadAppInit_DLLs=1 — ACTIVE)" }
        Add-Result "Startup" "AppInit_DLLs (global DLL injection)" "$($appInitValues.Count) DLL(s) configured$loadNote" "WARN" "DLLs detected: $($appInitValues -join ' | ') — identify and validate; treat any unknown DLL in AppInit_DLLs as suspicious"
    }
} catch {
    Add-Result "Startup" "AppInit_DLLs (global DLL injection)" "Unable to read" "INFO" "Error: $($_.Exception.Message)"
}

}

# ──────────────────────────────────────────────
#  16. WINDOWS DEFENDER EXCLUSIONS
# ──────────────────────────────────────────────
if (ShouldRunSection "16_Exclusions") {
Write-Log "=== 16. WINDOWS DEFENDER EXCLUSIONS ===" -Level SECTION

try {
    $Prefs = Get-MpPreference -ErrorAction Stop
    $PathExclusions = @($Prefs.ExclusionPath)
    $ExtExclusions  = @($Prefs.ExclusionExtension)
    $ProcExclusions = @($Prefs.ExclusionProcess)

    Add-Result "Defender" "Path exclusions" $(
        if ($PathExclusions.Count -gt 0) { "$($PathExclusions.Count): $($PathExclusions -join ', ')" } else { "0" }
    ) "INFO" $(if($PathExclusions.Count -gt 0){"Paths excluded from Defender scanning"})
    Add-Result "Defender" "Extension exclusions" $(
        if ($ExtExclusions.Count -gt 0) { "$($ExtExclusions.Count): $($ExtExclusions -join ', ')" } else { "0" }
    ) "INFO" $(if($ExtExclusions.Count -gt 0){"Extensions excluded from Defender scanning"})
    Add-Result "Defender" "Process exclusions" $(
        if ($ProcExclusions.Count -gt 0) { "$($ProcExclusions.Count): $($ProcExclusions -join ', ')" } else { "0" }
    ) "INFO" $(if($ProcExclusions.Count -gt 0){"Processes excluded from Defender scanning"})

    # NOTE v2.0: what really matters here is the BREADTH of an exclusion
    # (drive root, entire Windows/Users folder, generic wildcard) — that
    # effectively disables protection on all of its content. A targeted
    # exclusion like the hosts file is normal and expected, not a problem.
    $BroadPatterns = @('^[A-Za-z]:\\?$', '^[A-Za-z]:\\Windows\\?$', '^[A-Za-z]:\\Users\\?$', '^[A-Za-z]:\\Program Files', '\*$')
    foreach ($path in $PathExclusions) {
        $isBroad = $false
        foreach ($pattern in $BroadPatterns) { if ($path -match $pattern) { $isBroad = $true } }
        if ($isBroad) {
            Add-Result "Defender" "Broad exclusion detected" $path "WARN" "This exclusion covers a very broad folder — check that it's intentional and no broader than needed"
        }
    }
} catch {
    Add-Result "Defender" "Exclusions" "Unable to read" "WARN" "Error: $($_.Exception.Message)"
}

}

# ──────────────────────────────────────────────
#  17. WINDOWS HELLO / PIN
# ──────────────────────────────────────────────
if (ShouldRunSection "17_Hello") {
Write-Log "=== 17. WINDOWS HELLO ===" -Level SECTION

Add-Result "Windows Hello" "PIN/biometrics configured on the machine" $(
    if ($HelloConfigured) { "Yes" } elseif ($HelloIndeterminate) { "Undeterminable" } else { "Not detected" }
) "INFO" $(
    if ($HelloConfigured) {
        "At least one Windows Hello credential (PIN/biometrics) is registered on this machine — detection at the machine level, not per specific user"
    } elseif ($HelloIndeterminate) {
        "Some credential containers are protected by system ACLs and stay unreadable even as an administrator (only SYSTEM has access) — this script can't confirm or rule this out with certainty. Check in Settings > Accounts > Sign-in options"
    } else {
        "No Windows Hello credential detected in the locations accessible without SYSTEM privilege — if you sign in with a classic password only, this is consistent; otherwise check in Settings > Accounts > Sign-in options"
    }
)

}

# ──────────────────────────────────────────────
#  18. VIRTUALIZATION-BASED SECURITY (VBS)
# ──────────────────────────────────────────────
if (ShouldRunSection "18_VBS") {
Write-Log "=== 18. VBS / CREDENTIAL GUARD / MEMORY INTEGRITY ===" -Level SECTION

try {
    $DG = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction Stop

    $VBSStatus = switch ([int]$DG.VirtualizationBasedSecurityStatus) {
        0 { "Disabled" }
        1 { "Enabled but not started" }
        2 { "Enabled and running" }
        default { "Unknown" }
    }
    Add-Result "VBS" "Virtualization-based security" $VBSStatus $(
        if ([int]$DG.VirtualizationBasedSecurityStatus -eq 2) { "OK" } else { "WARN" }
    ) "Requires a compatible CPU (VT-x/AMD-V) + enabling at startup (Core Isolation)"

    $RunningServices = @($DG.SecurityServicesRunning)
    $CredGuardRunning = $RunningServices -contains 1
    $HVCIRunning      = $RunningServices -contains 2

    Add-Result "VBS" "Credential Guard" $(if($CredGuardRunning){"Active"}else{"Inactive"}) $(
        if ($CredGuardRunning) { "OK" } else { "INFO" }
    ) "Protects credentials in memory against theft (pass-the-hash) — mainly relevant in a domain environment, optional on a personal machine"

    Add-Result "VBS" "Memory Integrity (HVCI)" $(if($HVCIRunning){"Active"}else{"Inactive"}) $(
        if ($HVCIRunning) { "OK" } else { "WARN" }
    ) "Prevents unsigned/malicious drivers from loading in kernel mode — enable via Settings > Privacy & Security > Windows Security > Core Isolation"
} catch {
    Add-Result "VBS" "Reading VBS status" "Not available" "INFO" "WMI class absent or inaccessible on this configuration: $($_.Exception.Message)"
}

# NOTE v3.0: LSA Protection (RunAsPPL) — runs lsass.exe as a Protected
# Process Light, preventing a tool like Mimikatz from reading credentials
# in memory even with regular administrator rights. Complements Credential
# Guard above (RunAsPPL protects the process itself, Credential Guard
# isolates secrets in a separate VBS container); the two can be active
# independently of each other.
$LsaKey = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
$LsaPplRaw = (Get-ItemProperty $LsaKey -Name RunAsPPL -EA SilentlyContinue).RunAsPPL
if ($null -eq $LsaPplRaw) {
    Add-Result "VBS" "LSA Protection (RunAsPPL)" "Not configured" "WARN" "lsass.exe is running with no PPL protection — vulnerable to credential dumping by tools like Mimikatz, even with a local administrator account. Enable via 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -> RunAsPPL = 1 (DWORD), then restart"
} else {
    $LsaPplLabel = switch ([int]$LsaPplRaw) {
        1 { "Enabled" }
        2 { "Enabled (UEFI lock)" }
        default { "Non-standard value ($LsaPplRaw)" }
    }
    Add-Result "VBS" "LSA Protection (RunAsPPL)" $LsaPplLabel $(
        if ([int]$LsaPplRaw -ge 1) { "OK" } else { "WARN" }
    ) "Protects lsass.exe against in-memory credential reading by tools like Mimikatz"
}

# NOTE v4.4: Kernel-mode Hardware-enforced Stack Protection (KHEStackProtect).
# Protects kernel driver execution stacks against ROP (Return-Oriented
# Programming) attacks at the hardware level. Requires:
# - Intel Tiger Lake (11th gen+) or AMD Zen 3+ CPU with CET (Control-flow
#   Enforcement Technology)
# - HVCI active (Memory Integrity)
# - Windows 11 22H2+
# The HVCIOptions value in HKLM:\SYSTEM\CurrentControlSet\Control\CI\Config
# is a bitmask: bit 0 = HVCI, bit 3 = KHEStack (value 8 or 9 if both).
$CIConfigKey = "HKLM:\SYSTEM\CurrentControlSet\Control\CI\Config"
try {
    $HVCIOptions = (Get-ItemProperty -LiteralPath $CIConfigKey -Name "HVCIOptions" -ErrorAction Stop).HVCIOptions
    $KHEActive = ([int]$HVCIOptions -band 8) -eq 8
    $label = if ($KHEActive) { "Active (HVCIOptions=0x$("{0:X}" -f [int]$HVCIOptions))" } else { "Inactive (HVCIOptions=0x$("{0:X}" -f [int]$HVCIOptions))" }
    Add-Result "VBS" "Kernel Hardware-enforced Stack Protection" $label $(
        if ($KHEActive) { "OK" } else { "INFO" }
    ) "Hardware protection of the kernel stack against ROP attacks — requires an Intel 11th gen+/AMD Zen 3+ CPU and active HVCI"
} catch {
    Add-Result "VBS" "Kernel Hardware-enforced Stack Protection" "Not available" "INFO" "CI\Config key absent or inaccessible — probably unsupported on this CPU/configuration: $($_.Exception.Message)"
}

}

# ──────────────────────────────────────────────
#  19. TRUSTED ROOT CERTIFICATES
# ──────────────────────────────────────────────
if (ShouldRunSection "19_Certificates") {
Write-Log "=== 19. TRUSTED ROOT CERTIFICATES ===" -Level SECTION

# NOTE v3.1: trust in a certificate no longer rests SOLELY on its presence
# in AuthRoot — it's now cross-checked against $TrustedRootThumbprintAllowlist
# (thumbprint = a cryptographic identity that can't be forged, see
# CONFIGURATION). The name (Subject CN) is still shown in full so you can
# recognize it, but it NEVER serves as a criterion for legitimacy — only
# the thumbprint does. A full record (name, issuer, location, thumbprint,
# legitimacy status, estimated danger level) is produced for every
# certificate outside the Microsoft list, verified or not, hiding nothing.
try {
    $RootCerts = Get-ChildItem -Path "Cert:\LocalMachine\Root" -ErrorAction Stop
    $AuthRootCerts = Get-ChildItem -Path "Cert:\LocalMachine\AuthRoot" -ErrorAction SilentlyContinue
    $AuthRootThumbprints = @($AuthRootCerts | Select-Object -ExpandProperty Thumbprint)

    Add-Result "Certificates" "Installed root certificates" $RootCerts.Count "INFO" "Cert:\LocalMachine\Root store"

    $UnknownRootCerts = $RootCerts | Where-Object {
        $AuthRootThumbprints -notcontains $_.Thumbprint -and $_.Subject -notmatch "Microsoft"
    }

    if ($UnknownRootCerts.Count -eq 0) {
        Add-Result "Certificates" "Root certificates outside the Microsoft list" "0" "OK" "Every root certificate present is aligned with Microsoft's trust list (AuthRoot CTL) or issued by Microsoft"
    } else {
        $VerifiedCerts   = $UnknownRootCerts | Where-Object { $TrustedRootThumbprintAllowlist.ContainsKey($_.Thumbprint) }
        $UnverifiedCerts = $UnknownRootCerts | Where-Object { -not $TrustedRootThumbprintAllowlist.ContainsKey($_.Thumbprint) }

        Add-Result "Certificates" "Root certificates outside the Microsoft list" $UnknownRootCerts.Count $(
            if ($UnverifiedCerts.Count -eq 0) { "OK" } else { "WARN" }
        ) "$($VerifiedCerts.Count) manually verified (known thumbprint) | $($UnverifiedCerts.Count) unverified, to review. Detail below for each"

        foreach ($cert in $UnknownRootCerts) {
            $daysToExpiry = ($cert.NotAfter - (Get-Date)).Days
            $isVerified   = $TrustedRootThumbprintAllowlist.ContainsKey($cert.Thumbprint)

            # Readable name (CN) if present — purely informational, never
            # used to decide trust (a name can be forged).
            $cnMatch    = [regex]::Match($cert.Subject, '^CN=([^,]+)')
            $isGuidLike = $false
            if ($cnMatch.Success) {
                $displayName = $cnMatch.Groups[1].Value
                $isGuidLike  = $displayName -match '^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$'
                $nameNote    = if ($isGuidLike) { "Non-descriptive name (technical identifier/GUID, not a company name)" } else { "Readable name (standard CN)" }
            } else {
                $displayName = "(no CN — identified by OU/O only)"
                $nameNote    = "No CN — an unusual Subject structure for a commercial CA"
            }

            # NOTE v3.4: end-entity vs CA detection in the Root store.
            # A "Trusted Root" store should contain ONLY certificates with
            # BasicConstraints CA:TRUE (IssuanceTypes include CA). An
            # "end-entity" certificate (CA:FALSE) placed in Root is
            # unusually positioned but far less dangerous than a genuine
            # unrecognized CA: it CANNOT sign other certificates or
            # intercept TLS traffic (MITM impossible).
            # Detected via the BasicConstraints extension (OID 2.5.29.19).
            $isEndEntity = $false
            $bcExt = $cert.Extensions | Where-Object { $_.Oid.Value -eq "2.5.29.19" }
            if ($bcExt) {
                try {
                    $bcText = $bcExt.Format($false)
                    # "Subject Type=End Entity" or the localized French equivalent "Entité finale"
                    $isEndEntity = $bcText -match "End Entity|Entité finale|Subject Type=End"
                } catch {}
            }

            # EKU detection to enrich the description
            $ekuLabel = ""
            $ekuExt = $cert.Extensions | Where-Object { $_.Oid.Value -eq "2.5.29.37" }
            if ($ekuExt) {
                try { $ekuLabel = " | EKU: $($ekuExt.Format($false))" } catch {}
            }

            if ($isVerified) {
                $legitLabel = "Manually verified — $($TrustedRootThumbprintAllowlist[$cert.Thumbprint])"
                $riskLabel  = if ($isEndEntity) { "Very low (thumbprint confirmed + end-entity: can't sign other certificates or do MITM)" } else { "Low (thumbprint confirmed)" }
                $certStatus = "OK"
            } else {
                $legitLabel = "Unverified — absent from both the Microsoft CTL (AuthRoot) and the local allowlist"
                if ($isEndEntity) {
                    $riskLabel  = "Moderate (end-entity: MITM impossible, but non-standard placement in Root — identify the origin)"
                    $certStatus = "WARN"
                } elseif ($isGuidLike -or -not $cnMatch.Success) {
                    $riskLabel  = "Review as a priority (possible CA + non-descriptive name + unverified)"
                    $certStatus = "WARN"
                } else {
                    $riskLabel  = "Review (possible CA, unverified, readable name)"
                    $certStatus = "WARN"
                }
            }

            $typeNote   = if ($isEndEntity) { "End entity — CANNOT sign other certificates" } else { "Certificate Authority (CA) — can sign other certificates" }
            $certDetail = "Name (CN): $displayName ($nameNote) | Type: $typeNote | Issuer: $($cert.Issuer) | Location: Cert:\LocalMachine\Root | Expiration: $(Format-AuditDate $cert.NotAfter -DateOnly) ($daysToExpiry days) | Thumbprint (SHA-1): $($cert.Thumbprint)$ekuLabel | Legitimacy: $legitLabel | Estimated danger: $riskLabel"

            Add-Result "Certificates" "Root certificate: $displayName" "$($cert.Subject)" $certStatus $certDetail
        }
    }
} catch {
    Add-Result "Certificates" "Reading root certificates" "Unable to read" "INFO" "Error: $($_.Exception.Message)"
}

# NOTE v5.0: expired certificates in Cert:\LocalMachine\My.
# The machine personal store accumulates expired certificates over time
# (old signing certs, revoked enterprise certs, etc.) that Windows doesn't
# remove automatically. An expired cert in My doesn't create a direct
# security risk (it can't be used to sign/encrypt new data), but it's a
# sign of PKI hygiene worth improving and can cause errors in applications
# that reference it.
# Thresholds: expired for >365d = WARN, expired for <365d = INFO.
try {
    $PersonalCerts = Get-ChildItem -Path "Cert:\LocalMachine\My" -ErrorAction Stop
    $Now = Get-Date
    $ExpiredCerts = $PersonalCerts | Where-Object { $_.NotAfter -lt $Now }
    $ValidCerts   = $PersonalCerts | Where-Object { $_.NotAfter -ge $Now }

    Add-Result "Certificates" "Machine personal store (Cert:\LocalMachine\My)" "$($PersonalCerts.Count) certificate(s), $($ValidCerts.Count) valid" "INFO" "The machine's personal certificate store — used for code signing, mutual TLS authentication, etc."

    if ($ExpiredCerts.Count -eq 0) {
        Add-Result "Certificates" "Expired certificates (Cert:\LocalMachine\My)" "0" "OK" "No expired certificate in the machine personal store"
    } else {
        $OldExpired = $ExpiredCerts | Where-Object { ($Now - $_.NotAfter).TotalDays -gt 365 }
        $RecentExp  = $ExpiredCerts | Where-Object { ($Now - $_.NotAfter).TotalDays -le 365 }
        $expStatus  = if ($OldExpired.Count -gt 0) { "WARN" } else { "INFO" }
        $expDetails = $ExpiredCerts | Select-Object -First 10 | ForEach-Object {
            $daysSince = [int]($Now - $_.NotAfter).TotalDays
            $cn = if ($_.Subject -match 'CN=([^,]+)') { $Matches[1] } else { $_.Subject }
            "$cn (expired $daysSince d ago — $($_.Thumbprint.Substring(0,12))...)"
        }
        $moreNote = if ($ExpiredCerts.Count -gt 10) { " (+$($ExpiredCerts.Count - 10) more)" } else { "" }
        Add-Result "Certificates" "Expired certificates (Cert:\LocalMachine\My)" "$($ExpiredCerts.Count) expired certificate(s)$moreNote" $expStatus "$(if($OldExpired.Count -gt 0){"$($OldExpired.Count) expired for over a year — cleanup recommended. "})Details: $($expDetails -join ' | '). To clean up: Get-ChildItem Cert:\LocalMachine\My | Where-Object {`$_.NotAfter -lt (Get-Date)} | Remove-Item"
    }
} catch {
    Add-Result "Certificates" "Expired certificates (Cert:\LocalMachine\My)" "Unable to read" "INFO" "Error: $($_.Exception.Message)"
}

}

# ──────────────────────────────────────────────
#  20. TLS/SSL PROTOCOLS AND CIPHER SUITES (SCHANNEL)
# ──────────────────────────────────────────────
if (ShouldRunSection "20_TLS") {
Write-Log "=== 20. TLS/SSL & CIPHER SUITES ===" -Level SECTION

# NOTE v4.0: SCHANNEL governs SSL/TLS protocols at the Windows system level
# (IIS, WinHTTP, RDP, LDAPS, etc.). Keys under Protocols\ are organized
# into subfolders named by protocol, each with a Client and Server
# subfolder, and a DWORD "Enabled" value (1 = forced active, 0 = forced
# inactive).
# WARNING: a MISSING key doesn't mean "disabled" — Windows applies its own
# default values, which vary by build. So this explicitly distinguishes
# "forced disabled via registry key" / "forced enabled" / "not configured
# (Windows default)".

$SchannelBase = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols"

$TlsProtos = @(
    @{ Name="SSL 2.0";  WarnIfEnabled=$true;  WarnIfAbsent=$false; ShouldBeDisabled=$true  },
    @{ Name="SSL 3.0";  WarnIfEnabled=$true;  WarnIfAbsent=$false; ShouldBeDisabled=$true  },
    @{ Name="TLS 1.0";  WarnIfEnabled=$true;  WarnIfAbsent=$true;  ShouldBeDisabled=$true  },
    @{ Name="TLS 1.1";  WarnIfEnabled=$true;  WarnIfAbsent=$true;  ShouldBeDisabled=$true  },
    @{ Name="TLS 1.2";  WarnIfEnabled=$false; WarnIfAbsent=$false; ShouldBeDisabled=$false },
    @{ Name="TLS 1.3";  WarnIfEnabled=$false; WarnIfAbsent=$false; ShouldBeDisabled=$false }
)

foreach ($proto in $TlsProtos) {
    foreach ($role in @("Client","Server")) {
        $keyPath = "$SchannelBase\$($proto.Name)\$role"
        try {
            $keyExists = Test-Path -LiteralPath $keyPath -ErrorAction Stop
            if ($keyExists) {
                $enabledVal = (Get-ItemProperty -LiteralPath $keyPath -Name "Enabled" -ErrorAction SilentlyContinue).Enabled
                if ($null -eq $enabledVal) {
                    $label  = "Not configured (Windows default — key present, Enabled value absent)"
                    $status = "INFO"
                } elseif ([int]$enabledVal -eq 0) {
                    $label  = "Forced DISABLED (registry)"
                    $status = if ($proto.ShouldBeDisabled) { "OK" } else { "WARN" }
                    $detail = if (-not $proto.ShouldBeDisabled) { "$($proto.Name) is forced disabled on the $role side — this protocol should stay active (risk of connections being blocked)" } else { "" }
                } else {
                    $label  = "Forced ENABLED (registry, value $enabledVal)"
                    $status = if ($proto.ShouldBeDisabled) { "FAIL" } else { "OK" }
                    $detail = if ($proto.ShouldBeDisabled) { "$($proto.Name) is explicitly enabled on the $role side — deprecated/vulnerable protocol, should be disabled (POODLE, BEAST...)" } else { "" }
                }
            } else {
                $label = "Not configured (Windows default — key absent)"
                if ($proto.ShouldBeDisabled -and $proto.WarnIfAbsent) {
                    $status = "WARN"
                    $detail = "$($proto.Name) isn't explicitly disabled via the registry — Windows may enable it by default on some builds/configurations. Recommended: force Enabled=0 to guarantee it stays disabled."
                } elseif (-not $proto.ShouldBeDisabled -and $proto.WarnIfAbsent) {
                    $status = "WARN"
                    $detail = "$($proto.Name) isn't explicitly enabled via the registry — Windows should enable it by default on Win11, but with no forcing key this isn't guaranteed across every configuration."
                } else {
                    $status = "INFO"
                    $detail = ""
                }
            }
            Add-Result "TLS/SCHANNEL" "$($proto.Name) ($role)" $label $status $detail
        } catch {
            Add-Result "TLS/SCHANNEL" "$($proto.Name) ($role)" "Unable to read" "INFO" "Error: $($_.Exception.Message)"
        }
    }
}

$CipherPolicyKey = "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002"
$WeakCipherPatterns = @("RC4","3DES","DES","NULL","EXPORT","ANON")

try {
    if (Test-Path -LiteralPath $CipherPolicyKey -ErrorAction Stop) {
        $cipherList = (Get-ItemProperty -LiteralPath $CipherPolicyKey -Name "Functions" -ErrorAction SilentlyContinue).Functions
        if ($cipherList) {
            $suites      = $cipherList -split ","
            $weakFound   = [System.Collections.Generic.List[string]]::new()
            foreach ($suite in $suites) {
                $s = $suite.Trim()
                foreach ($pattern in $WeakCipherPatterns) {
                    if ($s -match $pattern) { $weakFound.Add($s); break }
                }
            }
            if ($weakFound.Count -gt 0) {
                Add-Result "TLS/SCHANNEL" "Weak cipher suites (GPO/registry)" "$($weakFound.Count) weak suite(s) detected" "FAIL" "At-risk suites in the forced list: $($weakFound -join ', ') — RC4/NULL/EXPORT must be removed immediately"
            } else {
                Add-Result "TLS/SCHANNEL" "Cipher suites (GPO/registry)" "$($suites.Count) suite(s) configured" "OK" "No weak suite detected in the GPO/registry-forced list"
            }
        } else {
            Add-Result "TLS/SCHANNEL" "Cipher suites (GPO/registry)" "Key present, Functions value absent" "INFO" "The policy key exists but doesn't contain a suite list — Windows manages the default suites"
        }
    } else {
        Add-Result "TLS/SCHANNEL" "Cipher suites (GPO/registry)" "Not configured (Windows default)" "INFO" "No cipher suite list forced via GPO or registry — Windows 11 manages default cipher suites (TLS_AES_256_GCM_SHA384, ECDHE_AES_256, etc. — generally secure)"
    }
} catch {
    Add-Result "TLS/SCHANNEL" "Cipher suites (GPO/registry)" "Unable to read" "INFO" "Error: $($_.Exception.Message)"
}

# NOTE v5.2.0: individual SCHANNEL cipher-suite state
# (HKLM:\...\SCHANNEL\Ciphers). This is a DIFFERENT mechanism from the
# "Cipher suites (GPO/registry)" check above: that one reads a GPO-forced
# *cipher suite order* list (all-or-nothing, rarely configured outside a
# domain). This one reads whether each individual legacy cipher has been
# explicitly disabled via its own Enabled=0 subkey — the mechanism
# Harden-TLS.ps1 actually uses, and the previous check had no visibility
# into it at all (a machine hardened by Harden-TLS still showed "Windows
# default" here). A missing subkey means Windows applies its own default,
# which still allows some of these legacy ciphers to be negotiated on
# older builds — reported as WARN with detail, not silently OK.
$SchannelCiphersBase = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers"
$WeakCipherSuites = @(
    "RC4 40/128", "RC4 56/128", "RC4 64/128", "RC4 128/128",
    "DES 56/56", "RC2 40/128", "RC2 56/128", "RC2 128/128",
    "Triple DES 168", "NULL"
)
$CiphersDisabled    = [System.Collections.Generic.List[string]]::new()
$CiphersNotDisabled = [System.Collections.Generic.List[string]]::new()
foreach ($cipher in $WeakCipherSuites) {
    $cipherKey = "$SchannelCiphersBase\$cipher"
    try {
        $isDisabled = $false
        if (Test-Path -LiteralPath $cipherKey -ErrorAction Stop) {
            $enabledVal = (Get-ItemProperty -LiteralPath $cipherKey -Name "Enabled" -ErrorAction SilentlyContinue).Enabled
            $isDisabled = ($null -ne $enabledVal -and [int]$enabledVal -eq 0)
        }
        if ($isDisabled) { $CiphersDisabled.Add($cipher) } else { $CiphersNotDisabled.Add($cipher) }
    } catch {
        $CiphersNotDisabled.Add($cipher)
    }
}
if ($CiphersNotDisabled.Count -eq 0) {
    Add-Result "TLS/SCHANNEL" "Legacy cipher suites (SCHANNEL\Ciphers)" "$($CiphersDisabled.Count)/$($WeakCipherSuites.Count) explicitly disabled" "OK" "Every legacy cipher (RC4, DES, RC2, Triple DES 168, NULL) is explicitly disabled via the registry"
} else {
    Add-Result "TLS/SCHANNEL" "Legacy cipher suites (SCHANNEL\Ciphers)" "$($CiphersDisabled.Count)/$($WeakCipherSuites.Count) explicitly disabled" "WARN" "Not explicitly disabled (Windows default applies, may still be negotiable on older builds): $($CiphersNotDisabled -join ', '). Disable via Harden-TLS.ps1, or manually under $SchannelCiphersBase"
}

# NOTE v5.2.0: weak hash algorithms (SCHANNEL\Hashes), same read-only
# pattern as the ciphers above. "SHA" is the legacy SCHANNEL registry name
# for SHA-1, not SHA-256/384/512 — those are never disabled and aren't
# checked here.
$SchannelHashesBase = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes"
$WeakHashAlgorithms = @("MD5", "SHA")
$HashesDisabled    = [System.Collections.Generic.List[string]]::new()
$HashesNotDisabled = [System.Collections.Generic.List[string]]::new()
foreach ($hashAlgo in $WeakHashAlgorithms) {
    $hashLabel = if ($hashAlgo -eq "SHA") { "SHA-1" } else { $hashAlgo }
    $hashKey = "$SchannelHashesBase\$hashAlgo"
    try {
        $isDisabled = $false
        if (Test-Path -LiteralPath $hashKey -ErrorAction Stop) {
            $enabledVal = (Get-ItemProperty -LiteralPath $hashKey -Name "Enabled" -ErrorAction SilentlyContinue).Enabled
            $isDisabled = ($null -ne $enabledVal -and [int]$enabledVal -eq 0)
        }
        if ($isDisabled) { $HashesDisabled.Add($hashLabel) } else { $HashesNotDisabled.Add($hashLabel) }
    } catch {
        $HashesNotDisabled.Add($hashLabel)
    }
}
if ($HashesNotDisabled.Count -eq 0) {
    Add-Result "TLS/SCHANNEL" "Weak hash algorithms (SCHANNEL\Hashes)" "$($HashesDisabled.Count)/$($WeakHashAlgorithms.Count) explicitly disabled" "OK" "MD5 and SHA-1 are both explicitly disabled via the registry"
} else {
    Add-Result "TLS/SCHANNEL" "Weak hash algorithms (SCHANNEL\Hashes)" "$($HashesDisabled.Count)/$($WeakHashAlgorithms.Count) explicitly disabled" "WARN" "Not explicitly disabled (Windows default applies): $($HashesNotDisabled -join ', '). Disable via Harden-TLS.ps1, or manually under $SchannelHashesBase"
}

# NOTE v5.2.0: Diffie-Hellman minimum key length (Logjam, CVE-2015-4000).
# Windows enforces no minimum by default absent this key — a value below
# 2048 bits (or the key missing entirely) allows a downgrade to a weak DH
# group. 2048 has been Microsoft's own recommendation since 2016.
$DhKeyPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\Diffie-Hellman"
$DhMinRecommended = 2048
foreach ($dhRole in @(
    @{ Value = "ClientMinKeyBitLength"; Label = "Diffie-Hellman minimum key length (Client)" },
    @{ Value = "ServerMinKeyBitLength"; Label = "Diffie-Hellman minimum key length (Server)" }
)) {
    try {
        $dhVal = (Get-ItemProperty -LiteralPath $DhKeyPath -Name $dhRole.Value -ErrorAction Stop).($dhRole.Value)
        if ([int]$dhVal -ge $DhMinRecommended) {
            Add-Result "TLS/SCHANNEL" $dhRole.Label "$dhVal bits" "OK" "Meets or exceeds the $DhMinRecommended-bit minimum recommended since 2016 (Logjam)"
        } else {
            Add-Result "TLS/SCHANNEL" $dhRole.Label "$dhVal bits" "WARN" "Below the $DhMinRecommended-bit recommended minimum — vulnerable to a Logjam-style downgrade. Raise via Harden-TLS.ps1, or set $($dhRole.Value)=$DhMinRecommended under $DhKeyPath"
        }
    } catch {
        Add-Result "TLS/SCHANNEL" $dhRole.Label "Not configured (Windows default)" "WARN" "No minimum key length is enforced — Windows accepts whatever the peer proposes, including weak DH groups. Set via Harden-TLS.ps1, or manually under $DhKeyPath"
    }
}

# NOTE v5.2.0: .NET Framework Strong Crypto (SchUseStrongCrypto,
# SystemDefaultTlsVersions). Without these, a .NET application (or WinRM)
# can keep negotiating through its own TLS stack instead of the SCHANNEL
# settings checked above, silently bypassing all of it. Checked on every
# .NET Framework path actually present on the machine (v4.0.30319 native +
# Wow6432Node on 64-bit, plus legacy v2.0.50727 only if genuinely
# installed) — never assumes a path that isn't there, mirroring
# Harden-TLS.ps1's own Get-DotNetPaths.
$DotNetPaths = @("HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319")
if (Test-Path -LiteralPath "HKLM:\SOFTWARE\Wow6432Node" -ErrorAction SilentlyContinue) {
    $DotNetPaths += "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319"
}
foreach ($legacyDotNet in @(
    "HKLM:\SOFTWARE\Microsoft\.NETFramework\v2.0.50727",
    "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v2.0.50727"
)) {
    if (Test-Path -LiteralPath $legacyDotNet -ErrorAction SilentlyContinue) { $DotNetPaths += $legacyDotNet }
}

foreach ($dotNetPath in $DotNetPaths) {
    $shortLabel = $dotNetPath -replace [regex]::Escape("HKLM:\SOFTWARE\"), ""
    try {
        $ssc  = (Get-ItemProperty -LiteralPath $dotNetPath -Name "SchUseStrongCrypto" -ErrorAction Stop).SchUseStrongCrypto
        $sdtv = (Get-ItemProperty -LiteralPath $dotNetPath -Name "SystemDefaultTlsVersions" -ErrorAction SilentlyContinue).SystemDefaultTlsVersions
        if ([int]$ssc -eq 1 -and $null -ne $sdtv -and [int]$sdtv -eq 1) {
            Add-Result "TLS/SCHANNEL" ".NET Strong Crypto ($shortLabel)" "SchUseStrongCrypto=1, SystemDefaultTlsVersions=1" "OK" "This .NET Framework install uses the system TLS stack and modern crypto defaults"
        } else {
            Add-Result "TLS/SCHANNEL" ".NET Strong Crypto ($shortLabel)" "SchUseStrongCrypto=$ssc, SystemDefaultTlsVersions=$sdtv" "WARN" "A .NET application on this install could still negotiate TLS through its own legacy stack rather than the SCHANNEL settings above. Enable via Harden-TLS.ps1, or set both DWORDs to 1 under $dotNetPath"
        }
    } catch {
        Add-Result "TLS/SCHANNEL" ".NET Strong Crypto ($shortLabel)" "Not configured (Windows default)" "WARN" "Neither value is set — this .NET Framework install may negotiate TLS through its own legacy stack. Enable via Harden-TLS.ps1, or set SchUseStrongCrypto=1 and SystemDefaultTlsVersions=1 under $dotNetPath"
    }
}

}

# ──────────────────────────────────────────────
#  21. VULNERABLE DRIVERS (HVCI BLOCKLIST + RECENT DRIVERS)
# ──────────────────────────────────────────────
if (ShouldRunSection "21_Drivers") {
Write-Log "=== 21. VULNERABLE DRIVERS ===" -Level SECTION

# NOTE v4.4: two complementary checks on the driver attack surface.
#
# 1. Microsoft Vulnerable Driver Blocklist (HVCI Blocklist)
$VDBLKey = "HKLM:\SYSTEM\CurrentControlSet\Control\CI\Config"
try {
    $VDBLVal = (Get-ItemProperty -LiteralPath $VDBLKey -Name "VulnerableDriverBlocklistEnable" -ErrorAction Stop).VulnerableDriverBlocklistEnable
    if ([int]$VDBLVal -eq 1) {
        Add-Result "Startup" "HVCI Vulnerable Driver Blocklist" "Enabled (forced via registry)" "OK" "Microsoft's blocklist of known vulnerable drivers is forced via the registry — BYOVD protection active independently of HVCI"
    } else {
        Add-Result "Startup" "HVCI Vulnerable Driver Blocklist" "Disabled (value=$VDBLVal)" "WARN" "The blocklist is explicitly disabled — known vulnerable drivers (BYOVD) aren't blocked at load time"
    }
} catch {
    Add-Result "Startup" "HVCI Vulnerable Driver Blocklist" "Not forced (HVCI default)" "INFO" "VulnerableDriverBlocklistEnable key absent — the blocklist is active if Memory Integrity (HVCI) is enabled, otherwise not applied"
}

# 2. Recently installed drivers (System event 7045, 24h)
try {
    $RecentDrivers = Get-WinEvent -FilterHashtable @{
        LogName   = "System"
        Id        = 7045
        StartTime = (Get-Date).AddHours(-24)
    } -MaxEvents 50 -ErrorAction SilentlyContinue

    $driverCount = if ($null -eq $RecentDrivers) { 0 } else { @($RecentDrivers).Count }

    if ($driverCount -eq 0) {
        Add-Result "Startup" "Recently installed drivers (24h)" "0" "OK" "No new kernel service/driver installed in the last 24h"
    } else {
        $suspDrivers = [System.Collections.Generic.List[string]]::new()
        $okDrivers   = [System.Collections.Generic.List[string]]::new()

        foreach ($ev in @($RecentDrivers)) {
            try {
                $svcName  = $ev.Properties[0].Value
                $svcPath  = "$($ev.Properties[1].Value)"
                $isKernel = $ev.Properties[2].Value -match "kernel"
                $isSuspect = $svcPath -notmatch "(?i)system32\\drivers|driverstore\\filerepository|windows\\inf|program files\\wsl|program files\\windowsapps" -and
                             $svcPath -ne "0"
                if ($isSuspect) {
                    $suspDrivers.Add("$svcName : $svcPath$(if($isKernel){' [kernel]'})")
                } else {
                    $okDrivers.Add($svcName)
                }
            } catch {}
        }

        $status = if ($suspDrivers.Count -gt 0) { "WARN" } else { "INFO" }
        $detail = if ($suspDrivers.Count -gt 0) {
            "Drivers outside the normal Windows delivery channel: $($suspDrivers -join ' | ')"
        } else {
            "All drivers are in standard Windows paths: $($okDrivers -join ', ')"
        }
        Add-Result "Startup" "Recently installed drivers (24h)" "$driverCount service(s)/driver(s)" $status $detail
    }
} catch {
    Add-Result "Startup" "Recently installed drivers (24h)" "Unable to read" "INFO" "Error: $($_.Exception.Message)"
}

}

# ──────────────────────────────────────────────
#  22. SHADOW COPY / VSS (RANSOMWARE RESILIENCE)
# ──────────────────────────────────────────────
if (ShouldRunSection "22_VSS") {
Write-Log "=== 22. SHADOW COPY / VSS ===" -Level SECTION

# NOTE v5.0: ransomware systematically deletes shadow copies (vssadmin
# delete shadows /all /quiet or wmic shadowcopy delete) before encrypting
# files, to prevent any recovery. The presence of recent shadow copies on
# C: is therefore a resilience indicator: ransomware that failed to delete
# them (active VSS protection, Defender tamper protection, etc.) will
# leave a usable restore point.
#
# Two complementary checks:
# 1. VSS service status — stopped in Manual mode is normal (VSS is
#    started on demand by Windows), but Disabled is an anomaly.
# 2. Existence of recent shadow copies via vssadmin list shadows.
#    Parses the text output (available on every Win11 edition including
#    Home, unlike the WMI VSS cmdlets which sometimes require the service
#    to be Running to be queried).

# 1. VSS service status
try {
    $VssSvc = Get-Service -Name VSS -ErrorAction Stop
    if ($VssSvc.StartType -eq "Disabled") {
        Add-Result "Backup" "VSS service (Volume Shadow Copy)" "DISABLED ($($VssSvc.StartType))" "FAIL" "The VSS service is disabled — no shadow copy can be created. Windows backups, restore points, and VSS-based ransomware resilience are all inactive. Re-enable: Set-Service VSS -StartupType Manual"
    } else {
        Add-Result "Backup" "VSS service (Volume Shadow Copy)" "$($VssSvc.Status) (startup: $($VssSvc.StartType))" "OK" "The VSS service has Manual startup (normal — started on demand for backup/snapshot operations)"
    }
} catch {
    Add-Result "Backup" "VSS service (Volume Shadow Copy)" "Unable to read" "WARN" "Error: $($_.Exception.Message)"
}

# 2. Existing shadow copies via vssadmin list shadows
try {
    # NOTE v5.0: vssadmin can produce UTF-16LE output on some
    # configurations — same pattern used by Check-Boot_Win11's SFC/DISM
    # section (stripping NULs via -replace "`0","").
    $vssOutput = & vssadmin list shadows /for=$env:SystemDrive 2>&1
    $vssText = ($vssOutput -join "`n") -replace "`0",""

    # NOTE v5.0.1: two distinct detection levels, in order:
    # 1. vssadmin explicitly reports no shadow copies -> direct FAIL.
    # 2. Count "Shadow Copy ID" blocks BEFORE attempting date parsing.
    #    If 0 blocks -> FAIL (no shadow copy despite non-empty output, e.g.
    #    header message only with no block). If N blocks > 0 -> attempt
    #    date parsing to refine (OK/WARN by age). If parsing fails despite
    #    blocks being present -> INFO with the exact count (shadow copies
    #    present but date format not parsable on this locale/build).
    #
    # NOTE v5.0.3: on Windows 11 Home, vssadmin list shadows /for=C:
    # systematically returns 0 results because generic VSS shadow copies
    # aren't created automatically. Only SYSTEM RESTORE POINTS exist,
    # which are technically VSS shadow copies but cataloged differently
    # (they don't show up with /for=C: but are indeed VSS-protected).
    # Get-ComputerRestorePoint is queried as a fallback — if it returns
    # recent restore points, that's a valid ransomware protection and
    # OK/WARN is shown based on age, with no unjustified FAIL.
    $isExplicitlyEmpty = $vssText -match "Aucun.+trouv|No items found|Il n.existe aucun|There are no|no shadow copies"

    # Count blocks independently of the date format (locale-robust)
    $shadowBlockCount = ([regex]::Matches($vssText, "ID de clich|Shadow Copy ID|Snapshot ID")).Count

    # System restore points (Win11 Home — fallback to vssadmin)
    $RestorePoints = $null
    try {
        $RestorePoints = Get-ComputerRestorePoint -ErrorAction Stop |
            Sort-Object -Property CreationTime -Descending
    } catch {}

    if ($shadowBlockCount -gt 0) {
        # Generic VSS shadow copies present — parsing the dates
        $shadowDates = [regex]::Matches($vssText, 'Date et heure de cr[ée]ation\s*:\s*(.+)|Creation Time\s*:\s*(.+)|Date de cr[ée]ation\s*:\s*(.+)') |
            ForEach-Object {
                $dateStr = ($_.Groups[1].Value + $_.Groups[2].Value + $_.Groups[3].Value).Trim()
                if ($dateStr -ne "") { try { [datetime]::Parse($dateStr) } catch { $null } }
            } | Where-Object { $_ -ne $null } | Sort-Object -Descending

        if ($shadowDates.Count -gt 0) {
            $mostRecent = $shadowDates[0]
            $ageInDays  = [int]((Get-Date) - $mostRecent).TotalDays
            if ($ageInDays -le 7) {
                Add-Result "Backup" "Shadow copies on $env:SystemDrive" "$shadowBlockCount snapshot(s) — last one $ageInDays day(s) ago" "OK" "VSS shadow copies present and recent — good ransomware resilience. Last snapshot: $(Format-AuditDate $mostRecent)"
            } elseif ($ageInDays -le 30) {
                Add-Result "Backup" "Shadow copies on $env:SystemDrive" "$shadowBlockCount snapshot(s) — last one $ageInDays day(s) ago" "WARN" "VSS shadow copies present but the most recent is $ageInDays days old. Last one: $(Format-AuditDate $mostRecent)"
            } else {
                Add-Result "Backup" "Shadow copies on $env:SystemDrive" "$shadowBlockCount snapshot(s) — last one $ageInDays day(s) ago" "WARN" "VSS shadow copies very old ($ageInDays days) — consider a new restore point: Checkpoint-Computer -Description 'Manual' -RestorePointType MODIFY_SETTINGS"
            }
        } else {
            Add-Result "Backup" "Shadow copies on $env:SystemDrive" "$shadowBlockCount snapshot(s) detected" "INFO" "$shadowBlockCount block(s) detected — shadow copies present but date not parsable. Check: vssadmin list shadows /for=$env:SystemDrive"
        }
    } elseif ($RestorePoints -and $RestorePoints.Count -gt 0) {
        # No generic VSS shadow copies but system restore points exist
        # -> valid ransomware protection on Win11 Home
        $lastRP  = $RestorePoints[0]
        $rpDate  = [Management.ManagementDateTimeConverter]::ToDateTime($lastRP.CreationTime)
        $rpAge   = [int]((Get-Date) - $rpDate).TotalDays
        $rpNames = ($RestorePoints | Select-Object -First 3 | ForEach-Object {
            $dt = [Management.ManagementDateTimeConverter]::ToDateTime($_.CreationTime)
            "$($_.Description) ($(Format-AuditDate $dt -DateOnly))"
        }) -join " | "

        if ($rpAge -le 30) {
            Add-Result "Backup" "Shadow copies on $env:SystemDrive" "0 generic VSS — $($RestorePoints.Count) restore point(s)" "OK" "No generic VSS shadow copy (normal on Win11 Home) but $($RestorePoints.Count) system restore point(s) present — valid ransomware protection. Last one: $rpAge day(s) ago. Points: $rpNames"
        } else {
            Add-Result "Backup" "Shadow copies on $env:SystemDrive" "0 generic VSS — $($RestorePoints.Count) restore point(s) (last: $rpAge d)" "WARN" "Restore points present but old ($rpAge days). Points: $rpNames. Create a new one: Checkpoint-Computer -Description 'Manual' -RestorePointType MODIFY_SETTINGS"
        }
    } else {
        # Genuinely no VSS protection — neither shadow copy nor restore point
        Add-Result "Backup" "Shadow copies on $env:SystemDrive" "0" "FAIL" "No shadow copy or restore point on $env:SystemDrive — in the event of ransomware, no VSS recovery is possible. Enable system protection on C: then: Checkpoint-Computer -Description 'Manual' -RestorePointType MODIFY_SETTINGS, or via Settings > System > About > System Protection"
    }
} catch {
    Add-Result "Backup" "Shadow copies" "Unable to read" "WARN" "Error calling vssadmin: $($_.Exception.Message)"
}

# NOTE v5.0.4: system image backup via wbadmin (Windows Backup /
# "Windows 7 Backup"). wbadmin get versions lists the full backup versions
# available across all connected volumes. Parses the text output to
# extract the dates and target volume.
# Thresholds: >30d WARN, >90d FAIL, 0 versions -> INFO (no wbadmin backup
# configured — not necessarily a problem if another solution is in place).
try {
    $wbOutput = & wbadmin get versions 2>&1
    $wbText   = ($wbOutput -join "`n") -replace "`0",""

    $isNoBackup = $wbText -match "Aucune sauvegarde|No backup|n.a pas pu|could not"

    # Extract backup dates
    # (not "Heure de la sauvegarde" as assumed in v5.0.4 — corrected after
    # analyzing the actual output on NEPH-DESKTOP). Date format: dd/MM/yyyy HH:mm,
    # parsed with [datetime]::ParseExact to avoid MM/dd vs dd/MM ambiguity.
    $wbDates = [regex]::Matches($wbText, "Dur[eé]e de sauvegarde\s*:\s*(\d{2}/\d{2}/\d{4}\s+\d{2}:\d{2})|Backup time\s*:\s*(.+)") |
        ForEach-Object {
            $dateStr = ($_.Groups[1].Value + $_.Groups[2].Value).Trim()
            if ($dateStr -ne "") {
                try {
                    [datetime]::ParseExact($dateStr, "dd/MM/yyyy HH:mm",
                        [System.Globalization.CultureInfo]::InvariantCulture)
                } catch {
                    try { [datetime]::Parse($dateStr) } catch { $null }
                }
            }
        } | Where-Object { $_ -ne $null } | Sort-Object -Descending

    # Extract the target volume (e.g. "Disque dur étiqueté Auto_Save_Windows(E:)")
    $wbTargets = [regex]::Matches($wbText, "Cible de sauvegarde\s*:\s*(.+)|Backup target\s*:\s*(.+)") |
        ForEach-Object { ($_.Groups[1].Value + $_.Groups[2].Value).Trim() } |
        Where-Object { $_ -ne "" } | Select-Object -Unique

    $wbTargetStr = if ($wbTargets.Count -gt 0) { $wbTargets -join ", " } else { "unidentified volume" }

    if ($isNoBackup -or $wbDates.Count -eq 0) {
        Add-Result "Backup" "System image backup (wbadmin)" "No version found" "INFO" "No wbadmin system image backup detected on connected volumes — if another backup solution is in place (Macrium, Veeam, etc.), this result is normal"
    } else {
        $lastBackup = $wbDates[0]
        $ageInDays  = [int]((Get-Date) - $lastBackup).TotalDays
        $countStr   = "$($wbDates.Count) version(s)"
        $lastStr    = Format-AuditDate $lastBackup

        if ($ageInDays -le 30) {
            Add-Result "Backup" "System image backup (wbadmin)" "$countStr — last one $ageInDays day(s) ago" "OK" "Recent system image backup on $wbTargetStr. Last one: $lastStr — full system restore possible"
        } elseif ($ageInDays -le 90) {
            Add-Result "Backup" "System image backup (wbadmin)" "$countStr — last one $ageInDays day(s) ago" "WARN" "Last image backup $ageInDays days ago ($lastStr) on $wbTargetStr — run a manual backup: Control Panel -> Backup and Restore (Windows 7)"
        } else {
            Add-Result "Backup" "System image backup (wbadmin)" "$countStr — last one $ageInDays day(s) ago" "FAIL" "Last image backup $ageInDays days ago ($lastStr) on $wbTargetStr — very old backup, run one immediately"
        }
    }
} catch {
    Add-Result "Backup" "System image backup (wbadmin)" "Unable to read" "INFO" "Error calling wbadmin: $($_.Exception.Message)"
}

# NOTE v5.0.6: Windows Backup scheduling (Win11 Home).
# wbadmin get schedule isn't available on Windows Home (the command is
# reserved for Windows Server). On Home, scheduling is managed by the
# scheduled task \Microsoft\Windows\WindowsBackup\AutomaticBackup.
# This task is queried via Get-ScheduledTask to determine whether
# automatic scheduling is active.
# Possible states:
#   Ready    = task active and waiting for its next run -> OK
#   Running  = backup in progress -> OK
#   Disabled = scheduling disabled -> WARN
#   Absent   = task deleted or never configured -> INFO
try {
    $WbTask = Get-ScheduledTask -TaskPath "\Microsoft\Windows\WindowsBackup\" `
                                -TaskName "AutomaticBackup" `
                                -ErrorAction Stop

    $taskState  = $WbTask.State.ToString()
    $taskInfo   = Get-ScheduledTaskInfo -TaskPath "\Microsoft\Windows\WindowsBackup\" `
                                         -TaskName "AutomaticBackup" `
                                         -ErrorAction SilentlyContinue

    # Extract the trigger (scheduled frequency)
    $triggerDesc = if ($WbTask.Triggers.Count -gt 0) {
        $t = $WbTask.Triggers[0]
        $freq = switch ($t.CimClass.CimClassName) {
            "MSFT_TaskDailyTrigger"   { "Daily" }
            "MSFT_TaskWeeklyTrigger"  { "Weekly" }
            "MSFT_TaskTimeTrigger"    { "One-time" }
            default                   { $t.CimClass.CimClassName -replace "MSFT_Task|Trigger","" }
        }
        $startTime = if ($t.StartBoundary) {
            try { ([datetime]$t.StartBoundary).ToString("HH:mm") } catch { "?" }
        } else { "?" }
        "$freq at $startTime"
    } else { "No trigger configured" }

    $nextRun = if ($taskInfo -and $taskInfo.NextRunTime -and
                   $taskInfo.NextRunTime -gt [datetime]"2000-01-01") {
        Format-AuditDate $taskInfo.NextRunTime
    } else { "Not scheduled" }

    $lastRun = if ($taskInfo -and $taskInfo.LastRunTime -and
                   $taskInfo.LastRunTime -gt [datetime]"2000-01-01") {
        Format-AuditDate $taskInfo.LastRunTime
    } else { "Never" }

    switch ($taskState) {
        "Ready" {
            Add-Result "Backup" "Automatic backup scheduling (wbadmin)" "$triggerDesc — next: $nextRun" "OK" "The AutomaticBackup task is active. Frequency: $triggerDesc. Next run: $nextRun. Last run: $lastRun"
        }
        "Running" {
            Add-Result "Backup" "Automatic backup scheduling (wbadmin)" "Backup in progress" "OK" "An automatic backup is currently running"
        }
        "Disabled" {
            Add-Result "Backup" "Automatic backup scheduling (wbadmin)" "Disabled" "WARN" "The AutomaticBackup task is disabled — backups no longer run automatically. Re-enable via: Control Panel -> Backup and Restore (Windows 7) -> Change settings"
        }
        default {
            Add-Result "Backup" "Automatic backup scheduling (wbadmin)" $taskState "INFO" "AutomaticBackup task state: $taskState"
        }
    }
} catch {
    # Task absent = backup never configured or deleted
    if ($_.Exception.Message -match "No MSFT_ScheduledTask|introuvable|not found|cannot find") {
        Add-Result "Backup" "Automatic backup scheduling (wbadmin)" "Task absent" "INFO" "The AutomaticBackup task doesn't exist — no automatic backup scheduled. If you only use manual backup, this result is normal. To configure: Control Panel -> Backup and Restore (Windows 7) -> Set up backup"
    } else {
        Add-Result "Backup" "Automatic backup scheduling (wbadmin)" "Unable to read" "INFO" "Error: $($_.Exception.Message)"
    }
}

}

# ──────────────────────────────────────────────
#  SUMMARY
# ──────────────────────────────────────────────
$TotalOK   = ($AuditResults | Where-Object { $_.Status -eq "OK"   }).Count
$TotalWARN = ($AuditResults | Where-Object { $_.Status -eq "WARN" }).Count
$TotalFAIL = ($AuditResults | Where-Object { $_.Status -eq "FAIL" }).Count
$TotalINFO = ($AuditResults | Where-Object { $_.Status -eq "INFO" }).Count
$Total     = $AuditResults.Count

# NOTE v4.1: scoring overhaul — moving from a "linear penalty" model to a
# "per-category weighted success rate" model.
#
# PROBLEM with the old model (v3.x/v4.0):
#   Score = 100 − sum(penalty per FAIL/WARN result)
#   With 3 BitLocker FAIL (weight 1.6) -> 3 x 10 x 1.6 = 48 penalty points
#   alone, before even counting the WARNs. Adding a new TLS section with 6
#   WARN -> 25 more points -> score = 1/100 despite a machine that's
#   overall well secured (HVCI active, LSA PPL, ASR, Secure Boot...). The
#   linear model is uncontrollable: every new check drags the score down
#   even on a healthy machine, because it ignores the total number of checks.
#
# NEW MODEL:
#   For each category C:
#     - Count OK/INFO checks (passed) and WARN/FAIL checks (failed)
#     - Weight FAIL at 0.0 and WARN at 0.5 (half-pass), OK/INFO at 1.0
#     - rate_C = sum(status value) / number of checks in C
#   Final score = Σ(weight_C × rate_C) / Σ(weight_C) × 100
#
#   Properties:
#   - Invariant to the number of checks per category (1 or 20 doesn't
#     drift the score).
#   - A BitLocker FAIL impacts the BitLocker category (-> 0%), not the others.
#   - A category at 0% (all FAIL) removes exactly weight_C / Σweight_C from the score.
#   - A machine with everything OK = 100. A machine with everything FAIL = 0.
#   - Categories with no defined weight get 1.0.

$CatStats = @{}
foreach ($result in $AuditResults) {
    $cat = $result.Category
    if (-not $CatStats.ContainsKey($cat)) {
        $CatStats[$cat] = @{ WeightedSum = 0.0; Count = 0 }
    }
    $val = switch ($result.Status) {
        "OK"   { 1.0 }
        "INFO" { 1.0 }
        "WARN" { 0.5 }
        "FAIL" { 0.0 }
        default { 1.0 }
    }
    $CatStats[$cat].WeightedSum += $val
    $CatStats[$cat].Count++
}

$ScoreNumerator   = 0.0
$ScoreDenominator = 0.0
foreach ($cat in $CatStats.Keys) {
    $weight   = if ($CategoryWeights.ContainsKey($cat)) { $CategoryWeights[$cat] } else { 1.0 }
    $catRate  = $CatStats[$cat].WeightedSum / $CatStats[$cat].Count
    $ScoreNumerator   += $weight * $catRate
    $ScoreDenominator += $weight
}
$Score = if ($ScoreDenominator -gt 0) {
    [int][math]::Round(100 * $ScoreNumerator / $ScoreDenominator)
} else { 100 }
$ScoreColor = if ($Score -ge 80) { "#a8ce81" } elseif ($Score -ge 50) { "#ffb347" } else { "#ef7066" }

Write-Log "=== SUMMARY ===" -Level SECTION
Write-Log "Total checks: $Total | OK: $TotalOK | WARN: $TotalWARN | FAIL: $TotalFAIL | INFO: $TotalINFO" -Level INFO
Write-Log "Estimated security score (weighted by category): $Score / 100" -Level $(if($Score -ge 80){"OK"}elseif($Score -ge 50){"WARN"}else{"FAIL"})

# ──────────────────────────────────────────────
#  EVOLUTION SINCE THE LAST AUDIT (DELTAS)
# ──────────────────────────────────────────────
$Deltas = [System.Collections.Generic.List[object]]::new()

if ($PreviousAudit -and $PreviousAudit.Results) {
    $PrevMap = @{}
    foreach ($p in @($PreviousAudit.Results)) { $PrevMap["$($p.Category)|$($p.Check)"] = $p }

    foreach ($cur in $AuditResults) {
        $key = "$($cur.Category)|$($cur.Check)"
        if ($PrevMap.ContainsKey($key)) {
            $prev = $PrevMap[$key]
            if ($prev.Status -ne $cur.Status) {
                $degrade = (@("FAIL","WARN") -contains $cur.Status) -and (@("OK","INFO") -contains $prev.Status)
                $ameliore = (@("OK","INFO") -contains $cur.Status) -and (@("FAIL","WARN") -contains $prev.Status)
                $Deltas.Add([PSCustomObject]@{
                    Category = $cur.Category; Check = $cur.Check
                    Before = $prev.Status; After = $cur.Status
                    Type = if ($degrade) { "New issue" } elseif ($ameliore) { "Resolved" } else { "Changed" }
                })
            }
            $PrevMap.Remove($key)
        } elseif (@("FAIL","WARN") -contains $cur.Status) {
            $Deltas.Add([PSCustomObject]@{ Category=$cur.Category; Check=$cur.Check; Before="(new check)"; After=$cur.Status; Type="New check" })
        }
    }
    foreach ($remaining in $PrevMap.Values) {
        if (@("FAIL","WARN") -contains $remaining.Status) {
            $Deltas.Add([PSCustomObject]@{ Category=$remaining.Category; Check=$remaining.Check; Before=$remaining.Status; After="(gone)"; Type="Check gone" })
        }
    }

    $PrevScore = $PreviousAudit.Score
    $ScoreDiff = $Score - $PrevScore
    Write-Log "Score evolution since the last audit ($($PreviousAudit.Date)): $PrevScore -> $Score ($(if($ScoreDiff -ge 0){'+'})$ScoreDiff)" -Level $(if($ScoreDiff -ge 0){"OK"}else{"WARN"})

    # NOTE v4.0: regression alert — if the score drops by more than
    # $ScoreRegressionThreshold points, a FAIL is emitted in the console so
    # a scheduled run (-Silent) surfaces it in the logs.
    if ($ScoreDiff -le -$ScoreRegressionThreshold) {
        Write-Log "REGRESSION ALERT: the score dropped by $([math]::Abs($ScoreDiff)) points ($PrevScore -> $Score) — configured threshold: $ScoreRegressionThreshold pts" -Level FAIL
    }
} else {
    Write-Log "No previous audit found — first run or missing baseline, no comparison possible" -Level INFO
}

# Save the current run as the reference for the next run
try {
    [PSCustomObject]@{
        Date    = Get-Date -Format "o"
        Score   = $Score
        Results = ($AuditResults | Select-Object Category, Check, Value, Status)
    } | ConvertTo-Json -Depth 5 | Out-File -FilePath $BaselineFile -Encoding UTF8 -Force
} catch {
    Write-Log "Unable to write the baseline for future comparison: $($_.Exception.Message)" -Level WARN
}

# Full JSON export of the current run (usable by other tools/scripts)
try {
    [PSCustomObject]@{
        Machine       = $env:COMPUTERNAME
        Date          = Get-Date -Format "o"
        ScriptVersion = $ScriptVersion
        Score         = $Score
        Summary       = [PSCustomObject]@{ Total=$Total; OK=$TotalOK; WARN=$TotalWARN; FAIL=$TotalFAIL; INFO=$TotalINFO }
        Results       = $AuditResults
        Deltas        = $Deltas
    } | ConvertTo-Json -Depth 6 | Out-File -FilePath $ReportJSON -Encoding UTF8 -Force
} catch {
    Write-Log "Unable to write the JSON export: $($_.Exception.Message)" -Level WARN
}

# NOTE v3.0: CSV export for quick use in Excel/LibreOffice, in addition to
# the existing TXT/JSON. Same columns as the HTML report table.
try {
    $AuditResults | Select-Object Category, Check, Value, Status, Detail |
        Export-Csv -Path $ReportCSV -NoTypeInformation -Encoding UTF8 -Delimiter ";"
} catch {
    Write-Log "Unable to write the CSV export: $($_.Exception.Message)" -Level WARN
}

# NOTE v3.0: multi-run history, distinct from the baseline (which only
# keeps the previous run). Adds the current run, truncates to the most
# recent $MaxHistoryRuns, and rewrites the whole file (no incremental
# append, to avoid invalid JSON if writing is interrupted mid-way).
try {
    $ScoreHistory.Add([PSCustomObject]@{ Date = Get-Date -Format "o"; Score = $Score })
    $HistoryToKeep = $ScoreHistory | Select-Object -Last $MaxHistoryRuns
    $HistoryToKeep | ConvertTo-Json -Depth 3 | Out-File -FilePath $HistoryFile -Encoding UTF8 -Force
    $ScoreHistory = [System.Collections.Generic.List[object]]::new()
    foreach ($h in @($HistoryToKeep)) { $ScoreHistory.Add($h) }
} catch {
    Write-Log "Unable to write the multi-run history: $($_.Exception.Message)" -Level WARN
}

# ──────────────────────────────────────────────
#  HTML REPORT GENERATION
# ──────────────────────────────────────────────
Write-Log "Generating the HTML report: $ReportHTML" -Level INFO

# NOTE v4.2: executive summary — "Critical points" block shown at the top
# of the HTML report, before the detailed table. Gives an immediate
# at-a-glance view without having to scroll. FAIL first (red), then WARN
# (orange). Limited to 10 items so as not to flood the page. If everything
# is OK/INFO: a green banner.
$CriticalItems = @(
    @($AuditResults | Where-Object { $_.Status -eq "FAIL" }) +
    @($AuditResults | Where-Object { $_.Status -eq "WARN" })
) | Select-Object -First 10

if ($CriticalItems.Count -eq 0) {
    $ExecSummaryHTML = @"
  <div class="exec-summary exec-ok">
    <span class="exec-icon">✅</span>
    <span><strong>No problem detected</strong> — Every check is green on this run.</span>
  </div>
"@
} else {
    $execItemsHTML = ""
    foreach ($item in $CriticalItems) {
        $itemClass = if ($item.Status -eq "FAIL") { "exec-fail" } else { "exec-warn" }
        $itemIcon  = if ($item.Status -eq "FAIL") { "✘" } else { "⚠" }
        $execItemsHTML += @"
    <div class="exec-item $itemClass">
      <span class="exec-badge">$itemIcon $($item.Status)</span>
      <span class="exec-cat">$(He $item.Category)</span>
      <span class="exec-ctrl">$(He $item.Check)</span>
      <span class="exec-val">$(He $item.Value)</span>
    </div>
"@
    }
    $moreNote = if (($AuditResults | Where-Object { $_.Status -in "FAIL","WARN" }).Count -gt 10) {
        "<div class='exec-more'>... and $( ($AuditResults | Where-Object { $_.Status -in 'FAIL','WARN' }).Count - 10 ) more — see the full table below.</div>"
    } else { "" }
    $ExecSummaryHTML = @"
  <div class="exec-summary">
    <div class="exec-title">⚑ Critical points ($TotalFAIL FAIL · $TotalWARN WARN)</div>
$execItemsHTML
$moreNote
  </div>
"@
}

# NOTE v5.0: per-category score table — exposes the weighted calculation
# breakdown so the user can immediately identify which category is
# dragging the score down. Sorted by ascending partial score (worst
# categories first).
$CatScoreRows = ""
$CatScoreData = $CatStats.GetEnumerator() | ForEach-Object {
    $cat     = $_.Key
    $weight  = if ($CategoryWeights.ContainsKey($cat)) { $CategoryWeights[$cat] } else { 1.0 }
    $rate    = $_.Value.WeightedSum / $_.Value.Count
    $partial = [int][math]::Round($rate * 100)
    $count   = $_.Value.Count
    [PSCustomObject]@{ Cat=$cat; Weight=$weight; Rate=$rate; Partial=$partial; Count=$count }
} | Sort-Object Partial

foreach ($row in $CatScoreData) {
    $barColor = if ($row.Partial -ge 80) { "#27ae60" } elseif ($row.Partial -ge 50) { "#f39c12" } else { "#e74c3c" }
    $weightStr = "$($row.Weight.ToString('0.0'))"
    $CatScoreRows += @"
      <tr>
        <td class="cat-cell" style="white-space:nowrap">$($row.Cat)</td>
        <td>
          <div style="display:flex;align-items:center;gap:8px">
            <div style="flex:1;background:var(--surface2);border-radius:4px;height:10px;overflow:hidden">
              <div style="width:$($row.Partial)%;height:100%;background:$barColor;border-radius:4px"></div>
            </div>
            <span style="color:$barColor;font-weight:700;width:36px;text-align:right">$($row.Partial)%</span>
          </div>
        </td>
        <td style="color:var(--muted);text-align:center">$weightStr</td>
        <td style="color:var(--muted);text-align:center">$($row.Count)</td>
      </tr>
"@
}

$CatScoreTableHTML = @"
  <div class="delta-wrap">
    <div class="delta-header" style="margin-bottom:14px">
      <span class="section-title" style="margin:0">Score by category</span>
      <span style="color:var(--muted);font-size:12px">Weighted overall score: <strong style="color:$ScoreColor">$Score / 100</strong></span>
    </div>
    <table style="margin:0">
      <thead>
        <tr>
          <th>Category</th>
          <th>Partial score</th>
          <th style="text-align:center">Weight</th>
          <th style="text-align:center">Checks</th>
        </tr>
      </thead>
      <tbody>
$CatScoreRows
      </tbody>
    </table>
  </div>
"@

# "Evolution since the last audit" block
$DeltaSectionHTML = ""
if ($PreviousAudit -and $PreviousAudit.Results) {
    # NOTE v2.3: ConvertFrom-Json on PowerShell 7+ automatically detects
    # ISO-8601 strings (the ones produced by "Get-Date -Format 'o'") and
    # converts them into real [DateTime] objects, not plain strings —
    # unlike the v2.0/2.1/2.2 assumption, which called .Substring()
    # assuming a string every time. This crashed with "Method invocation
    # failed ... does not contain a method named 'Substring'" as soon as
    # the JSON was reloaded. Now explicitly formatted, whether the value
    # is a [DateTime] or stayed a [string] (the case of an older baseline,
    # or an environment where the auto-conversion doesn't happen).
    $PrevDateDisplay = try {
        if ($PreviousAudit.Date -is [DateTime]) {
            Format-AuditDate $PreviousAudit.Date
        } else {
            Format-AuditDate ([DateTime]::Parse("$($PreviousAudit.Date)"))
        }
    } catch {
        "$($PreviousAudit.Date)"
    }

    $ScoreDiff = $Score - [int]$PreviousAudit.Score
    $diffClass = if ($ScoreDiff -gt 0) { "up" } elseif ($ScoreDiff -lt 0) { "down" } else { "flat" }
    $diffText  = if ($ScoreDiff -gt 0) { "+$ScoreDiff" } else { "$ScoreDiff" }

    # NOTE v4.0: red regression banner — shown only if the drop exceeds
    # $ScoreRegressionThreshold, above the Evolution block.
    $RegressionBannerHTML = ""
    if ($ScoreDiff -le -$ScoreRegressionThreshold) {
        $absDiff = [math]::Abs($ScoreDiff)
        $RegressionBannerHTML = @"
  <div class="regression-banner">
    <span class="regression-icon">⚠</span>
    <span><strong>Regression alert</strong> — The score dropped by <strong>$absDiff points</strong> since the last audit ($([int]$PreviousAudit.Score) → $Score). Check the new problems below.</span>
  </div>
"@
    }
    $deltaItemsHTML = ""
    if ($Deltas.Count -eq 0) {
        $deltaItemsHTML = "<div class='delta-empty'>No status change since the last audit.</div>"
    } else {
        foreach ($d in $Deltas) {
            $tagClass = switch ($d.Type) {
                "New issue"  { "worse" }
                "Resolved"   { "better" }
                "Check gone" { "neutral" }
                "New check"  { "neutral" }
                default      { "neutral" }
            }
            $deltaItemsHTML += @"
            <div class="delta-item $tagClass">
              <span class="tag">$($d.Type)</span>
              <span>$($d.Category) — $($d.Check)</span>
              <span class="arrow">$($d.Before) → $($d.After)</span>
            </div>
"@
        }
    }

    $DeltaSectionHTML = @"
  $RegressionBannerHTML
  <div class="delta-wrap">
    <div class="delta-header">
      <span class="section-title" style="margin:0">Evolution since the last audit ($PrevDateDisplay)</span>
      <span class="delta-score-diff $diffClass">$([int]$PreviousAudit.Score) → $Score ($diffText)</span>
    </div>
    <div class="delta-list">
      $deltaItemsHTML
    </div>
  </div>
"@
}

# NOTE v3.0: SVG mini-chart (sparkline) of the score evolution over recent
# runs, based on $ScoreHistory (a file distinct from the baseline, see the
# CONFIGURATION section). Coordinates formatted in InvariantCulture — a
# pattern already established across the suite (Check-Boot) to avoid a
# decimal comma on an FR-locale Windows, which would invalidate the SVG's
# "points" attribute.
$HistoryChartHTML = ""
if ($ScoreHistory.Count -ge 2) {
    $Inv = [System.Globalization.CultureInfo]::InvariantCulture
    $ChartW = 600; $ChartH = 80; $Pad = 8
    $HistScores = @($ScoreHistory | ForEach-Object { [int]$_.Score })
    $MinS = ($HistScores | Measure-Object -Minimum).Minimum
    $MaxS = ($HistScores | Measure-Object -Maximum).Maximum
    if ($MaxS -eq $MinS) { $MaxS = $MinS + 1 }
    $StepX = ($ChartW - 2 * $Pad) / [math]::Max(1, ($HistScores.Count - 1))

    $Points = [System.Collections.Generic.List[string]]::new()
    for ($i = 0; $i -lt $HistScores.Count; $i++) {
        $x = $Pad + ($i * $StepX)
        $yRatio = ($HistScores[$i] - $MinS) / [double]($MaxS - $MinS)
        $y = $ChartH - $Pad - ($yRatio * ($ChartH - 2 * $Pad))
        $Points.Add("$($x.ToString('0.##', $Inv)),$($y.ToString('0.##', $Inv))")
    }
    $PolylinePoints = $Points -join " "
    $LastX = $Points[-1].Split(',')[0]
    $LastY = $Points[-1].Split(',')[1]

    $HistoryChartHTML = @"
  <div class="delta-wrap">
    <div class="delta-header">
      <span class="section-title" style="margin:0">Score history (last $($ScoreHistory.Count) runs)</span>
      <span class="detail">Min $MinS — Max $MaxS</span>
    </div>
    <svg viewBox="0 0 $ChartW $ChartH" width="100%" height="$ChartH" preserveAspectRatio="none">
      <polyline points="$PolylinePoints" fill="none" stroke="var(--accent)" stroke-width="2" />
      <circle cx="$LastX" cy="$LastY" r="3.5" fill="$ScoreColor" />
    </svg>
  </div>
"@
}

# NOTE v4.3: DeltaMap — a Category|Check -> delta type lookup table, built
# from $Deltas (computed in the EVOLUTION section above). Used while
# generating the <tr> rows to show the inline Δ icon.
$DeltaMap = @{}
foreach ($d in $Deltas) {
    $DeltaMap["$($d.Category)|$($d.Check)"] = $d.Type
}

# Group by category
$Categories = $AuditResults | Select-Object -ExpandProperty Category -Unique

# NOTE v3.0: anchors + data-* attributes for the JS filter and direct links
# to critical checks (see the <script> block further down). Every FAIL row
# gets a unique id ("fail-N") referenced by the link list at the top of the report.
$TableRows = ""
$FailAnchorsHTML = ""
$FailCounter = 0
foreach ($cat in $Categories) {
    $items = $AuditResults | Where-Object { $_.Category -eq $cat }
    $first = $true
    foreach ($item in $items) {
        $rowClass = switch ($item.Status) {
            "FAIL" { "row-fail" }
            "WARN" { "row-warn" }
            "OK"   { "row-ok"   }
            default { "" }
        }
        $catCell = if ($first) {
            "<td class='cat-cell' rowspan='$($items.Count)'>$cat</td>"
            $first = $false
        } else { "" }

        $detail = if ($item.Detail) { "<br><small class='detail'>$($item.Detail)</small>" } else { "" }

        # NOTE v3.2: contextual help links only on WARN/FAIL checks — an
        # OK/INFO check doesn't need remediation documentation, it would
        # just clutter the table for nothing.
        # Exception: two INFO categories still deserve links:
        # - Software: the CVE search (NVD) is useful even when the status
        #   is INFO (no real-time version comparison is done).
        # - Certificates: the crt.sh link (search by thumbprint) is useful
        #   even on individual detailed certificates classified as INFO.
        $helpLinks = ""
        $needsLinks = $item.Status -in @("WARN","FAIL") -or
                      ($item.Status -eq "INFO" -and $item.Category -eq "Software" -and $item.Check -like "Software to watch:*") -or
                      ($item.Status -eq "INFO" -and $item.Category -eq "Certificates" -and $item.Check -like "Root certificate:*")
        if ($needsLinks) {
            $helpLinks = Get-HelpLinks -Category $item.Category -Check $item.Check -Value $item.Value -Detail $item.Detail
        }

        $rowId = ""
        if ($item.Status -eq "FAIL") {
            $FailCounter++
            $rowId = "fail-$FailCounter"
            $FailAnchorsHTML += "<a href=`"#$rowId`" class=`"fail-link`">$($item.Category) — $($item.Check)</a>"
        }

        $searchText = ("$($item.Category) $($item.Check) $($item.Value) $($item.Detail)").ToLower() -replace '"','&quot;'

        # NOTE v4.3: inline Δ icon — cross-referenced with $DeltaMap
        $deltaKey  = "$($item.Category)|$($item.Check)"
        $deltaIcon = ""
        if ($DeltaMap.ContainsKey($deltaKey)) {
            $deltaIcon = switch ($DeltaMap[$deltaKey]) {
                "New issue"  { " <span class='delta-inline worse' title='Worsened since the last audit'>▲</span>" }
                "Resolved"   { " <span class='delta-inline better' title='Improved since the last audit'>▼</span>" }
                "New check"  { " <span class='delta-inline neutral' title='New check'>●</span>" }
                "Check gone" { "" }
                default      { "" }
            }
        }

        $TableRows += @"
        <tr class="$rowClass" id="$rowId" data-status="$($item.Status)" data-search="$searchText">
            $catCell
            <td>$($item.Check)</td>
            <td>$($item.Value)$detail$helpLinks</td>
            <td>$(Get-StatusBadge $item.Status)$deltaIcon</td>
        </tr>
"@
    }
}

# NOTE v3.0: block of direct links to FAIL checks, shown at the top of the
# report only if there's at least one — otherwise nothing is shown instead
# of an empty box.
$FailAnchorsBlockHTML = ""
if ($FailCounter -gt 0) {
    $FailAnchorsBlockHTML = @"
  <div class="delta-wrap">
    <p class="section-title">Direct access to critical checks ($FailCounter)</p>
    <div class="fail-links">
      $FailAnchorsHTML
    </div>
  </div>
"@
}


$HTML = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Check-Security v$ScriptVersion — $env:COMPUTERNAME</title>
<style>
  :root {
    --bg: #080b12; --surface: #111827; --surface2: #1a2235;
    --border: #1e2d45; --text: #e2e8f0; --muted: #94a3b8;
    --ok: #a8ce81; --warn: #ffb347; --fail: #ef7066; --info: #7c6af7;
    --accent: #00d4ff; --accent2: #0099cc; --accent3: #005f80;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: var(--bg); color: var(--text); font-family: 'Segoe UI', system-ui, sans-serif; font-size: 14px; line-height: 1.5; }

  header { background: linear-gradient(160deg,#060c1a 0%,#0a1628 50%,#060a14 100%); border-bottom: 2px solid var(--accent3); padding: 32px 40px 24px; position: relative; overflow: hidden; }
  header::before { content:''; position:absolute; top:0; left:0; right:0; bottom:0; background: radial-gradient(ellipse at 20% 50%,rgba(0,212,255,.06) 0%,transparent 60%), radial-gradient(ellipse at 80% 20%,rgba(124,106,247,.05) 0%,transparent 50%); pointer-events:none; }
  .titlerow { display:flex; align-items:flex-end; gap:0; position:relative; z-index:1; }
  .title-text h1 { font-family:'Cascadia Code','Consolas','Courier New',monospace; font-size:26px; font-weight:700; color:var(--accent); text-shadow:0 0 20px rgba(0,212,255,.4); letter-spacing:1px; margin:0 0 10px 0; }
  .logo-sub { font-family:'Cascadia Code','Consolas',monospace; font-size:12px; color:var(--muted); letter-spacing:2px; margin-bottom:14px; }
  .logo-sub b { color:var(--accent); }
  .meta-bar { display:flex; flex-wrap:wrap; gap:8px 24px; font-size:11.5px; color:#475569; border-top:1px solid var(--border); padding-top:12px; margin-top:4px; position:relative; z-index:1; }
  .meta-bar span { display:flex; align-items:center; gap:6px; }
  .meta-bar b { color:var(--muted); }
  .meta-dot { width:5px; height:5px; border-radius:50%; background:var(--accent); display:inline-block; box-shadow:0 0 6px var(--accent); }

  .container { max-width: 1400px; margin: 0 auto; padding: 32px 40px; }

  .summary-grid { display: grid; grid-template-columns: repeat(5, 1fr); gap: 16px; margin-bottom: 32px; }
  .stat-card { background: var(--surface); border: 1px solid var(--border); border-radius: 12px; padding: 20px; text-align: center; }
  .stat-card .num { font-size: 36px; font-weight: 800; line-height: 1; margin-bottom: 6px; }
  .stat-card .lbl { color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: 0.5px; }
  .stat-card.ok   .num { color: var(--ok);   }
  .stat-card.warn .num { color: var(--warn);  }
  .stat-card.fail .num { color: var(--fail);  }
  .stat-card.info .num { color: var(--info);  }
  .stat-card.score .num { color: $ScoreColor; }

  .section-title { font-size: 12px; font-weight: 600; text-transform: uppercase; letter-spacing: 1px; color: var(--muted); margin-bottom: 12px; }

  table { width: 100%; border-collapse: collapse; background: var(--surface); border: 1px solid var(--border); border-radius: 12px; overflow: hidden; margin-bottom: 32px; }
  thead th { background: var(--surface2); padding: 12px 16px; text-align: left; font-size: 11px; text-transform: uppercase; letter-spacing: 0.8px; color: var(--muted); border-bottom: 1px solid var(--border); }
  tbody td { padding: 10px 16px; border-bottom: 1px solid var(--border); vertical-align: top; }
  tbody tr:last-child td { border-bottom: none; }
  .cat-cell { color: var(--accent); font-weight: 600; font-size: 12px; text-transform: uppercase; letter-spacing: 0.5px; background: var(--surface2); border-right: 1px solid var(--border); vertical-align: top; white-space: nowrap; }
  .row-fail { background: rgba(239,112,102,0.05); }
  .row-warn { background: rgba(255,179,71,0.05); }
  .row-ok   { background: rgba(168,206,129,0.03);  }
  .detail   { color: var(--muted); }

  .badge { display: inline-block; padding: 3px 10px; border-radius: 20px; font-size: 11px; font-weight: 600; white-space: nowrap; }
  .badge.ok   { background: rgba(168,206,129,0.15);  color: var(--ok);   border: 1px solid rgba(168,206,129,0.3);  }
  .badge.warn { background: rgba(255,179,71,0.15); color: var(--warn); border: 1px solid rgba(255,179,71,0.3); }
  .badge.fail { background: rgba(239,112,102,0.15);  color: var(--fail); border: 1px solid rgba(239,112,102,0.3);  }
  .badge.info { background: rgba(124,106,247,0.15); color: var(--info); border: 1px solid rgba(124,106,247,0.3); }

  .score-bar-wrap { background: var(--surface); border: 1px solid var(--border); border-radius: 12px; padding: 24px; margin-bottom: 32px; }
  .score-bar-track { background: var(--surface2); border-radius: 8px; height: 18px; overflow: hidden; margin-top: 10px; }
  .score-bar-fill { height: 100%; border-radius: 8px; background: linear-gradient(90deg, $ScoreColor, ${ScoreColor}99); width: ${Score}%; transition: width 1s; }
  .score-label { display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px; }
  .score-label span:first-child { font-weight: 700; font-size: 16px; }
  .score-value { font-size: 28px; font-weight: 800; color: $ScoreColor; }

  footer { text-align: center; padding: 24px; color: var(--muted); font-size: 12px; border-top: 1px solid var(--border); margin-top: 16px; }

  .delta-wrap { background: var(--surface); border: 1px solid var(--border); border-radius: 12px; padding: 24px; margin-bottom: 32px; }
  .delta-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px; }
  .delta-score-diff { font-size: 20px; font-weight: 800; }
  .delta-score-diff.up   { color: var(--ok);   }
  .delta-score-diff.down { color: var(--fail); }
  .delta-score-diff.flat { color: var(--muted); }
  .delta-list { display: flex; flex-direction: column; gap: 8px; }
  .delta-item { display: flex; align-items: center; gap: 10px; padding: 10px 14px; border-radius: 8px; background: var(--surface2); font-size: 13px; }
  .delta-item .tag { font-size: 10px; text-transform: uppercase; letter-spacing: 0.5px; font-weight: 700; padding: 2px 8px; border-radius: 6px; white-space: nowrap; }
  .delta-item.worse .tag { background: rgba(239,112,102,0.18); color: var(--fail); }
  .delta-item.better .tag { background: rgba(168,206,129,0.18); color: var(--ok); }
  .delta-item.neutral .tag { background: rgba(124,106,247,0.18); color: var(--info); }
  .delta-item .arrow { color: var(--muted); }
  .delta-empty { color: var(--muted); font-size: 13px; }

  .fail-links { display: flex; flex-wrap: wrap; gap: 8px; }
  .fail-link { font-size: 12px; padding: 6px 12px; border-radius: 20px; background: rgba(239,112,102,0.12); color: var(--fail); border: 1px solid rgba(239,112,102,0.3); text-decoration: none; white-space: nowrap; }

  .help-links { margin-top: 6px; display: flex; flex-wrap: wrap; gap: 6px; }
  .help-link { font-size: 11px; padding: 3px 10px; border-radius: 12px; background: var(--surface2); color: var(--accent); border: 1px solid var(--border); text-decoration: none; white-space: nowrap; }
  .help-link:hover { background: var(--accent); color: white; border-color: var(--accent); }
  .help-link::before { content: "🔗 "; }
  .fail-link:hover { background: rgba(239,112,102,0.22); }

  .search-box { width: 100%; max-width: 420px; margin-bottom: 16px; padding: 10px 14px; border-radius: 8px; border: 1px solid var(--border); background: var(--surface); color: var(--text); font-size: 13px; }
  .search-box:focus { outline: none; border-color: var(--accent); }
  .filter-bar { display: flex; align-items: center; gap: 12px; margin-bottom: 12px; flex-wrap: wrap; }
  .filter-chip { font-size: 11px; padding: 5px 12px; border-radius: 20px; border: 1px solid var(--border); background: var(--surface2); color: var(--muted); cursor: pointer; user-select: none; }
  .filter-chip.active { background: var(--accent); color: white; border-color: var(--accent); }
  .no-results { color: var(--muted); font-size: 13px; padding: 16px; text-align: center; display: none; }

  .regression-banner { display: flex; align-items: center; gap: 14px; background: rgba(239,112,102,0.12); border: 1px solid rgba(239,112,102,0.4); border-radius: 12px; padding: 16px 20px; margin-bottom: 16px; color: var(--fail); }
  .regression-icon { font-size: 22px; flex-shrink: 0; }

  .exec-summary { background: var(--surface); border: 1px solid var(--border); border-radius: 12px; padding: 18px 20px; margin-bottom: 20px; }
  .exec-summary.exec-ok { border-color: rgba(168,206,129,0.4); background: rgba(168,206,129,0.07); display: flex; align-items: center; gap: 12px; color: var(--ok); }
  .exec-icon { font-size: 20px; }
  .exec-title { font-weight: 600; font-size: 13px; color: var(--muted); text-transform: uppercase; letter-spacing: .05em; margin-bottom: 10px; }
  .exec-item { display: grid; grid-template-columns: 80px 130px 1fr auto; gap: 10px; align-items: center; padding: 8px 10px; border-radius: 8px; margin-bottom: 5px; font-size: 13px; }
  .exec-item.exec-fail { background: rgba(239,112,102,0.08); }
  .exec-item.exec-warn { background: rgba(255,179,71,0.08); }
  .exec-badge { font-weight: 700; font-size: 11px; }
  .exec-item.exec-fail .exec-badge { color: var(--fail); }
  .exec-item.exec-warn .exec-badge { color: var(--warn); }
  .exec-cat { color: var(--muted); font-size: 11px; }
  .exec-ctrl { color: var(--text); }
  .exec-val { color: var(--muted); font-size: 11px; text-align: right; }
  .exec-more { font-size: 12px; color: var(--muted); text-align: center; margin-top: 8px; }

  .delta-inline { font-size: 11px; margin-left: 6px; font-weight: 700; vertical-align: middle; }
  .delta-inline.worse   { color: var(--fail); }
  .delta-inline.better  { color: var(--ok); }
  .delta-inline.neutral { color: var(--muted); }
</style>
</head>
<body>
<header>
  <div class="titlerow">
    <div class="title-text">
      <h1>Check-Security v$ScriptVersion</h1>
      <div class="logo-sub">by <b>Nephren</b></div>
    </div>
    <svg xmlns="http://www.w3.org/2000/svg" viewBox="9.39 8.477 484.197 428.149" style="width:76px;height:76px;margin-left:24px;align-self:flex-end;filter:drop-shadow(0 0 12px rgba(0,212,255,.4));flex-shrink:0"><path d="m347.015 235.334 42.877-112.525 67.515 25.727-42.877 112.524z" fill="#a8ce81"/><path d="m303.267 350.143 42.92-112.634 67.514 25.726-42.919 112.634z" fill="#fddb1d"/><path d="m263.921 207.033 42.879-112.525 67.406 25.685-42.877 112.525z" fill="#ef7066"/><path d="m220.505 320.972 42.588-111.764 67.406 25.685-42.588 111.764z" fill="#6eaed7"/><path d="m415.69 247.559c-12.962-10.418-30.606-21.623-53.002-30.158-1.455-.43-2.827-1.077-4.131-1.574l33.307-87.41c1.755.295 3.277.875 4.893 1.864 22.194 8.083 39.661 19.097 52.64 29.147zm-44.284 116.221a216.14 216.14 0 0 0 -53.045-30.048c-1.496-.321-2.91-.86-4.131-1.574l34.136-89.586c1.673.513 3.236.984 4.893 1.865 22.153 8.192 39.62 19.206 52.392 29.8zm122.181-212.166s-25.485-37.351-81.827-59.07c-56.66-21.216-98.7-15.447-98.482-15.364l-15.038 39.466c-.135-.3 27.632-5.533 68.583 3.971l-33.597 88.172c-41.045-9.913-68.776-3.795-68.693-4.013l-10.29 27.33s27.736-7.111 69.123 2.558l-34.717 91.108c-33.74-8.499-58.772-7.828-67.506-6.798l-14.5 38.052c10.873-1.087 47.89-2.17 95.075 15.809 56.467 21.392 82.284 57.873 82.408 57.547zm-241.467-32.87 14.747-38.705 41.45-2.259-14.748 38.705zm-91.514 240.162 14.748-38.704 41.45-2.259-14.5 38.052zm16.364-42.944 13.38-35.117 41.492-2.367-13.423 35.225zm60.11-157.752 13.382-35.118 41.45-2.259-13.381 35.117zm-30.034 78.821 13.381-35.116 41.45-2.26-13.381 35.117zm-15.038 39.466 13.38-35.117 41.45-2.26-13.38 35.117zm30.035-78.823 13.422-35.225 41.45-2.259-13.423 35.225zm-10.213-90.174 11.476-30.115 40.145-2.756-11.766 30.876zm-110.927-84.974 4.93-12.937 16.36-1.112-4.93 12.937zm76.852 67.881 8.99-23.592 35.117-2.306-9.03 23.7zm-28.691-20.768 6.835-17.94 28.455-1.483-6.836 17.94zm-24.068-24.734 5.469-14.351 23.495-.884-5.179 13.59zm40.932 183.057 11.476-30.115 39.855-1.995-11.475 30.115zm-110.927-84.974 4.93-12.938 16.36-1.111-5.178 13.59zm76.852 67.881 9.031-23.7 35.077-2.198-9.032 23.7zm-28.691-20.769 6.835-17.938 28.455-1.484-6.835 17.939zm-24.067-24.734 5.22-13.698 23.743-1.536-5.179 13.59zm41.222 182.297 11.475-30.115 40.145-2.757-11.475 30.116zm-110.927-84.974 5.178-13.59 16.112-.46-4.93 12.938zm77.1 67.229 8.74-22.94 35.119-2.307-8.783 23.05zm-28.691-20.769 6.587-17.287 28.454-1.483-6.587 17.286zm-24.026-24.843 5.178-13.59 23.495-.883-5.178 13.59z" fill="#000101"/><path d="m114.017 84.174 4.889-12.83 17.411-1.582-4.888 12.829zm88.133 61.472 9.529-25.006 32.364-1.612-9.28 24.353zm-34.836-17.383 7.913-20.766 29.355-1.887-7.913 20.766zm-29.271-19.247 6.049-15.873 22.733-1.173-6.007 15.764zm-50.589-48.909 4.102-10.763 12.995-.776-4.101 10.764zm11.525 63.532 4.93-12.938 17.411-1.583-4.93 12.938zm88.133 61.472 9.57-25.114 32.612-2.265-9.528 25.006zm-34.588-18.035 7.664-20.113 29.397-1.996-7.954 20.874zm-29.478-18.703 6.007-15.764 22.734-1.174-5.758 15.112zm-50.63-48.8 4.392-11.525 12.995-.775-4.392 11.524z" fill="#ef7066"/><path d="m68.115 204.635 4.93-12.937 17.122-.822-4.93 12.938zm87.844 62.234 9.57-25.114 32.653-2.374-9.57 25.114zm-34.547-18.144 7.913-20.766 29.107-1.235-7.664 20.113zm-29.229-19.355 5.717-15.004 22.733-1.173-5.717 15.003zm-50.92-48.04 4.391-11.524 12.995-.776-4.35 11.416zm11.814 62.77 4.93-12.937 17.122-.822-4.93 12.938zm88.133 61.473 9.28-24.353 32.654-2.374-9.57 25.115zm-34.836-17.383 7.913-20.765 29.397-1.996-7.955 20.874zm-29.229-19.355 5.717-15.004 23.023-1.934-6.007 15.764zm-50.631-48.801 4.102-10.763 12.995-.775-4.101 10.763z" fill="#6eaed7"/></svg>
  </div>
  <div class="meta-bar">
    <span><span class="meta-dot"></span>Machine: <b>$env:COMPUTERNAME</b></span>
    <span>Date: <b>$(Format-AuditDate (Get-Date))</b></span>
    <span>OS: <b>$($OS.Caption) Build $($OS.BuildNumber)</b></span>
  </div>
</header>
<div class="container">

  <!-- Score -->
  <div class="score-bar-wrap">
    <div class="score-label">
      <span>Overall security score</span>
      <span class="score-value">$Score / 100</span>
    </div>
    <div class="score-bar-track"><div class="score-bar-fill"></div></div>
  </div>

  $DeltaSectionHTML

  $FailAnchorsBlockHTML

  $HistoryChartHTML

  <!-- Summary -->
  <p class="section-title">Check summary</p>
  <div class="summary-grid">
    <div class="stat-card score"><div class="num">$Total</div><div class="lbl">Total checks</div></div>
    <div class="stat-card ok">  <div class="num">$TotalOK</div>  <div class="lbl">OK</div></div>
    <div class="stat-card warn"><div class="num">$TotalWARN</div><div class="lbl">Warning</div></div>
    <div class="stat-card fail"><div class="num">$TotalFAIL</div><div class="lbl">Critical</div></div>
    <div class="stat-card info"><div class="num">$TotalINFO</div><div class="lbl">Info</div></div>
  </div>

  <!-- Executive summary — Critical points (v4.2) -->
  $ExecSummaryHTML

  <!-- Score by category (v5.0) -->
  $CatScoreTableHTML

  <!-- Full table -->
  <p class="section-title">Detailed results</p>
  <input type="text" id="searchBox" class="search-box" placeholder="🔎 Search (category, check, value, detail)...">
  <div class="filter-bar">
    <span class="filter-chip active" data-filter="ALL">All</span>
    <span class="filter-chip" data-filter="FAIL">Critical</span>
    <span class="filter-chip" data-filter="WARN">Warning</span>
    <span class="filter-chip" data-filter="OK">OK</span>
    <span class="filter-chip" data-filter="INFO">Info</span>
  </div>
  <table id="resultsTable">
    <thead>
      <tr>
        <th style="width:130px">Category</th>
        <th style="width:280px">Check</th>
        <th>Value / Description</th>
        <th style="width:120px">Status</th>
      </tr>
    </thead>
    <tbody>
      $TableRows
    </tbody>
  </table>
  <p class="no-results" id="noResults">No result matches this filter.</p>
</div>
<footer>Report automatically generated by Check-Security.ps1 v$ScriptVersion — $env:COMPUTERNAME — $(Format-AuditDate (Get-Date))</footer>
<script>
  // NOTE v3.0: client-side search/filter, same pattern as Block-Telemetry v5.
  // No external dependency; everything relies on the data-status /
  // data-search attributes set on each <tr> from the PowerShell side.
  (function () {
    var searchBox = document.getElementById('searchBox');
    var chips = document.querySelectorAll('.filter-chip');
    var rows = document.querySelectorAll('#resultsTable tbody tr');
    var noResults = document.getElementById('noResults');
    var activeStatus = 'ALL';

    function applyFilters() {
      var term = (searchBox.value || '').toLowerCase().trim();
      var visibleCount = 0;
      rows.forEach(function (row) {
        var matchesStatus = (activeStatus === 'ALL') || (row.getAttribute('data-status') === activeStatus);
        var matchesSearch = !term || (row.getAttribute('data-search') || '').indexOf(term) !== -1;
        var show = matchesStatus && matchesSearch;
        row.style.display = show ? '' : 'none';
        if (show) visibleCount++;
      });
      noResults.style.display = (visibleCount === 0) ? 'block' : 'none';
    }

    searchBox.addEventListener('input', applyFilters);
    chips.forEach(function (chip) {
      chip.addEventListener('click', function () {
        chips.forEach(function (c) { c.classList.remove('active'); });
        chip.classList.add('active');
        activeStatus = chip.getAttribute('data-filter');
        applyFilters();
      });
    });
  })();
</script>
</body>
</html>
"@

$HTML | Out-File -FilePath $ReportHTML -Encoding UTF8 -Force

# ──────────────────────────────────────────────
#  FINAL DISPLAY
# ──────────────────────────────────────────────
# NOTE v2.2: aligned with SpicyCheck-v7.0's behavior — the report is no
# longer opened automatically (it's OFFERED via a Y/n question), and the
# console window no longer closes on its own at the end (ENTER pause), to
# leave time to read the summary before the window disappears.
# As with the rest of the script, all of this is skipped in -Silent mode.
if (-not $Silent) {
    $scoreColor = if ($Score -ge 80) { "Green" } elseif ($Score -ge 50) { "Yellow" } else { "Red" }
    $barWidth = 62

    # NOTE v5.0.9: same ╔═╗ frame style as the section banners, for
    # end-to-end visual consistency across the script.
    Write-Host ""
    Write-Host ("╔" + ("═" * $barWidth) + "╗") -ForegroundColor Cyan
    Write-Host "║" -NoNewline -ForegroundColor Cyan
    Write-Host (" ✓ AUDIT COMPLETE").PadRight($barWidth) -NoNewline -ForegroundColor Green
    Write-Host "║" -ForegroundColor Cyan
    Write-Host ("╚" + ("═" * $barWidth) + "╝") -ForegroundColor Cyan
    Write-Host ""

    # Mini visual score gauge (20 blocks), same color thresholds as the HTML.
    $gaugeBlocks = 20
    $filled = [math]::Round(($Score / 100) * $gaugeBlocks)
    $gauge = ("█" * $filled) + ("░" * ($gaugeBlocks - $filled))
    Write-Host "   Security score      " -NoNewline -ForegroundColor Gray
    Write-Host "$gauge" -NoNewline -ForegroundColor $scoreColor
    Write-Host "  $Score/100" -ForegroundColor $scoreColor

    Write-Host "   Checks              " -NoNewline -ForegroundColor Gray
    Write-Host "$Total total" -NoNewline -ForegroundColor White
    Write-Host "  ·  " -NoNewline -ForegroundColor DarkGray
    Write-Host "✓ $TotalOK OK" -NoNewline -ForegroundColor Green
    Write-Host "  ·  " -NoNewline -ForegroundColor DarkGray
    Write-Host "! $TotalWARN WARN" -NoNewline -ForegroundColor Yellow
    Write-Host "  ·  " -NoNewline -ForegroundColor DarkGray
    Write-Host "✗ $TotalFAIL FAIL" -ForegroundColor Red

    if ($PreviousAudit -and $PreviousAudit.Results) {
        $ScoreDiffDisplay = $Score - [int]$PreviousAudit.Score
        $diffStr = if ($ScoreDiffDisplay -ge 0) { "+$ScoreDiffDisplay" } else { "$ScoreDiffDisplay" }
        $diffColor = if ($ScoreDiffDisplay -ge 0) { "Green" } else { "Yellow" }
        Write-Host "   Evolution           " -NoNewline -ForegroundColor Gray
        Write-Host "$diffStr point(s)" -NoNewline -ForegroundColor $diffColor
        Write-Host "  ($($Deltas.Count) status change(s) since the last audit)" -ForegroundColor DarkGray
    }

    # NOTE v4.7: FAIL/WARN detail in the console banner — up to 5 of each
    # for an at-a-glance view without opening the HTML report.
    $FailItems = @($AuditResults | Where-Object { $_.Status -eq "FAIL" })
    $WarnItems = @($AuditResults | Where-Object { $_.Status -eq "WARN" })

    if ($FailItems.Count -gt 0) {
        Write-Host ""
        Write-Host "   ✗ FAIL" -ForegroundColor Red
        $FailItems | Select-Object -First 5 | ForEach-Object {
            Write-Host "      • [$($_.Category)] $($_.Check): $($_.Value)" -ForegroundColor Red
        }
        if ($FailItems.Count -gt 5) { Write-Host "      ... and $($FailItems.Count - 5) more" -ForegroundColor DarkRed }
    }
    if ($WarnItems.Count -gt 0) {
        Write-Host ""
        Write-Host "   ! WARN" -ForegroundColor Yellow
        $WarnItems | Select-Object -First 5 | ForEach-Object {
            Write-Host "      • [$($_.Category)] $($_.Check): $($_.Value)" -ForegroundColor Yellow
        }
        if ($WarnItems.Count -gt 5) { Write-Host "      ... and $($WarnItems.Count - 5) more" -ForegroundColor DarkYellow }
    }

    Write-Host ""
    Write-Host "   »  HTML report    " -NoNewline -ForegroundColor DarkGray
    Write-Host "$ReportHTML" -ForegroundColor Cyan
    Write-Host "   »  TXT report     " -NoNewline -ForegroundColor DarkGray
    Write-Host "$ReportTXT" -ForegroundColor Cyan
    Write-Host "   »  JSON export    " -NoNewline -ForegroundColor DarkGray
    Write-Host "$ReportJSON" -ForegroundColor Cyan
    Write-Host "   »  CSV export     " -NoNewline -ForegroundColor DarkGray
    Write-Host "$ReportCSV" -ForegroundColor Cyan
    Write-Host ("─" * ($barWidth + 2)) -ForegroundColor DarkCyan
    Write-Host ""

    if ($ReportHTML -and (Test-Path $ReportHTML)) {
        $OpenAnswer = Read-Host "  Open the report in your browser? [Y/n]"
        if ($OpenAnswer -eq '' -or $OpenAnswer -match '^[OoYy]') {
            Start-Process $ReportHTML
        }
    }

    Write-Host ""
    Write-Host "  ╔═══════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "  ║" -ForegroundColor Cyan -NoNewline
    Write-Host "  Press ENTER to close this window...                " -ForegroundColor Yellow -NoNewline
    Write-Host "║" -ForegroundColor Cyan
    Write-Host "  ╚═══════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Read-Host | Out-Null
}

# SIG # Begin signature block
# MIIFwgYJKoZIhvcNAQcCoIIFszCCBa8CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCB7n7mNKYWwUMEL
# tMv9c8O10gz5FmCDGS6ALp7UN3QPiqCCAygwggMkMIICDKADAgECAhB6X4r8AlBU
# p0MV3JpMuQ6sMA0GCSqGSIb3DQEBCwUAMCoxKDAmBgNVBAMMH05lcGhyZW4gUG93
# ZXJTaGVsbCBDb2RlIFNpZ25pbmcwHhcNMjYwNzA0MDIzMzIwWhcNMzEwNzA0MDI0
# MzIwWjAqMSgwJgYDVQQDDB9OZXBocmVuIFBvd2VyU2hlbGwgQ29kZSBTaWduaW5n
# MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1JnV5AocUnAMNIG3nYF9
# 5mOQz5NzMYJqc9D6mq3pjRlmuYIgvYEuJL5dvt8eoAiUKd+XHTaY5wl+zt7LUon+
# TmEldVwfrYvROpI+5TDyBRc5BzY4uACsA4JUM4ienjX04BBKT3uH6JwHzBluWqcG
# Xrg16NqzDiae7WNzVrev+BME00mgSvBo3hKp3sHIvFQaAmjGXLyJd+llfnBpmoD9
# JnOxMKO7VFIlhAz5cEUnFu/xDLHgARdBUfXA5odScWKiDvygNZsH1vHo07Oo7pDK
# awR3bT6lcXWRXSUmawgE1mZra+b9qpeNol+5J+86zN83RccBKZBUtQQoyy+cv20x
# VQIDAQABo0YwRDAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUHAwMw
# HQYDVR0OBBYEFNxVaDYoNv8UXQWnbtEy/DTaQHjYMA0GCSqGSIb3DQEBCwUAA4IB
# AQCE4NqZbeximmbNEORyLxvIYiMQwP59B9R95blQQ/zugPSt4wab61yBbgO1E3mH
# mUdN0fCHhN/u0uB7h7ZBYw1w4hnzoiBac4UYzsXH4/D41gBjutbtDllRy6/zs3dl
# /hbbHAmwKXdjNVLG9cPkpWlkvKR1DJLMugU2uj+S6k+U7DfHo76sbAKqiu3biXtd
# mao6PP99EU7JBYZjsJ+BsnYcZ2KcnZ8TKiRuhSXoxAyPman7Z0BVo1H2O+fxd96b
# 4W8VclmpFh7T2CyRAHolwEy5coFYyueisO0PZg+nKwXr66+m1T1CBLQYwh79/SKO
# wGUJyU5RtTryD+hfLwkTQKVCMYIB8DCCAewCAQEwPjAqMSgwJgYDVQQDDB9OZXBo
# cmVuIFBvd2VyU2hlbGwgQ29kZSBTaWduaW5nAhB6X4r8AlBUp0MV3JpMuQ6sMA0G
# CWCGSAFlAwQCAQUAoIGEMBgGCisGAQQBgjcCAQwxCjAIoAKAAKECgAAwGQYJKoZI
# hvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcC
# ARUwLwYJKoZIhvcNAQkEMSIEIAJxqXDHZSeBPu56ZcV+BEI8JPwbgK2jyBdF/6Wg
# ixb+MA0GCSqGSIb3DQEBAQUABIIBAGw4ScxtbKpJZDZkqd2dBdOFTEWjoE6mbJM1
# 4IDBBx7T9iaShAWC3MWNK0FM19Bd/YgwAyfsMT83TLEp8pTflfumkRFERB7xbTZn
# y8/2+yuH3SZAwzP+/lqFssTqbUjNjsa9cIfgy6BG7OPV+TN6W7evrqNKIYXGpISi
# 65xtn9QGMlGNvGwOhiRkVMDKgMr+hBcR5hrKdMM1nHxlPRC4kcaoUh0LIke4j850
# AyiSthDUCQqkuQZE8y9QKlHJjzqVyuX/Cs/emey7EN7I1cgVfl7VPQgjCwZ1gM6p
# jifVm59AUos+e/40BZoH0DPacqCZ/fq0m7CBYba/zHqHfIeH3R0=
# SIG # End signature block
