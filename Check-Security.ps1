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
    - Non-standard trusted root certificates (machine and current user) + expired certificates (Cert:\LocalMachine\My)
    - Controlled Folder Access, credential-exposure settings, WMI / Winlogon persistence (v5.6.0)
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
    - Legacy name resolution (LLMNR / mDNS / NetBIOS) + IPv6 transition tunnels
      (Teredo / 6to4 / ISATAP)
    - Defender protections: Tamper Protection, PUA, Network Protection, cloud protection
      (MAPS level, sample submission, block at first sight, block level, extended timeout)
    - PowerShell 2.0 downgrade route
    - Remote-access services (Remote Registry, WebClient, ...) + Telnet client / TFTP
    - Automatic logon / plaintext DefaultPassword stored in Winlogon
    - "Fix with" hints pointing to the matching Toolbox-SystemCommands command
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
    Version : 5.7.5
    Date    : 2026-11-21
    Auto-elevates via UAC if not already run as Administrator

    CHANGELOG v5.7.5 (2026-11-21): two more help links, no change to any check or to the score.
    - "Turn on Secure Boot" and "Set up Windows Hello" (support.microsoft.com): Microsoft renamed these articles
      and an audit of the addresses could not open the old ones (support.microsoft.com cuts the connection of a
      script, so they could not be confirmed either way). They are replaced by pages confirmed to exist:
      "Windows 11 and Secure Boot" and "Learn about Windows Hello and set it up". The buttons are now named
      "Microsoft Support: ..." (they never were Microsoft Learn pages).
    - -SelfTest: the two old addresses join the list of pages that must not be used, and the replacements join
      the list of pages that must be present (same 3 assertions, no new one).

    CHANGELOG v5.7.4 (2026-11-21): help links of the HTML report audited against Microsoft's servers (a script
    that opens every Learn / Support address of this file), no change to any check or to the score.
    - Windows lifecycle button (System rows "Windows 11 build" / "Uptime"): the page
      learn.microsoft.com/lifecycle/products/windows-11 no longer exists (404). It is replaced by the "Windows 11
      Home and Pro" and "Windows 11 Enterprise and Education" lifecycle pages, which also join the "Windows
      build support status" row.
    - Ten buttons opened a page through a redirect (Microsoft renamed or moved the page). They now point to
      the current address: Defender exclusions, cloud protection (3 buttons), tamper protection (2 buttons),
      Windows Update troubleshooting, Windows Firewall configuration, Remote Desktop access, system restore point.
    - "Secure Windows services" (Services > Non-system auto services) pointed to an archived Windows 10 page that
      does not match its name: removed (the Autoruns button stays).
    - The password-policy and LAN-Manager-level buttons already opened the archived Windows 10 pages that
      Microsoft now serves for these settings: the address is now the real one instead of a redirect.
    - -SelfTest: the list of known dead addresses is now kept as path endings (no full address), so that an
      audit of the addresses of the script does not report the test list; it covers all the pages above and the
      duplicate test ignores the "#section" part (two buttons to the same page are still caught).

    CHANGELOG v5.7.3 (2026-11-21): three help-link problems of the HTML report fixed, no change to any check
    or to the score.
    - Section 24 / Controlled Folder Access card: the two Microsoft Learn pages "Enable controlled folder
      access" and "Customize controlled folder access" had been merged by Microsoft into a single page, so
      both buttons opened the same page. They are replaced by "Controlled folder access overview" and
      "Configure controlled folder access".
    - Accounts rows ("Local user: ...", etc.): the "Local account security" button led to a page that no
      longer exists (404). It now opens Microsoft's "Local accounts" page.
    - TLS/SCHANNEL rows (TLS 1.0 / 1.1 / SSL): two buttons with different names opened the same Microsoft
      page ("TLS registry settings"). They are merged into one button.
    - -SelfTest: 3 new assertions: no card or rule lists the same page twice, the three addresses above are
      not used any more, and the replacement pages are in place.

    CHANGELOG v5.7.2 (2026-11-21): HTML report only, no change to any check or to the score.
    - The three checks whose conclusion rests on a Microsoft reference (Defender platform / engine
      version, Windows build support status, Secure Boot certificates 2023 renewal) now show their
      reference link as a button in the HTML report whatever their status. Until now the report only
      showed buttons on WARN / FAIL rows, so these rows showed a raw, non-clickable address (Defender,
      Secure Boot) or no link (lifecycle). The raw addresses are removed from the details.
    - New help-link rule "Defender platform" (before the generic Antivirus rule, so it also wins when
      the row is a WARN).
    - -SelfTest: 7 new assertions.

    CHANGELOG v5.7.1 (2026-11-20): five new read-only checks. The score model, the weights and every
    existing check are unchanged.
    - Updates, "Windows Update policies": deferral and intranet-server policies are INFO; WARN only when
      a policy turns Automatic Updates off (NoAutoUpdate = 1).
    - Antivirus, "Defender platform / engine version": age of the platform and engine, from the versions
      Get-MpComputerStatus already returns. WARN from 4 months behind the current release series
      (Microsoft supports the latest and the two previous versions); INFO when Defender is passive.
    - Network, "SMBv1 client feature": the existing check only read the SMBv1 server. The client feature
      comes from the optional-feature list already cached for sections 25 and 26 (the DISM read is now
      paid in section 8 instead of 25, same total time). WARN if enabled.
    - Audit, "Process creation auditing (event 4688)": subcategory queried by GUID, the Windows setting
      shown as returned (never interpreted), plus whether the command line is added to the events. INFO.
    - PowerShell, "Application control (AppLocker / WDAC / language mode)": overview, INFO.
    - -SelfTest: 30 new assertions on the pure decision functions.

    CHANGELOG v5.7.0 (2026-11-19): three new read-only checks. The score model, the weights and every
    existing check are unchanged.
    - Network, "Listening UDP endpoints (non-loopback)" (end of section 23): one line, endpoints
      de-duplicated by (process, port). WARN only for a sensitive port (69, 161, 1434, 11211), a program
      outside Windows on a NetBIOS port, an unverified program on every interface, or a Windows process
      bound to UDP 5355 / 5353 / 137-138 while the matching protocol (LLMNR / mDNS / NetBIOS) is turned
      off just above. Everything else is INFO.
    - Updates, "Windows build support status": the installed Windows 11 version against Microsoft's
      end-of-updates dates (edition from OperatingSystemSKU, build and UBR from the registry). OK, WARN
      within 90 days of the end, FAIL once ended. A table older than 6 months never answers OK. Windows
      10, LTSC and unknown editions give INFO (no date is guessed).
    - UEFI Security, "Secure Boot certificates (2023 renewal)": the Windows UEFI CA 2023 and KEK 2K CA 2023
      are looked for in the firmware databases and cross-checked with the servicing status Windows keeps
      in the registry. OK only with that evidence; blocked or pending states are INFO.
    - -SelfTest: 48 new assertions on the pure decision functions.

    CHANGELOG v5.6.2 (2026-11-17): Defender's own processes were flagged "unverified".
    - MsMpEng, MpDefenderCoreService, NisSrv, SgrmBroker and MsSense run as protected processes and,
      like lsass, hide their image path even from an administrator. A public connection from one of
      them (Defender updating its signatures or querying the cloud) was therefore reported as
      "name matches a known process but its image could not be verified" (WARN). They are now accepted
      when, and only when, the path is unreadable: a look-alike started by a user has a readable path
      and is judged on it.

    CHANGELOG v5.6.1 (2026-11-17): presentation of section 24.
    - Controlled Folder Access now follows the other Defender settings (after "Cloud extended
      timeout") instead of coming after the help line, and the help line closes the section.
    - Controlled Folder Access has its own card in the HTML report (where to change it in Windows
      Security, English and French paths, values 0 to 4, commands, Microsoft Learn links), so the
      help line is true for every row of the section. Its value is now shown like the others,
      e.g. "Enabled (1)". Status rules unchanged (1 OK, 0 WARN, others INFO).
    - The help line starts with "»" instead of "↳" (missing from many console fonts).

    CHANGELOG v5.6.0 (2026-11-16): technical audit release (detection reliability).

    Results that were wrong or silently lost
    - Baseline and score history are no longer overwritten by a run limited with -Category (the
      partial score polluted the history chart and produced false "new check" deltas and
      regression alerts at the next full run). A filtered run no longer compares with the baseline.
    - Windows PowerShell 5.1: "Join-String" (PowerShell 7 only) made the WinRM check fail.
    - UAC: ConsentPromptBehaviorAdmin 1 and 2 (prompt on the secure desktop) are stricter than the
      default and are no longer a WARN; a value that is not set is no longer read as "disabled";
      the legend was wrong. EnableLUA / PromptOnSecureDesktop follow the same rule.
    - Windows Defender in passive mode (another antivirus is active): real-time protection,
      scans, IOAV, behaviour monitoring and ASR are INFO instead of FAIL/WARN. The Security Center
      productState of third-party products is decoded (on/off, signatures up to date).
    - Firewall: rules whose profile is "Any" (they also apply to Public) were skipped; rules are read
      from the ActiveStore (GPO / Intune included); a default inbound action of Allow is a FAIL; the
      Enabled state is read as text; port ranges and seven more exposed services are checked.
    - BitLocker: suspended protection, locked volumes, encryption in progress, encryption method and
      key protectors are read (a suspended volume was reported as "not encrypted").
    - VBS / HVCI: hardware that cannot run them is INFO "not supported", not a WARN.
    - LSA protection: a missing RunAsPPL value is confirmed or not by the Wininit event 12.
    - Kernel stack protection: the undocumented "bit 3 of HVCIOptions" is replaced by the running
      services list and the documented KernelShadowStacks key.
    - Smart App Control: the unsourced "Tiger Lake / Zen 3" CPU requirement and the "cannot be
      re-enabled" claim are removed.
    - ASR: "no rule" was counted as one rule (@($null)); Warn mode (6) was counted "inactive"; the
      three Microsoft standard-protection rules are checked.
    - DoH: the "DohFlag" property does not exist, so the check could never detect DoH. It now compares
      the DNS servers in use with the DoH table and the per-interface settings.
    - An unreadable Security log (failed logons, 4648, 4720, 4726) is "Unable to read", no longer
      "0 events = OK". Get-HotFix entries without a date no longer give "no patch for 60 days".
      Uptime with Fast Startup is INFO. A pending restart is reported. A lockout duration of 0
      (until an administrator unlocks) is no longer "very short". "net accounts" in another
      language is read through secedit.
    - Services, drivers, tasks, certificates, connections, ports, shares: see "Trust" below.

    Trust no longer rests on a name or a substring
    - Services: every automatic running service is evaluated (63 of 67 were skipped on a standard
      machine): Windows folders by anchored path, Microsoft by signature + ACL, others reviewed
      (writable location, unsigned outside Program Files, unquoted path, user account).
    - Scheduled tasks: the folder \Microsoft\ no longer exempts a task; interpreters are matched by
      file name (pwsh, msiexec, certutil...); Running tasks are included; an encoded command, a
      download or a hidden window is flagged; the script a task runs must really be what it runs; an
      ELEVATED task running a script a non-administrator can modify is no longer trusted by path.
    - Root certificates: the "Microsoft in the subject" exclusion is replaced by a thumbprint list of
      the roots Windows ships; Cert:\CurrentUser\Root is now audited.
    - Established connections and listening ports: names are matched exactly and the process image is
      verified (path / signature / ACL); PowerShell is no longer allowlisted; a port is only "normal"
      for a verified Windows process; an unverified process listening on all interfaces is a WARN.
    - Firewall rules without a program are recognised by their resource group (language-independent),
      not by an English display name; the location test is anchored; the publisher must be a Microsoft
      signing identity.
    - Recent drivers: anchored location test. Shares: only the default administrative shares are
      ignored. Defender exclusions: extensions and processes are judged, Program Files is no longer
      "broad" as a whole.

    New checks
    - Controlled Folder Access (ransomware protection), WDigest, NoLMHash, EveryoneIncludesAnonymous,
      RestrictAnonymousSAM, Guest account, remote UAC token filtering, Winlogon Shell / Userinit,
      WMI command / script event consumers, cleared event logs (1102 / 104), restart pending.

    Score, exports, report
    - Results that could not be performed ("Unable to read" / "Not available") are flagged
      Indeterminate and left out of the score instead of counting as 100 %. The weights and the
      model are unchanged. A newly FAIL check raises its own alert whatever the score does. The exact
      score and the script version are stored next to the rounded score in the history.
    - CSV: cells starting with = + - @ are neutralised (formula injection).
    - HTML: the filter no longer hides the tables inside the Defender cards; the category cell is
      rebuilt when rows are filtered; media queries; contrast of the active chip; no empty id; a
      Content-Security-Policy. TXT is written in UTF-8; the report is opened through explorer.exe so
      the browser is not started elevated. "Set-ExecutionPolicy Bypass" was removed; a permissive
      execution policy is a WARN (Microsoft: not a security boundary).

    Known limits (not changed in this release): the Windows build support lifecycle, UDP listeners,
    the Secure Boot 2023 certificate update, and per-section error isolation are not covered yet.
    The list of Windows-shipped root thumbprints must be verified against Microsoft documentation.

    CHANGELOG v5.5.3 (2026-11-12):

    - Defender cards, PUA: the "Block apps" / "Block downloads" sub-options are no longer
      named. They come from the Windows 10 documentation: the current Windows 11 page of
      Microsoft only names the section "Potentially unwanted app blocking" (App & browser
      control > Reputation-based protection), and a Windows 11 25H2 machine shows a single
      switch there ("Blocage d'application potentiellement indésirable" in French), with no
      separate options. The card now says to switch that section on, and that audit mode
      needs PowerShell.
    - Windows Security is localized: the cards of the settings that have a switch also give
      the French path ("On a French Windows: ..."), built from the names shown by the French
      app and by Microsoft's French documentation, since English names alone cannot be found
      on a French install.
    - -SelfTest: every setting with a Windows Security switch has its French path, the card
      shows it, and no card names the "Block apps" / "Block downloads" sub-options.

    CHANGELOG v5.5.2 (2026-11-12):

    - Defender cards: the simplest way comes first. Each card now starts with an
      "Easiest way" line telling where to change the setting in the Windows Security
      app (switch names and path), or stating that the app has no switch for it
      (block level, extended timeout, Network Protection) and that PowerShell, Group
      Policy or Intune are needed. The Detail sentence of a row that is not on the
      recommended value names the Windows Security path first, then the PowerShell
      command. Settings with a partial switch say what the switch cannot do (cloud
      protection: no Basic level; PUA: no audit mode; sample submission: on / off only).
      Block at first sight has no switch of its own: it turns on by itself when cloud
      protection and automatic sample submission are both on, and the card says so.
    - The audit no longer shows any command that turns a protection OFF: real-time
      protection (-DisableRealtimeMonitoring $true), block at first sight
      (-DisableBlockAtFirstSeen $true), cloud protection Disabled, PUA Disabled and
      Network Protection Disabled are gone, as is the sample submission "AlwaysPrompt"
      level (Microsoft says it lowers protection). Commands that turn a protection ON or
      tune it stay, and so do legitimate choices (NeverSend for privacy, Basic cloud
      membership, a lower block level). The VALUE tables stay complete, for
      information. Real-time protection keeps only the command that turns it back on,
      and its note explains why: Windows turns it back on by itself, Tamper Protection
      can block a script, and switching Defender off is one of the first things malware
      does.
    - When a policy manages a setting, the card also warns that a Windows Security switch
      for it may be greyed out or switch back.
    - -SelfTest: new assertions (every card says where to change the setting, no command
      turns a protection off, real-time protection offers only the command that turns it
      on, the Windows Security way comes before PowerShell, a setting without a switch
      goes straight to PowerShell).

    CHANGELOG v5.5.1 (2026-11-11):

    - Defender section (24): the cloud protection is now audited in depth, with
      four new checks read from Get-MpPreference (no extra call, the object was
      already loaded): "Cloud sample submission" (SubmitSamplesConsent),
      "Block at first sight" (DisableBlockAtFirstSeen), "Cloud block level"
      (CloudBlockLevel) and "Cloud extended timeout" (CloudExtendedTimeout).
      A property that an older Defender platform doesn't expose is reported as
      "Unable to determine" instead of being read as 0 / False.
    - The Defender rows now show the plain-language name AND the raw value
      exactly as Get-MpPreference prints it, e.g. "Advanced (2)", "Enabled, block
      (1)", "High+ (4)", "+20 s (about 30 s maximum wait)". Labels of the existing
      checks are unchanged, so the comparison with a previous audit still matches.
    - New expandable card under each Defender setting in the HTML report (the
      console stays one compact line per check; one grey pointer line at the end
      of section 24 tells where the details are): what the setting does, EVERY
      possible value with its meaning (the current one highlighted), the command
      that reads it, the Set-MpPreference commands that change it, the trade-off,
      and the Microsoft Learn pages (always visible, even when the status is OK).
      Cards exist for Tamper Protection, Real-time protection (section 4), cloud
      protection (MAPS), sample submission, block at first sight, cloud block
      level, extended timeout, PUA and Network Protection. All of it comes from
      ONE table ($script:DefenderRef) that also builds the short Detail sentence,
      so the explanation of the current value can never contradict the card.
    - Policy awareness: when a Group Policy, Intune or a hardening tool sets a value
      (registry key under HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender), the
      Detail and the card say so and warn that Set-MpPreference has no effect while
      the policy exists. This is why Get-MpPreference can show 20 while the
      non-policy MpEngine key still holds an older, ignored 30. The audit reads the
      effective value from Get-MpPreference, never from that non-policy key.
    - Severities follow the existing philosophy: INFO (never WARN / FAIL) for the
      optional cloud choices, since sample submission is a privacy decision and a
      longer cloud wait is a trade-off. OK for MAPS Basic / Advanced, sample
      submission 1 or 3, block level Default / High / High+, block at first sight
      on. The extended timeout adds to the default 10 s (0 to 50, maximum 60 s).
    - Section 4: the "Real-time protection" row now has a Detail and a card that
      explains DisableRealtimeMonitoring (its name is inverted: False = protection ON).
      No duplicate row: the card is attached to the existing check.
    - HTML: the search box also finds a setting by its PowerShell name
      (e.g. "CloudBlockLevel"). Rows that have a card show its links instead of the
      generic WARN / FAIL links, so a link never appears twice.
    - -SelfTest: new assertions for the reference table (complete entries, Microsoft
      Learn links only, unique rows, value formatting, range matching, current-value
      highlight, policy warning, HTML escaping).
    - The Authenticode signature block was removed: any edit invalidates it. Sign
      the script again (Manage-ScriptSignatures) before publishing.

    CHANGELOG v5.5.0 (2026-11-08):

    - 5 new sections (23 to 27) covering gaps the existing sections left open.
      They are attached to EXISTING result categories (Network, Defender,
      PowerShell, Services, Accounts) - no new category - so they keep their
      weights in $CategoryWeights and the -Category filter keeps working:
        23_NameResolution (Network): LLMNR (EnableMulticast policy), mDNS
            (EnableMDNS) and NetBIOS over TCP/IP per active adapter - the
            fallback name-resolution protocols that any device on the local
            network can answer, which Responder-type tools abuse to capture
            NTLM hashes. Plus the three IPv6 transition tunnels (Teredo, 6to4,
            ISATAP), read through the NetworkTransition cmdlets (typed values,
            language independent) rather than by parsing netsh text output.
        24_DefenderProtections (Defender): Tamper Protection, PUA protection,
            Network Protection and cloud protection (MAPS). Skipped with an
            INFO when Defender is not the active antivirus (passive mode).
        25_PowerShell2 (PowerShell): the PowerShell 2.0 optional features, a
            downgrade route that bypasses AMSI and script logging (removed by
            Microsoft from Windows 11 24H2 onwards: reported as such).
        26_RemoteServices (Services): Remote Registry, WebClient (WebDAV, used
            in NTLM relay attacks), RemoteAccess / sshd / SSDP / UPnP, the
            Telnet client and TFTP features, and Remote Assistance.
        27_Credentials (Accounts): Winlogon automatic logon and a plaintext
            DefaultPassword (existence only - the value is never read into the
            report).
    - Severities follow this script's philosophy of not penalizing what is the
      Windows default on a healthy personal machine: FAIL only for a stored
      plaintext password, a running Remote Registry service and Tamper
      Protection off; WARN for LLMNR / NetBIOS enabled (the real exposure
      depends on the networks the machine joins), PowerShell 2.0 enabled,
      WebClient / RemoteAccess running, Telnet / TFTP enabled and an active
      Teredo tunnel; INFO for mDNS, PUA / Network Protection / cloud settings,
      inactive tunnels left on Default and Remote Assistance (enabled by
      default, still needs an invitation). The score model is a per-category
      success rate, so these additions do not drag the score down on a healthy
      machine; new checks appear as "New check" in the first comparison.
    - Credential Manager entries (cmdkey /list) are deliberately NOT audited:
      the output is localized text, the exact trap that caused the v5.4.2
      vssadmin false positive.
    - New "Fix with" hints: findings on these checks now name the matching
      command of the Toolbox-SystemCommands launcher (Quick security category),
      e.g. "Fix with Toolbox-SystemCommands > Quick security > 'Disable
      PowerShell 2.0'". This script stays strictly read-only: it detects, the
      Toolbox fixes. Hints are only added when the status is not OK, can be
      hidden with $ShowToolboxHints = $false, and the labels live in one table
      ($ToolboxLabels) matching the English Toolbox catalog.
    - New help links in the HTML report for Tamper Protection, PUA, Network
      Protection (Microsoft Learn) and PowerShell 2.0 (Microsoft Support).
      Links normally show on WARN / FAIL rows only; INFO rows of the PUA and
      Network Protection checks are now included too, since INFO is their
      worst case and the link is what explains how to turn them on.
    - Teredo: when Get-NetTeredoState returns no state (Windows keeps the
      tunnel inactive), the value reads "Default, no active tunnel" instead of
      an empty "Default / ".
    - Section 4: the check labelled "Network protection" actually read
      IoavProtectionEnabled, i.e. Defender's IOAV protection (scanning of
      downloaded files and e-mail attachments), NOT the Network Protection
      feature of Exploit Guard (that one is audited in section 24). Renamed
      "Download/attachment scanning (IOAV)", with an explanatory detail.
      Logic and severity are unchanged; it shows once as "New check" in the
      first comparison after the update.
    - Section 5: "Local Administrators members" now annotates each member, e.g.
      "COMPUTER\Administrator (built-in, disabled), COMPUTER\username".
      The built-in Administrator (RID-500) is always in the group, even when
      disabled, so the plain list looked like two accounts for one person; the
      WARN threshold (more than 3) now counts only members that can sign in.
      The detail of the "Local user: ..." lines no longer starts with an
      orphan " | ".
    - -SelfTest no longer writes outside its own sandbox: the Add-Result
      assertions used to leave a stray "Check-Security_<date>.txt" (one
      "[OK] TestCat | TestCtrl" line) in the Maintenance_Reports folder, and
      the folder itself was created on the Desktop. The TXT log is now
      redirected to a temporary file deleted before exiting, the folder is no
      longer created in -SelfTest mode, and two assertions check it.
    - Get-WinFeatures: one cached DISM call per run, shared by sections 25 and
      26, instead of one call per feature.
    - -SelfTest: the SectionCategoryMap assertion now expects 27 keys, and a new
      "New v5.5.0 features" block checks the five new mappings, the -Category
      filter on a new section, Get-ToolboxHint (fix / check wording, unknown
      key, hints disabled), the label table, two new help-link rules and the
      two assertions on the redirected SelfTest log.
    - Section 19: an unverified root certificate is now only a WARN when it is
      a real CA (BasicConstraints CA:TRUE), the only kind able to sign other
      certificates and intercept TLS. An unverified end-entity certificate
      placed in the Root store (cannot sign anything, MITM impossible) is now
      INFO, which keeps full score credit, so it no longer requires editing
      $TrustedRootThumbprintAllowlist. The summary line counts both kinds
      separately, and the detail of an unverified CA now lists the usual
      legitimate sources (antivirus HTTPS scanning, corporate proxy/VPN,
      developer tools) and how to check one.
    - Section 11: a task script with a valid Authenticode signature from a
      publisher in the Trusted Publishers store (CurrentUser or LocalMachine) is
      now recognized automatically, with no setting to edit in the script.
      $TrustedSignerSubjectMatch is now an optional extra.
    - Section 21: "Recently installed drivers (24h)" no longer raises a WARN for
      a user-mode service (.exe) with a valid signature (Edge Update, vendor
      updaters): it is listed as INFO with its signer. Kernel drivers (.sys) and
      unsigned or invalid executables still raise the WARN, now annotated with the
      reason ("[signature: <status>]" or "[file not found on disk]").
    - Section 16: fixed the count of Defender exclusions. With no exclusion,
      Get-MpPreference returns $null and @($null) counted as ONE empty element,
      so the report showed "1:" for an empty list. Empty entries are now ignored
      (the value is "0").
    - Section 23: Teredo turned off with netsh is now recognized. Get-NetTeredoConfiguration
      keeps reporting the configured type ("Default") while netsh reports the effective
      type "disabled", so the check showed "Allowed, not active". The effective type is
      now also read (value token only, not the localized labels) and counts as disabled.
    - Section 8 (and four other places): in Windows PowerShell 5.1, a CIM cmdlet that
      returns exactly ONE object gives a single object with no Count property, so
      "Established TCP connections (outbound)" read " connection(s)" with no number
      (PowerShell 7 was fine). The results of Get-NetTCPConnection (x2),
      Get-NetFirewallRule, Get-SmbShare, Get-CimInstance and Get-HotFix are now
      wrapped in @() before .Count is used.
    - Section 11: $TrustedTaskNames no longer ships with personal task names
      (BloatRemoval, EdgeRemoval, OneDriveRemoval) and is empty by default: a name-only
      match would also ignore a malicious task given the same name. Tasks created by
      Winhance (folder \Winhance\, script under %ProgramData%\Winhance\Scripts) are
      recognized by Test-WinhanceTaskTrusted, only if the script and its folder can't
      be modified by a non-administrator (owner and ACL checked by SID).
    - Section 5: the SAM "password not required" flag no longer raises a WARN for an
      account linked to a Microsoft or Entra ID account (its password is managed online).
      For a local account the WARN stays, since the script can't see whether the password
      is blank (testing it would count as a failed sign-in), but the detail now gives the
      fix: net user <name> /passwordreq:yes.
    - Section 5: fixed "Pwd expires": Get-LocalUser has no PasswordNeverExpires property,
      so every account read "Yes" and the "Password never expires" WARN never fired. An
      empty PasswordExpires is now read as "never expires" (an account linked to a
      Microsoft or Entra ID account shows "Managed online" and is not flagged). An account
      that never had a password (built-in Administrator, Guest, DefaultAccount) shows
      "n/a (no password set)" instead of "Never"; an enabled one flagged "password not
      required" is now said to very probably have an empty password.
    - Section 22, VSS shadow storage: a bounded limit at 80% or more is now a WARN only when
      the volume keeps fewer than 3 snapshots (or the count can't be read); with 3 or more
      it is INFO, because a bounded limit always ends up full and VSS then recycles the
      oldest snapshots. A limit that is not bounded and uses 20% or more of the host disk
      stays a WARN.
    - Section 3, open inbound rules: the detail used to list each rule by name only, so an
      application with one TCP and one UDP rule looked duplicated. Rules are now grouped by
      application with their protocols ("Steam [Valve Corp.] x2 (TCP, UDP)"), publishers are
      shown by CN only, and the detail states how many distinct entries make up the count.
    - HTML report: the Check, Value and Detail columns, the failure links and the delta list
      are now HTML-escaped. They were inserted raw, so text between angle brackets (such as
      the "<larger size>" placeholder of the VSS fix command) was swallowed by the browser,
      and a service, task or path name containing markup would have been injected into the
      report. The JSON, CSV and TXT exports were not affected.

    CHANGELOG v5.4.2 (2026-10-23):

    - Fix false CRITICAL on section 22 "Shadow copies on C:" (value "0") although
      5 VSS snapshots and 1 restore point existed on the machine. Cause: the
      detection parsed the text output of "vssadmin list shadows" with regexes
      that did not match the real French output ("ID du cliché instantané" vs
      the "ID de clich" pattern; case-sensitive "Date de création" vs the real
      "à la date de création"), so 0 blocks were counted. The fallback to
      Get-ComputerRestorePoint was wrapped in an empty catch{}, hiding any
      failure. Fix: detection now uses CIM (Win32_ShadowCopy filtered on the
      system volume DeviceID — locale-independent, real [datetime] values, other
      volumes' snapshots such as wbadmin images are excluded); vssadmin parsing
      is kept only as a fallback with case-insensitive FR/EN regexes; restore
      points are the last resort; detection errors are now appended to the
      detail text; and if every method errors out, the result is a WARN
      "Unable to read" instead of a false FAIL.
    - New check "VSS shadow storage" (section 22, Backup): reads
      Win32_ShadowStorage per volume. WARN when a bounded limit is >= 80% used
      (Windows then drops the oldest snapshots itself, which caps the restore
      history — e.g. C: stuck around 5 snapshots with a 4.75 GB limit), and WARN
      when a volume has NO limit and its snapshots already use >= 20% of the
      host disk (e.g. wbadmin snapshots of E: stored on F:, 254 GB and growing);
      INFO below that. The fix command (vssadmin resize shadowstorage ...) is
      given in the detail. The "Shadow copies on C:" detail now states that it
      counts local C: snapshots only and that wbadmin images are listed apart.
    - Fix empty counters when exactly one result has a given status: in Windows
      PowerShell 5.1 a single [PSCustomObject] has no .Count property, so
      ($AuditResults | Where-Object {...}).Count returned $null (seen as
      "FAIL:  |" in the summary, "X  FAIL" in the final box, and a blank
      Critical card in the reports once the shadow-copy FAIL was fixed and
      only the BitLocker C: FAIL remained). All such counts (totals, "and N
      more" notes, per-category rowspan, DoH/public connections/IPv6 lists)
      are now wrapped in @(...).
    - Fix the right edge of the "Press ENTER to close this window..." box being
      shifted by 2 columns at the end of the run: the text line was padded to 53
      characters while the ═ borders were 51 wide. Both now derive from one
      $enterBoxWidth variable (PadRight).
    - The v5.0.3 note claiming vssadmin never lists restore points on Win11 Home
      was wrong (confirmed on a real machine) and has been replaced by the note
      above in section 22.

    CHANGELOG v5.4.1 (2026-09-27):

    - Critical launch fix, found via real testing: the script only ever ran via
      right-click -> "Run as administrator" or from an already-elevated terminal.
      A plain ".\Check-Security.ps1" from a normal prompt, or a double-click
      shortcut, failed immediately with a ScriptRequiresElevation error, despite no
      self-elevation logic existing anywhere in the script to recover from that.
      Cause: the script relied solely on "#Requires -RunAsAdministrator", which
      makes PowerShell refuse to even start the script in a non-elevated session,
      before a single line of the script's own code can run. Fix: an
      AUTO-ELEVATION block was added right after the parameter block (checks
      WindowsPrincipal, relaunches itself via Start-Process -Verb RunAs carrying
      over -Silent/-SelfTest/-Category, then exits the non-elevated copy); the
      blocking #Requires directive was removed, since it would otherwise still
      prevent this new block from ever running. Same root cause already hit - and
      fixed the same way - on Check-Boot and SpicyCheck.

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
      Systematic false positive on a real machine (full scan 11 days old →
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



    CHANGELOG v5.0.5 (hotfix after a real-machine run, 2026-06-29):

    - SECTION 22 — Fixed wbadmin parsing: "Backup time" field
      v5.0.4 looked for "Heure de la sauvegarde" — a field that doesn't exist
      on the FR locale. The actual wbadmin output on a French-locale machine uses:
        "Durée de sauvegarde : dd/MM/yyyy HH:mm"
        "Cible de sauvegarde : Disque dur étiqueté BackupDisk(E:)"
      Regex updated to cover "Durée de sauvegarde" (FR) and "Backup time"
      (EN). Dates parsed via ParseExact dd/MM/yyyy HH:mm (InvariantCulture)
      to avoid MM/dd vs dd/MM ambiguity on dates where the day is ≤ 12.
      Falls back to Parse() if ParseExact fails.
      With 9 backups on E:\BackupDisk (05/13 → 06/28/2026), expected
      result: OK "9 version(s) — last one 1 day(s) ago".



    CHANGELOG v5.0.4 (2026-06-29):

    - SECTION 22 — Added a wbadmin system image backup check
      wbadmin get versions lists the full backups available across all
      connected volumes (e.g. E:\BackupDisk). Parses the date of the
      latest version and the target volume.
      Thresholds: ≤30d → OK, 31-90d → WARN, >90d → FAIL, 0 versions → INFO.
      This check is independent of the VSS/shadow copy check — both coexist
      in section 22: VSS covers system restore points, wbadmin covers full
      system images.



    CHANGELOG v5.0.3 (hotfix after a real-machine run, 2026-06-29):

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



    CHANGELOG v5.0.2 (hotfix after a real-machine run, 2026-06-29):

    - SECTION 8 — False positive public TCP: pwsh flagged WARN
      PowerShell itself (pwsh) can have an active public TCP connection at
      audit time — the script currently running, a parallel PS session, or a
      PSGallery/Update request. Added pwsh, powershell and powershell_ise to
      $SystemProcsAllowlist.
      Expected result: TCP connections to public IPs → INFO if only
      recognized processes are present.



    CHANGELOG v5.0.1 (hotfix after a real-machine run, 2026-06-29):

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
       On a CPU not compatible with SAC (e.g. Kaby Lake, predates the
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
      After analyzing real events on a real machine: every 4648 event comes
      from svchost.exe / winlogon.exe / wininit.exe to localhost (accounts
      DWM-1, UMFD-0/1, the user's own account) — normal system noise generated at session
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
         "My Scripts\Script.ps1" and fails silently, leaving
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
#  AUTO-ELEVATION
# ──────────────────────────────────────────────
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal(
    [Security.Principal.WindowsIdentity]::GetCurrent()
)

if (-not $currentPrincipal.IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)) {

    $ArgList = "-ExecutionPolicy Bypass -NoProfile -File `"$PSCommandPath`""
    if ($Silent)   { $ArgList += " -Silent" }
    if ($SelfTest) { $ArgList += " -SelfTest" }
    if ($Category) { $ArgList += " -Category " + (($Category | ForEach-Object { "`"$_`"" }) -join ",") }

    Start-Process powershell.exe -Verb RunAs -ArgumentList $ArgList
    exit
}

# NOTE v5.6.0: the former "Set-ExecutionPolicy Bypass -Scope Process" was removed. The script is
# already running (so the policy let it start), the elevated relaunch above passes
# -ExecutionPolicy Bypass itself, and the call only produced an error when a GPO controls the policy.

# ──────────────────────────────────────────────
#  CONFIGURATION
# ──────────────────────────────────────────────
$ScriptVersion  = "5.7.5"
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

# NOTE v5.7.0: Windows 11 lifecycle table (end-of-updates dates) used by the "Windows build support
# status" check (section 2). Source: Microsoft Learn, "Windows 11 release information" and
# "Supported versions of Windows client" (rows 26H2, 25H2), and the Microsoft Lifecycle page "Windows 11
# Home and Pro" (25H2 and 24H2 Home/Pro dates confirmed there); the 24H2 Enterprise/Education date comes
# from the Microsoft message center reminder MC1454882 and is still to be re-checked on the Lifecycle page
# "Windows 11 Enterprise and Education". Update this table (and
# the date below) when Microsoft publishes a new version: after 6 months without an update the
# check no longer answers OK (see Get-WindowsLifecycleStatus).
# HomePro = Home / Pro (24 months), EntEdu = Enterprise / Education (36 months).
$WindowsLifecycleTableDate = [datetime]"2026-11-19"
$WindowsLifecycleTable = @(
    [PSCustomObject]@{ Build = 26300; Version = "26H2"; HomePro = [datetime]"2028-10-10"; EntEdu = [datetime]"2029-10-09" }
    [PSCustomObject]@{ Build = 26200; Version = "25H2"; HomePro = [datetime]"2027-10-12"; EntEdu = [datetime]"2028-10-10" }
    [PSCustomObject]@{ Build = 26100; Version = "24H2"; HomePro = [datetime]"2026-10-13"; EntEdu = [datetime]"2027-10-12" }
)
# 21H2 (22000), 22H2 (22621) and 23H2 (22631): out of support for every edition
# (the latest end date, 23H2 Enterprise/Education, was 2026-11-10).
$WindowsLifecycleEndedBuilds = @(22000, 22621, 22631)

# NOTE v5.5.0: when $true, findings on the checks added in v5.5.0 end with a
# "Fix with Toolbox-SystemCommands > Quick security > '<command>'" hint. This
# script never changes anything itself; the hint just names the Toolbox command
# that does. Set to $false to hide the hints (e.g. if the Toolbox isn't used).
$ShowToolboxHints = $true

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
    "23_NameResolution"      = @("Network")
    "24_DefenderProtections" = @("Defender")
    "25_PowerShell2"         = @("PowerShell")
    "26_RemoteServices"      = @("Services")
    "27_Credentials"         = @("Accounts")
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

# NOTE v5.5.0: single table of the Toolbox-SystemCommands commands that the
# v5.5.0 checks point to (Quick security category, English catalog). Keeping
# them in one place means a renamed Toolbox command is a one-line fix here.
$ToolboxLabels = @{
    NameResolutionFix   = "Disable legacy name resolution (LLMNR / NetBIOS / mDNS)"
    IPv6TunnelsFix      = "Disable automatic IPv6 tunnels"
    DefenderDepth       = "Defender in depth (Tamper, PUA, cloud, exclusions)"
    PowerShell2Fix      = "Disable PowerShell 2.0"
    RemoteServicesFix   = "Disable Remote Registry and WebClient"
    RemoteServicesState = "Remote access services - state"
    AutologonFix        = "Disable automatic logon (Winlogon)"
}

# Returns the sentence appended to the detail of a finding, naming the matching
# Toolbox-SystemCommands command: -Mode Fix -> "Fix with ...", -Mode Check ->
# "Details in ..." (read-only command, for settings that can't be fixed by
# script). Returns "" when hints are disabled or the key is unknown.
function Get-ToolboxHint {
    param(
        [string]$Key,
        [ValidateSet("Fix","Check")][string]$Mode = "Fix"
    )
    if (-not $ShowToolboxHints) { return "" }
    if (-not $ToolboxLabels.ContainsKey($Key)) { return "" }
    $verb = if ($Mode -eq "Fix") { "Fix with" } else { "Details in" }
    return " $verb Toolbox-SystemCommands > Quick security > '$($ToolboxLabels[$Key])'."
}

# ──────────────────────────────────────────────
#  DEFENDER SETTINGS REFERENCE (v5.5.1)
# ──────────────────────────────────────────────
# NOTE v5.5.1: one entry per Defender setting audited by sections 4 and 24. It feeds
# two things, always from the same data so they can never disagree:
#   - the short "Detail" sentence of each row (what the CURRENT value means), and
#   - the expandable card of the HTML report: every possible value (the current one
#     highlighted), the command that reads it, the commands that change it, a note
#     on the trade-off, and the Microsoft Learn pages.
# The console stays one compact line per check; nothing here is printed there.
# Entry fields: Key = Get-MpPreference / Get-MpComputerStatus property name;
# Row = "Category|Check" of the result row the card is attached to; Values = Value
# (a number, True / False, or a range like 1-50) / Name / Meaning / optional Fix
# (command appended to the Detail when the value is not the recommended one);
# WinSecFr = the same path with the names shown by a French Windows Security app (the app is localized);
# WinSec = where to change it in the Windows Security app (the simplest way for most people;
# or the statement that the app has no switch for it); WinSecShort = the same as a short path
# for the Detail sentence (absent when there is no switch); Commands = only commands that turn
# a protection ON or tune it: none turns Defender protection off (see -SelfTest).
# PolicyPath + PolicyValue = the registry value that a Group Policy / Intune / hardening
# tool writes: when it exists it OVERRIDES Set-MpPreference (what Get-MpPreference
# shows is then the policy value, while the non-policy key can still hold an old,
# ignored value). The audit never changes anything: commands are shown, not run.
$script:RefState = @{}

$script:DefenderRef = @(
    @{
        Key   = 'IsTamperProtected'
        Row   = 'Defender|Tamper Protection'
        Title = 'Tamper Protection'
        What  = 'Tamper Protection stops other programs, including malware and scripts running as administrator, from switching Defender off or changing its main settings.'
        Read  = @('Get-MpComputerStatus | Select-Object IsTamperProtected')
        Values = @(
            @{ Value='True';  Name='Enabled';  Meaning='Other programs, including malware, cannot turn off the main Defender protections.' }
            @{ Value='False'; Name='Disabled'; Meaning='Malware, or a script running as administrator, can switch Defender off. Turn it on in Windows Security > Virus & threat protection > Manage settings > Tamper Protection (it cannot be changed by script).' }
        )
        Commands = @()
        WinSec = 'Windows Security > Virus & threat protection > Manage settings > Tamper Protection (on/off switch).'
        WinSecFr = 'Sécurité Windows > Protection contre les virus et menaces > Paramètres de protection contre les virus et menaces > Protection contre les falsifications'
        Note  = 'It can only be changed from the Windows Security app (or by an organization through Intune or the Defender portal): a script cannot change it, on purpose. While it is on, it can also block changes made with Set-MpPreference.'
        Links = @(
            @{ Label='MS Learn: Tamper protection'; Url='https://learn.microsoft.com/en-us/defender-endpoint/tamper-protection-overview' }
        )
    }
    @{
        Key   = 'DisableRealtimeMonitoring'
        Row   = 'Antivirus|Real-time protection'
        Title = 'Real-time protection'
        What  = 'Real-time protection scans files as they are opened, downloaded or run. The setting is named the other way round: DisableRealtimeMonitoring = False means the protection is ON.'
        Read  = @('Get-MpPreference | Select-Object DisableRealtimeMonitoring', '(Get-MpComputerStatus).RealTimeProtectionEnabled')
        Values = @(
            @{ Value='False'; Name='Protection on';  Meaning='Real-time protection is on: files are scanned as they are opened, downloaded or run (DisableRealtimeMonitoring = False).' }
            @{ Value='True';  Name='Protection off'; Meaning='Real-time protection is off: threats are only found by scans you start or schedule, so malware can run unnoticed.'; Fix='Set-MpPreference -DisableRealtimeMonitoring $false' }
        )
        Commands = @('Set-MpPreference -DisableRealtimeMonitoring $false   # turn it on')
        WinSec = 'Windows Security > Virus & threat protection > Manage settings > Real-time protection (on/off switch). The simplest way to turn it back on.'
        WinSecShort = 'Windows Security > Virus & threat protection > Manage settings > Real-time protection'
        WinSecFr = 'Sécurité Windows > Protection contre les virus et menaces > Paramètres de protection contre les virus et menaces > Protection en temps réel'
        Note  = 'Do not leave it off: the PC is then exposed to malware. Windows turns it back on by itself after a while, and Tamper Protection can block attempts to turn it off with a script. That is why this audit only shows the command that turns it ON.'
        PolicyPath  = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection'
        PolicyValue = 'DisableRealtimeMonitoring'
        Links = @(
            @{ Label='MS Learn: Set-MpPreference'; Url='https://learn.microsoft.com/en-us/powershell/module/defender/set-mppreference' }
            @{ Label='MS Learn: Defender Antivirus with PowerShell'; Url='https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-antivirus-using-powershell' }
        )
    }
    @{
        Key   = 'MAPSReporting'
        Row   = 'Defender|Cloud protection (MAPS)'
        Title = 'Cloud-delivered protection (MAPS)'
        What  = 'Defender can ask the Microsoft cloud about files it does not know yet, and the cloud answers in seconds, long before a signature update would. MAPS (Microsoft Active Protection Service) is the setting that turns this on and decides how much information is shared.'
        Read  = @('Get-MpPreference | Select-Object MAPSReporting')
        Values = @(
            @{ Value='0'; Name='Disabled'; Meaning='Cloud protection is off: Defender relies only on the signatures stored on this PC and does not ask the cloud about unknown files, which weakens detection of brand-new threats.'; Fix='Set-MpPreference -MAPSReporting Advanced' }
            @{ Value='1'; Name='Basic';    Meaning='Cloud protection is on (basic membership): Defender asks the cloud about unknown files and sends basic information about detected threats: where the software came from, the action taken and whether it worked.' }
            @{ Value='2'; Name='Advanced'; Meaning='Cloud protection is on (advanced membership): same as Basic, plus more detail about malicious or unwanted software (its location, file names, how it behaves). This helps Microsoft detect new threats faster; the trade-off is that a little more information leaves the PC.' }
        )
        Commands = @('Set-MpPreference -MAPSReporting Advanced   # most protection', 'Set-MpPreference -MAPSReporting Basic      # less information shared')
        WinSec = 'Windows Security > Virus & threat protection > Manage settings > Cloud-delivered protection (on/off switch). The switch only turns it on or off: choosing the Basic level needs PowerShell.'
        WinSecShort = 'Windows Security > Virus & threat protection > Manage settings > Cloud-delivered protection'
        WinSecFr = 'Sécurité Windows > Protection contre les virus et menaces > Paramètres de protection contre les virus et menaces > Protection dans le cloud'
        Note  = 'The four cloud settings below (sample submission, block at first sight, block level, extended timeout) only work while this one is not Disabled.'
        PolicyPath  = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet'
        PolicyValue = 'SpynetReporting'
        Links = @(
            @{ Label='MS Learn: Turn on cloud protection'; Url='https://learn.microsoft.com/en-us/defender-endpoint/cloud-protection-configure' }
            @{ Label='MS Learn: Cloud protection and sample submission'; Url='https://learn.microsoft.com/en-us/defender-endpoint/cloud-protection-microsoft-antivirus-sample-submission' }
            @{ Label='MS Learn: Set-MpPreference'; Url='https://learn.microsoft.com/en-us/powershell/module/defender/set-mppreference' }
        )
    }
    @{
        Key   = 'SubmitSamplesConsent'
        Row   = 'Defender|Cloud sample submission'
        Title = 'Automatic sample submission'
        What  = 'When Defender finds a suspicious file it cannot judge on its own, it can send a copy (a sample) to Microsoft for analysis. This setting decides whether that happens automatically, only after asking you, or never.'
        Read  = @('Get-MpPreference | Select-Object SubmitSamplesConsent')
        Values = @(
            @{ Value='0'; Name='Always prompt';     Meaning='Windows asks before sending any file. Microsoft notes that this lowers the protection level of the device, because suspicious files are not analyzed automatically.' }
            @{ Value='1'; Name='Send safe samples'; Meaning='Suspicious files that are unlikely to contain personal data are sent automatically; Windows asks before sending the others. A balance between protection and privacy.' }
            @{ Value='2'; Name='Never send';        Meaning='No file is ever sent. Microsoft states that block at first sight then does not work and that cloud analysis is limited to file metadata. A valid privacy choice, with weaker protection against brand-new threats.' }
            @{ Value='3'; Name='Send all samples';  Meaning='Every suspicious file is sent automatically, even if it may contain personal data. The strongest cloud analysis, the least privacy.' }
        )
        Commands = @('Set-MpPreference -SubmitSamplesConsent SendSafeSamples', 'Set-MpPreference -SubmitSamplesConsent SendAllSamples', 'Set-MpPreference -SubmitSamplesConsent NeverSend   # privacy choice: block at first sight stops working')
        WinSec = 'Windows Security > Virus & threat protection > Manage settings > Automatic sample submission (on/off switch). The switch only turns it on or off: the other levels (all samples, never send) need PowerShell.'
        WinSecShort = 'Windows Security > Virus & threat protection > Manage settings > Automatic sample submission'
        WinSecFr = 'Sécurité Windows > Protection contre les virus et menaces > Paramètres de protection contre les virus et menaces > Envoi automatique d’’un échantillon'
        Note  = 'Block at first sight needs automatic sending (value 1 or 3). Nothing is sent while cloud protection (MAPS) is Disabled. Choosing between privacy and protection is yours: this audit reports it as information, not as a problem.'
        PolicyPath  = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet'
        PolicyValue = 'SubmitSamplesConsent'
        Links = @(
            @{ Label='MS Learn: Cloud protection and sample submission'; Url='https://learn.microsoft.com/en-us/defender-endpoint/cloud-protection-microsoft-antivirus-sample-submission' }
            @{ Label='MS Learn: Turn on cloud protection'; Url='https://learn.microsoft.com/en-us/defender-endpoint/cloud-protection-configure' }
            @{ Label='MS Learn: Set-MpPreference'; Url='https://learn.microsoft.com/en-us/powershell/module/defender/set-mppreference' }
        )
    }
    @{
        Key   = 'CloudBlockLevel'
        Row   = 'Defender|Cloud block level'
        Title = 'Cloud block level'
        What  = 'How aggressively Defender blocks and scans suspicious files while it waits for the cloud verdict. A higher level catches more unknown threats, at the price of more false alarms (legitimate files wrongly blocked).'
        Read  = @('Get-MpPreference | Select-Object CloudBlockLevel')
        Values = @(
            @{ Value='0'; Name='Default';        Meaning='Microsoft standard blocking level: nothing extra is forced. A good choice for most people.' }
            @{ Value='1'; Name='Moderate';       Meaning='Less aggressive than the default: only detections the cloud is very sure about are blocked.' }
            @{ Value='2'; Name='High';           Meaning='A strong level of detection: unknown files are blocked more aggressively than by default.' }
            @{ Value='4'; Name='High+';          Meaning='High, plus extra protection measures. Microsoft warns it might affect performance and increase false positives.' }
            @{ Value='6'; Name='Zero tolerance'; Meaning='Blocks every unknown executable until the cloud has confirmed it is safe. Maximum protection, but new or rare legitimate programs may be blocked or delayed.' }
        )
        Commands = @('Set-MpPreference -CloudBlockLevel Default', 'Set-MpPreference -CloudBlockLevel Moderate', 'Set-MpPreference -CloudBlockLevel High', 'Set-MpPreference -CloudBlockLevel HighPlus', 'Set-MpPreference -CloudBlockLevel ZeroTolerance')
        WinSec = 'no switch for this setting. Use PowerShell, Group Policy or Intune.'
        Note  = 'Needs cloud protection (MAPS) to be on. Raise it step by step: if a program you trust gets blocked, go back one level.'
        PolicyPath  = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine'
        PolicyValue = 'MpCloudBlockLevel'
        Links = @(
            @{ Label='MS Learn: Specify the cloud protection level'; Url='https://learn.microsoft.com/en-us/defender-endpoint/cloud-protection-configure#specify-the-cloud-protection-level' }
            @{ Label='MS Learn: Set-MpPreference'; Url='https://learn.microsoft.com/en-us/powershell/module/defender/set-mppreference' }
        )
    }
    @{
        Key   = 'CloudExtendedTimeout'
        Row   = 'Defender|Cloud extended timeout'
        Title = 'Cloud extended timeout'
        What  = 'While the cloud analyzes a suspicious file, Defender holds the file back for 10 seconds by default. This setting ADDS extra seconds (0 to 50) on top of those 10, so the maximum wait is 10 + the value, up to 60 seconds.'
        Read  = @('Get-MpPreference | Select-Object CloudExtendedTimeout')
        Values = @(
            @{ Value='0';    Name='No extra time';  Meaning='A suspicious file is held at most the default 10 seconds while the cloud checks it.' }
            @{ Value='1-50'; Name='Extra seconds';  Meaning='Extra seconds added to the default 10: 20 = up to about 30 seconds, 50 = up to 60 seconds (the maximum). More time lets the cloud analyze deeper, but the first launch of an unknown program may feel slower.' }
        )
        Commands = @('Set-MpPreference -CloudExtendedTimeout 20   # any value from 0 to 50', 'Set-MpPreference -CloudExtendedTimeout 0    # back to the default 10 seconds')
        WinSec = 'no switch for this setting. Use PowerShell, Group Policy or Intune.'
        Note  = 'Microsoft requires cloud protection, block at first sight and automatic sample submission to be enabled for this to apply.'
        PolicyPath  = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine'
        PolicyValue = 'MpBafsExtendedTimeout'
        Links = @(
            @{ Label='MS Learn: Configure the cloud block timeout'; Url='https://learn.microsoft.com/en-us/defender-endpoint/configure-cloud-block-timeout-period-microsoft-defender-antivirus' }
            @{ Label='MS Learn: Set-MpPreference'; Url='https://learn.microsoft.com/en-us/powershell/module/defender/set-mppreference' }
        )
    }
    @{
        Key   = 'EnableControlledFolderAccess'
        Row   = 'Defender|Controlled Folder Access (ransomware protection)'
        Title = 'Controlled Folder Access (ransomware protection)'
        What  = 'Controlled Folder Access stops programs that Defender does not trust from changing or deleting files in protected folders (Documents, Pictures, Videos, Desktop...). It is Windows'' built-in protection against ransomware, which works by encrypting exactly those files. It is OFF by default.'
        Read  = @('Get-MpPreference | Select-Object EnableControlledFolderAccess')
        Values = @(
            @{ Value='0'; Name='Disabled'; Meaning='Ransomware protection is off (the Windows default): any program can modify the files in your personal folders, which is exactly what ransomware needs.'; Fix='Set-MpPreference -EnableControlledFolderAccess Enabled' }
            @{ Value='1'; Name='Enabled';  Meaning='Untrusted programs are blocked from changing files in the protected folders. Windows shows a notification when it blocks one.' }
            @{ Value='2'; Name='Audit mode'; Meaning='Nothing is blocked: attempts are only recorded in the event log. Useful to see which of your programs would be blocked before switching to Enabled.'; Fix='Set-MpPreference -EnableControlledFolderAccess Enabled' }
            @{ Value='3'; Name='Block disk modification only'; Meaning='Only writes to the disk sectors themselves (what some wipers and boot-sector malware do) are blocked; files in the protected folders are not protected.'; Fix='Set-MpPreference -EnableControlledFolderAccess Enabled' }
            @{ Value='4'; Name='Audit disk modification only'; Meaning='Direct disk writes are only recorded, nothing is blocked.'; Fix='Set-MpPreference -EnableControlledFolderAccess Enabled' }
        )
        Commands = @('Set-MpPreference -EnableControlledFolderAccess Enabled   # block untrusted changes', 'Set-MpPreference -EnableControlledFolderAccess AuditMode   # only log, to assess the impact first')
        WinSec = 'Windows Security > Virus & threat protection > Ransomware protection > Manage ransomware protection > Controlled folder access (on/off switch). Turning it on there is the same as Enabled.'
        WinSecShort = 'Windows Security > Virus & threat protection > Ransomware protection > Manage ransomware protection > Controlled folder access'
        WinSecFr = 'Sécurité Windows > Protection contre les virus et menaces > Protection contre les ransomware > Gérer la protection contre les ransomware > Accès contrôlé aux dossiers'
        Note  = 'Some legitimate programs (games, backup tools, editors saving into Documents) can be blocked at first: start with Audit mode, or allow the program in the same Windows Security page ("Allow an app through Controlled folder access").'
        PolicyPath  = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access'
        PolicyValue = 'EnableControlledFolderAccess'
        Links = @(
            @{ Label='MS Learn: Controlled folder access overview'; Url='https://learn.microsoft.com/en-us/defender-endpoint/controlled-folder-access-overview' }
            @{ Label='MS Learn: Configure controlled folder access'; Url='https://learn.microsoft.com/en-us/defender-endpoint/controlled-folder-access-configure' }
            @{ Label='MS Learn: Set-MpPreference'; Url='https://learn.microsoft.com/en-us/powershell/module/defender/set-mppreference' }
        )
    }
    @{
        Key   = 'DisableBlockAtFirstSeen'
        Row   = 'Defender|Block at first sight'
        Title = 'Block at first sight'
        What  = 'Block at first sight holds a brand-new file downloaded from the Internet while the cloud analyzes it, and blocks it within seconds if it is malware. The setting is named the other way round: DisableBlockAtFirstSeen = False means the feature is ON.'
        Read  = @('Get-MpPreference | Select-Object DisableBlockAtFirstSeen')
        Values = @(
            @{ Value='False'; Name='Enabled';  Meaning='Block at first sight is on: new, never-seen files can be held and blocked within seconds if the cloud finds them malicious.' }
            @{ Value='True';  Name='Disabled'; Meaning='Block at first sight is off: protection against brand-new malware is lower. Microsoft recommends not turning it off permanently.'; Fix='Set-MpPreference -DisableBlockAtFirstSeen $false' }
        )
        Commands = @('Set-MpPreference -DisableBlockAtFirstSeen $false   # turn it on')
        WinSec = 'Turn on Cloud-delivered protection AND Automatic sample submission (Windows Security > Virus & threat protection > Manage settings): block at first sight then turns on by itself, it has no switch of its own.'
        WinSecShort = 'Windows Security > Virus & threat protection > Manage settings: turn on Cloud-delivered protection and Automatic sample submission, and block at first sight turns on by itself'
        WinSecFr = 'Sécurité Windows > Protection contre les virus et menaces > Paramètres de protection contre les virus et menaces : activez « Protection dans le cloud » et « Envoi automatique d’’un échantillon », block at first sight s’’active alors tout seul'
        Note  = 'It only works while cloud protection is on AND samples are sent automatically (sample submission set to Send safe samples or Send all samples).'
        PolicyPath  = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet'
        PolicyValue = 'DisableBlockAtFirstSeen'
        RawPrefix   = 'DisableBlockAtFirstSeen'
        Links = @(
            @{ Label='MS Learn: Turn on block at first sight'; Url='https://learn.microsoft.com/en-us/defender-endpoint/configure-block-at-first-sight-microsoft-defender-antivirus' }
            @{ Label='MS Learn: Cloud protection and sample submission'; Url='https://learn.microsoft.com/en-us/defender-endpoint/cloud-protection-microsoft-antivirus-sample-submission' }
        )
    }
    @{
        Key   = 'PUAProtection'
        Row   = 'Defender|PUA protection'
        Title = 'PUA protection (potentially unwanted applications)'
        What  = 'PUA are programs that are not exactly malware but that most people do not want: adware, bundled toolbars, fake system optimizers, installers that add extra software. This setting decides whether Defender blocks them.'
        Read  = @('Get-MpPreference | Select-Object PUAProtection')
        Values = @(
            @{ Value='0'; Name='Disabled';       Meaning='Potentially unwanted applications (adware, bundled toolbars, fake optimizers) are not blocked.'; Fix='Set-MpPreference -PUAProtection Enabled' }
            @{ Value='1'; Name='Enabled, block'; Meaning='Potentially unwanted applications (adware, bundled toolbars, fake optimizers) are blocked.' }
            @{ Value='2'; Name='Audit mode';     Meaning='Potentially unwanted applications are detected and logged but not blocked.'; Fix='Set-MpPreference -PUAProtection Enabled' }
        )
        Commands = @('Set-MpPreference -PUAProtection Enabled     # block', 'Set-MpPreference -PUAProtection AuditMode   # log only')
        WinSec = 'Windows Security > App & browser control > Reputation-based protection > Potentially unwanted app blocking: switch it on (it is a single switch). Audit mode needs PowerShell.'
        WinSecShort = 'Windows Security > App & browser control > Reputation-based protection > Potentially unwanted app blocking'
        WinSecFr = 'Sécurité Windows > Contrôle des applications et du navigateur > Protection basée sur la réputation > Blocage d’’application potentiellement indésirable'
        Note  = 'Audit mode is a good way to see what would be blocked before switching to Enabled. This is an optional layer, so it is reported as information when it is not on.'
        PolicyPath  = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender'
        PolicyValue = 'PUAProtection'
        Links = @(
            @{ Label='MS Learn: Detect and block potentially unwanted apps'; Url='https://learn.microsoft.com/en-us/defender-endpoint/detect-block-potentially-unwanted-apps-microsoft-defender-antivirus' }
            @{ Label='MS Learn: Set-MpPreference'; Url='https://learn.microsoft.com/en-us/powershell/module/defender/set-mppreference' }
        )
    }
    @{
        Key   = 'EnableNetworkProtection'
        Row   = 'Defender|Network Protection'
        Title = 'Network Protection'
        What  = 'Network Protection blocks connections to known malicious or phishing domains and addresses, in every application (not only in the browser).'
        Read  = @('Get-MpPreference | Select-Object EnableNetworkProtection')
        Values = @(
            @{ Value='0'; Name='Disabled';       Meaning='Network Protection is an optional layer (off by default) that blocks connections to malicious domains in every application. It is off.'; Fix='Set-MpPreference -EnableNetworkProtection Enabled' }
            @{ Value='1'; Name='Enabled, block'; Meaning='Connections to known malicious domains and addresses are blocked, in every application.' }
            @{ Value='2'; Name='Audit mode';     Meaning='Malicious connections are logged but not blocked.'; Fix='Set-MpPreference -EnableNetworkProtection Enabled' }
        )
        Commands = @('Set-MpPreference -EnableNetworkProtection Enabled     # block', 'Set-MpPreference -EnableNetworkProtection AuditMode   # log only')
        WinSec = 'no switch for this setting. Use PowerShell, Group Policy or Intune.'
        Note  = 'It can occasionally interfere with an application or a self-signed internal site: try Audit mode first, check the events, then switch to Enabled. Reported as information when it is not on, since it is optional.'
        PolicyPath  = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection'
        PolicyValue = 'EnableNetworkProtection'
        Links = @(
            @{ Label='MS Learn: Network protection'; Url='https://learn.microsoft.com/en-us/defender-endpoint/network-protection' }
            @{ Label='MS Learn: Enable network protection'; Url='https://learn.microsoft.com/en-us/defender-endpoint/enable-network-protection' }
        )
    }
)

function Get-SettingRefByKey {
    param([string]$Key)
    foreach ($r in $script:DefenderRef) { if ($r.Key -eq $Key) { return $r } }
    return $null
}

# The reference entry attached to a result row (by Category + Check), or $null.
function Get-SettingRef {
    param([string]$Category, [string]$Check)
    $rowKey = "$Category|$Check"
    foreach ($r in $script:DefenderRef) { if ($r.Row -eq $rowKey) { return $r } }
    return $null
}

# Does the current value match this entry of the Values table? Exact text match
# (numbers and True / False are compared as text), or inside a "min-max" range.
function Test-RefValueMatch {
    param($Entry, [string]$Current)
    if ([string]::IsNullOrEmpty($Current)) { return $false }
    if ("$($Entry.Value)" -eq $Current) { return $true }
    if ("$($Entry.Value)" -match '^(\d+)-(\d+)$') {
        $lo = [int]$Matches[1]; $hi = [int]$Matches[2]
        $n = 0
        if ([int]::TryParse($Current, [ref]$n)) { return ($n -ge $lo -and $n -le $hi) }
    }
    return $false
}

# Value of the registry policy that manages a setting, or $null when no policy
# sets it (the usual case on a personal machine). Never throws.
function Get-DefenderPolicyValue {
    param($Ref)
    if ($null -eq $Ref -or -not $Ref.PolicyPath -or -not $Ref.PolicyValue) { return $null }
    try {
        $p = Get-ItemProperty -Path $Ref.PolicyPath -Name $Ref.PolicyValue -ErrorAction Stop
        return $p.($Ref.PolicyValue)
    } catch { return $null }
}

# Remembers the current value (and the managing policy, if any) of a setting so
# the HTML card can highlight it.
function Set-SettingState {
    param([string]$Key, $Current)
    $pol = Get-DefenderPolicyValue (Get-SettingRefByKey $Key)
    $script:RefState[$Key] = @{ Current = "$Current"; Policy = $pol }
}

# "Advanced (2)", "Enabled, block (1)", "Enabled (DisableBlockAtFirstSeen = False)":
# the plain-language name, then the raw value exactly as Get-MpPreference shows it.
function Format-SettingValue {
    param([string]$Key, $Current)
    $ref = Get-SettingRefByKey $Key
    $cur = "$Current"
    if ($null -ne $ref) {
        foreach ($v in $ref.Values) {
            if (Test-RefValueMatch $v $cur) {
                $prefix = if ($ref.RawPrefix) { "$($ref.RawPrefix) = " } else { "" }
                return "$($v.Name) ($prefix$cur)"
            }
        }
    }
    return "Unknown ($cur)"
}

# Short sentence for the Detail column: what the CURRENT value means, the command
# to change it when it is not the recommended one, and a policy warning if a
# policy overrides Set-MpPreference.
function Get-SettingDetail {
    param([string]$Key, $Current, [string]$Extra = "")
    $ref = Get-SettingRefByKey $Key
    if ($null -eq $ref) { return $Extra.Trim() }
    $cur  = "$Current"
    $text = ""
    foreach ($v in $ref.Values) {
        if (Test-RefValueMatch $v $cur) {
            $text = $v.Meaning
            if ($v.Fix) {
                if ($ref.WinSecShort) { $text += " Easiest: $($ref.WinSecShort). Or, in an elevated PowerShell: $($v.Fix)." }
                elseif ($ref.WinSec -match '^no switch') { $text += " Windows Security has no switch for this one; in an elevated PowerShell: $($v.Fix)." }
                else          { $text += " To change it (elevated PowerShell): $($v.Fix)." }
            }
            break
        }
    }
    $state = $script:RefState[$Key]
    if ($state -and $null -ne $state.Policy) {
        $text += " A policy sets this value ($($ref.PolicyValue) = $($state.Policy)): Set-MpPreference has no effect while the policy exists."
    }
    return ("$text $Extra").Trim()
}

# One Defender setting = state for the HTML card + one result row.
function Add-DefenderSettingResult {
    param(
        [string]$Check,
        [string]$Key,
        $Current,
        [string]$Status,
        [string]$Value = "",
        [string]$Extra = "",
        [switch]$Hint
    )
    Set-SettingState -Key $Key -Current $Current
    if (-not $Value) { $Value = Format-SettingValue -Key $Key -Current $Current }
    $detail = Get-SettingDetail -Key $Key -Current $Current -Extra $Extra
    if ($Hint -and $Status -ne "OK") { $detail += (Get-ToolboxHint "DefenderDepth" -Mode Check) }
    Add-Result "Defender" $Check $Value $Status $detail
}

# HTML of the card attached to a result row ("" when the row has none): the Microsoft
# links (always visible), then a collapsed block with every possible value (the
# current one highlighted), the commands, and the notes. Everything is HTML-escaped.
function Get-SettingRefHtml {
    param([string]$Category, [string]$Check)
    $ref = Get-SettingRef -Category $Category -Check $Check
    if ($null -eq $ref) { return "" }
    $state = $script:RefState[$ref.Key]
    $cur = ""; $pol = $null
    if ($state) { $cur = "$($state.Current)"; $pol = $state.Policy }

    $sb = [System.Text.StringBuilder]::new()

    if (@($ref.Links).Count -gt 0) {
        $itemsHtml = ($ref.Links | ForEach-Object { "<a href='$(He $_.Url)' target='_blank' rel='noopener' class='help-link'>$(He $_.Label)</a>" }) -join ""
        [void]$sb.Append("<div class='help-links'>$itemsHtml</div>")
    }

    [void]$sb.Append("<details class='ref'><summary>All possible values and PowerShell commands</summary>")
    [void]$sb.Append("<p>$(He $ref.What)</p>")
    $hasSwitch = [bool]$ref.WinSecShort -or ($ref.WinSec -and $ref.WinSec -notmatch '^no switch')
    if ($ref.WinSec) {
        $easyLabel = if ($hasSwitch) { 'Easiest way:' } else { 'In Windows Security:' }
        $frHtml = if ($ref.WinSecFr) { "<br><span class='ref-fr'>On a French Windows: $(He $ref.WinSecFr)</span>" } else { "" }
        [void]$sb.Append("<p class='ref-easy'><b>$easyLabel</b> $(He $ref.WinSec)$frHtml</p>")
    }

    [void]$sb.Append("<table><thead><tr><th>Value</th><th>Meaning</th></tr></thead><tbody>")
    foreach ($v in $ref.Values) {
        $isCur = Test-RefValueMatch $v $cur
        $rowCls = if ($isCur) { " class='cur'" } else { "" }
        $mark   = if ($isCur) { " <span class='ref-cur'>&#9664; your value</span>" } else { "" }
        [void]$sb.Append("<tr$rowCls><td><code>$(He $v.Value)</code><br>$(He $v.Name)$mark</td><td>$(He $v.Meaning)</td></tr>")
    }
    [void]$sb.Append("</tbody></table>")

    # Read the current value (+ is a policy managing it?)
    $readLines = @($ref.Read)
    if ($ref.PolicyPath -and $ref.PolicyValue) {
        $readLines += "# Is a policy managing it? (an error means no policy)"
        $readLines += "Get-ItemProperty -Path '$($ref.PolicyPath)' -Name '$($ref.PolicyValue)'"
    }
    [void]$sb.Append("<p class='ref-label'>Read the current value</p><pre class='cmd'>$(He ($readLines -join "`n"))</pre>")

    if (@($ref.Commands).Count -gt 0) {
        [void]$sb.Append("<p class='ref-label'>$(if ($hasSwitch) { 'Or with PowerShell (run as administrator)' } else { 'Change it with PowerShell (run as administrator)' })</p><pre class='cmd'>$(He (@($ref.Commands) -join "`n"))</pre>")
    }

    if ($null -ne $pol) {
        [void]$sb.Append("<p class='ref-warn'>&#9888; A policy sets this value ($(He $ref.PolicyValue) = $(He "$pol")): it overrides Set-MpPreference, so the commands above have no effect until the policy is removed (use the tool or the Group Policy / Intune setting that created it). A Windows Security switch for it may be greyed out or switch back.</p>")
    } elseif ($ref.PolicyPath) {
        [void]$sb.Append("<p>If Group Policy, Intune or a hardening tool manages this setting, it overrides Set-MpPreference and the commands above have no effect: the policy check above tells you.</p>")
    }

    if ($ref.Note) { [void]$sb.Append("<p>$(He $ref.Note)</p>") }
    [void]$sb.Append("<p>This audit only reads settings: it never changes anything.</p>")
    [void]$sb.Append("</details>")
    return $sb.ToString()
}

# NOTE v5.5.0: Windows optional features, read ONCE per run (a DISM call takes a
# few seconds) and shared by sections 25 and 26. $script:WinFeaturesOK tells an
# unreadable list apart from a genuinely absent feature - on Windows 11 24H2+,
# PowerShell 2.0 is absent, which is a good result, not an error.
$script:WinFeatures       = @()
$script:WinFeaturesLoaded = $false
$script:WinFeaturesOK     = $false
function Get-WinFeatures {
    if (-not $script:WinFeaturesLoaded) {
        $script:WinFeaturesLoaded = $true
        $oldProgress = $ProgressPreference
        $ProgressPreference = "SilentlyContinue"
        try {
            $script:WinFeatures   = @(Get-WindowsOptionalFeature -Online -ErrorAction Stop)
            $script:WinFeaturesOK = $true
        } catch {
            $script:WinFeatures   = @()
            $script:WinFeaturesOK = $false
        } finally {
            $ProgressPreference = $oldProgress
        }
    }
    return $script:WinFeatures
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
    # Verified manually (certificate thumbprints confirmed legitimate):
    "DDFB16CD4931C973A2037D3FC83A4D7D775D05E4" = "DigiCert Trusted Root G4 — major, widely deployed commercial CA"
    "BE36A4562FB2EE05DBB3D32323ADF445084ED656" = "Thawte Timestamping CA — legacy timestamping CA, expired but deliberately kept by Windows to validate the date of old signatures"
    "18F7C1FCC3090203FD5BAA2F861A754976C8DD25" = "VeriSign Time Stamping Service Root — same, expired legacy timestamping CA deliberately kept"
}

# Folders considered yours (your own scheduled scripts) — adjust as needed.
# Any scheduled task whose script sits under one of these paths won't be
# counted as suspicious. Tasks whose script is validly signed by a publisher in
# your Trusted Publishers store are recognized too (see $TrustedSignerSubjectMatch).
$TrustedScriptPathPatterns = @(
    "$env:USERPROFILE\Desktop\*",
    "$env:USERPROFILE\Documents\*",
    "$env:USERPROFILE\Scripts\*"
)
# OPTIONAL. Tasks whose script has a valid Authenticode signature from a publisher
# in your Trusted Publishers store are already recognized automatically, with no
# setting to edit. This text is an extra match on the signing certificate's
# Subject: leave it as is unless you want that, the placeholder never matches.
$TrustedSignerSubjectMatch = "YourCertificateName"

# OPTIONAL (v5.5.0: empty by default). Names of your own scheduled tasks to
# recognize regardless of their action. Matched by NAME ONLY: a malicious task
# given the same name would be ignored too, so leave it empty unless you need it.
# Tasks created by Winhance (folder \Winhance\, script under
# %ProgramData%\Winhance\Scripts) are recognized automatically, and only when
# the script can't be modified by a non-administrator (Test-WinhanceTaskTrusted).
$TrustedTaskNames = @()

# Create the output folder
# NOTE v5.5.0: not in -SelfTest mode, which promises "no report generated, no
# changes made" and used to create this folder on the Desktop as a side effect.
if (-not $SelfTest -and -not (Test-Path $OutputDir)) {
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

# NOTE v5.6.0: a run limited with -Category only covers a subset of the checks.
# Its score and results are not comparable with a full audit, so it neither
# compares itself with the baseline nor overwrites the baseline / history.
$IsFilteredRun = (@($Category).Count -gt 0)
if ($IsFilteredRun) { $PreviousAudit = $null }

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
    Add-Content -Path $ReportTXT -Value "[$timestamp] [$Level] $Message" -Encoding UTF8
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
    @{ Cat='Antivirus';      Pattern='Defender platform';        Links=@(
        @{ Label='MS Learn: Defender platform and engine updates'; Url='https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-antivirus-updates' }
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
        @{ Label='MS Learn: TLS registry settings (SCHANNEL)'; Url='https://learn.microsoft.com/en-us/windows-server/security/tls/tls-registry-settings' }
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
    @{ Cat='Network';        Pattern='NTLM restriction|LmCompatibilityLevel'; Links=@(        @{ Label='MS Learn: LAN Manager authentication level'; Url='https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/network-security-lan-manager-authentication-level' }
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
        @{ Label='MS Learn: Secure RDP connections'; Url='https://learn.microsoft.com/en-us/windows-server/remote/remote-desktop-services/remotepc/remote-desktop-allow-access' }
    )}
    @{ Cat='Network';        Pattern='Network shares';           Links=@(
        @{ Label='MS Learn: SMB share security'; Url='https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-security' }
    )}
    @{ Cat='Firewall';       Pattern='Sensitive port';             Links=@(
        @{ Label='MS Learn: Windows Firewall configuration'; Url='https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/configure' }
    )}
    @{ Cat='Firewall';       Pattern='.*';                        Links=@(
        @{ Label='MS Learn: Windows Defender Firewall'; Url='https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/' }
    )}
    @{ Cat='Password Policy';  Pattern='.*';                        Links=@(
        @{ Label='MS Learn: Password policy'; Url='https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/password-policy' }
    )}
    @{ Cat='Accounts';        Pattern='Local administrators';    Links=@(
        @{ Label='MS Learn: Local admin account best practices'; Url='https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-b--privileged-accounts-and-groups-in-active-directory' }
    )}
    @{ Cat='Accounts';        Pattern='.*';                        Links=@(
        @{ Label='MS Learn: Local accounts'; Url='https://learn.microsoft.com/en-us/windows/security/identity-protection/access-control/local-accounts' }
    )}
    @{ Cat='Defender';       Pattern='Exclusion';                 Links=@(
        @{ Label='MS Learn: Configure Defender exclusions'; Url='https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-antivirus-exclusions-configure' }
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
    @{ Cat='Updates';   Pattern='Windows build support';     Links=@(
        @{ Label='MS Learn: Windows 11 release information';        Url='https://learn.microsoft.com/en-us/windows/release-health/windows11-release-information' }
        @{ Label='MS Learn: Supported versions of Windows client'; Url='https://learn.microsoft.com/en-us/windows/release-health/supported-versions-windows-client' }
        @{ Label='MS Learn: Windows 11 Home and Pro lifecycle';    Url='https://learn.microsoft.com/en-us/lifecycle/products/windows-11-home-and-pro' }
        @{ Label='MS Learn: Windows 11 Enterprise and Education lifecycle'; Url='https://learn.microsoft.com/en-us/lifecycle/products/windows-11-enterprise-and-education' }
    )}
    @{ Cat='Updates';   Pattern='.*';                        Links=@(
        @{ Label='MS Learn: Troubleshoot Windows Update';             Url='https://learn.microsoft.com/en-us/troubleshoot/windows-client/installing-updates-features-roles/windows-update-issues-troubleshooting' }
    )}
    @{ Cat='Services';       Pattern='Non-system auto services'; Links=@(
        @{ Label='Sysinternals Autoruns — services';               Url='https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns' }
    )}
    @{ Cat='Services';       Pattern='.*';                        Links=@(
        @{ Label='MS Learn: Manage Windows services';          Url='https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/sc-query' }
    )}
    @{ Cat='System';        Pattern='Build|Uptime';              Links=@(
        @{ Label='MS Learn: Windows 11 build history';    Url='https://learn.microsoft.com/en-us/windows/release-health/windows11-release-information' }
        @{ Label='MS Learn: Windows 11 Home and Pro lifecycle';                Url='https://learn.microsoft.com/en-us/lifecycle/products/windows-11-home-and-pro' }
        @{ Label='MS Learn: Windows 11 Enterprise and Education lifecycle';    Url='https://learn.microsoft.com/en-us/lifecycle/products/windows-11-enterprise-and-education' }
    )}
    @{ Cat='Backup';     Pattern='Shadow Copy|VSS|Snapshots';   Links=@(
        @{ Label='MS Learn: Volume Shadow Copy Service overview';         Url='https://learn.microsoft.com/en-us/windows-server/storage/file-server/volume-shadow-copy-service' }
        @{ Label='MS Learn: Create a system restore point'; Url='https://support.microsoft.com/en-us/windows/experience/backup-recovery/system-protection' }
    )}
    @{ Cat='Certificates';    Pattern='expir';                      Links=@(
        @{ Label='MS Learn: Manage certificates with PowerShell';  Url='https://learn.microsoft.com/en-us/powershell/module/pki/' }
    )}
    @{ Cat='Network';         Pattern='IPv6';                       Links=@(
        @{ Label='MS Learn: IPv6 and Windows Defender Firewall';   Url='https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/' }
    )}
    @{ Cat='UEFI Security';  Pattern='Secure Boot certificates'; Links=@(
        @{ Label='Microsoft Support: Secure Boot certificate expiration and CA updates'; Url='https://support.microsoft.com/en-us/servicing/os/secure-boot/2025/06/windows-secure-boot-certificate-expiration-and-ca-updates' }
        @{ Label='Microsoft Support: sample detection script';        Url='https://support.microsoft.com/en-us/servicing/os/windows/2026/03/sample-detect-securebootcertupdatestatus-ps1-script' }
    )}
    @{ Cat='UEFI Security';  Pattern='Secure Boot';              Links=@(
        @{ Label='MS Learn: Secure Boot overview';         Url='https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/oem-secure-boot' }
        @{ Label='Microsoft Support: Windows 11 and Secure Boot';  Url='https://support.microsoft.com/en-us/windows/secure-boot-overview-a8ff1202-c0d9-42f5-940f-843abef64fad' }
    )}
    @{ Cat='UEFI Security';  Pattern='TPM';                      Links=@(
        @{ Label='MS Learn: TPM overview';                 Url='https://learn.microsoft.com/en-us/windows/security/hardware-security/tpm/trusted-platform-module-overview' }
        @{ Label='MS Learn: Troubleshoot TPM issues';          Url='https://learn.microsoft.com/en-us/windows/security/hardware-security/tpm/initialize-and-configure-ownership-of-the-tpm' }
    )}
    @{ Cat='Windows Hello';  Pattern='.*';                        Links=@(
        @{ Label='MS Learn: Windows Hello for Business overview'; Url='https://learn.microsoft.com/en-us/windows/security/identity-protection/hello-for-business/' }
        @{ Label='Microsoft Support: Learn about Windows Hello and set it up'; Url='https://support.microsoft.com/en-us/help/4028017' }
    )}
    @{ Cat='Defender';       Pattern='Tamper Protection';        Links=@(
        @{ Label='MS Learn: Tamper protection'; Url='https://learn.microsoft.com/en-us/defender-endpoint/tamper-protection-overview' }
    )}
    @{ Cat='Defender';       Pattern='PUA';                       Links=@(
        @{ Label='MS Learn: Detect and block potentially unwanted apps'; Url='https://learn.microsoft.com/en-us/defender-endpoint/detect-block-potentially-unwanted-apps-microsoft-defender-antivirus' }
    )}
    @{ Cat='Defender';       Pattern='Network Protection';        Links=@(
        @{ Label='MS Learn: Network protection'; Url='https://learn.microsoft.com/en-us/defender-endpoint/network-protection' }
        @{ Label='MS Learn: Enable network protection'; Url='https://learn.microsoft.com/en-us/defender-endpoint/enable-network-protection' }
    )}
    @{ Cat='PowerShell';     Pattern='PowerShell 2.0';            Links=@(
        @{ Label='Microsoft Support: PowerShell 2.0 removal from Windows'; Url='https://support.microsoft.com/help/5065506' }
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
            # NOTE v5.5.0: crt.sh only indexes the public Certificate Transparency logs.
            # It is useful for a certificate issued by a public CA, never for an
            # end-entity or self-issued certificate created locally, so it is only
            # offered for CA certificates.
            if ($Detail -notmatch 'Type: End entity') {
                $links.Add(@{ Label='crt.sh (public CT logs)'; Url="https://crt.sh/?q=$tp" })
            }
            # The thumbprint is the only identity that can't be forged: searching it
            # (exact phrase) is far more telling than searching a GUID-like name.
            $links.Add(@{ Label='Web search on this thumbprint'; Url="https://www.google.com/search?q=%22$tp%22" })
        }
        $links.Add(@{ Label='Microsoft root store participants'; Url='https://aka.ms/trustcertpartners' })
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
        # NOTE v5.6.0: a check that could not be performed (read error, feature
        # absent) must not raise the score: such INFO results are flagged and
        # left out of the score calculation (they stay visible in every report).
        Indeterminate = ($Status -eq "INFO" -and $Value -match '^(Unable to read|Unable to determine|Not available)')
    })
    # NOTE v5.0.9: $Message stays "$Category | $Check : $Value" for the TXT
    # file (format unchanged); the extra -Category/-Check/-Value only serve
    # console alignment in Write-Log.
    Write-Log "$Category | $Check : $Value" -Level $Status -Category $Category -Check $Check -Value $Value
}

# ──────────────────────────────────────────────
#  v5.6.0 HELPERS (pure functions, covered by -SelfTest)
# ──────────────────────────────────────────────

# Weighted score (0-100, not rounded) from a list of results. Same model as
# before: per-category rate (OK/INFO = 1, WARN = 0.5, FAIL = 0), weighted by
# category. Results flagged Indeterminate (check not performed) are ignored.
function Get-AuditScoreRaw {
    param($Results, [hashtable]$Weights)
    $stats = @{}
    foreach ($r in @($Results)) {
        if ($r.Indeterminate) { continue }
        $c = $r.Category
        if (-not $stats.ContainsKey($c)) { $stats[$c] = @{ Sum = 0.0; Count = 0 } }
        $v = switch ($r.Status) { "OK" { 1.0 } "INFO" { 1.0 } "WARN" { 0.5 } "FAIL" { 0.0 } default { 1.0 } }
        $stats[$c].Sum += $v
        $stats[$c].Count++
    }
    $num = 0.0; $den = 0.0
    foreach ($c in $stats.Keys) {
        $w = if ($Weights.ContainsKey($c)) { $Weights[$c] } else { 1.0 }
        $num += $w * ($stats[$c].Sum / $stats[$c].Count)
        $den += $w
    }
    if ($den -gt 0) { return (100.0 * $num / $den) } else { return 100.0 }
}

# CSV export: a cell starting with = + - @ (or a tab / CR) is interpreted as a
# formula by Excel / LibreOffice. Names of tasks, services, certificates or
# firewall rules are attacker-controllable, so such cells get a leading
# apostrophe. Plain numbers are left untouched.
function ConvertTo-SafeCsvCell {
    param($Value)
    if ($null -eq $Value) { return "" }
    $s = [string]$Value
    if ($s -match '^[=+\-@\t\r]' -and $s -notmatch '^[+\-]?\d+([.,]\d+)?$') { return "'" + $s }
    return $s
}

# UAC decision table. ConsentPromptBehaviorAdmin: 0 = elevate without prompt,
# 1 = credentials on the secure desktop, 2 = consent on the secure desktop,
# 3 = credentials, 4 = consent, 5 = consent for non-Windows binaries (default).
# A value that is not set means "Windows default", which is not a failure.
function Get-UacAssessment {
    param([ValidateSet("Consent","LUA","SecureDesktop")][string]$Setting, $Value)
    $n = $null
    if ($null -ne $Value -and "$Value" -match '^\d+$') { $n = [int]$Value }
    switch ($Setting) {
        "LUA" {
            if ($null -eq $n)  { return [PSCustomObject]@{ Value = "Not set (Windows default: enabled)"; Status = "INFO"; Detail = "EnableLUA is not defined; Windows then keeps UAC enabled" } }
            if ($n -eq 1)      { return [PSCustomObject]@{ Value = "Yes"; Status = "OK"; Detail = "" } }
            return [PSCustomObject]@{ Value = "NO"; Status = "FAIL"; Detail = "UAC disabled — critical risk!" }
        }
        "SecureDesktop" {
            if ($null -eq $n)  { return [PSCustomObject]@{ Value = "Not set (Windows default: enabled)"; Status = "INFO"; Detail = "PromptOnSecureDesktop is not defined; Windows then uses the secure desktop" } }
            if ($n -eq 1)      { return [PSCustomObject]@{ Value = "Enabled"; Status = "OK"; Detail = "" } }
            return [PSCustomObject]@{ Value = "Disabled"; Status = "WARN"; Detail = "UAC prompts are shown on the normal desktop, where other programs can interfere with them" }
        }
        default {
            $legend = "0 = no prompt (dangerous), 1 = credentials on the secure desktop, 2 = consent on the secure desktop, 3 = credentials, 4 = consent, 5 = consent for non-Windows binaries (default)"
            if ($null -eq $n) { return [PSCustomObject]@{ Value = "Not set (Windows default: 5)"; Status = "INFO"; Detail = "ConsentPromptBehaviorAdmin is not defined; Windows then uses 5. $legend" } }
            if ($n -eq 0)     { return [PSCustomObject]@{ Value = "$n"; Status = "FAIL"; Detail = "Administrators are elevated without any prompt. $legend" } }
            if ($n -le 2)     { return [PSCustomObject]@{ Value = "$n"; Status = "OK"; Detail = "Stricter than the default (prompt on the secure desktop). $legend" } }
            if ($n -le 5)     { return [PSCustomObject]@{ Value = "$n"; Status = "OK"; Detail = $legend } }
            return [PSCustomObject]@{ Value = "$n"; Status = "INFO"; Detail = "Unknown value. $legend" }
        }
    }
}

# Path normalisation without touching the disk (OS-independent, testable):
# expands %VARS%, strips \??\ and quotes, resolves \SystemRoot\, '.' and '..'.
function ConvertTo-NormalizedWinPath {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return "" }
    $p = [Environment]::ExpandEnvironmentVariables($Path.Trim().Trim('"')).Replace('/', '\')
    if ($p.StartsWith('\??\')) { $p = $p.Substring(4) }
    if ($p -match '(?i)^\\SystemRoot(\\|$)') { $p = "$env:SystemRoot" + $p.Substring(11) }
    $parts = New-Object System.Collections.Generic.List[string]
    foreach ($seg in ($p -split '\\')) {
        if ($seg -eq '' -or $seg -eq '.') { continue }
        if ($seg -eq '..') { if ($parts.Count -gt 1) { $parts.RemoveAt($parts.Count - 1) }; continue }
        $parts.Add($seg)
    }
    return ($parts -join '\')
}

# Anchored location test: is the path really inside one of the roots? A plain
# substring match ("...\Temp\system32\drivers\x.sys" contains "system32\drivers")
# proves nothing, because the name of a folder is chosen by whoever creates it.
function Test-PathUnderRoot {
    param([string]$Path, [string[]]$Roots)
    $full = ConvertTo-NormalizedWinPath $Path
    if (-not $full) { return $false }
    foreach ($r in @($Roots)) {
        $root = ConvertTo-NormalizedWinPath $r
        if (-not $root) { continue }
        if ($full.Equals($root, [StringComparison]::OrdinalIgnoreCase) -or
            $full.StartsWith($root + '\', [StringComparison]::OrdinalIgnoreCase)) { return $true }
    }
    return $false
}

# Is this the signer of a Microsoft binary? The CN must be one of Microsoft's own
# signing identities; the mere presence of the word "Microsoft" anywhere in the
# subject (e.g. "CN=Microsoft Scam LLC") is not enough.
function Test-MicrosoftSigner {
    param([string]$Subject)
    if (-not $Subject) { return $false }
    return [bool]($Subject -match '(?i)(^|,\s*)CN="?(Microsoft Corporation|Microsoft Windows|Microsoft Windows Publisher)"?(\s*,|$)')
}

# Language-independent origin of a port-only firewall rule: built-in Windows rules
# carry a resource-string group such as "@FirewallAPI.dll,-80200" or an app
# package group "@{Microsoft.Windows.xxx?ms-resource://...}". Display names are
# translated (and attacker-chosen), so they are never used to trust a rule.
# The group is only a label: it reduces noise, it does not prove anything.
function Test-FirewallBuiltInGroup {
    param([string]$Group)
    if (-not $Group) { return $false }
    if ($Group -match '(?i)^@(%systemroot%\\system32\\|%windir%\\system32\\)?[a-z0-9_.\-]+\.dll,-\d+$') { return $true }
    if ($Group -match '(?i)^@\{(Microsoft\.|MicrosoftWindows\.|Windows\.)[^}?]+(\?[^}]*)?\}$') { return $true }
    return $false
}

$script:AdminLikeSids = @("S-1-5-18","S-1-5-32-544","S-1-3-0","S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464")
$script:FileWriteMask = [System.Security.AccessControl.FileSystemRights]"WriteData, AppendData, Delete, ChangePermissions, TakeOwnership"
$script:DirWriteMask  = [System.Security.AccessControl.FileSystemRights]"DeleteSubdirectoriesAndFiles, Delete, ChangePermissions, TakeOwnership"

function Get-NonAdminWriteGrants {
    param($Security, [System.Security.AccessControl.FileSystemRights]$Mask)
    foreach ($r in $Security.Access) {
        if ($r.AccessControlType -ne "Allow") { continue }
        if ([int]($r.FileSystemRights -band $Mask) -eq 0) { continue }
        try { $sid = $r.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value }
        catch { $sid = "$($r.IdentityReference)" }
        if ($script:AdminLikeSids -notcontains $sid) { "$($r.IdentityReference)" }
    }
}


# True  = neither the file nor its folder can be modified by a non-administrator, and the owner
#         is SYSTEM / Administrators / TrustedInstaller;
# False = a non-administrator can replace the file (or it is owned by one);
# $null = could not be determined (file missing, access denied).
function Test-FileLocationProtected {
    param([string]$Path)
    try {
        $Path = [Environment]::ExpandEnvironmentVariables("$Path".Trim().Trim('"'))
        if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $null }
        $fileAcl  = Get-Acl -LiteralPath $Path -ErrorAction Stop
        $dirAcl   = Get-Acl -LiteralPath (Split-Path $Path -Parent) -ErrorAction Stop
        $ownerSid = $fileAcl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
    } catch { return $null }
    if ($script:AdminLikeSids -notcontains $ownerSid) { return $false }
    if (@(Get-NonAdminWriteGrants $fileAcl $script:FileWriteMask).Count -gt 0) { return $false }
    if (@(Get-NonAdminWriteGrants $dirAcl  $script:DirWriteMask).Count  -gt 0) { return $false }
    return $true
}

# Executable of a service ImagePath / task action: quoted path, or the text up to the first
# ".exe" (a path with spaces and no quotes is common), or the first word.
function Get-ServiceImagePath {
    param([string]$PathName)
    if ([string]::IsNullOrWhiteSpace($PathName)) { return "" }
    $s = $PathName.Trim()
    if ($s -match '^"([^"]+)"') { return $Matches[1] }
    if ($s -match '(?i)^(.+?\.(exe|sys|com|bat|cmd))(\s|$)') { return $Matches[1] }
    return ($s -split ' ')[0]
}

# Unquoted service path whose executable path contains a space: Windows tries
# "C:\Program.exe" first, which is a local privilege-escalation route when a
# parent folder is writable.
function Test-UnquotedServicePath {
    param([string]$PathName)
    if ([string]::IsNullOrWhiteSpace($PathName)) { return $false }
    $s = $PathName.Trim()
    if ($s.StartsWith('"')) { return $false }
    $img = Get-ServiceImagePath $s
    return [bool]($img -match '\s')
}

# Command-line fragments that have no place in a legitimate maintenance task:
# encoded commands, in-memory download / execution, hidden windows, URLs.
function Test-SuspiciousTaskArgs {
    param([string]$Arguments)
    if ([string]::IsNullOrWhiteSpace($Arguments)) { return $false }
    return [bool]($Arguments -match '(?i)(-enc(odedcommand)?\b|\s-e\s+[A-Za-z0-9+/=]{20,}|FromBase64String|DownloadString|DownloadFile|Invoke-WebRequest|\biwr\b|\bIEX\b|Invoke-Expression|\bhttps?://|-w(indowstyle)?\s+hidden|certutil.*-urlcache|bitsadmin.*/transfer)')
}

# The task really RUNS the script: before the script path there are only
# PowerShell switches, and nothing suspicious around it. A script path that merely
# appears somewhere in the arguments (after an encoded command, for instance) proves nothing.
function Test-TaskScriptInvocation {
    param([string]$Arguments, [string]$ScriptPath)
    if (-not $Arguments -or -not $ScriptPath) { return $false }
    $i = $Arguments.IndexOf($ScriptPath, [StringComparison]::OrdinalIgnoreCase)
    if ($i -lt 0) { return $false }
    $prefix = $Arguments.Substring(0, $i)
    $suffix = $Arguments.Substring($i + $ScriptPath.Length)
    if ((Test-SuspiciousTaskArgs $prefix) -or (Test-SuspiciousTaskArgs $suffix)) { return $false }
    return [bool]($prefix.Trim() -match '^["''&\s]*((-(NoProfile|NoLogo|NonInteractive|NoExit|Sta|Mta|Command|c|File|f)\b|-(ExecutionPolicy|ep|WindowStyle|w)\s+\S+)\s*)*["''&\s]*$')
}

# End-entity test through the typed BasicConstraints extension (language-independent).
# A certificate without the extension is treated as a possible CA (the cautious answer).
function Test-CertEndEntity {
    param($Cert)
    try {
        $bc = $Cert.Extensions | Where-Object { $_.Oid.Value -eq "2.5.29.19" }
        if (-not $bc) { return $false }
        if ($bc -is [System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]) { return (-not $bc.CertificateAuthority) }
    } catch { }
    return $false
}

# Trust class of a running process from its image path (never from its name):
#   Windows           image under System32 / SysWOW64 / SystemApps (or explorer.exe itself)
#   Microsoft         valid Authenticode signature, signer CN = Microsoft
#   Signed            valid signature of another publisher
#   ProtectedUnsigned unsigned, but in Program Files with an ACL non-administrators cannot modify
#   Unverified        anything else, including an unknown path
function Get-ProcessTrustClass {
    param([string]$Path, [hashtable]$SigCache, [string]$Name)
    if ([string]::IsNullOrWhiteSpace($Path)) {
        # Protected processes (System, lsass, wininit, services, and Defender's anti-malware services MsMpEng,
        # NisSrv, MpDefenderCoreService...) do not expose their image path, even to an administrator. Only in that case, and only for these core names, the name is accepted: a look-alike
        # process started by a user has a readable path and is judged on it.
        if ($Name -and (("$Name" -replace '\.exe$','') -in @('System','Registry','smss','csrss','wininit','services','lsass','MemCompression','Memory Compression','Secure System','MsMpEng','NisSrv','MpDefenderCoreService','SgrmBroker','MsSense'))) { return "Windows" }
        return "Unverified"
    }
    $osRoots = @("$env:SystemRoot\System32", "$env:SystemRoot\SysWOW64", "$env:SystemRoot\SystemApps", "$env:SystemRoot\explorer.exe")
    if (Test-PathUnderRoot $Path $osRoots) { return "Windows" }
    $key = (ConvertTo-NormalizedWinPath $Path).ToLowerInvariant()
    if ($SigCache -and $SigCache.ContainsKey($key)) { $sig = $SigCache[$key] }
    else {
        $sig = $null
        try { $sig = Get-AuthenticodeSignature -FilePath $Path -ErrorAction Stop } catch { }
        if ($SigCache) { $SigCache[$key] = $sig }
    }
    if ($sig -and $sig.Status -eq "Valid") {
        if (Test-MicrosoftSigner $sig.SignerCertificate.Subject) { return "Microsoft" }
        return "Signed"
    }
    $pf = @($env:ProgramFiles, ${env:ProgramFiles(x86)}) | Where-Object { $_ }
    if ((Test-PathUnderRoot $Path $pf) -and ((Test-FileLocationProtected $Path) -eq $true)) { return "ProtectedUnsigned" }
    return "Unverified"
}

# Security Center productState (decimal DWORD) of an antivirus product. Bit 0x1000 = protection
# on; bit 0x10 = signatures out of date. 397568 (0x061100) is Windows Defender on and up to date.
function Get-AvProductState {
    param($ProductState)
    $n = 0
    if ($null -eq $ProductState -or -not [int]::TryParse("$ProductState", [ref]$n)) {
        return [PSCustomObject]@{ Known = $false; Enabled = $false; UpToDate = $false; Hex = "" }
    }
    return [PSCustomObject]@{
        Known    = $true
        Enabled  = (($n -band 0x1000) -ne 0)
        UpToDate = (($n -band 0x10) -eq 0)
        Hex      = ('0x{0:X6}' -f $n)
    }
}

# Defender exclusions that switch protection off for far more than they should.
function Test-BroadDefenderExclusion {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    if ($Path.Trim().EndsWith('*')) { return $true }
    $n = ConvertTo-NormalizedWinPath $Path
    if ($n -match '(?i)^[A-Za-z]:$') { return $true }
    if ($n -match '(?i)^[A-Za-z]:\\(Windows|Users|ProgramData|Program Files|Program Files \(x86\)|Temp)$') { return $true }
    if ($n -match '(?i)^[A-Za-z]:\\Users\\[^\\]+$') { return $true }
    if ($n -match '(?i)\\(Downloads|AppData\\Local\\Temp|AppData\\Roaming|AppData\\Local|Windows\\Temp)$') { return $true }
    return $false
}
# An extension exclusion for something that is executable or a script lets any such file through.
function Test-RiskyExclusionExtension {
    param([string]$Extension)
    if ([string]::IsNullOrWhiteSpace($Extension)) { return $false }
    $e = $Extension.Trim().TrimStart('.').ToLowerInvariant()
    return [bool]($e -match '^(exe|dll|sys|com|scr|cpl|msi|ps1|psm1|bat|cmd|vbs|vbe|js|jse|wsf|wsh|hta|lnk|jar|py|reg)$' -or $e -eq '*')
}
# A process exclusion for an interpreter / LOLBin, or with a wildcard, exempts whatever it runs.
function Test-RiskyExclusionProcess {
    param([string]$Process)
    if ([string]::IsNullOrWhiteSpace($Process)) { return $false }
    if ($Process.Contains('*')) { return $true }
    $leaf = (($Process.Trim().Trim('"').Replace('/', '\')) -split '\\')[-1]
    return [bool]($leaf -match '(?i)^(powershell|pwsh|cmd|wscript|cscript|mshta|rundll32|regsvr32|msbuild|installutil|python|pythonw|node|java|javaw|wsl|bash)(\.exe)?$')
}

# Winlogon hijack test: Shell must be explorer.exe and Userinit must be the single Windows
# userinit.exe (extra entries run at every sign-in, a classic persistence trick).
function Test-WinlogonShellUserinit {
    param([string]$Shell, [string]$Userinit)
    $shellOk = ([string]::IsNullOrWhiteSpace($Shell) -or ($Shell.Trim() -ieq "explorer.exe"))
    $entries = @("$Userinit" -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    $expected = ConvertTo-NormalizedWinPath "$env:SystemRoot\System32\userinit.exe"
    $userinitOk = ($entries.Count -eq 0) -or ($entries.Count -eq 1 -and ((ConvertTo-NormalizedWinPath $entries[0]) -ieq $expected))
    return [PSCustomObject]@{ ShellOk = $shellOk; UserinitOk = $userinitOk }
}

# Password / lockout policy from a "secedit /export" INF (language-independent keys).
# -1 = never expires / locked until an administrator unlocks. Returns $null when nothing matches.
function ConvertFrom-SeceditPolicy {
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $null }
    $get = {
        param($key)
        $m = [regex]::Match($Text, "(?m)^\s*$key\s*=\s*(-?\d+)")
        if ($m.Success) { return [int]$m.Groups[1].Value } else { return $null }
    }
    $minLen  = & $get "MinimumPasswordLength"
    $lockCnt = & $get "LockoutBadCount"
    if ($null -eq $minLen -and $null -eq $lockCnt) { return $null }
    return [PSCustomObject]@{
        MinPwdLen         = $minLen
        MaxPwdAgeDays     = & $get "MaximumPasswordAge"
        MinPwdAgeDays     = & $get "MinimumPasswordAge"
        LockoutThreshold  = $lockCnt
        LockoutDurMinutes = & $get "LockoutDuration"
    }
}

# BitLocker decision for one volume. Looks beyond ProtectionStatus: a volume
# that is fully encrypted but whose protection is suspended is NOT "not
# encrypted"; a locked volume is encrypted; encryption method and key
# protectors are reported.
function Get-BitLockerAssessment {
    param($Volume, [bool]$IsSystemVolume)
    $prot   = "$($Volume.ProtectionStatus)"
    $vstat  = "$($Volume.VolumeStatus)"
    $lock   = "$($Volume.LockStatus)"
    $method = "$($Volume.EncryptionMethod)"
    $pct    = $null
    if ($null -ne $Volume.EncryptionPercentage -and "$($Volume.EncryptionPercentage)" -match '^\d+$') { $pct = [int]$Volume.EncryptionPercentage }
    $types  = @($Volume.KeyProtector | ForEach-Object { "$($_.KeyProtectorType)" } | Where-Object { $_ })
    $protTxt = if ($types.Count -gt 0) { "protectors: " + ($types -join ", ") } else { "no key protector reported" }
    $info = "Method: $(if($method){$method}else{'unknown'}); $protTxt"
    $legacy = if ($method -match '^(Aes128|Aes256)$') { " Legacy CBC mode; XTS-AES is the current default for new encryptions." } else { "" }
    $fully = ($vstat -match 'FullyEncrypted') -or ($null -ne $pct -and $pct -ge 100)
    $inProgress = ($vstat -match 'InProgress')

    if ($lock -eq "Locked") {
        return [PSCustomObject]@{ Status = "OK"; Detail = "Volume locked: its content is encrypted. $info" }
    }
    if ($prot -eq "On") {
        if ($types.Count -gt 0 -and ($types -notcontains "RecoveryPassword")) {
            return [PSCustomObject]@{ Status = "WARN"; Detail = "Protection is on but no recovery-password protector exists — if the TPM or the PIN is lost the data cannot be recovered. $info.$legacy" }
        }
        return [PSCustomObject]@{ Status = "OK"; Detail = "$info.$legacy" }
    }
    if ($prot -eq "Off") {
        if ($inProgress) {
            return [PSCustomObject]@{ Status = "INFO"; Detail = "Encryption or decryption is in progress ($vstat). $info" }
        }
        if ($fully) {
            return [PSCustomObject]@{ Status = "WARN"; Detail = "The volume is fully encrypted but its protection is SUSPENDED: the key is stored in clear on the disk until protection is resumed (Resume-BitLocker). $info" }
        }
        if ($IsSystemVolume) {
            return [PSCustomObject]@{ Status = "FAIL"; Detail = "System volume not encrypted — data exposed if the machine is lost or stolen!" }
        }
        return [PSCustomObject]@{ Status = "WARN"; Detail = "Data volume not encrypted — its data is exposed if the drive is lost or stolen; encrypt it if it holds anything sensitive" }
    }
    return [PSCustomObject]@{ Status = "WARN"; Detail = "BitLocker protection state could not be determined ($prot / $vstat)" }
}

# ──────────────────────────────────────────────
#  v5.7.0 — PURE DECISION FUNCTIONS
# ──────────────────────────────────────────────
# NOTE v5.7.0: the three checks added in this version (UDP endpoints, Windows build support
# status, Secure Boot 2023 certificates) read the system in their section and hand the raw
# values to the pure functions below, so every decision rule is covered by -SelfTest without
# any Windows API.

# One UDP endpoint bound to a non-loopback address -> INFO or WARN, with the reason.
# $Disabled: @{ LLMNR = $bool; mDNS = $bool; NetBIOS = $bool } = "this protocol is turned off".
# A UDP port bound to an address is not necessarily reachable (the firewall can still drop the
# packets), so WARN is kept for what is wrong by nature: a sensitive service port, a program that
# cannot be verified listening on every interface, or a Windows process bound to a name-resolution
# port whose protocol is turned off (inconsistency with the settings read in section 23).
function Get-UdpEndpointAssessment {
    param([int]$Port, [string]$TrustClass, [bool]$AllInterfaces, [hashtable]$Disabled)
    $isWin = ($TrustClass -eq "Windows" -or $TrustClass -eq "Microsoft")
    $off = if ($Disabled) { $Disabled } else { @{} }
    if ($Port -eq 5355 -and $isWin -and $off["LLMNR"]) {
        return [PSCustomObject]@{ Status = "WARN"; Reason = "LLMNR is turned off by policy, yet a Windows process listens on UDP 5355 (LLMNR)" }
    }
    if ($Port -eq 5353 -and $isWin -and $off["mDNS"]) {
        return [PSCustomObject]@{ Status = "WARN"; Reason = "mDNS is turned off, yet a Windows process listens on UDP 5353 (mDNS)" }
    }
    if ($Port -eq 137 -or $Port -eq 138) {
        if (-not $isWin) {
            return [PSCustomObject]@{ Status = "WARN"; Reason = "a program that is not part of Windows listens on a NetBIOS port" }
        }
        if ($off["NetBIOS"]) {
            return [PSCustomObject]@{ Status = "WARN"; Reason = "NetBIOS over TCP/IP is turned off, yet a Windows process listens on UDP $Port (NetBIOS)" }
        }
        return [PSCustomObject]@{ Status = "INFO"; Reason = "NetBIOS name service port (the NetBIOS check of section 23 already covers it)" }
    }
    $sensitive = @{ 69 = "TFTP"; 161 = "SNMP"; 1434 = "SQL Server Browser"; 11211 = "memcached" }
    if ($sensitive.ContainsKey($Port)) {
        return [PSCustomObject]@{ Status = "WARN"; Reason = "UDP $Port is a sensitive service port ($($sensitive[$Port]))" }
    }
    if ($TrustClass -eq "Unverified" -and $AllInterfaces) {
        return [PSCustomObject]@{ Status = "WARN"; Reason = "an unverified program listens on every interface" }
    }
    return [PSCustomObject]@{ Status = "INFO"; Reason = "" }
}

# Edition family of the OS from Win32_OperatingSystem.OperatingSystemSKU. The values are the
# PRODUCT_* constants documented by Microsoft (GetProductInfo, Microsoft Learn) and do not depend
# on the display language. Anything else (Server, evaluation, Team, ...) is "Unknown" on purpose:
# a lifecycle date is never guessed for an edition that is not in the table.
function Get-WindowsEditionFamily {
    param($Sku)
    $n = 0
    if ($null -eq $Sku -or -not [int]::TryParse("$Sku", [ref]$n)) { return "Unknown" }
    # Home 101 / Home N 98 / Home Single Language 100, Pro 48 / Pro N 49 / Pro for Workstations 161
    # and 162 / Pro Education 164: the 24-month "Home, Pro" column of the Microsoft table.
    if ($n -in 98, 100, 101, 48, 49, 161, 162, 164) { return "HomePro" }
    # Enterprise 4 / Enterprise N 27 / Education 121 / Education N 122 / IoT Enterprise 188:
    # the 36-month "Enterprise, Education" column.
    if ($n -in 4, 27, 121, 122, 188) { return "EntEdu" }
    # Enterprise LTSB/LTSC 125 and 126, IoT Enterprise LTSC 191: their own lifecycle.
    if ($n -in 125, 126, 191) { return "Ltsc" }
    return "Unknown"
}

# Support status of the installed Windows 11 build. $Table rows: Build, Version, HomePro, EntEdu
# (end-of-updates dates). OK is only returned from a table that is not older than 6 months: an
# old table must never produce a misleading "supported". FAIL and WARN stay valid whatever the
# age of the table (Microsoft does not bring an end date forward).
function Get-WindowsLifecycleStatus {
    param(
        [int]$Build, $Sku, [datetime]$Today, [object[]]$Table, [int[]]$EndedBuilds,
        [datetime]$TableDate, [string]$DisplayVersion = "", $Ubr = $null
    )
    $inv = [System.Globalization.CultureInfo]::InvariantCulture
    $tdTxt = $TableDate.ToString("yyyy-MM-dd", $inv)
    $src = "Source: Microsoft Learn, Windows 11 release information (table dated $tdTxt)."
    $buildTxt = if ($null -ne $Ubr -and "$Ubr" -match '^\d+$') { "$Build.$Ubr" } else { "$Build" }
    $verTxt = if ($DisplayVersion) { "$DisplayVersion (build $buildTxt)" } else { "build $buildTxt" }

    if ($Build -lt 22000) {
        return [PSCustomObject]@{ Status = "INFO"; Value = "Not available (Windows 10 or older, build $Build)"
            Detail = "This table only covers Windows 11. The 'Windows 11 build' check of section 1 already reports an older Windows." }
    }
    $family = Get-WindowsEditionFamily $Sku
    if ($family -eq "Ltsc") {
        return [PSCustomObject]@{ Status = "INFO"; Value = "Long-term servicing edition ($verTxt)"
            Detail = "LTSB/LTSC and IoT LTSC editions have their own lifecycle, which is not in this table. Check it on Microsoft Learn (lifecycle search)." }
    }
    if ($family -eq "Unknown") {
        return [PSCustomObject]@{ Status = "INFO"; Value = "Not available (edition not recognised, SKU $Sku)"
            Detail = "The edition of this Windows is not in the table (Server, evaluation or special edition): no date is guessed. $src" }
    }
    if ($EndedBuilds -contains $Build) {
        return [PSCustomObject]@{ Status = "FAIL"; Value = "$verTxt - support ended"
            Detail = "This Windows 11 version is out of support for every edition: it no longer receives security updates. Install the latest feature update (Settings > Windows Update). $src" }
    }
    $row = @($Table | Where-Object { [int]$_.Build -eq $Build }) | Select-Object -First 1
    if (-not $row) {
        return [PSCustomObject]@{ Status = "INFO"; Value = "Build not in the lifecycle table ($verTxt)"
            Detail = "This build is not in the table built into the script (newer version, Insider build or unusual build): check it on Microsoft Learn. $src" }
    }
    $end = if ($family -eq "EntEdu") { [datetime]$row.EntEdu } else { [datetime]$row.HomePro }
    $famTxt = if ($family -eq "EntEdu") { "Enterprise/Education" } else { "Home/Pro" }
    $endTxt = $end.ToString("yyyy-MM-dd", $inv)
    $days = [int]($end.Date - $Today.Date).TotalDays
    if ($days -lt 0) {
        return [PSCustomObject]@{ Status = "FAIL"; Value = "$verTxt - support ended on $endTxt ($([Math]::Abs($days)) day(s) ago)"
            Detail = "$famTxt editions of this Windows 11 version no longer receive security updates. Install the latest feature update (Settings > Windows Update). $src" }
    }
    if ($days -le 90) {
        return [PSCustomObject]@{ Status = "WARN"; Value = "$verTxt - support ends on $endTxt (in $days day(s))"
            Detail = "$famTxt editions of this Windows 11 version stop receiving security updates on $endTxt. Plan the next feature update. $src" }
    }
    $tableAge = ($Today.Date - $TableDate.Date).TotalDays
    if ($tableAge -gt 180) {
        return [PSCustomObject]@{ Status = "INFO"; Value = "$verTxt - supported until $endTxt according to a table dated $tdTxt"
            Detail = "The lifecycle table built into the script is more than 6 months old: an 'OK' would not be reliable. Check the current dates on Microsoft Learn. $src" }
    }
    return [PSCustomObject]@{ Status = "OK"; Value = "$verTxt - supported until $endTxt (in $days day(s))"
        Detail = "$famTxt edition: security updates until $endTxt. $src" }
}

# True / False when the bytes of a UEFI variable (db, KEK) contain the given certificate name
# (ASCII), $null when the variable could not be read. Same test as the Microsoft guidance
# for the 2023 certificates; the name is stored as plain text inside the X.509 certificate.
function Test-UefiSignatureText {
    param($Bytes, [string]$Text)
    if ($null -eq $Bytes -or @($Bytes).Count -eq 0) { return $null }
    return ([System.Text.Encoding]::ASCII.GetString([byte[]]$Bytes)).Contains($Text)
}

# Secure Boot certificate renewal (Microsoft 2011 certificates -> 2023 certificates).
# $SecureBootEnabled / $DbHas2023 / $KekHas2023: $true / $false / $null (unknown).
# $Status: Servicing\UEFICA2023Status (Updated / InProgress / NotStarted, "" if absent).
# $EventIds: ids found in the System log ($null = log unreadable, @() = none). Used only when the
# status is not "Updated". Never OK without evidence, never WARN from partial information.
function Get-SecureBootCertAssessment {
    param($SecureBootEnabled, [string]$Status, [string]$ErrorValue, [string]$ErrorEvent, $DbHas2023, $KekHas2023, $EventIds)
    $note = "Microsoft's 2011 Secure Boot certificates expire in 2026; a device that has not received the 2023 certificates keeps starting and installing updates (Microsoft). Source: Microsoft Support, Windows Secure Boot certificate expiration and CA updates."
    if ($null -eq $SecureBootEnabled) {
        return [PSCustomObject]@{ Status = "INFO"; Value = "Unable to determine (Secure Boot state unreadable)"; Detail = "Secure Boot could not be read (legacy BIOS, virtual machine or insufficient rights), so the certificate renewal cannot be assessed." }
    }
    if (-not $SecureBootEnabled) {
        return [PSCustomObject]@{ Status = "INFO"; Value = "Not applicable (Secure Boot is off)"; Detail = "Secure Boot is off, see the Secure Boot line above. The certificate renewal only matters when it is on." }
    }
    $hasErr = ((-not [string]::IsNullOrWhiteSpace($ErrorValue)) -and $ErrorValue -ne "0") -or ((-not [string]::IsNullOrWhiteSpace($ErrorEvent)) -and $ErrorEvent -ne "0")
    $ids = @($EventIds | Where-Object { $null -ne $_ })
    $blocked = @($ids | Where-Object { $_ -in 1795, 1796, 1802, 1803 })
    $pending = @($ids | Where-Object { $_ -in 1800, 1801 })
    $st = "$Status".Trim()

    if ($st -eq "Updated") {
        if ($DbHas2023 -eq $true -and $KekHas2023 -eq $true) {
            return [PSCustomObject]@{ Status = "OK"; Value = "Updated (2023 certificates present in db and KEK)"; Detail = "Windows reports the renewal as completed and the firmware databases contain the Windows UEFI CA 2023 and the Microsoft KEK 2K CA 2023. $note" }
        }
        if ($DbHas2023 -eq $true) {
            return [PSCustomObject]@{ Status = "INFO"; Value = "Updated, KEK 2023 not confirmed"; Detail = "The Windows UEFI CA 2023 is in db, but the Microsoft KEK 2K CA 2023 was not found in the KEK. $note" }
        }
        if ($DbHas2023 -eq $false) {
            return [PSCustomObject]@{ Status = "INFO"; Value = "Reported as Updated, 2023 certificate not found in db"; Detail = "Windows says Updated but the Windows UEFI CA 2023 was not found in db: contradictory, verify with Microsoft's detection script. $note" }
        }
        return [PSCustomObject]@{ Status = "INFO"; Value = "Unable to determine (firmware db unreadable)"; Detail = "Windows reports Updated but the firmware db could not be read to confirm it. $note" }
    }
    if ([string]::IsNullOrEmpty($st)) {
        if ($DbHas2023 -eq $true) {
            return [PSCustomObject]@{ Status = "INFO"; Value = "2023 certificate present in db, servicing status not reported"; Detail = "The Windows UEFI CA 2023 is in db but Windows does not report a servicing status. $note" }
        }
        return [PSCustomObject]@{ Status = "INFO"; Value = "Unable to determine (no servicing status)"; Detail = "This Windows does not report the Secure Boot certificate servicing status (older build or key absent). $note" }
    }
    if ($st -eq "NotStarted" -or $st -eq "InProgress") {
        if ($hasErr -or $blocked.Count -gt 0) {
            $why = if ($blocked.Count -gt 0) { "event(s) " + (($blocked | Sort-Object -Unique) -join ", ") } else { "error recorded by Windows" }
            return [PSCustomObject]@{ Status = "INFO"; Value = "$st - blocked ($why)"; Detail = "The update could not be applied (firmware limitation or missing OEM key). A firmware (BIOS/UEFI) update from the device maker may be required. $note" }
        }
        if ($DbHas2023 -eq $true) {
            return [PSCustomObject]@{ Status = "INFO"; Value = "$st - 2023 certificate already in db"; Detail = "The Windows UEFI CA 2023 is already in db while the servicing is not finished: transitional state. $note" }
        }
        if ($st -eq "InProgress" -or $pending.Count -gt 0) {
            return [PSCustomObject]@{ Status = "INFO"; Value = "$st - restart may be needed"; Detail = "The renewal is under way and usually needs a restart to complete. $note" }
        }
        if ($null -eq $EventIds) {
            return [PSCustomObject]@{ Status = "INFO"; Value = "Unable to determine ($st, event log unreadable)"; Detail = "The status is $st but the System event log could not be read to look for a blocking error. $note" }
        }
        return [PSCustomObject]@{ Status = "WARN"; Value = "Not started - update available, not applied"; Detail = "The 2023 certificates are not installed and nothing blocks the update: install the latest Windows updates and restart; Microsoft delivers the renewal through Windows Update. $note" }
    }
    return [PSCustomObject]@{ Status = "INFO"; Value = "Unable to determine (unrecognised status '$st')"; Detail = "Windows reports a status this script does not know. $note" }
}

# ──────────────────────────────────────────────
#  v5.7.1 — PURE DECISION FUNCTIONS
# ──────────────────────────────────────────────

# Windows Update policies (registry under HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate,
# AU subkey for NoAutoUpdate / UseWUServer). Source: Microsoft Learn, "Manage additional Windows
# Update settings" (NoAutoUpdate: 0 = Automatic Updates enabled, default; 1 = disabled).
# Deferrals and an intranet update server are legitimate choices: INFO. Only "Automatic Updates
# disabled by policy" is WARN. All inputs are raw registry values ($null = value absent).
function Get-WindowsUpdatePolicyAssessment {
    param($NoAutoUpdate, $UseWUServer, $DeferFeature, $DeferFeatureDays, $DeferQuality, $DeferQualityDays)
    if ("$NoAutoUpdate" -match '^\d+$' -and [int]$NoAutoUpdate -eq 1) {
        return [PSCustomObject]@{ Status = "WARN"; Value = "Automatic Updates disabled by policy (NoAutoUpdate = 1)"
            Detail = "A policy turns Automatic Updates off: this PC will not install updates by itself. Remove the NoAutoUpdate value (or set it to 0) under HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU, then check Settings > Windows Update. Source: Microsoft Learn, Manage additional Windows Update settings." }
    }
    $parts = @()
    if ("$DeferFeature" -match '^\d+$' -and [int]$DeferFeature -eq 1) {
        $d = if ("$DeferFeatureDays" -match '^\d+$') { [int]$DeferFeatureDays } else { 0 }
        $parts += "feature updates deferred $d day(s)"
    }
    if ("$DeferQuality" -match '^\d+$' -and [int]$DeferQuality -eq 1) {
        $d = if ("$DeferQualityDays" -match '^\d+$') { [int]$DeferQualityDays } else { 0 }
        $parts += "quality updates deferred $d day(s)"
    }
    if ("$UseWUServer" -match '^\d+$' -and [int]$UseWUServer -eq 1) { $parts += "updates come from an intranet update server (WSUS)" }
    if ($parts.Count -eq 0) {
        return [PSCustomObject]@{ Status = "OK"; Value = "No update-delaying policy (Windows defaults)"
            Detail = "No policy defers updates, redirects them to an intranet server or turns Automatic Updates off." }
    }
    return [PSCustomObject]@{ Status = "INFO"; Value = ($parts -join "; ")
        Detail = "Policies delay or redirect Windows updates. This is a legitimate choice, so it is not scored; the only WARN raised here is Automatic Updates disabled by policy (NoAutoUpdate = 1). Source: Microsoft Learn, Manage additional Windows Update settings." }
}

# Release month of a Microsoft Defender platform / engine version, read from the version number:
# 4.18.26100.4 / 1.1.26100.4 -> October 2026 (YYMM, then one more digit). Observed on the Microsoft
# release table (4.18.24080.9 = August-2024 release, 4.18.25100.9008 = October-2025 release) and
# valid for the older 4-digit form (4.18.2203.5). $null when the version is not in that format.
function Get-DefenderVersionSeries {
    param([string]$Version)
    $m = [regex]::Match("$Version", '^\d+\.\d+\.(\d{2})(\d{2})\d?\.\d+')
    if (-not $m.Success) { return $null }
    $yy = [int]$m.Groups[1].Value; $mm = [int]$m.Groups[2].Value
    if ($mm -lt 1 -or $mm -gt 12) { return $null }
    return [datetime]::new(2000 + $yy, $mm, 1)
}

# Age of the Defender platform / engine. Microsoft ships both every month and supports the latest
# plus the two previous versions (N-2) at technical support only; older ones are unsupported
# (Microsoft Learn, "Microsoft Defender Antivirus security intelligence and product updates").
# A package reaches the device about a month after its series month and the series is decoded from
# the version number, so the WARN threshold is deliberately loose: series 4 months old or more.
# Defender in passive mode (another antivirus is active): INFO only.
function Get-DefenderVersionAssessment {
    param([string]$PlatformVersion, [string]$EngineVersion, [datetime]$Today, [bool]$Passive = $false)
    $inv = [System.Globalization.CultureInfo]::InvariantCulture
    $ps = Get-DefenderVersionSeries $PlatformVersion
    $es = Get-DefenderVersionSeries $EngineVersion
    $src = "Source: Microsoft Learn, Microsoft Defender Antivirus security intelligence and product updates."
    if ($null -eq $ps -and $null -eq $es) {
        return [PSCustomObject]@{ Status = "INFO"; Value = "Unable to determine (version not recognised: platform '$PlatformVersion', engine '$EngineVersion')"
            Detail = "The platform / engine version could not be read or is not in the expected format. $src" }
    }
    $nowIdx = $Today.Year * 12 + $Today.Month
    $ages = @()
    $pTxt = if ($ps) { $ages += [Math]::Max(0, $nowIdx - ($ps.Year * 12 + $ps.Month)); "platform $PlatformVersion (series " + $ps.ToString("yyyy-MM", $inv) + ")" } else { "platform '$PlatformVersion' (series not decoded)" }
    $eTxt = if ($es) { $ages += [Math]::Max(0, $nowIdx - ($es.Year * 12 + $es.Month)); "engine $EngineVersion (series " + $es.ToString("yyyy-MM", $inv) + ")" } else { "engine '$EngineVersion' (series not decoded)" }
    $worst = ($ages | Measure-Object -Maximum).Maximum
    $value = "$pTxt / $eTxt"
    $note = "Microsoft ships a Defender platform and engine update every month and fully supports only the latest versions (the two previous ones get technical support only, older ones none). The month is read from the version number and a package reaches the device about a month later, so this is an estimate. $src"
    if ($worst -ge 4) {
        $st = if ($Passive) { "INFO" } else { "WARN" }
        return [PSCustomObject]@{ Status = $st; Value = $value; Detail = "About $worst month(s) behind the current release series: the platform or engine is no longer being kept up to date. Check Windows Update and Microsoft Defender updates (MpCmdRun.exe -SignatureUpdate). $note" }
    }
    return [PSCustomObject]@{ Status = "OK"; Value = $value; Detail = "About $worst month(s) behind the current release series. $note" }
}

# SMBv1 CLIENT feature (the existing "SMBv1 enabled" check only reads the server side).
# $State: Windows optional feature state of "SMB1Protocol-Client".
function Get-Smb1ClientAssessment {
    param([bool]$ListReadable, [bool]$Found, [string]$State)
    if (-not $ListReadable) {
        return [PSCustomObject]@{ Status = "INFO"; Value = "Unable to read"; Detail = "The list of Windows optional features could not be read, so the SMBv1 client could not be checked." }
    }
    if (-not $Found) {
        return [PSCustomObject]@{ Status = "OK"; Value = "Not present in this Windows"; Detail = "The SMB1Protocol-Client optional feature does not exist on this Windows." }
    }
    switch -Regex ($State) {
        '^(Enabled|EnablePending)$' {
            return [PSCustomObject]@{ Status = "WARN"; Value = "$State"; Detail = "The SMBv1 client lets this PC talk to servers that only speak SMBv1, a protocol with known remote-code-execution flaws (WannaCry, NotPetya). Turn it off: Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol-Client" }
        }
        '^(Disabled|DisablePending|DisabledWithPayloadRemoved)$' {
            return [PSCustomObject]@{ Status = "OK"; Value = "$State"; Detail = "The SMBv1 client feature is turned off." }
        }
    }
    return [PSCustomObject]@{ Status = "INFO"; Value = "Unable to determine (feature state '$State')"; Detail = "The SMB1Protocol-Client feature reports a state this script does not interpret." }
}

# AppLocker policy XML (Get-AppLockerPolicy -Effective -Xml) -> rules per rule collection and the
# collections in enforcement ("Enabled") or audit ("AuditOnly") mode. $null when the text is not XML.
function Get-AppLockerSummary {
    param([string]$Xml)
    try { $doc = [xml]$Xml } catch { return $null }
    $rules = 0; $enforced = @(); $audit = @()
    foreach ($c in @($doc.SelectNodes("//RuleCollection"))) {
        $n = @($c.ChildNodes | Where-Object { $_.NodeType -eq "Element" }).Count
        $rules += $n
        if ($n -gt 0) {
            $mode = $c.GetAttribute("EnforcementMode"); $type = $c.GetAttribute("Type")
            if ($mode -eq "Enabled") { $enforced += $type } elseif ($mode -eq "AuditOnly") { $audit += $type }
        }
    }
    return [PSCustomObject]@{ Rules = $rules; Enforced = $enforced; Audit = $audit }
}

# Application control overview, informational only (there is no universal good value: most PCs do not
# use AppLocker or a custom WDAC policy). WDAC status values (Win32_DeviceGuard): 0 off, 1 audit
# mode, 2 enforced mode (Microsoft .NET reference "DeviceGuardConfigCodeIntegrityStatus").
function Get-AppControlAssessment {
    param([bool]$AppLockerAvailable, $AppLocker, $WdacKernel, $WdacUser, [string]$LanguageMode)
    $ci = { param($v) switch ("$v") { "0" { "off" } "1" { "audit mode" } "2" { "enforced" } default { "unknown" } } }
    $al = if (-not $AppLockerAvailable) { "AppLocker: not available (cmdlets absent)" }
          elseif ($null -eq $AppLocker) { "AppLocker: unreadable" }
          elseif ($AppLocker.Rules -eq 0) { "AppLocker: no rule" }
          else {
              $x = "AppLocker: $($AppLocker.Rules) rule(s)"
              if (@($AppLocker.Enforced).Count -gt 0) { $x += ", enforced for " + (@($AppLocker.Enforced) -join "/") }
              if (@($AppLocker.Audit).Count -gt 0)    { $x += ", audit for " + (@($AppLocker.Audit) -join "/") }
              $x
          }
    $wd = if ($null -eq $WdacKernel -and $null -eq $WdacUser) { "WDAC: unreadable" }
          else { "WDAC: kernel-mode " + (& $ci $WdacKernel) + ", user-mode " + (& $ci $WdacUser) }
    $lm = if ($LanguageMode) { "PowerShell language mode: $LanguageMode" } else { "PowerShell language mode: unreadable" }
    if (-not $AppLockerAvailable -and $null -eq $WdacKernel -and $null -eq $WdacUser -and -not $LanguageMode) {
        return [PSCustomObject]@{ Status = "INFO"; Value = "Unable to determine"; Detail = "Neither AppLocker, WDAC nor the PowerShell language mode could be read." }
    }
    return [PSCustomObject]@{ Status = "INFO"; Value = "$al | $wd | $lm"
        Detail = "Informational: application control (AppLocker, Windows Defender Application Control) restricts which programs and scripts may run. The WDAC value reports enforcement of the code-integrity policy and does not say which policy is in force. Language mode: FullLanguage = no restriction, ConstrainedLanguage = restricted by an application-control policy." }
}

# Inclusion setting of an `auditpol /get /subcategory:{GUID} /r` output (CSV: machine, target, name,
# GUID, inclusion, exclusion). Read by position from the end, so the localized header and the text of
# the setting never matter. $null when the output is not recognised.
function Get-AuditpolInclusion {
    param($Lines)
    $data = @($Lines | Where-Object { "$_".Trim() -ne "" })
    if ($data.Count -lt 2) { return $null }
    $f = "$($data[$data.Count - 1])".Split(",")
    if ($f.Count -lt 3) { return $null }
    return $f[$f.Count - 2].Trim()
}

# NOTE v5.7.2: rows whose conclusion rests on a Microsoft reference (a decoded Defender version, the
# lifecycle table, the Secure Boot certificate renewal) show their reference link whatever the status,
# so the data can be checked at the source. The other OK / INFO rows keep no link (the report shows
# links on WARN / FAIL only, to avoid clutter). The links themselves come from $script:HelpLinksDb.
function Test-HelpLinksReferenceRow {
    param([string]$Category, [string]$Check)
    return (($Category -eq "Antivirus" -and $Check -like "Defender platform*") -or
            ($Category -eq "Updates" -and $Check -like "Windows build support*") -or
            ($Category -eq "UEFI Security" -and $Check -like "Secure Boot certificates*"))
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

    # NOTE v5.5.0: Add-Result calls Write-Log, which appends every line to the TXT
    # report. The Add-Result assertions below therefore used to leave a stray
    # "Check-Security_<date>.txt" (one "[OK] TestCat | TestCtrl" line) in the real
    # reports folder. For the whole SelfTest the TXT path now points to a
    # temporary file, deleted before exiting.
    $ST_RealTXT = $ReportTXT
    $script:ReportTXT = Join-Path ([System.IO.Path]::GetTempPath()) "Check-Security_SelfTest_$PID.txt"
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
Assert-SelfTest "SelfTest log: redirected to the temp folder"                 ($script:ReportTXT.StartsWith([System.IO.Path]::GetTempPath()))
Assert-SelfTest "SelfTest log: nothing written to the real TXT report path"   (-not (Test-Path -LiteralPath $ST_RealTXT))
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
    Assert-SelfTest "TrustedTaskNames is defined (optional list)"  ($null -ne $TrustedTaskNames)

    Write-Host ""
    Write-Host "  New v4.4 features" -ForegroundColor DarkGray

    # BitLocker: check that the C: FAIL / other WARN logic is correct.
    # Simulates two fake volumes and checks the switch.
    # v5.6.0: uses the real Get-BitLockerAssessment (the test used to re-implement the former switch)
    # and no longer depends on %SystemDrive% being defined.
    $ST_SystemDrive = if ($env:SystemDrive) { $env:SystemDrive } else { "C:" }
    $ST_VolSystem = [PSCustomObject]@{ MountPoint = $ST_SystemDrive; ProtectionStatus = "Off"; EncryptionPercentage = 0 }
    $ST_VolData   = [PSCustomObject]@{ MountPoint = "E:";            ProtectionStatus = "Off"; EncryptionPercentage = 0 }
    $ST_IsSystem  = ("$($ST_VolSystem.MountPoint)".TrimEnd('\') -eq $ST_SystemDrive)
    $ST_IsData    = ("$($ST_VolData.MountPoint)".TrimEnd('\')   -eq $ST_SystemDrive)
    $ST_StSystem  = (Get-BitLockerAssessment $ST_VolSystem $ST_IsSystem).Status
    $ST_StData    = (Get-BitLockerAssessment $ST_VolData   $ST_IsData).Status
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
    # real -Category value. One key per section, 27 sections (22 + the five of v5.5.0).
    Assert-SelfTest "SectionCategoryMap has all 27 section keys" ($SectionCategoryMap.Count -eq 27) "Got: $($SectionCategoryMap.Count)"

    # Get-NetAccountsValue (v5.4.0) — bilingual FR/EN extraction, the same
    # pattern used to fix the Password Policy section's ADSI unreliability
    $ST_FrSample = "Seuil de verrouillage :                                                5"
    $ST_EnSample = "Lockout threshold:                                    5"
    $ST_Patterns = @('Seuil de verrouillage\s*:\s*(.+)', 'Lockout threshold\s*:\s*(.+)')
    Assert-SelfTest "Get-NetAccountsValue: French label matches"  ((Get-NetAccountsValue $ST_FrSample $ST_Patterns) -eq "5")
    Assert-SelfTest "Get-NetAccountsValue: English label matches" ((Get-NetAccountsValue $ST_EnSample $ST_Patterns) -eq "5")
    Assert-SelfTest "Get-NetAccountsValue: no match returns null"  ($null -eq (Get-NetAccountsValue "unrelated text" $ST_Patterns))

    Write-Host ""
    Write-Host "  New v5.5.0 features" -ForegroundColor DarkGray

    # The five new sections are wired to EXISTING categories (no new category)
    Assert-SelfTest "SectionCategoryMap: 23_NameResolution -> Network"      ($SectionCategoryMap["23_NameResolution"]      -contains "Network")
    Assert-SelfTest "SectionCategoryMap: 24_DefenderProtections -> Defender" ($SectionCategoryMap["24_DefenderProtections"] -contains "Defender")
    Assert-SelfTest "SectionCategoryMap: 25_PowerShell2 -> PowerShell"       ($SectionCategoryMap["25_PowerShell2"]         -contains "PowerShell")
    Assert-SelfTest "SectionCategoryMap: 26_RemoteServices -> Services"      ($SectionCategoryMap["26_RemoteServices"]      -contains "Services")
    Assert-SelfTest "SectionCategoryMap: 27_Credentials -> Accounts"         ($SectionCategoryMap["27_Credentials"]         -contains "Accounts")

    # -Category reaches a new section, and only the right one
    $script:Category = @("Services")
    Assert-SelfTest "ShouldRunSection: 'Services' -> 26_RemoteServices OK"            (ShouldRunSection "26_RemoteServices")
    Assert-SelfTest "ShouldRunSection: 'Services' -> 24_DefenderProtections excluded" (-not (ShouldRunSection "24_DefenderProtections"))
    $script:Category = @()  # reset

    # Get-ToolboxHint — Fix / Check wording, unknown key, hints switched off
    $ST_HintFix = Get-ToolboxHint "NameResolutionFix"
    Assert-SelfTest "Get-ToolboxHint: Fix mode names the Toolbox command" ($ST_HintFix -match "Fix with Toolbox-SystemCommands" -and $ST_HintFix.Contains($ToolboxLabels["NameResolutionFix"])) "Got: $ST_HintFix"
    Assert-SelfTest "Get-ToolboxHint: Check mode wording"                 ((Get-ToolboxHint "DefenderDepth" -Mode Check) -match "Details in Toolbox-SystemCommands")
    Assert-SelfTest "Get-ToolboxHint: unknown key -> empty string"        ((Get-ToolboxHint "NoSuchKey") -eq "")
    $ST_HintsSaved = $script:ShowToolboxHints
    $script:ShowToolboxHints = $false
    Assert-SelfTest "Get-ToolboxHint: hints disabled -> empty string"     ((Get-ToolboxHint "NameResolutionFix") -eq "")
    $script:ShowToolboxHints = $ST_HintsSaved  # reset
    Assert-SelfTest "ToolboxLabels: every label is non-empty"             (@($ToolboxLabels.Values | Where-Object { [string]::IsNullOrWhiteSpace($_) }).Count -eq 0)

    # Help links added for the new Defender / PowerShell checks
    Assert-SelfTest "HelpLinks: 'Tamper Protection' has a rule"   ((Get-HelpLinks "Defender" "Tamper Protection" "Disabled" "") -ne "")
    Assert-SelfTest "HelpLinks: 'PowerShell 2.0' has a rule"      ((Get-HelpLinks "PowerShell" "PowerShell 2.0 (downgrade route)" "Enabled" "") -ne "")

    # Defender settings reference (v5.5.1): the table that feeds both the Detail sentences and
    # the expandable HTML cards. These checks run without Defender (pure data + string logic).
    Write-Host ""
    Write-Host "  New v5.5.1 features" -ForegroundColor DarkGray

    $ST_Refs = @($script:DefenderRef)
    $ST_Incomplete = @($ST_Refs | Where-Object {
        -not $_.Key -or -not $_.Row -or -not $_.Title -or -not $_.What -or
        @($_.Values).Count -lt 2 -or @($_.Read).Count -lt 1 -or @($_.Links).Count -lt 1
    })
    Assert-SelfTest "DefenderRef: every entry is complete (key, row, title, text, values, read command, link)" ($ST_Incomplete.Count -eq 0) "Incomplete: $(($ST_Incomplete | ForEach-Object { $_.Key }) -join ', ')"

    $ST_BadValues = @($ST_Refs | ForEach-Object { $_.Values } | Where-Object { "$($_.Value)" -eq "" -or -not $_.Name -or -not $_.Meaning })
    Assert-SelfTest "DefenderRef: every value has a name and a meaning" ($ST_BadValues.Count -eq 0)

    $ST_BadLinks = @($ST_Refs | ForEach-Object { $_.Links } | Where-Object { $_.Url -notmatch '^https://learn\.microsoft\.com/en-us/' -or -not $_.Label })
    Assert-SelfTest "DefenderRef: every link is a labelled Microsoft Learn (en-us) page" ($ST_BadLinks.Count -eq 0) "Bad: $(($ST_BadLinks | ForEach-Object { $_.Url }) -join ', ')"

    $ST_BadPolicy = @($ST_Refs | Where-Object { [bool]$_.PolicyPath -ne [bool]$_.PolicyValue })
    Assert-SelfTest "DefenderRef: PolicyPath and PolicyValue always come together" ($ST_BadPolicy.Count -eq 0)

    Assert-SelfTest "DefenderRef: keys and rows are unique" ((@($ST_Refs | ForEach-Object { $_.Key } | Select-Object -Unique).Count -eq $ST_Refs.Count) -and (@($ST_Refs | ForEach-Object { $_.Row } | Select-Object -Unique).Count -eq $ST_Refs.Count))

    # v5.5.2: a card always says where to change the setting, and no command shown by the audit
    # turns a Defender protection OFF (the audit teaches how to turn things on or tune them).
    $ST_NoWinSec = @($ST_Refs | Where-Object { -not $_.WinSec })
    Assert-SelfTest "DefenderRef: every entry says where to change it in Windows Security (or that there is no switch)" ($ST_NoWinSec.Count -eq 0) "Missing: $(($ST_NoWinSec | ForEach-Object { $_.Key }) -join ', ')"
    $ST_ShortNoLong = @($ST_Refs | Where-Object { $_.WinSecShort -and ($_.WinSec -match '^no switch') })
    Assert-SelfTest "DefenderRef: an entry with a short Windows Security path is not marked 'no switch'" ($ST_ShortNoLong.Count -eq 0)
    $ST_NoFr = @($ST_Refs | Where-Object { ($_.WinSecShort -or ($_.WinSec -notmatch '^no switch')) -and -not $_.WinSecFr })
    Assert-SelfTest "DefenderRef: every setting with a Windows Security switch also gives the French path" ($ST_NoFr.Count -eq 0) "Missing: $(($ST_NoFr | ForEach-Object { $_.Key }) -join ', ')"
    Assert-SelfTest "DefenderRef: no card names the 'Block apps' / 'Block downloads' sub-options (not found on Windows 11)" (@($ST_Refs | Where-Object { "$($_.WinSec) $($_.WinSecShort)" -match 'Block apps|Block downloads' }).Count -eq 0)
    $ST_AllCmds = @($ST_Refs | ForEach-Object { $_.Commands }) + @($ST_Refs | ForEach-Object { $_.Values } | ForEach-Object { $_.Fix } | Where-Object { $_ })
    $ST_OffCmds = @($ST_AllCmds | Where-Object { $_ -match '-Disable\w+\s+\$true' -or $_ -match '-(MAPSReporting|PUAProtection|EnableNetworkProtection|EnableControlledFolderAccess)\s+(Disabled|0)\b' })
    Assert-SelfTest "DefenderRef: no command turns a Defender protection off" ($ST_OffCmds.Count -eq 0) "Found: $($ST_OffCmds -join ' ; ')"
    Assert-SelfTest "DefenderRef: real-time protection only offers the command that turns it ON" ((@((Get-SettingRefByKey "DisableRealtimeMonitoring").Commands).Count -eq 1) -and ((Get-SettingRefByKey "DisableRealtimeMonitoring").Commands[0] -match '\$false'))

    # Every Defender setting row of sections 4 and 24 has its card
    $ST_Rows = @("Defender|Tamper Protection","Defender|PUA protection","Defender|Network Protection","Defender|Cloud protection (MAPS)",
                 "Defender|Cloud sample submission","Defender|Block at first sight","Defender|Cloud block level","Defender|Cloud extended timeout",
                 "Antivirus|Real-time protection","Defender|Controlled Folder Access (ransomware protection)")
    $ST_Missing = @($ST_Rows | Where-Object { $p = $_ -split '\|', 2; $null -eq (Get-SettingRef $p[0] $p[1]) })
    Assert-SelfTest "Get-SettingRef: all ten Defender setting rows have a card" ($ST_Missing.Count -eq 0) "Missing: $($ST_Missing -join ', ')"
    Assert-SelfTest "Get-SettingRef: an unrelated row has none" ($null -eq (Get-SettingRef "Firewall" "Domain profile"))

    # Value formatting: plain-language name + raw value as Get-MpPreference prints it
    Assert-SelfTest "Format-SettingValue: MAPS 2 -> 'Advanced (2)'"                ((Format-SettingValue "MAPSReporting" 2) -eq "Advanced (2)")
    Assert-SelfTest "Format-SettingValue: PUA 1 -> 'Enabled, block (1)'"           ((Format-SettingValue "PUAProtection" 1) -eq "Enabled, block (1)")
    Assert-SelfTest "Format-SettingValue: CloudBlockLevel 4 -> 'High+ (4)'"        ((Format-SettingValue "CloudBlockLevel" 4) -eq "High+ (4)")
    Assert-SelfTest "Format-SettingValue: block at first sight shows the property" ((Format-SettingValue "DisableBlockAtFirstSeen" $false) -eq "Enabled (DisableBlockAtFirstSeen = False)")
    Assert-SelfTest "Format-SettingValue: unknown value is flagged, not guessed"   ((Format-SettingValue "MAPSReporting" 9) -eq "Unknown (9)")

    # Range matching (the extended timeout is a number of seconds from 0 to 50)
    $ST_Timeout = (Get-SettingRefByKey "CloudExtendedTimeout").Values
    Assert-SelfTest "Test-RefValueMatch: 0 -> 'No extra time' only"      ((Test-RefValueMatch $ST_Timeout[0] "0") -and -not (Test-RefValueMatch $ST_Timeout[1] "0"))
    Assert-SelfTest "Test-RefValueMatch: 20 and 50 are inside 1-50"      ((Test-RefValueMatch $ST_Timeout[1] "20") -and (Test-RefValueMatch $ST_Timeout[1] "50"))
    Assert-SelfTest "Test-RefValueMatch: 51 and text are outside 1-50"   (-not (Test-RefValueMatch $ST_Timeout[1] "51") -and -not (Test-RefValueMatch $ST_Timeout[1] "abc"))

    # Detail sentence + HTML card, with a controlled state (no registry read)
    $ST_StateBackup = $script:RefState
    $script:RefState = @{}
    $script:RefState["PUAProtection"] = @{ Current = "2"; Policy = $null }
    $ST_Detail = Get-SettingDetail -Key "PUAProtection" -Current 2
    Assert-SelfTest "Get-SettingDetail: audit mode explains itself and gives the command" (($ST_Detail -match 'logged but not blocked') -and ($ST_Detail -match 'Set-MpPreference -PUAProtection Enabled'))
    $ST_Html = Get-SettingRefHtml "Defender" "PUA protection"
    Assert-SelfTest "Get-SettingRefHtml: the current value is highlighted exactly once" ((([regex]::Matches($ST_Html, "class='cur'")).Count -eq 1) -and ($ST_Html -match 'your value'))
    Assert-SelfTest "Get-SettingRefHtml: lists every value, a command and a Microsoft link" (($ST_Html -match 'Audit mode') -and ($ST_Html -match 'Set-MpPreference -PUAProtection AuditMode') -and ($ST_Html -match 'learn\.microsoft\.com'))
    Assert-SelfTest "Get-SettingRefHtml: no policy -> no policy warning"                   ($ST_Html -notmatch 'ref-warn')

    $ST_Html = Get-SettingRefHtml "Defender" "PUA protection"
    Assert-SelfTest "Get-SettingRefHtml: the Windows Security way comes first, PowerShell second" (($ST_Html -match "Easiest way:") -and ($ST_Html -match 'Potentially unwanted app blocking') -and ($ST_Html -match 'Or with PowerShell'))
    Assert-SelfTest "Get-SettingDetail: names the Windows Security path before the command"   (($ST_Detail -match 'Easiest: Windows Security') -and ($ST_Detail.IndexOf('Easiest') -lt $ST_Detail.IndexOf('Set-MpPreference')))
    Assert-SelfTest "Get-SettingRefHtml: the card also shows the French path" (($ST_Html -match 'On a French Windows') -and ($ST_Html -match 'Blocage d’’application potentiellement indésirable'))
    $ST_Html = Get-SettingRefHtml "Defender" "Cloud block level"
    Assert-SelfTest "Get-SettingRefHtml: a setting without a switch says so and goes straight to PowerShell" (($ST_Html -match 'In Windows Security:') -and ($ST_Html -match 'no switch for this setting') -and ($ST_Html -match 'Change it with PowerShell') -and ($ST_Html -notmatch 'Or with PowerShell'))
    $script:RefState["DisableRealtimeMonitoring"] = @{ Current = "True"; Policy = $null }
    Assert-SelfTest "Get-SettingDetail: real-time protection OFF points to the Windows Security switch first" ((Get-SettingDetail -Key "DisableRealtimeMonitoring" -Current "True") -match 'Easiest: Windows Security > Virus & threat protection > Manage settings > Real-time protection')
    $script:RefState["CloudExtendedTimeout"] = @{ Current = "20"; Policy = 20 }
    $ST_Html = Get-SettingRefHtml "Defender" "Cloud extended timeout"
    Assert-SelfTest "Get-SettingRefHtml: a policy value triggers the override warning"     (($ST_Html -match 'ref-warn') -and ($ST_Html -match 'overrides Set-MpPreference'))
    Assert-SelfTest "Get-SettingDetail: a policy value is named in the Detail"             ((Get-SettingDetail -Key "CloudExtendedTimeout" -Current 20) -match 'MpBafsExtendedTimeout = 20')
    Assert-SelfTest "Get-SettingRefHtml: a row without a card returns an empty string"     ((Get-SettingRefHtml "Firewall" "Domain profile") -eq "")
    $script:RefState = $ST_StateBackup

    # HTML escaping: nothing coming from the table may reach the report as markup
    $ST_RefBackup = $script:DefenderRef
    $script:DefenderRef = @(@{
        Key = 'TestKey'; Row = 'TestCat|TestCheck'; Title = 't'; What = '<b>what</b>'; Read = @('a <b>')
        Values = @(@{ Value = '1'; Name = 'n&n'; Meaning = '<script>alert(1)</script>' }); Commands = @('c <d>')
        Links = @(@{ Label = 'l'; Url = 'https://learn.microsoft.com/en-us/x?a=1&b=2' })
    })
    $script:RefState['TestKey'] = @{ Current = '1'; Policy = $null }
    $ST_Html = Get-SettingRefHtml "TestCat" "TestCheck"
    Assert-SelfTest "Get-SettingRefHtml: content is HTML-escaped (no raw <script> / <b>)" (($ST_Html -notmatch '<script') -and ($ST_Html -notmatch '<b>') -and ($ST_Html -match '&lt;script&gt;'))
    Assert-SelfTest "Get-SettingRefHtml: ampersands in URLs and names are escaped"          (($ST_Html -match 'a=1&amp;b=2') -and ($ST_Html -match 'n&amp;n'))
    # v5.6.1: the real table is restored here (it used to be restored at the very end of the SelfTest,
    # which hid it from every test added after the escaping tests).
    $script:DefenderRef = $ST_RefBackup

    # ── v5.6.0 ───────────────────────────────────────────────────────────────
    Write-Host ""
    Write-Host "  New v5.6.0 features" -ForegroundColor White
    $script:AuditResults = New-Object System.Collections.Generic.List[object]
    Add-Result "TestCat" "Indet1" "Unable to read" "INFO" ""
    Add-Result "TestCat" "Indet2" "Not available on this build" "INFO" ""
    Add-Result "TestCat" "Plain"  "Disabled" "INFO" ""
    Add-Result "TestCat" "OkRow"  "Unable to read" "WARN" ""
    Assert-SelfTest "Add-Result: 'Unable to read' INFO is flagged Indeterminate"          ([bool]$script:AuditResults[0].Indeterminate)
    Assert-SelfTest "Add-Result: 'Not available' INFO is flagged Indeterminate"           ([bool]$script:AuditResults[1].Indeterminate)
    Assert-SelfTest "Add-Result: a normal INFO is not Indeterminate"                      (-not [bool]$script:AuditResults[2].Indeterminate)
    Assert-SelfTest "Add-Result: a WARN is never Indeterminate"                           (-not [bool]$script:AuditResults[3].Indeterminate)
    $ST_W = @{ A = 2.0 }
    $ST_R = @(
        [PSCustomObject]@{ Category = "A"; Status = "FAIL"; Indeterminate = $false },
        [PSCustomObject]@{ Category = "A"; Status = "WARN"; Indeterminate = $false },
        [PSCustomObject]@{ Category = "A"; Status = "OK";   Indeterminate = $false })
    Assert-SelfTest "Get-AuditScoreRaw: 1 FAIL + 1 WARN + 1 OK -> 50"                     ([math]::Round((Get-AuditScoreRaw $ST_R $ST_W), 2) -eq 50)
    $ST_R2 = $ST_R + @([PSCustomObject]@{ Category = "A"; Status = "INFO"; Indeterminate = $true })
    Assert-SelfTest "Get-AuditScoreRaw: an Indeterminate result does not raise the score" ([math]::Round((Get-AuditScoreRaw $ST_R2 $ST_W), 2) -eq 50)
    Assert-SelfTest "Get-AuditScoreRaw: nothing but indeterminate results -> 100"         ((Get-AuditScoreRaw @([PSCustomObject]@{ Category = "A"; Status = "INFO"; Indeterminate = $true }) $ST_W) -eq 100)

    Assert-SelfTest "ConvertTo-SafeCsvCell: '=' prefixed"                                 ((ConvertTo-SafeCsvCell '=HYPERLINK("x")') -like "'=*")
    Assert-SelfTest "ConvertTo-SafeCsvCell: '@' prefixed"                                 ((ConvertTo-SafeCsvCell '@SUM(1)') -like "'@*")
    Assert-SelfTest "ConvertTo-SafeCsvCell: '+20 s ...' prefixed"                         ((ConvertTo-SafeCsvCell '+20 s (about 30 s)') -like "'+*")
    Assert-SelfTest "ConvertTo-SafeCsvCell: a plain number is left alone"                 ((ConvertTo-SafeCsvCell '-5') -eq '-5')
    Assert-SelfTest "ConvertTo-SafeCsvCell: normal text and null"                         (((ConvertTo-SafeCsvCell 'Steam') -eq 'Steam') -and ((ConvertTo-SafeCsvCell $null) -eq ''))

    Assert-SelfTest "UAC: consent 0 -> FAIL"                                              ((Get-UacAssessment Consent 0).Status -eq "FAIL")
    Assert-SelfTest "UAC: consent 1 and 2 (secure desktop) -> OK, not WARN"               (((Get-UacAssessment Consent 1).Status -eq "OK") -and ((Get-UacAssessment Consent 2).Status -eq "OK"))
    Assert-SelfTest "UAC: consent 5 (default) -> OK"                                      ((Get-UacAssessment Consent 5).Status -eq "OK")
    Assert-SelfTest "UAC: consent not set -> INFO (Windows default), not WARN"            ((Get-UacAssessment Consent $null).Status -eq "INFO")
    Assert-SelfTest "UAC: EnableLUA 0 -> FAIL, 1 -> OK, not set -> INFO"                  (((Get-UacAssessment LUA 0).Status -eq "FAIL") -and ((Get-UacAssessment LUA 1).Status -eq "OK") -and ((Get-UacAssessment LUA $null).Status -eq "INFO"))
    Assert-SelfTest "UAC: secure desktop 0 -> WARN, 1 -> OK, not set -> INFO"             (((Get-UacAssessment SecureDesktop 0).Status -eq "WARN") -and ((Get-UacAssessment SecureDesktop 1).Status -eq "OK") -and ((Get-UacAssessment SecureDesktop $null).Status -eq "INFO"))

    function New-STVol($p, $v, $pct, $m, $lock, $kp) { [PSCustomObject]@{ ProtectionStatus = $p; VolumeStatus = $v; EncryptionPercentage = $pct; EncryptionMethod = $m; LockStatus = $lock; KeyProtector = @($kp | ForEach-Object { [PSCustomObject]@{ KeyProtectorType = $_ } }) } }
    Assert-SelfTest "BitLocker: system volume off and decrypted -> FAIL"                  ((Get-BitLockerAssessment (New-STVol 'Off' 'FullyDecrypted' 0 'None' 'Unlocked' @()) $true).Status -eq "FAIL")
    Assert-SelfTest "BitLocker: data volume off and decrypted -> WARN"                    ((Get-BitLockerAssessment (New-STVol 'Off' 'FullyDecrypted' 0 'None' 'Unlocked' @()) $false).Status -eq "WARN")
    Assert-SelfTest "BitLocker: protection on with TPM + recovery password -> OK"         ((Get-BitLockerAssessment (New-STVol 'On' 'FullyEncrypted' 100 'XtsAes256' 'Unlocked' @('Tpm','RecoveryPassword')) $true).Status -eq "OK")
    Assert-SelfTest "BitLocker: protection on, no recovery password -> WARN"              ((Get-BitLockerAssessment (New-STVol 'On' 'FullyEncrypted' 100 'XtsAes256' 'Unlocked' @('Tpm')) $true).Status -eq "WARN")
    Assert-SelfTest "BitLocker: fully encrypted but suspended -> WARN (not FAIL)"         (((Get-BitLockerAssessment (New-STVol 'Off' 'FullyEncrypted' 100 'XtsAes256' 'Unlocked' @('Tpm')) $true).Status -eq "WARN") -and ((Get-BitLockerAssessment (New-STVol 'Off' 'FullyEncrypted' 100 'XtsAes256' 'Unlocked' @('Tpm')) $true).Detail -match "SUSPENDED"))
    Assert-SelfTest "BitLocker: locked volume is encrypted -> OK"                         ((Get-BitLockerAssessment (New-STVol 'Unknown' 'FullyEncrypted' 100 'XtsAes256' 'Locked' @()) $false).Status -eq "OK")
    Assert-SelfTest "BitLocker: encryption in progress -> INFO"                           ((Get-BitLockerAssessment (New-STVol 'Off' 'EncryptionInProgress' 40 'XtsAes256' 'Unlocked' @('Tpm')) $true).Status -eq "INFO")
    Assert-SelfTest "BitLocker: unreadable state -> WARN"                                 ((Get-BitLockerAssessment (New-STVol 'Unknown' 'Unknown' $null '' 'Unlocked' @()) $false).Status -eq "WARN")

    Assert-SelfTest "Path: inside the root"                                               (Test-PathUnderRoot 'C:\Windows\System32\drivers\a.sys' @('C:\Windows\System32\drivers'))
    Assert-SelfTest "Path: 'system32\drivers' inside a Temp folder is NOT the Windows folder" (-not (Test-PathUnderRoot 'C:\Users\x\AppData\Local\Temp\system32\drivers\a.sys' @('C:\Windows\System32\drivers')))
    Assert-SelfTest "Path: '..' cannot escape the root"                                   (-not (Test-PathUnderRoot 'C:\Windows\System32\..\Temp\x.exe' @('C:\Windows\System32')))
    Assert-SelfTest "Path: case-insensitive, quotes and \??\ prefix handled"              ((Test-PathUnderRoot 'c:\WINDOWS\system32\svchost.exe' @('C:\Windows\System32')) -and (Test-PathUnderRoot '"C:\Windows\System32\x.exe"' @('C:\Windows\System32')) -and (Test-PathUnderRoot '\??\C:\Windows\System32\drivers\x.sys' @('C:\Windows\System32')))
    Assert-SelfTest "Path: a sibling folder with the same prefix is not inside"           (-not (Test-PathUnderRoot 'C:\Windows\System32evil\x.exe' @('C:\Windows\System32')))

    Assert-SelfTest "Signer: Microsoft Corporation / Microsoft Windows accepted"          ((Test-MicrosoftSigner 'CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US') -and (Test-MicrosoftSigner 'CN=Microsoft Windows, O=Microsoft Corporation, C=US'))
    Assert-SelfTest "Signer: 'Microsoft' only in another name is rejected"                ((-not (Test-MicrosoftSigner 'CN=Microsoft Scam LLC, O=Not Microsoft, C=US')) -and (-not (Test-MicrosoftSigner 'CN=Evil Inc, O=Microsoft Corporation')) -and (-not (Test-MicrosoftSigner 'CN=Valve Corp., O=Valve Corp.')))

    Assert-SelfTest "Firewall group: built-in resource strings recognised"                ((Test-FirewallBuiltInGroup '@FirewallAPI.dll,-80201') -and (Test-FirewallBuiltInGroup '@%SystemRoot%\system32\firewallapi.dll,-80201') -and (Test-FirewallBuiltInGroup '@wlansvc.dll,-37002'))
    Assert-SelfTest "Firewall group: packaged Windows apps recognised"                    (Test-FirewallBuiltInGroup '@{Microsoft.Windows.StartMenuExperienceHost_10.0.26100.4768_neutral_neutral_cw5n1h2txyewy?ms-resource://Microsoft.Windows.StartMenuExperienceHost/StartMenuExperienceHost/AppName}')
    Assert-SelfTest "Firewall group: a display name, a GUID, an empty or user-path group is not built-in" ((-not (Test-FirewallBuiltInGroup 'Microsoft Edge WebView2 Runtime')) -and (-not (Test-FirewallBuiltInGroup '{78E1CD88-49E3-476E-B926-580E596AD309}')) -and (-not (Test-FirewallBuiltInGroup '')) -and (-not (Test-FirewallBuiltInGroup '@C:\Users\x\evil.dll,-1')))

    Assert-SelfTest "Service path: quoted path with arguments"                            ((Get-ServiceImagePath '"C:\Program Files\X Y\svc.exe" -k run') -eq 'C:\Program Files\X Y\svc.exe')
    Assert-SelfTest "Service path: unquoted path with spaces and arguments"               ((Get-ServiceImagePath 'C:\Program Files\X Y\svc.exe -k run') -eq 'C:\Program Files\X Y\svc.exe')
    Assert-SelfTest "Service path: unquoted path containing spaces is detected"           ((Test-UnquotedServicePath 'C:\Program Files\X\svc.exe -a') -and (-not (Test-UnquotedServicePath '"C:\Program Files\X\svc.exe" -a')) -and (-not (Test-UnquotedServicePath 'C:\Windows\system32\svchost.exe -k x')))

    Assert-SelfTest "Task args: encoded command / download / hidden window are suspicious" ((Test-SuspiciousTaskArgs '-NoP -enc SQBFAFgA') -and (Test-SuspiciousTaskArgs '-Command "IEX (New-Object Net.WebClient).DownloadString(''http://x'')"') -and (Test-SuspiciousTaskArgs '-WindowStyle Hidden -File x.ps1'))
    Assert-SelfTest "Task args: a plain -File invocation is not suspicious"               (-not (Test-SuspiciousTaskArgs '-NoProfile -ExecutionPolicy Bypass -File "C:\Users\a\Desktop\x.ps1"'))
    $ST_Sp = 'C:\Users\a\Desktop\x.ps1'
    Assert-SelfTest "Task script: -File / positional / & invocation is accepted"          ((Test-TaskScriptInvocation "-NoProfile -ExecutionPolicy Bypass -File `"$ST_Sp`"" $ST_Sp) -and (Test-TaskScriptInvocation "-NoProfile `"$ST_Sp`"" $ST_Sp) -and (Test-TaskScriptInvocation "-File `"$ST_Sp`" -Mode Weekly" $ST_Sp))
    Assert-SelfTest "Task script: a path that merely appears after other code is rejected" ((-not (Test-TaskScriptInvocation "-enc SQBFAFgA # $ST_Sp" $ST_Sp)) -and (-not (Test-TaskScriptInvocation "-Command Remove-Item C:\foo ; $ST_Sp" $ST_Sp)) -and (-not (Test-TaskScriptInvocation "-File other.ps1" $ST_Sp)))

    Assert-SelfTest "Defender exclusion: broad folders flagged"                           ((Test-BroadDefenderExclusion 'C:\') -and (Test-BroadDefenderExclusion 'C:\Users') -and (Test-BroadDefenderExclusion 'C:\Users\bob') -and (Test-BroadDefenderExclusion 'C:\Program Files') -and (Test-BroadDefenderExclusion 'D:\data\*') -and (Test-BroadDefenderExclusion 'C:\Users\bob\Downloads'))
    Assert-SelfTest "Defender exclusion: a single application folder is not broad"        ((-not (Test-BroadDefenderExclusion 'C:\Program Files\MyApp')) -and (-not (Test-BroadDefenderExclusion 'C:\Windows\System32\drivers\etc\hosts')))
    Assert-SelfTest "Defender exclusion: executable / script extensions and interpreters are risky" ((Test-RiskyExclusionExtension '.exe') -and (Test-RiskyExclusionExtension 'ps1') -and (-not (Test-RiskyExclusionExtension '.log')) -and (Test-RiskyExclusionProcess 'powershell.exe') -and (Test-RiskyExclusionProcess '*') -and (-not (Test-RiskyExclusionProcess 'steam.exe')))

    Assert-SelfTest "AV state: 397568 (0x061100) = on and up to date"                     (((Get-AvProductState 397568).Enabled) -and ((Get-AvProductState 397568).UpToDate))
    Assert-SelfTest "AV state: 393472 (0x060100) = off; 397584 (0x061110) = on, out of date" ((-not (Get-AvProductState 393472).Enabled) -and ((Get-AvProductState 397584).Enabled) -and (-not (Get-AvProductState 397584).UpToDate))
    Assert-SelfTest "AV state: unreadable value is not 'known'"                           (-not (Get-AvProductState $null).Known)

    Assert-SelfTest "Winlogon: defaults accepted, extra Userinit / foreign Shell rejected" ((Test-WinlogonShellUserinit 'explorer.exe' "$env:SystemRoot\System32\userinit.exe,").UserinitOk -and (Test-WinlogonShellUserinit 'explorer.exe' "$env:SystemRoot\System32\userinit.exe,").ShellOk -and (-not (Test-WinlogonShellUserinit 'explorer.exe' "$env:SystemRoot\System32\userinit.exe,C:\evil.exe").UserinitOk) -and (-not (Test-WinlogonShellUserinit 'evil.exe' '').ShellOk))
    $ST_Inf = "[System Access]`r`nMinimumPasswordAge = 1`r`nMaximumPasswordAge = -1`r`nMinimumPasswordLength = 10`r`nLockoutBadCount = 5`r`nLockoutDuration = -1`r`n"
    $ST_Pol = ConvertFrom-SeceditPolicy $ST_Inf
    Assert-SelfTest "Secedit policy: keys read whatever the language of Windows"          (($ST_Pol.MinPwdLen -eq 10) -and ($ST_Pol.MaxPwdAgeDays -eq -1) -and ($ST_Pol.LockoutThreshold -eq 5) -and ($ST_Pol.LockoutDurMinutes -eq -1))
    Assert-SelfTest "Secedit policy: unrelated text returns null"                         ($null -eq (ConvertFrom-SeceditPolicy "nothing here"))
    Assert-SelfTest "Process trust: protected core processes without a readable path are Windows" (((Get-ProcessTrustClass '' $null 'lsass') -eq 'Windows') -and ((Get-ProcessTrustClass '' $null 'System') -eq 'Windows') -and ((Get-ProcessTrustClass $null $null 'wininit.exe') -eq 'Windows') -and ((Get-ProcessTrustClass '' $null 'services') -eq 'Windows'))
    # ── v5.6.1 ───────────────────────────────────────────────────────────────
    Write-Host ""
    Write-Host "  New v5.6.1 features" -ForegroundColor White
    Assert-SelfTest "Controlled Folder Access: values are named like the other Defender settings"  (((Format-SettingValue "EnableControlledFolderAccess" 1) -eq "Enabled (1)") -and ((Format-SettingValue "EnableControlledFolderAccess" 0) -eq "Disabled (0)") -and ((Format-SettingValue "EnableControlledFolderAccess" 2) -eq "Audit mode (2)"))
    $ST_CfaDetail = Get-SettingDetail -Key "EnableControlledFolderAccess" -Current 0
    Assert-SelfTest "Controlled Folder Access: Disabled names the Windows Security path, then the command to turn it ON" (($ST_CfaDetail -match 'Ransomware protection') -and ($ST_CfaDetail -match 'Set-MpPreference -EnableControlledFolderAccess Enabled'))
    Assert-SelfTest "Controlled Folder Access: the card gives the French path and the Microsoft Learn links"       ($null -ne (Get-SettingRef "Defender" "Controlled Folder Access (ransomware protection)") -and ((Get-SettingRefByKey "EnableControlledFolderAccess").WinSecFr -match 'Accès contrôlé aux dossiers') -and (@((Get-SettingRefByKey "EnableControlledFolderAccess").Links).Count -ge 2))
    Assert-SelfTest "Process trust: Defender's protected services without a readable path are Windows (v5.6.2)" (((Get-ProcessTrustClass '' $null 'MsMpEng') -eq 'Windows') -and ((Get-ProcessTrustClass '' $null 'MpDefenderCoreService') -eq 'Windows') -and ((Get-ProcessTrustClass '' $null 'NisSrv.exe') -eq 'Windows') -and ((Get-ProcessTrustClass '' $null 'MsMpEng2') -eq 'Unverified'))
    Assert-SelfTest "Process trust: any other process without a readable path stays Unverified" (((Get-ProcessTrustClass '' $null 'chrome') -eq 'Unverified') -and ((Get-ProcessTrustClass '' $null 'lsass2') -eq 'Unverified') -and ((Get-ProcessTrustClass '' $null) -eq 'Unverified'))
    $script:RefState.Remove('TestKey')

    # ── v5.7.0 ────────────────────────────────────────
    Write-Host ""
    Write-Host "  New v5.7.0 features" -ForegroundColor White
    # UDP endpoints
    $ST_UdpOff = @{ LLMNR = $true; mDNS = $true; NetBIOS = $true }
    $ST_UdpOn  = @{ LLMNR = $false; mDNS = $false; NetBIOS = $false }
    Assert-SelfTest "UDP: Windows process on 5355 while LLMNR is off -> WARN"        ((Get-UdpEndpointAssessment -Port 5355 -TrustClass "Windows" -AllInterfaces $true -Disabled $ST_UdpOff).Status -eq "WARN")
    Assert-SelfTest "UDP: Windows process on 5355 while LLMNR is on -> INFO"         ((Get-UdpEndpointAssessment -Port 5355 -TrustClass "Windows" -AllInterfaces $true -Disabled $ST_UdpOn).Status -eq "INFO")
    Assert-SelfTest "UDP: Windows process on 5353 while mDNS is off -> WARN"         ((Get-UdpEndpointAssessment -Port 5353 -TrustClass "Windows" -AllInterfaces $true -Disabled $ST_UdpOff).Status -eq "WARN")
    Assert-SelfTest "UDP: a signed browser on 5353 while mDNS is off stays INFO"      ((Get-UdpEndpointAssessment -Port 5353 -TrustClass "Signed" -AllInterfaces $true -Disabled $ST_UdpOff).Status -eq "INFO")
    Assert-SelfTest "UDP: Windows process on 137 while NetBIOS is off -> WARN"       ((Get-UdpEndpointAssessment -Port 137 -TrustClass "Windows" -AllInterfaces $false -Disabled $ST_UdpOff).Status -eq "WARN")
    Assert-SelfTest "UDP: Windows process on 137 while NetBIOS is on -> INFO"        ((Get-UdpEndpointAssessment -Port 137 -TrustClass "Windows" -AllInterfaces $false -Disabled $ST_UdpOn).Status -eq "INFO")
    Assert-SelfTest "UDP: non-Windows program on a NetBIOS port -> WARN"             ((Get-UdpEndpointAssessment -Port 138 -TrustClass "Signed" -AllInterfaces $false -Disabled $ST_UdpOn).Status -eq "WARN")
    Assert-SelfTest "UDP: sensitive ports 69 / 161 / 1434 / 11211 -> WARN"           (((69, 161, 1434, 11211) | Where-Object { (Get-UdpEndpointAssessment -Port $_ -TrustClass "Signed" -AllInterfaces $false -Disabled $ST_UdpOn).Status -ne "WARN" }).Count -eq 0)
    Assert-SelfTest "UDP: unverified program on every interface -> WARN"             ((Get-UdpEndpointAssessment -Port 40000 -TrustClass "Unverified" -AllInterfaces $true -Disabled $ST_UdpOn).Status -eq "WARN")
    Assert-SelfTest "UDP: unverified program on one address only -> INFO"            ((Get-UdpEndpointAssessment -Port 40000 -TrustClass "Unverified" -AllInterfaces $false -Disabled $ST_UdpOn).Status -eq "INFO")
    Assert-SelfTest "UDP: usual Windows ports (123, 1900, 3702, 500, ephemeral) -> INFO" (((123, 1900, 3702, 500, 58675) | Where-Object { (Get-UdpEndpointAssessment -Port $_ -TrustClass "Windows" -AllInterfaces $true -Disabled $ST_UdpOff).Status -ne "INFO" }).Count -eq 0)
    Assert-SelfTest "UDP: missing flags table does not fail"                         ((Get-UdpEndpointAssessment -Port 5353 -TrustClass "Windows" -AllInterfaces $true -Disabled $null).Status -eq "INFO")
    # Windows editions (OperatingSystemSKU, Microsoft GetProductInfo constants)
    Assert-SelfTest "Edition: Home (101) and Pro (48) -> HomePro"                    (((Get-WindowsEditionFamily 101) -eq "HomePro") -and ((Get-WindowsEditionFamily 48) -eq "HomePro") -and ((Get-WindowsEditionFamily "101") -eq "HomePro"))
    Assert-SelfTest "Edition: Enterprise (4) and Education (121) -> EntEdu"         (((Get-WindowsEditionFamily 4) -eq "EntEdu") -and ((Get-WindowsEditionFamily 121) -eq "EntEdu"))
    Assert-SelfTest "Edition: LTSC (125, 191) -> Ltsc"                               (((Get-WindowsEditionFamily 125) -eq "Ltsc") -and ((Get-WindowsEditionFamily 191) -eq "Ltsc"))
    Assert-SelfTest "Edition: Server (7), null and text -> Unknown (no guessed date)" (((Get-WindowsEditionFamily 7) -eq "Unknown") -and ((Get-WindowsEditionFamily $null) -eq "Unknown") -and ((Get-WindowsEditionFamily "x") -eq "Unknown"))
    # Windows build lifecycle (fixed test table, independent from the real dates)
    $ST_LcTable = @(
        [PSCustomObject]@{ Build = 26200; Version = "25H2"; HomePro = [datetime]"2027-10-12"; EntEdu = [datetime]"2028-10-10" }
        [PSCustomObject]@{ Build = 26100; Version = "24H2"; HomePro = [datetime]"2026-10-13"; EntEdu = [datetime]"2027-10-12" }
    )
    $ST_LcDate  = [datetime]"2026-11-19"
    $ST_LcEnded = @(22000, 22621, 22631)
    function Get-StLifecycle { param($Build, $Sku, [string]$Today) Get-WindowsLifecycleStatus -Build $Build -Sku $Sku -Today ([datetime]$Today) -Table $ST_LcTable -EndedBuilds $ST_LcEnded -TableDate $ST_LcDate -DisplayVersion "25H2" -Ubr 9974 }
    $ST_Lc1 = Get-StLifecycle 26200 101 "2026-11-19"
    Assert-SelfTest "Lifecycle: 25H2 Home, supported -> OK with end date and days left" (($ST_Lc1.Status -eq "OK") -and ($ST_Lc1.Value -match '2027-10-12') -and ($ST_Lc1.Value -match '327 day') -and ($ST_Lc1.Value -match '26200\.9974'))
    Assert-SelfTest "Lifecycle: 25H2 Pro uses the Home/Pro date"                     (((Get-StLifecycle 26200 48 "2026-11-19").Value) -match '2027-10-12')
    Assert-SelfTest "Lifecycle: 25H2 Enterprise uses the Enterprise/Education date"  (((Get-StLifecycle 26200 4 "2026-11-19").Value) -match '2028-10-10')
    Assert-SelfTest "Lifecycle: less than 90 days left -> WARN"                      ((Get-StLifecycle 26200 101 "2027-08-01").Status -eq "WARN")
    Assert-SelfTest "Lifecycle: last day of support -> WARN, next day -> FAIL"       (((Get-StLifecycle 26200 101 "2027-10-12").Status -eq "WARN") -and ((Get-StLifecycle 26200 101 "2027-10-13").Status -eq "FAIL"))
    Assert-SelfTest "Lifecycle: 24H2 Home after its end date -> FAIL"                ((Get-StLifecycle 26100 101 "2026-11-19").Status -eq "FAIL")
    Assert-SelfTest "Lifecycle: 24H2 Enterprise still supported -> OK"               ((Get-StLifecycle 26100 4 "2026-11-19").Status -eq "OK")
    Assert-SelfTest "Lifecycle: table older than 6 months -> a supported build is INFO, not OK" (((Get-StLifecycle 26200 101 "2027-06-07").Status -eq "INFO") -and ((Get-StLifecycle 26100 101 "2027-06-07").Status -eq "FAIL"))
    Assert-SelfTest "Lifecycle: 23H2 (22631) -> FAIL"                                ((Get-StLifecycle 22631 101 "2026-11-19").Status -eq "FAIL")
    Assert-SelfTest "Lifecycle: build newer than the table -> INFO"                  ((Get-StLifecycle 26400 101 "2026-11-19").Status -eq "INFO")
    $ST_LcLtsc = Get-StLifecycle 26100 125 "2026-11-19"
    Assert-SelfTest "Lifecycle: LTSC edition -> INFO, never a guessed date"          (($ST_LcLtsc.Status -eq "INFO") -and ($ST_LcLtsc.Value -notmatch '^Not available'))
    $ST_LcSrv = Get-StLifecycle 26100 7 "2026-11-19"
    Assert-SelfTest "Lifecycle: unknown edition (Server) -> INFO flagged 'Not available'" (($ST_LcSrv.Status -eq "INFO") -and ($ST_LcSrv.Value -match '^Not available'))
    Assert-SelfTest "Lifecycle: Windows 10 build -> INFO 'Not available' (already FAIL in section 1)" (((Get-StLifecycle 19045 101 "2026-11-19").Status -eq "INFO") -and ((Get-StLifecycle 19045 101 "2026-11-19").Value -match '^Not available'))
    Assert-SelfTest "Lifecycle: the real table is consistent (unique builds, Ent/Edu >= Home/Pro, 25H2 present)" ((@($WindowsLifecycleTable | ForEach-Object { [int]$_.Build } | Select-Object -Unique).Count -eq $WindowsLifecycleTable.Count) -and (@($WindowsLifecycleTable | Where-Object { $_.EntEdu -lt $_.HomePro }).Count -eq 0) -and (@($WindowsLifecycleTable | Where-Object { [int]$_.Build -eq 26200 }).Count -eq 1))
    Assert-SelfTest "Lifecycle: 25H2 Home on the real table at the table date -> OK" ((Get-WindowsLifecycleStatus -Build 26200 -Sku 101 -Today $WindowsLifecycleTableDate -Table $WindowsLifecycleTable -EndedBuilds $WindowsLifecycleEndedBuilds -TableDate $WindowsLifecycleTableDate).Status -eq "OK")
    # Secure Boot 2023 certificates
    function Get-StSb { param($Sb = $true, $Status = "", $Err = "", $ErrEv = "", $Db = $null, $Kek = $null, $Ev = @()) Get-SecureBootCertAssessment -SecureBootEnabled $Sb -Status $Status -ErrorValue $Err -ErrorEvent $ErrEv -DbHas2023 $Db -KekHas2023 $Kek -EventIds $Ev }
    Assert-SelfTest "Secure Boot certs: unreadable Secure Boot state -> INFO 'Unable to determine'" (((Get-StSb -Sb $null).Status -eq "INFO") -and ((Get-StSb -Sb $null).Value -match '^Unable to determine'))
    Assert-SelfTest "Secure Boot certs: Secure Boot off -> INFO not applicable"       (((Get-StSb -Sb $false).Status -eq "INFO") -and ((Get-StSb -Sb $false).Value -match 'Not applicable'))
    Assert-SelfTest "Secure Boot certs: Updated + 2023 certificates in db and KEK -> OK" ((Get-StSb -Status "Updated" -Db $true -Kek $true).Status -eq "OK")
    Assert-SelfTest "Secure Boot certs: Updated but KEK not confirmed -> INFO"        ((Get-StSb -Status "Updated" -Db $true -Kek $false).Status -eq "INFO")
    Assert-SelfTest "Secure Boot certs: Updated but not found in db -> INFO, never OK" ((Get-StSb -Status "Updated" -Db $false -Kek $false).Status -eq "INFO")
    Assert-SelfTest "Secure Boot certs: Updated with unreadable db -> 'Unable to determine'" (((Get-StSb -Status "Updated").Status -eq "INFO") -and ((Get-StSb -Status "Updated").Value -match '^Unable to determine'))
    Assert-SelfTest "Secure Boot certs: no servicing status -> 'Unable to determine', never OK" (((Get-StSb -Status "").Status -eq "INFO") -and ((Get-StSb -Status "").Value -match '^Unable to determine'))
    Assert-SelfTest "Secure Boot certs: NotStarted, nothing blocking -> WARN"         ((Get-StSb -Status "NotStarted" -Db $false -Kek $false -Ev @()).Status -eq "WARN")
    Assert-SelfTest "Secure Boot certs: NotStarted with event 1802 or 1803 -> INFO (blocked)" (((Get-StSb -Status "NotStarted" -Ev @(1802)).Status -eq "INFO") -and ((Get-StSb -Status "NotStarted" -Ev @(1803)).Value -match 'blocked'))
    Assert-SelfTest "Secure Boot certs: NotStarted with a recorded error -> INFO (blocked)" ((Get-StSb -Status "NotStarted" -Err "5" -Ev @()).Status -eq "INFO")
    Assert-SelfTest "Secure Boot certs: error value 0 is not an error"               ((Get-StSb -Status "NotStarted" -Err "0" -ErrEv "0" -Db $false -Ev @()).Status -eq "WARN")
    Assert-SelfTest "Secure Boot certs: restart pending (1800/1801) or InProgress -> INFO" (((Get-StSb -Status "NotStarted" -Ev @(1801)).Status -eq "INFO") -and ((Get-StSb -Status "InProgress" -Ev @()).Status -eq "INFO"))
    Assert-SelfTest "Secure Boot certs: NotStarted but 2023 already in db -> INFO"    ((Get-StSb -Status "NotStarted" -Db $true -Ev @()).Status -eq "INFO")
    Assert-SelfTest "Secure Boot certs: unreadable event log is never turned into a WARN" (((Get-StSb -Status "NotStarted" -Db $false -Ev $null).Status -eq "INFO") -and ((Get-StSb -Status "NotStarted" -Db $false -Ev $null).Value -match '^Unable to determine'))
    Assert-SelfTest "Secure Boot certs: unknown status text -> 'Unable to determine'"  ((Get-StSb -Status "Foo").Value -match '^Unable to determine')
    $ST_UefiBytes = [System.Text.Encoding]::ASCII.GetBytes("xx Windows UEFI CA 2023 yy")
    Assert-SelfTest "UEFI variable text: found / not found / unreadable"             (((Test-UefiSignatureText $ST_UefiBytes "Windows UEFI CA 2023") -eq $true) -and ((Test-UefiSignatureText $ST_UefiBytes "Microsoft Windows Production PCA 2011") -eq $false) -and ($null -eq (Test-UefiSignatureText $null "x")))
    # Indeterminate flag on the new 'could not be assessed' values
    $script:AuditResults.Clear()
    Add-Result "TestCat" "Sb" (Get-StSb -Status "").Value "INFO" ""
    Add-Result "TestCat" "Lc" $ST_LcSrv.Value "INFO" ""
    Assert-SelfTest "New checks: 'could not be assessed' values are flagged Indeterminate (left out of the score)" (([bool]$script:AuditResults[0].Indeterminate) -and ([bool]$script:AuditResults[1].Indeterminate))

    # ── v5.7.1 ────────────────────────────────────────
    Write-Host ""
    Write-Host "  New v5.7.1 features" -ForegroundColor White
    # Windows Update policies
    Assert-SelfTest "WU policies: NoAutoUpdate = 1 -> WARN"                          ((Get-WindowsUpdatePolicyAssessment -NoAutoUpdate 1).Status -eq "WARN")
    Assert-SelfTest "WU policies: NoAutoUpdate = 0 or absent -> OK"                  (((Get-WindowsUpdatePolicyAssessment -NoAutoUpdate 0).Status -eq "OK") -and ((Get-WindowsUpdatePolicyAssessment).Status -eq "OK"))
    $ST_Wu = Get-WindowsUpdatePolicyAssessment -DeferFeature 1 -DeferFeatureDays 30 -DeferQuality 1 -DeferQualityDays 4
    Assert-SelfTest "WU policies: feature and quality deferrals -> INFO with the days" (($ST_Wu.Status -eq "INFO") -and ($ST_Wu.Value -match 'feature updates deferred 30 day') -and ($ST_Wu.Value -match 'quality updates deferred 4 day'))
    Assert-SelfTest "WU policies: intranet update server (UseWUServer = 1) -> INFO"  (((Get-WindowsUpdatePolicyAssessment -UseWUServer 1).Status -eq "INFO") -and ((Get-WindowsUpdatePolicyAssessment -UseWUServer 1).Value -match 'WSUS'))
    Assert-SelfTest "WU policies: deferral flag 0 with a period set is not a deferral" ((Get-WindowsUpdatePolicyAssessment -DeferFeature 0 -DeferFeatureDays 30).Status -eq "OK")
    Assert-SelfTest "WU policies: text values are read as numbers, junk is ignored"  (((Get-WindowsUpdatePolicyAssessment -NoAutoUpdate "1").Status -eq "WARN") -and ((Get-WindowsUpdatePolicyAssessment -NoAutoUpdate "x" -DeferQuality "y").Status -eq "OK"))
    # Defender platform / engine
    function Get-StSeries { param($v) $s = Get-DefenderVersionSeries $v; if ($s) { $s.ToString("yyyy-MM", [System.Globalization.CultureInfo]::InvariantCulture) } else { $null } }
    Assert-SelfTest "Defender series: 4.18.26100.4 and 1.1.26100.4 -> 2026-10"      (((Get-StSeries "4.18.26100.4") -eq "2026-10") -and ((Get-StSeries "1.1.26100.4") -eq "2026-10"))
    Assert-SelfTest "Defender series: Microsoft table examples (25100.9008, 24080.9)" (((Get-StSeries "4.18.25100.9008") -eq "2025-10") -and ((Get-StSeries "4.18.24080.9") -eq "2024-08"))
    Assert-SelfTest "Defender series: old 4-digit form 4.18.2203.5 -> 2022-03"      ((Get-StSeries "4.18.2203.5") -eq "2022-03")
    Assert-SelfTest "Defender series: invalid month, text and empty -> null"         (($null -eq (Get-DefenderVersionSeries "4.18.26130.1")) -and ($null -eq (Get-DefenderVersionSeries "abc")) -and ($null -eq (Get-DefenderVersionSeries "")))
    $ST_Today = [datetime]"2026-11-20"
    Assert-SelfTest "Defender age: current platform and engine -> OK"                ((Get-DefenderVersionAssessment -PlatformVersion "4.18.26100.4" -EngineVersion "1.1.26100.4" -Today $ST_Today).Status -eq "OK")
    Assert-SelfTest "Defender age: 3 months behind -> OK, 4 months behind -> WARN"   (((Get-DefenderVersionAssessment -PlatformVersion "4.18.26080.1" -EngineVersion "1.1.26080.1" -Today $ST_Today).Status -eq "OK") -and ((Get-DefenderVersionAssessment -PlatformVersion "4.18.26070.1" -EngineVersion "1.1.26070.1" -Today $ST_Today).Status -eq "WARN"))
    Assert-SelfTest "Defender age: an old engine alone is enough for a WARN"        ((Get-DefenderVersionAssessment -PlatformVersion "4.18.26100.4" -EngineVersion "1.1.26010.1" -Today $ST_Today).Status -eq "WARN")
    Assert-SelfTest "Defender age: passive mode -> INFO, never WARN"                 ((Get-DefenderVersionAssessment -PlatformVersion "4.18.26010.1" -EngineVersion "1.1.26010.1" -Today $ST_Today -Passive $true).Status -eq "INFO")
    $ST_DefBad = Get-DefenderVersionAssessment -PlatformVersion "" -EngineVersion "" -Today $ST_Today
    Assert-SelfTest "Defender age: unreadable versions -> 'Unable to determine'"     (($ST_DefBad.Status -eq "INFO") -and ($ST_DefBad.Value -match '^Unable to determine'))
    Assert-SelfTest "Defender age: one version not decodable -> still judged on the other" (((Get-DefenderVersionAssessment -PlatformVersion "4.18.26100.4" -EngineVersion "weird" -Today $ST_Today).Status -eq "OK") -and ((Get-DefenderVersionAssessment -PlatformVersion "4.18.26100.4" -EngineVersion "weird" -Today $ST_Today).Value -match 'not decoded'))
    # SMBv1 client
    Assert-SelfTest "SMBv1 client: feature list unreadable -> INFO 'Unable to read'" (((Get-Smb1ClientAssessment -ListReadable $false -Found $false -State "").Status -eq "INFO") -and ((Get-Smb1ClientAssessment -ListReadable $false -Found $false -State "").Value -eq "Unable to read"))
    Assert-SelfTest "SMBv1 client: feature absent from this Windows -> OK"           ((Get-Smb1ClientAssessment -ListReadable $true -Found $false -State "").Status -eq "OK")
    Assert-SelfTest "SMBv1 client: Enabled / EnablePending -> WARN"                  (((Get-Smb1ClientAssessment -ListReadable $true -Found $true -State "Enabled").Status -eq "WARN") -and ((Get-Smb1ClientAssessment -ListReadable $true -Found $true -State "EnablePending").Status -eq "WARN"))
    Assert-SelfTest "SMBv1 client: Disabled / DisablePending / payload removed -> OK" (((Get-Smb1ClientAssessment -ListReadable $true -Found $true -State "Disabled").Status -eq "OK") -and ((Get-Smb1ClientAssessment -ListReadable $true -Found $true -State "DisablePending").Status -eq "OK") -and ((Get-Smb1ClientAssessment -ListReadable $true -Found $true -State "DisabledWithPayloadRemoved").Status -eq "OK"))
    Assert-SelfTest "SMBv1 client: unknown state -> 'Unable to determine'"           (((Get-Smb1ClientAssessment -ListReadable $true -Found $true -State "Superseded").Status -eq "INFO") -and ((Get-Smb1ClientAssessment -ListReadable $true -Found $true -State "Superseded").Value -match '^Unable to determine'))
    # Application control
    $ST_AlXml = '<AppLockerPolicy Version="1"><RuleCollection Type="Exe" EnforcementMode="Enabled"><FilePathRule Id="a" Name="n" Description="" UserOrGroupSid="S-1-1-0" Action="Allow"><Conditions><FilePathCondition Path="*" /></Conditions></FilePathRule></RuleCollection><RuleCollection Type="Dll" EnforcementMode="AuditOnly"><FilePathRule Id="b" Name="n" Description="" UserOrGroupSid="S-1-1-0" Action="Allow"><Conditions><FilePathCondition Path="*" /></Conditions></FilePathRule><FilePathRule Id="c" Name="n" Description="" UserOrGroupSid="S-1-1-0" Action="Allow"><Conditions><FilePathCondition Path="*" /></Conditions></FilePathRule></RuleCollection><RuleCollection Type="Msi" EnforcementMode="Enabled" /></AppLockerPolicy>'
    $ST_AlSum = Get-AppLockerSummary $ST_AlXml
    Assert-SelfTest "AppLocker XML: rules counted, enforced and audit collections told apart" (($ST_AlSum.Rules -eq 3) -and ((@($ST_AlSum.Enforced) -join ",") -eq "Exe") -and ((@($ST_AlSum.Audit) -join ",") -eq "Dll"))
    Assert-SelfTest "AppLocker XML: empty policy -> 0 rule, invalid text -> null"    (((Get-AppLockerSummary '<AppLockerPolicy Version="1" />').Rules -eq 0) -and ($null -eq (Get-AppLockerSummary "not xml")))
    $ST_Ac = Get-AppControlAssessment -AppLockerAvailable $false -AppLocker $null -WdacKernel 2 -WdacUser 0 -LanguageMode "FullLanguage"
    Assert-SelfTest "App control: Home-like machine (no AppLocker, WDAC 2/0, FullLanguage) -> INFO" (($ST_Ac.Status -eq "INFO") -and ($ST_Ac.Value -match 'AppLocker: not available') -and ($ST_Ac.Value -match 'kernel-mode enforced, user-mode off') -and ($ST_Ac.Value -match 'FullLanguage'))
    Assert-SelfTest "App control: AppLocker policy shown with its enforced collections" ((Get-AppControlAssessment -AppLockerAvailable $true -AppLocker $ST_AlSum -WdacKernel 0 -WdacUser 1 -LanguageMode "ConstrainedLanguage").Value -match 'AppLocker: 3 rule\(s\), enforced for Exe, audit for Dll \| WDAC: kernel-mode off, user-mode audit mode \| PowerShell language mode: ConstrainedLanguage')
    Assert-SelfTest "App control: nothing readable -> 'Unable to determine'"         ((Get-AppControlAssessment -AppLockerAvailable $false -AppLocker $null -WdacKernel $null -WdacUser $null -LanguageMode "").Value -eq "Unable to determine")
    # auditpol subcategory output (localized text is never interpreted)
    $ST_Apos = [string][char]0x2019
    $ST_PcFr = @("Nom de l${ST_Apos}ordinateur,Cible de strat${ST_Apos}gie,Sous-cat${ST_Apos}gorie,GUID de sous-cat${ST_Apos}gorie,Param${ST_Apos}tre d${ST_Apos}inclusion,Param${ST_Apos}tre d${ST_Apos}exclusion", "NEPH-DESKTOP,Syst${ST_Apos}me,Cr${ST_Apos}ation du processus,{0CCE922B-69AE-11D9-BED3-505054503030},Pas d${ST_Apos}audit,")
    Assert-SelfTest "auditpol: inclusion setting read by position (French output)"    ((Get-AuditpolInclusion $ST_PcFr) -eq "Pas d${ST_Apos}audit")
    Assert-SelfTest "auditpol: English output with an exclusion setting, blank lines" ((Get-AuditpolInclusion @("", "Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting", "PC,System,Process Creation,{0CCE922B-69AE-11D9-BED3-505054503030},Success and Failure,Success", "")) -eq "Success and Failure")
    Assert-SelfTest "auditpol: unrecognised output -> null"                          (($null -eq (Get-AuditpolInclusion @("only one line"))) -and ($null -eq (Get-AuditpolInclusion $null)))
    # Indeterminate flag on the new 'could not be assessed' values
    $script:AuditResults.Clear()
    Add-Result "TestCat" "Smb" (Get-Smb1ClientAssessment -ListReadable $false -Found $false -State "").Value "INFO" ""
    Add-Result "TestCat" "Def" $ST_DefBad.Value "INFO" ""
    Add-Result "TestCat" "Ac"  (Get-AppControlAssessment -AppLockerAvailable $false -AppLocker $null -WdacKernel $null -WdacUser $null -LanguageMode "").Value "INFO" ""
    Assert-SelfTest "New checks: 'could not be assessed' values are flagged Indeterminate" (([bool]$script:AuditResults[0].Indeterminate) -and ([bool]$script:AuditResults[1].Indeterminate) -and ([bool]$script:AuditResults[2].Indeterminate))

    # ── v5.7.2 ────────────────────────────────────────
    Write-Host ""
    Write-Host "  New v5.7.2 features" -ForegroundColor White
    Assert-SelfTest "HelpLinks: 'Defender platform / engine version' links to the Defender updates page" (((Get-HelpLinks "Antivirus" "Defender platform / engine version" "" "") -match 'microsoft-defender-antivirus-updates') -and ((Get-HelpLinks "Antivirus" "Defender platform / engine version" "" "") -match 'Defender platform and engine updates'))
    Assert-SelfTest "HelpLinks: 'Windows build support status' links to the Windows 11 release information" ((Get-HelpLinks "Updates" "Windows build support status" "" "") -match 'windows11-release-information')
    Assert-SelfTest "HelpLinks: 'Secure Boot certificates (2023 renewal)' links to the Microsoft Support page" ((Get-HelpLinks "UEFI Security" "Secure Boot certificates (2023 renewal)" "" "") -match 'windows-secure-boot-certificate-expiration')
    Assert-SelfTest "HelpLinks: the other Antivirus rows keep their own links (generic and ASR)" (((Get-HelpLinks "Antivirus" "Real-time protection" "" "") -match 'troubleshoot-microsoft-defender-antivirus') -and ((Get-HelpLinks "Antivirus" "ASR rules (Attack Surface Reduction)" "" "") -match 'attack-surface-reduction-rules-reference'))
    Assert-SelfTest "HelpLinks: the three reference rows show their links whatever the status" ((Test-HelpLinksReferenceRow "Antivirus" "Defender platform / engine version") -and (Test-HelpLinksReferenceRow "Updates" "Windows build support status") -and (Test-HelpLinksReferenceRow "UEFI Security" "Secure Boot certificates (2023 renewal)"))
    Assert-SelfTest "HelpLinks: no other row is forced to show links (OK / INFO rows stay uncluttered)" (-not ((Test-HelpLinksReferenceRow "Antivirus" "Real-time protection") -or (Test-HelpLinksReferenceRow "Updates" "Windows Update policies") -or (Test-HelpLinksReferenceRow "Updates" "Last patch installed") -or (Test-HelpLinksReferenceRow "UEFI Security" "Secure Boot") -or (Test-HelpLinksReferenceRow "Audit" "Process creation auditing (event 4688)")))
    $ST_NoUrl = @(
        (Get-DefenderVersionAssessment -PlatformVersion "4.18.26100.4" -EngineVersion "1.1.26100.4" -Today ([datetime]"2026-11-20"))
        (Get-DefenderVersionAssessment -PlatformVersion "4.18.26010.1" -EngineVersion "1.1.26010.1" -Today ([datetime]"2026-11-20"))
        (Get-DefenderVersionAssessment -PlatformVersion "" -EngineVersion "" -Today ([datetime]"2026-11-20"))
        (Get-SecureBootCertAssessment -SecureBootEnabled $true -Status "Updated" -DbHas2023 $true -KekHas2023 $true -EventIds @())
        (Get-SecureBootCertAssessment -SecureBootEnabled $true -Status "NotStarted" -DbHas2023 $false -KekHas2023 $false -EventIds @())
        (Get-SecureBootCertAssessment -SecureBootEnabled $true -Status "NotStarted" -EventIds @(1802))
        (Get-SecureBootCertAssessment -SecureBootEnabled $null)
        (Get-StLifecycle 26200 101 "2026-11-19")
        (Get-StLifecycle 26200 101 "2027-08-01")
        (Get-StLifecycle 26100 101 "2026-11-19")
        (Get-StLifecycle 26400 101 "2026-11-19")
    )
    Assert-SelfTest "Details of the three reference checks carry no raw URL (the link button replaces it)" (@($ST_NoUrl | Where-Object { $_.Detail -match 'https?://' }).Count -eq 0)

    # ── v5.7.3 ────────────────────────────────────────
    Write-Host ""
    Write-Host "  New v5.7.3 features" -ForegroundColor White
    $ST_AllLinks = @()
    foreach ($ST_R in $script:DefenderRef) { foreach ($ST_L in @($ST_R.Links)) { $ST_AllLinks += [PSCustomObject]@{ Where = "card '$($ST_R.Key)'"; Url = "$($ST_L.Url)" } } }
    foreach ($ST_R in $script:HelpLinksDb) { foreach ($ST_L in @($ST_R.Links)) { $ST_AllLinks += [PSCustomObject]@{ Where = "rule '$($ST_R.Cat)/$($ST_R.Pattern)'"; Url = "$($ST_L.Url)" } } }
    $ST_DupLinks = @($ST_AllLinks | Group-Object Where | ForEach-Object { $_.Group | Group-Object { ($_.Url -replace '#.*$','').TrimEnd('/').ToLowerInvariant() } | Where-Object { $_.Count -gt 1 } | ForEach-Object { "$($_.Group[0].Where): $($_.Name)" } })
    Assert-SelfTest "Help links: no card and no rule lists the same page twice" ($ST_DupLinks.Count -eq 0) "Duplicates: $($ST_DupLinks -join ' | ')"
    # Path endings of pages that Microsoft removed or moved (no full address on purpose: an audit of the
    # addresses of this file must not report this list).
    $ST_DeadPatterns = @(
        'defender-endpoint/enable-controlled-folders$', 'defender-endpoint/customize-controlled-folders$',
        'identity/securing-local-accounts-in-active-directory-domains$', '/lifecycle/products/windows-11$',
        'defender-endpoint/configure-exclusions-microsoft-defender-antivirus$', 'defender-endpoint/enable-cloud-protection-microsoft-defender-antivirus$',
        'defender-endpoint/prevent-changes-to-security-settings-with-tamper-protection$', 'defender-endpoint/specify-cloud-protection-level-microsoft-defender-antivirus$',
        'windows/deployment/update/windows-update-troubleshooting$', 'windows-firewall/best-practices-configuring$',
        'threat-protection/overview-of-threat-mitigations-in-windows-10$', 'remote-desktop-services/clients/remote-desktop-allow-access$',
        'create-a-system-restore-point-[0-9a-f-]+$', 'windows/turn-on-secure-boot-[0-9a-f-]+$', 'windows/set-up-windows-hello-[0-9a-f-]+$'
    )
    $ST_DeadUsed = @($ST_AllLinks | Where-Object { $ST_U = ($_.Url -replace '#.*$','').TrimEnd('/'); @($ST_DeadPatterns | Where-Object { $ST_U -match $_ }).Count -gt 0 } | ForEach-Object { $_.Url })
    Assert-SelfTest "Help links: pages that Microsoft moved or removed are not used any more" ($ST_DeadUsed.Count -eq 0) "Still used: $($ST_DeadUsed -join ', ')"
    Assert-SelfTest "Help links: the current Microsoft pages are in place (Controlled Folder Access, Local accounts, lifecycle, cloud and tamper protection)" ((@($ST_AllLinks | Where-Object { $_.Url -match 'defender-endpoint/controlled-folder-access-(overview|configure)$' }).Count -ge 2) -and (@($ST_AllLinks | Where-Object { $_.Url -match 'access-control/local-accounts$' }).Count -ge 1) -and (@($ST_AllLinks | Where-Object { $_.Url -match 'lifecycle/products/windows-11-home-and-pro$' }).Count -ge 1) -and (@($ST_AllLinks | Where-Object { $_.Url -match 'defender-endpoint/cloud-protection-configure' }).Count -ge 1) -and (@($ST_AllLinks | Where-Object { $_.Url -match 'defender-endpoint/tamper-protection-overview$' }).Count -ge 1) -and (@($ST_AllLinks | Where-Object { $_.Url -match 'secure-boot-overview-a8ff1202-c0d9-42f5-940f-843abef64fad$' }).Count -ge 1) -and (@($ST_AllLinks | Where-Object { $_.Url -match 'support\.microsoft\.com/en-us/help/4028017$' }).Count -ge 1))

    # Remove the temporary log (see the NOTE at the top of the SelfTest block)
    Remove-Item -LiteralPath $script:ReportTXT -Force -ErrorAction SilentlyContinue
    $script:ReportTXT = $ST_RealTXT

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
# NOTE v5.6.0: with Fast Startup, "Shut down" does not restart the kernel, so the boot time (and this
# uptime) can be old on a machine that is switched off every night: that is not a missing restart.
$FastStartup = $null
try { $FastStartup = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" -Name HiberbootEnabled -ErrorAction Stop).HiberbootEnabled } catch { }
if ($Uptime.TotalDays -gt 30) {
    if ($FastStartup -eq 1) {
        Add-Result "System" "Machine uptime" "$([math]::Round($Uptime.TotalDays,1)) days" "INFO" "Fast Startup is on: a normal shutdown keeps the kernel session, so this figure is the time since the last FULL restart. Use Restart (not Shut down) from time to time so that updates and kernel changes really apply."
    } else {
        Add-Result "System" "Machine uptime" "$([math]::Round($Uptime.TotalDays,1)) days" "WARN" "Machine hasn't been restarted in over 30 days — pending patches?"
    }
} else {
    Add-Result "System" "Machine uptime" "$([math]::Round($Uptime.TotalDays,1)) days" "OK"
}
# NOTE v5.6.0: an update that is waiting for a restart is a real, directly readable signal (unlike uptime).
$PendingReboot = (Test-Path -LiteralPath "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired") -or
                 (Test-Path -LiteralPath "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending")
Add-Result "System" "Restart pending after an update" $(if ($PendingReboot) { "Yes" } else { "No" }) $(if ($PendingReboot) { "WARN" } else { "OK" }) $(
    if ($PendingReboot) { "Windows is waiting for a restart to finish installing an update; until then the fix is not fully applied." }
)

}

# ──────────────────────────────────────────────
#  2. WINDOWS UPDATE & PATCHES
# ──────────────────────────────────────────────
if (ShouldRunSection "2_Updates") {
Write-Log "=== 2. WINDOWS UPDATE & PATCHES ===" -Level SECTION

try {
    # NOTE v5.6.0: InstalledOn is empty for some hotfixes, and [datetime]$null is 0001-01-01: the age
    # was then computed as thousands of days and reported as "no patch in over 60 days". Only entries
    # with a real date are used; if there is none, the age is "undetermined" (not a FAIL).
    $HotFixes = @(Get-HotFix)
    $DatedFixes = @($HotFixes | Where-Object { $_.InstalledOn } | Sort-Object InstalledOn -Descending)
    Add-Result "Updates" "Number of installed patches" $HotFixes.Count "INFO"
    if ($DatedFixes.Count -eq 0) {
        Add-Result "Updates" "Last patch installed" "Unable to determine" "INFO" "No installed patch carries an installation date (Win32_QuickFixEngineering); check Settings > Windows Update > Update history"
    } else {
        $LastPatch = $DatedFixes[0]
        $DaysSincePatch = ((Get-Date) - [datetime]$LastPatch.InstalledOn).TotalDays
        Add-Result "Updates" "Last patch installed" "$($LastPatch.HotFixID) on $(Format-AuditDate ([datetime]$LastPatch.InstalledOn))" $(
            if ($DaysSincePatch -gt 60) { "FAIL" } elseif ($DaysSincePatch -gt 30) { "WARN" } else { "OK" }
        ) "$(if($DaysSincePatch -gt 60){'No patch in over 60 days'}elseif($DaysSincePatch -gt 30){'No patch in over 30 days'}else{'Recent patch'})"
    }
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

# NOTE v5.7.0: how long the installed Windows 11 version still receives security updates.
# Edition = Win32_OperatingSystem.OperatingSystemSKU (numeric, language independent) and
# build/UBR/DisplayVersion from the registry. ProductName is NOT used: it still says
# "Windows 10" on Windows 11. The decision is made by Get-WindowsLifecycleStatus.
try {
    if ($null -eq $OS -or -not $OS.BuildNumber) {
        Add-Result "Updates" "Windows build support status" "Unable to read" "INFO" "The operating system information could not be read"
    } else {
        $LcCv = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -ErrorAction Stop
        $Lc = Get-WindowsLifecycleStatus -Build ([int]$OS.BuildNumber) -Sku $OS.OperatingSystemSKU -Today (Get-Date) `
            -Table $WindowsLifecycleTable -EndedBuilds $WindowsLifecycleEndedBuilds -TableDate $WindowsLifecycleTableDate `
            -DisplayVersion "$($LcCv.DisplayVersion)" -Ubr $LcCv.UBR
        Add-Result "Updates" "Windows build support status" $Lc.Value $Lc.Status $Lc.Detail
    }
} catch {
    Add-Result "Updates" "Windows build support status" "Unable to read" "INFO" "Error: $($_.Exception.Message)"
}

# NOTE v5.7.1: Windows Update policies (registry). Deferral policies and an intranet update server
# are legitimate: INFO. WARN only when a policy turns Automatic Updates off (NoAutoUpdate = 1).
# Decision made by Get-WindowsUpdatePolicyAssessment.
try {
    $WuPolKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
    $WuPol    = Get-ItemProperty -LiteralPath $WuPolKey -ErrorAction SilentlyContinue
    $WuPolAu  = Get-ItemProperty -LiteralPath "$WuPolKey\AU" -ErrorAction SilentlyContinue
    $Wp = Get-WindowsUpdatePolicyAssessment -NoAutoUpdate $WuPolAu.NoAutoUpdate -UseWUServer $WuPolAu.UseWUServer `
        -DeferFeature $WuPol.DeferFeatureUpdates -DeferFeatureDays $WuPol.DeferFeatureUpdatesPeriodInDays `
        -DeferQuality $WuPol.DeferQualityUpdates -DeferQualityDays $WuPol.DeferQualityUpdatesPeriodInDays
    Add-Result "Updates" "Windows Update policies" $Wp.Value $Wp.Status $Wp.Detail
} catch {
    Add-Result "Updates" "Windows Update policies" "Unable to read" "INFO" "Error: $($_.Exception.Message)"
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
        # NOTE v5.6.0: Enabled is a GpoBoolean enum (True / False / NotConfigured);
        # read it as a string instead of relying on its numeric truthiness.
        $fwOn = ("$($fw.Enabled)" -ne "False")
        $st = if ($fwOn) { "OK" } else { "FAIL" }
        Add-Result "Firewall" "$profile profile" $(if ($fwOn) {"Enabled"} else {"DISABLED"}) $st $(
            if (-not $fwOn) { "The $profile profile firewall is disabled — high risk!" }
        )
        # Default policy
        # NOTE v5.6.0: a default inbound action of Allow accepts every inbound
        # connection that no rule blocks (the Windows default is Block): FAIL.
        $inAct = "$($fw.DefaultInboundAction)"
        Add-Result "Firewall" "$profile inbound policy" $fw.DefaultInboundAction $(if ($inAct -eq "Allow") { "FAIL" } else { "INFO" }) $(
            if ($inAct -eq "Allow") { "Default inbound action is Allow — every inbound connection is accepted unless a rule blocks it. The Windows default is Block." }
        )
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
# NOTE v5.6.0: (1) rules whose profile is "Any" also apply to the Public profile and
# were skipped by the former -match "Public"; (2) rules are read from the ActiveStore
# (effective rules, GPO / Intune included) with a fallback to the local store.
$FwRulesAll = $null
try   { $FwRulesAll = Get-NetFirewallRule -PolicyStore ActiveStore -Direction Inbound -Action Allow -Enabled True -ErrorAction Stop }
catch { $FwRulesAll = Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True -ErrorAction SilentlyContinue }
$PublicAllowRules = @($FwRulesAll | Where-Object { "$($_.Profile)" -match "Public|Any" })

# NOTE v5.6.0 (performance): the address / application / port filters of every rule are
# loaded once, in bulk, and looked up by InstanceID instead of three cmdlet calls per
# rule. If the bulk lookup does not return a filter, the former per-rule call is used.
$FwAddrMap = @{}; $FwAppMap = @{}; $FwPortMap = @{}
try { foreach ($f in @(Get-NetFirewallAddressFilter     -All -PolicyStore ActiveStore -ErrorAction Stop)) { $FwAddrMap["$($f.InstanceID)"] = $f } } catch { }
try { foreach ($f in @(Get-NetFirewallApplicationFilter -All -PolicyStore ActiveStore -ErrorAction Stop)) { $FwAppMap["$($f.InstanceID)"]  = $f } } catch { }
try { foreach ($f in @(Get-NetFirewallPortFilter        -All -PolicyStore ActiveStore -ErrorAction Stop)) { $FwPortMap["$($f.InstanceID)"] = $f } } catch { }
function Get-FwFilter {
    param($Rule, [string]$Kind)
    $id  = "$($Rule.InstanceID)"
    $map = switch ($Kind) { "Address" { $FwAddrMap } "App" { $FwAppMap } default { $FwPortMap } }
    if ($id -and $map.ContainsKey($id)) { return $map[$id] }
    switch ($Kind) {
        "Address" { return ($Rule | Get-NetFirewallAddressFilter     -ErrorAction SilentlyContinue) }
        "App"     { return ($Rule | Get-NetFirewallApplicationFilter -ErrorAction SilentlyContinue) }
        default   { return ($Rule | Get-NetFirewallPortFilter        -ErrorAction SilentlyContinue) }
    }
}
# Signature cache: one Authenticode check per executable, however many rules use it.
$FwSigCache = @{}
$FwStale    = [System.Collections.Generic.List[object]]::new()

Add-Result "Firewall" "Active inbound rules (Public)" $PublicAllowRules.Count "INFO" "Includes rules scoped by program/port — normal on a standard Windows install"

$TrulyOpenRules = [System.Collections.Generic.List[object]]::new()
foreach ($rule in $PublicAllowRules) {
    $addrFilter = Get-FwFilter $rule "Address"
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
# NOTE v5.5.0: the same application usually has TWO inbound rules with the same name, one
# TCP and one UDP (Windows creates both when you allow an app in the "Windows Security Alert"
# prompt), so the detail looked like a list of duplicates. Each rule now keeps its protocol
# and the detail groups the rules by application ("Steam x2 (TCP, UDP)"). The count stays the
# number of rules. Publishers are shown by their CN only.
function Get-FwProtoText {
    param($Rule)
    try {
        $pf = Get-FwFilter $Rule "Port"
        $p  = @($pf.Protocol) | Where-Object { $_ } | Select-Object -Unique
        if ($p) { return ($p -join "/") }
    } catch { }
    return "Any"
}
function Format-FwGroup {
    param($Items)
    foreach ($g in @($Items | Group-Object Label)) {
        $protos = (@($g.Group | ForEach-Object { $_.Proto }) | Sort-Object -Unique) -join ", "
        if ($g.Count -gt 1) { "$($g.Name) x$($g.Count) ($protos)" } else { "$($g.Name) ($protos)" }
    }
}
$FwMicrosoft = [System.Collections.Generic.List[object]]::new()
$FwThirdParty= [System.Collections.Generic.List[object]]::new()
$FwUnsigned  = [System.Collections.Generic.List[object]]::new()

foreach ($rule in $TrulyOpenRules) {
    $proto     = Get-FwProtoText $rule
    $appFilter = Get-FwFilter $rule "App"
    $exePath   = if ($appFilter) { $appFilter.Program } else { $null }

    if (-not $exePath -or $exePath -eq "Any" -or $exePath -eq "") {
        # Rule with no associated executable (port only).
        # NOTE v5.6.0: the former test on the DISPLAY NAME (English words such as
        # "Windows" or "Viewer") was language-dependent (French names were flagged) and
        # attacker-controlled. A built-in rule is now recognised by its resource-string
        # group (language-independent); when it points to a DLL, that DLL must exist in
        # System32 (a folder only an administrator can write to).
        $ruleName = $rule.DisplayName
        $grp = "$($rule.Group)"
        $isBuiltIn = Test-FirewallBuiltInGroup $grp
        if ($isBuiltIn -and $grp -match '(?i)^@(?:%(?:systemroot|windir)%\\system32\\)?([a-z0-9_.\-]+\.dll),-\d+$') {
            $isBuiltIn = (Test-Path -LiteralPath (Join-Path $env:SystemRoot ("System32\" + $Matches[1])) -ErrorAction SilentlyContinue)
        }
        if ($isBuiltIn) {
            $FwMicrosoft.Add([pscustomobject]@{ Label = $ruleName; Proto = $proto })
        } else {
            $FwUnsigned.Add([pscustomobject]@{ Label = "$ruleName [port only, no exe, group: $(if($grp){$grp}else{'none'})]"; Proto = $proto })
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
    # NOTE v5.6.0: the location is now tested with an anchored comparison (the former
    # unanchored regex also accepted "C:\Users\x\windows\system32\evil.exe").
    if ((Test-PathUnderRoot $exeResolved @("$env:SystemRoot\System32", "$env:SystemRoot\SysWOW64")) -or $exePath -eq "System") {
        $FwMicrosoft.Add([pscustomobject]@{ Label = "$($rule.DisplayName)"; Proto = $proto })
        continue
    }

    try {
        $sigKey = $exeResolved.ToLowerInvariant()
        if ($FwSigCache.ContainsKey($sigKey)) { $sig = $FwSigCache[$sigKey] }
        else { $sig = Get-AuthenticodeSignature -FilePath $exeResolved -ErrorAction Stop; $FwSigCache[$sigKey] = $sig }
        if ($sig.Status -eq "Valid") {
            $publisher = $sig.SignerCertificate.Subject
            $pubCn     = if ($publisher -match 'CN=("[^"]+"|[^,]+)') { $Matches[1].Trim('"') } else { $publisher }
            if (Test-MicrosoftSigner $publisher) {
                $FwMicrosoft.Add([pscustomobject]@{ Label = "$($rule.DisplayName)"; Proto = $proto })
            } else {
                $FwThirdParty.Add([pscustomobject]@{ Label = "$($rule.DisplayName) [$pubCn]"; Proto = $proto })
            }
        } else {
            $FwUnsigned.Add([pscustomobject]@{ Label = "$($rule.DisplayName) [$exeResolved — $($sig.Status)]"; Proto = $proto })
        }
    } catch {
        # NOTE v5.6.0: a rule whose executable no longer exists (an old Edge WebView version, a moved
        # application) is a STALE rule, not an unverifiable one: it is listed separately.
        if (-not (Test-Path -LiteralPath $exeResolved)) {
            $FwStale.Add([pscustomobject]@{ Label = "$($rule.DisplayName) [$exeResolved]"; Proto = $proto })
        } else {
            $FwUnsigned.Add([pscustomobject]@{ Label = "$($rule.DisplayName) [$exeResolved — not verified]"; Proto = $proto })
        }
    }
}

if ($FwMicrosoft.Count -gt 0) {
    $fwG = @(Format-FwGroup $FwMicrosoft)
    Add-Result "Firewall" "Open rules — Microsoft publisher" $FwMicrosoft.Count "INFO" "Native Windows rules (legitimate), $($fwG.Count) distinct for $($FwMicrosoft.Count) rules: $($fwG -join ' | ')"
}
if ($FwThirdParty.Count -gt 0) {
    $fwG = @(Format-FwGroup $FwThirdParty)
    Add-Result "Firewall" "Open rules — signed third-party publisher" $FwThirdParty.Count "WARN" "Signed third-party application rules, $($fwG.Count) distinct for $($FwThirdParty.Count) rules (one app often has a TCP and a UDP rule) — check whether the software is expected: $($fwG -join ' | ')"
}
if ($FwStale.Count -gt 0) {
    $fwG = @(Format-FwGroup $FwStale)
    Add-Result "Firewall" "Open rules — program no longer installed (stale)" $FwStale.Count "INFO" "$($fwG.Count) distinct for $($FwStale.Count) enabled allow rules whose executable no longer exists on disk (typically left behind by an updated or removed application). Harmless as long as nothing is created at that path, but they should be cleaned up: $($fwG -join ' | ')"
}
if ($FwUnsigned.Count -gt 0) {
    $fwG = @(Format-FwGroup $FwUnsigned)
    Add-Result "Firewall" "Open rules — unsigned/unknown executable" $FwUnsigned.Count "WARN" "Rules with no valid signature or no associated exe, $($fwG.Count) distinct for $($FwUnsigned.Count) rules — review manually: $($fwG -join ' | ')"
}

# NOTE v3.0: a raw count of rules "open to any IP" says nothing about the
# actual risk — a rule open on an obscure application port doesn't carry
# the same weight as one open on RDP/SMB/WinRM. Each genuinely open rule
# is now reclassified by the port it exposes, with a list of notoriously
# sensitive ports flagged as FAIL.
# NOTE v5.6.0: port ranges ("3389-3390") are now expanded, and a few notoriously exposed
# services were added (SSH, PostgreSQL, MongoDB, Redis, Elasticsearch, memcached, TFTP).
$DangerousPorts = @{
    3389 = "RDP"; 445 = "SMB"; 139 = "NetBIOS"; 135 = "RPC"
    5985 = "WinRM (HTTP)"; 5986 = "WinRM (HTTPS)"; 23 = "Telnet"
    21 = "FTP"; 1433 = "SQL Server"; 3306 = "MySQL"; 5900 = "VNC"
    22 = "SSH"; 5432 = "PostgreSQL"; 27017 = "MongoDB"; 6379 = "Redis"
    9200 = "Elasticsearch"; 11211 = "memcached"; 69 = "TFTP"
}
foreach ($rule in $TrulyOpenRules) {
    $portFilter = Get-FwFilter $rule "Port"
    if (-not $portFilter) { continue }
    foreach ($portEntry in @($portFilter.LocalPort)) {
        $hit = @()
        $portNum = 0
        if ([int]::TryParse("$portEntry", [ref]$portNum)) {
            if ($DangerousPorts.ContainsKey($portNum)) { $hit += $portNum }
        } elseif ("$portEntry" -match '^(\d+)-(\d+)$') {
            $lo = [int]$Matches[1]; $hi = [int]$Matches[2]
            $hit = @($DangerousPorts.Keys | Where-Object { $_ -ge $lo -and $_ -le $hi } | Sort-Object)
        }
        foreach ($portNum in $hit) {
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

# NOTE v5.6.0: when Windows Defender runs in PASSIVE mode (another antivirus is the active
# protection), its real-time protection, scans and behaviour monitoring are off BY DESIGN: they are
# reported as INFO instead of FAIL/WARN, and the real protection is the third-party product
# listed further down (its state is decoded from the Security Center productState).
$AvPassive = $false
$AvAmMode  = ""
try {
    $DefenderStatus = Get-MpComputerStatus -ErrorAction Stop
    $AvAmMode  = "$($DefenderStatus.AMRunningMode)"
    $AvPassive = ($AvAmMode -match 'Passive|EDR Block')

    $avEnabled = $DefenderStatus.AntivirusEnabled
    Add-Result "Antivirus" "Antivirus enabled"          $(if($avEnabled){"Yes"}elseif($AvPassive){"No (Defender in $AvAmMode)"}else{"NO"})          $(if($avEnabled){"OK"}elseif($AvPassive){"INFO"}else{"FAIL"}) $(if($AvPassive){"Windows Defender is in '$AvAmMode' because another antivirus is the active protection — see the detected AV product below"})
    # NOTE v5.5.1: Detail + expandable HTML card (DisableRealtimeMonitoring is inverted: False = ON).
    $rtpDisabled = -not [bool]$DefenderStatus.RealTimeProtectionEnabled
    Set-SettingState -Key "DisableRealtimeMonitoring" -Current $rtpDisabled
    Add-Result "Antivirus" "Real-time protection"     $(if($DefenderStatus.RealTimeProtectionEnabled){"Enabled"}elseif($AvPassive){"Off (passive mode)"}else{"DISABLED"})  $(if($DefenderStatus.RealTimeProtectionEnabled){"OK"}elseif($AvPassive){"INFO"}else{"FAIL"}) $(if(-not $DefenderStatus.RealTimeProtectionEnabled -and $AvPassive){"Defender's real-time protection is off because Defender is in '$AvAmMode': the active antivirus provides it"}else{(Get-SettingDetail -Key "DisableRealtimeMonitoring" -Current $rtpDisabled)})
    # NOTE v5.5.0: this check used to be labelled "Network protection", but
    # IoavProtectionEnabled is Defender's IOAV protection: it scans files
    # downloaded from the Internet and e-mail attachments when they are opened.
    # The real Network Protection feature (Exploit Guard) is audited in section 24.
    Add-Result "Antivirus" "Download/attachment scanning (IOAV)" $(if($DefenderStatus.IoavProtectionEnabled){"Enabled"}else{"Disabled"})      $(if($DefenderStatus.IoavProtectionEnabled){"OK"}elseif($AvPassive){"INFO"}else{"WARN"}) "Scans files downloaded from the Internet and e-mail attachments when they are opened (Defender IOAV). Not the same as Network Protection, which blocks malicious connections (see section 24)."
    Add-Result "Antivirus" "Behavior monitoring"$(if($DefenderStatus.BehaviorMonitorEnabled){"Enabled"}else{"Disabled"})     $(if($DefenderStatus.BehaviorMonitorEnabled){"OK"}elseif($AvPassive){"INFO"}else{"WARN"})

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
    # every audit (case observed on a real machine in a v5.0.x run).
    #
    # New model: two separate checks with tailored thresholds.
    # 1. QUICK SCAN (primary indicator) — should run at least every 3 days.
    #    >3d WARN, >7d FAIL. A missing quick scan = Defender is disrupted or stopped.
    # 2. FULL SCAN (secondary indicator) — wide thresholds, optional frequency.
    #    >30d WARN, >90d FAIL, never run = INFO (not an anomaly by itself).

    # 1. Quick scan
    if (-not $DefenderStatus.QuickScanEndTime -or
        $DefenderStatus.QuickScanEndTime -lt [datetime]"2000-01-01") {
        Add-Result "Antivirus" "Last quick scan" "No quick scan recorded" $(if($AvPassive){"INFO"}else{"WARN"}) "No recent quick scan detected — check that Defender is working correctly: 'Start-MpScan -ScanType QuickScan'"
    } else {
        $DaysSinceQuick = [math]::Round(((Get-Date) - $DefenderStatus.QuickScanEndTime).TotalDays, 1)
        $quickStatus = if ($AvPassive -and $DaysSinceQuick -gt 3) { "INFO" } elseif ($DaysSinceQuick -gt 7) { "FAIL" } elseif ($DaysSinceQuick -gt 3) { "WARN" } else { "OK" }
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

    # NOTE v5.7.1: age of the Defender platform and engine, from the versions Get-MpComputerStatus
    # already returned (no extra call). Own try/catch so that a problem here never turns the
    # whole Defender status into "Unable to read status".
    try {
        $DefVer = Get-DefenderVersionAssessment -PlatformVersion "$($DefenderStatus.AMProductVersion)" `
            -EngineVersion "$($DefenderStatus.AMEngineVersion)" -Today (Get-Date) -Passive $AvPassive
        Add-Result "Antivirus" "Defender platform / engine version" $DefVer.Value $DefVer.Status $DefVer.Detail
    } catch {
        Add-Result "Antivirus" "Defender platform / engine version" "Unable to read" "INFO" "Error: $($_.Exception.Message)"
    }

} catch {
    Add-Result "Antivirus" "Windows Defender" "Unable to read status: $_" "WARN"
}

# Check whether another AV is installed
try {
    $AVProducts = Get-CimInstance -Namespace root\SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction Stop
    foreach ($av in $AVProducts) {
        # NOTE v5.6.0: the productState is decoded (protection on/off, signatures up to date) instead
        # of being printed as a raw number; a registered third-party product whose protection is off
        # is a WARN (Windows Defender's own entry is judged by the checks above).
        $avSt   = Get-AvProductState $av.productState
        $isDef  = ($av.displayName -match 'Windows Defender|Microsoft Defender')
        $avText = if ($avSt.Known) { "State: $($av.productState) ($($avSt.Hex)) — protection $(if($avSt.Enabled){'ON'}else{'OFF'}), signatures $(if($avSt.UpToDate){'up to date'}else{'OUT OF DATE'})" } else { "State: $($av.productState)" }
        $avStatus = if (-not $isDef -and $avSt.Known -and -not $avSt.Enabled) { "WARN" } else { "INFO" }
        Add-Result "Antivirus" "Detected AV product" $av.displayName $avStatus $avText
    }
} catch {}

# NOTE v3.0: ASR (Attack Surface Reduction) rules — block generic attack
# techniques (Office macros spawning child processes, obfuscated scripts,
# unsigned executables from email, etc.) ahead of signature-based
# detection. Ids/Actions are two parallel arrays (same index = same rule).
# Action 1 = Block, 2 = Audit, 0/absent = Off.
try {
    $AsrPrefs   = Get-MpPreference -ErrorAction Stop
    # NOTE v5.6.0: @($null) is an array of ONE element, so "no rule" was counted as one rule; null
    # entries are filtered out. Action 6 (Warn: the user is prompted) is counted on its own instead
    # of being reported as "inactive".
    $AsrIds     = @($AsrPrefs.AttackSurfaceReductionRules_Ids     | Where-Object { $_ })
    $AsrActions = @($AsrPrefs.AttackSurfaceReductionRules_Actions | Where-Object { $null -ne $_ })
    $AsrBlocking = 0
    $AsrAuditing = 0
    $AsrWarnMode = 0
    $AsrBlockedIds = @{}
    for ($i = 0; $i -lt $AsrIds.Count; $i++) {
        if ($i -lt $AsrActions.Count) {
            if ([int]$AsrActions[$i] -eq 1) { $AsrBlocking++; $AsrBlockedIds["$($AsrIds[$i])".ToLowerInvariant()] = $true }
            elseif ([int]$AsrActions[$i] -eq 2) { $AsrAuditing++ }
            elseif ([int]$AsrActions[$i] -eq 6) { $AsrWarnMode++ }
        }
    }
    # The three "standard protection" rules Microsoft recommends enabling everywhere.
    $AsrStandardRules = [ordered]@{
        "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2" = "Block credential stealing from LSASS"
        "56a863a9-875e-4185-98a7-b882c64b5ce5" = "Block abuse of exploited vulnerable signed drivers"
        "e6db77e5-3df2-4cf1-b95a-636979351e5b" = "Block persistence through WMI event subscription"
    }
    $AsrStdMissing = @($AsrStandardRules.Keys | Where-Object { -not $AsrBlockedIds.ContainsKey($_) } | ForEach-Object { $AsrStandardRules[$_] })
    if ($AsrIds.Count -eq 0) {
        Add-Result "Antivirus" "ASR rules (Attack Surface Reduction)" "No rule configured" "WARN" "ASR rules block generic attack techniques (Office macros, obfuscated scripts, etc.) independently of signatures — none are active on this machine. See 'Add-MpPreference -AttackSurfaceReductionRules_Ids ... -AttackSurfaceReductionRules_Actions Enabled'"
    } else {
        Add-Result "Antivirus" "ASR rules (Attack Surface Reduction)" "$($AsrIds.Count) rule(s) configured" $(
            if ($AvPassive) { "INFO" } elseif ($AsrBlocking -eq 0 -or $AsrStdMissing.Count -gt 0) { "WARN" } else { "OK" }
        ) "$AsrBlocking in blocking mode, $AsrWarnMode in warn mode, $AsrAuditing in audit-only mode, $($AsrIds.Count - $AsrBlocking - $AsrWarnMode - $AsrAuditing) inactive$(if($AsrStdMissing.Count -gt 0){". Microsoft standard-protection rules NOT in blocking mode: $($AsrStdMissing -join ' | ')"})$(if($AvPassive){'. Defender is in passive mode: ASR rules are not enforced.'})"
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
    # NOTE v5.5.0: the pieces below are appended as " | text"; when the first one
    # is not the built-in Administrator message, the detail used to start with an
    # orphan " | ". It is now trimmed in the Add-Result call at the end of the loop.
    $detail  = ""

    if ($user.Enabled -and $user.Name -eq "Administrator") {
        $statusU = "WARN"; $detail = "The built-in Administrator account is enabled"
    }
    # NOTE v5.5.0: Get-LocalUser has NO "PasswordNeverExpires" property (it only exists as a
    # Set-LocalUser parameter), so the previous test was always $null: every account read
    # "Pwd expires: Yes" and the WARN below could never fire. An empty PasswordExpires means
    # the password never expires. An account linked to a Microsoft or Entra ID account has an
    # empty PasswordExpires too, because its password is managed online: it is not flagged.
    $isOnlineAccount = ("$($user.PrincipalSource)" -match 'MicrosoftAccount|AzureAD')
    # "Never expires" only makes sense for an account that has a password: a built-in account
    # that never had one (PasswordLastSet empty) also has an empty PasswordExpires.
    $neverExpires    = ($null -eq $user.PasswordExpires) -and ($null -ne $user.PasswordLastSet) -and (-not $isOnlineAccount)
    if ($user.Enabled -and $neverExpires) {
        $statusU = "WARN"; $detail += " | Password never expires"
    }
    if ($user.Enabled -and (-not $user.PasswordRequired)) {
        # NOTE v1.1: this SAM flag (UF_PASSWD_NOTREQD) can be set
        # automatically by Windows Hello (PIN/biometrics) without meaning
        # that no authentication is required at sign-in.
        # Downgraded to WARN (instead of FAIL).
        # NOTE v2.0: now relies on the Hello detection above to give a
        # concrete explanation rather than just a manual-check pointer.
        # NOTE v5.5.0: for an account linked to a Microsoft account (or Entra ID) the
        # password is managed online and the SAM flag is normal: no WARN. For a local
        # account, the WARN stays (the script can't see whether the password is blank)
        # but now gives the concrete fix instead of only a pointer.
        $fixHint = " | If this account does have a password, clear the flag with: net user $($user.Name) /passwordreq:yes (set a password first if it has none, otherwise you could no longer sign in)"
        if ($isOnlineAccount) {
            $detail += " | SAM reports 'password not required', which is normal for an account linked to a Microsoft or Entra ID account: its password is managed online and sign-in still asks for it or for a Windows Hello PIN"
        } else {
            $statusU = "WARN"
            if ($null -eq $user.PasswordLastSet) {
                $detail += " | No password has ever been set on this account: it very probably has an empty password"
            }
            if ($HelloConfigured) {
                $detail += " | SAM reports 'password not required', but a Windows Hello credential (PIN/biometrics) is registered on this machine — that's probably the explanation, not an active weakness"
            } elseif ($HelloIndeterminate) {
                $detail += " | SAM reports 'password not required' — Windows Hello detection couldn't access some system-protected containers to confirm or rule this out; check with 'net user $($user.Name)' or in Settings > Accounts > Sign-in options$fixHint"
            } else {
                $detail += " | SAM reports 'password not required' and no Windows Hello credential was detected on this machine — check with 'net user $($user.Name)' whether this is a real setting to fix$fixHint"
            }
        }
    }
    if (-not $user.Enabled) { $statusU = "INFO" }

    Add-Result "Accounts" "Local user: $($user.Name)" $(
        "$(if($user.Enabled){'Enabled'}else{'Disabled'}) | Pwd expires: $(if($isOnlineAccount){'Managed online'}elseif($null -eq $user.PasswordLastSet){'n/a (no password set)'}elseif($neverExpires){'Never'}else{'Yes'})"
    ) $statusU ($detail -replace '^\s*\|\s*', '')
}

# Members of the local Administrators group
# NOTE v1.1: the old version queried the group by its English name
# "Administrators", which can silently fail on a localized Windows (group
# named "Administrateurs" internally) — the error was swallowed by
# -ErrorAction SilentlyContinue and the script showed "OK" with an empty
# value. Now queried by universal SID (S-1-5-32-544, valid across every
# language) and a read failure is now clearly reported when it occurs.
# NOTE v5.5.0: the members are now annotated so two accounts can't be mistaken
# for one: "COMPUTER\Administrator (built-in, disabled), COMPUTER\username".
# The built-in Administrator account (SID ending in -500) is ALWAYS a member of
# this group, even when disabled, so it used to look like a second active admin.
# "built-in" = RID-500, "disabled" = account disabled; the WARN threshold (more
# than 3) now counts only members that can actually sign in.
try {
    $AdminGroup  = @(Get-LocalGroupMember -SID "S-1-5-32-544" -ErrorAction Stop)
    $AdminLabels = @()
    $AdminActive = 0
    foreach ($Member in $AdminGroup) {
        $MemberNote = ""
        $MemberOff  = $false
        if ("$($Member.ObjectClass)" -eq "User") {
            try {
                $MemberUser = Get-LocalUser -SID $Member.SID -ErrorAction Stop
                $MemberTags = @()
                if ("$($Member.SID)" -like "*-500") { $MemberTags += "built-in" }
                if (-not $MemberUser.Enabled)       { $MemberTags += "disabled"; $MemberOff = $true }
                if ($MemberTags.Count -gt 0)        { $MemberNote = " (" + ($MemberTags -join ", ") + ")" }
            } catch { }  # not a local account (e.g. domain user): no annotation
        }
        $AdminLabels += "$($Member.Name)$MemberNote"
        if (-not $MemberOff) { $AdminActive++ }
    }
    Add-Result "Accounts" "Local Administrators members" ($AdminLabels -join ", ") $(
        if ($AdminActive -gt 3) { "WARN" } else { "OK" }
    ) $(if($AdminActive -gt 3){"Too many active local administrator accounts"})
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

    $LockoutDurForever = ($LockoutDurRaw -and ($LockoutDurRaw -match '(?i)jamais|never' -or $LockoutDurRaw -match '^0+$'))
    if (-not $MinPwdLenRaw -and -not $LockoutThresholdRaw) {
        # NOTE v5.6.0: the labels of "net accounts" are translated, so other languages than French and
        # English were not recognised. The same values are read from the exported local security
        # policy (secedit, language-independent keys) into a temporary file that is deleted at once.
        $secTmp = Join-Path $env:TEMP ("checksec_secpol_{0}.inf" -f [guid]::NewGuid().ToString("N"))
        $secPol = $null
        try {
            & secedit.exe /export /cfg $secTmp /areas SECURITYPOLICY 2>&1 | Out-Null
            if (Test-Path -LiteralPath $secTmp) { $secPol = ConvertFrom-SeceditPolicy ([System.IO.File]::ReadAllText($secTmp, [System.Text.Encoding]::Unicode)) }
        } catch { } finally { Remove-Item -LiteralPath $secTmp -Force -ErrorAction SilentlyContinue }
        if (-not $secPol) { throw "Unrecognized 'net accounts' output and the secedit export could not be read" }
        $MinPwdLenRaw      = "$($secPol.MinPwdLen)"
        $MinPwdLen         = [int]$secPol.MinPwdLen
        $MaxPwdAgeUnlimited = ($secPol.MaxPwdAgeDays -lt 0)
        $MaxPwdAgeDays     = if ($MaxPwdAgeUnlimited) { 0 } else { [int]$secPol.MaxPwdAgeDays }
        $MinPwdAgeDays     = [int]$secPol.MinPwdAgeDays
        $LockoutThresholdRaw = "$($secPol.LockoutThreshold)"
        $LockoutThreshold  = [int]$secPol.LockoutThreshold
        $LockoutDisabled   = ($LockoutThreshold -eq 0)
        $LockoutDurForever = ($secPol.LockoutDurMinutes -lt 0)
        $LockoutDurMinutes = if ($LockoutDurForever) { 0 } else { [int]$secPol.LockoutDurMinutes }
        $LockoutDurRaw     = "$($secPol.LockoutDurMinutes)"
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
        # NOTE v5.6.0: a duration of 0 / "never" means the account stays locked until an
        # administrator unlocks it — the strictest setting, not a "very short" one.
        if ($LockoutDurForever) {
            Add-Result "Password Policy" "Lockout duration" "Until an administrator unlocks the account" "OK"
        } elseif (-not $LockoutDurRaw) {
            Add-Result "Password Policy" "Lockout duration" "Unable to determine" "INFO" "The lockout duration could not be read from the policy"
        } else {
            Add-Result "Password Policy" "Lockout duration" "$LockoutDurMinutes minute(s)" $(
                if ($LockoutDurMinutes -lt 5) { "WARN" } else { "OK" }
            ) $(if($LockoutDurMinutes -lt 5){"Very short lockout duration — makes repeated brute-force attempts in small bursts easier"})
        }
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

# NOTE v5.6.0: decision table in Get-UacAssessment. Values 1 and 2 (prompt on the
# secure desktop) are STRICTER than the default and are no longer a WARN, and a
# value that is not set (Windows default) is no longer read as "disabled".
$UacLua     = Get-UacAssessment -Setting "LUA"           -Value $EnableLUA
$UacConsent = Get-UacAssessment -Setting "Consent"       -Value $ConsentPrompt
$UacSecure  = Get-UacAssessment -Setting "SecureDesktop" -Value $SecureDesktop
Add-Result "UAC" "UAC enabled (EnableLUA)" $UacLua.Value     $UacLua.Status     $UacLua.Detail
Add-Result "UAC" "Admin consent level"     $UacConsent.Value $UacConsent.Status $UacConsent.Detail
Add-Result "UAC" "Secure desktop"          $UacSecure.Value  $UacSecure.Status  $UacSecure.Detail

# NOTE v5.6.0: LocalAccountTokenFilterPolicy = 1 lifts the UAC filtering of REMOTE connections made with
# a local administrator account: the remote session then gets a full administrator token, which makes
# pass-the-hash lateral movement possible. Windows default: not set (filtering active).
$LatfPolicy = $null
try { $LatfPolicy = (Get-ItemProperty -Path $UACKey -Name "LocalAccountTokenFilterPolicy" -ErrorAction Stop).LocalAccountTokenFilterPolicy } catch { }
Add-Result "UAC" "Remote UAC token filtering (LocalAccountTokenFilterPolicy)" $(if ($LatfPolicy -eq 1) { "Disabled (remote local admins get a full token)" } else { "Active (default)" }) $(if ($LatfPolicy -eq 1) { "WARN" } else { "OK" }) $(
    if ($LatfPolicy -eq 1) { "LocalAccountTokenFilterPolicy=1 lets remote connections using a local administrator account run with a full administrator token (pass-the-hash lateral movement). Remove the value unless a remote-management tool requires it." }
)

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
        # NOTE v5.6.0: Get-BitLockerAssessment also reads VolumeStatus, LockStatus,
        # the encryption method and the key protectors (suspended protection,
        # locked volume, encryption in progress, missing recovery key).
        $bl = Get-BitLockerAssessment -Volume $vol -IsSystemVolume $isSystemVol
        Add-Result "BitLocker" "Volume $($vol.MountPoint)" "Protection: $($vol.ProtectionStatus) | Encryption: $($vol.EncryptionPercentage)%" $bl.Status $bl.Detail
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

# NOTE v5.7.1: SMBv1 CLIENT. The check above only reads the server side (Get-SmbServerConfiguration).
# The client is the "SMB1Protocol-Client" Windows optional feature; the feature list is the one cached
# by Get-WinFeatures (read once for the whole run, also used by sections 25 and 26).
try {
    $null = Get-WinFeatures
    $Smb1Cli = @(Get-WinFeatures | Where-Object { $_.FeatureName -eq "SMB1Protocol-Client" }) | Select-Object -First 1
    $Smb1Cl = Get-Smb1ClientAssessment -ListReadable $script:WinFeaturesOK -Found ($null -ne $Smb1Cli) -State "$($Smb1Cli.State)"
    Add-Result "Network" "SMBv1 client feature" $Smb1Cl.Value $Smb1Cl.Status $Smb1Cl.Detail
} catch {
    Add-Result "Network" "SMBv1 client feature" "Unable to read" "INFO" "Error: $($_.Exception.Message)"
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

# NOTE v3.0: encrypted DNS (DoH) at the system level — a user may already run NextDNS
# as a dedicated app, so this check mainly verifies that the native Windows
# resolver (in case the NextDNS app is stopped) doesn't expose queries in
# the clear.
# NOTE v5.6.0: Get-DnsClientDohServerAddress lists the DoH servers Windows KNOWS about (a built-in
# table), not the ones in use, and the former "DohFlag" property does not exist on it (the check could
# only ever answer "No DoH server configured"). DoH is now in use for a DNS server when (a) the server
# address is in that table with AutoUpgrade on, or (b) a per-interface DoH setting is stored for it
# (Dnscache\InterfaceSpecificParameters\...\DohInterfaceSettings). A local resolver (127.0.0.1) is
# reported as such: its encryption depends on that resolver, not on Windows.
try {
    $DohTable = @(Get-DnsClientDohServerAddress -ErrorAction Stop)
    $DohAuto  = @{}
    foreach ($d in $DohTable) { if ($d.AutoUpgrade) { $DohAuto["$($d.ServerAddress)"] = $true } }
    $DnsServers = @(Get-DnsClientServerAddress -ErrorAction Stop | ForEach-Object { $_.ServerAddresses } | Where-Object { $_ } | Select-Object -Unique)
    $DohManual = @{}
    $dohRoot = "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\InterfaceSpecificParameters"
    foreach ($ifKey in @(Get-ChildItem -Path $dohRoot -ErrorAction SilentlyContinue)) {
        foreach ($srvKey in @(Get-ChildItem -LiteralPath "$($ifKey.PSPath)\DohInterfaceSettings\Doh" -ErrorAction SilentlyContinue)) {
            $fl = (Get-ItemProperty -LiteralPath $srvKey.PSPath -Name DohFlags -ErrorAction SilentlyContinue).DohFlags
            if ($fl) { $DohManual[$srvKey.PSChildName] = $true }
        }
    }
    $DnsLocal  = @($DnsServers | Where-Object { $_ -eq "127.0.0.1" -or $_ -eq "::1" })
    $DnsRemote = @($DnsServers | Where-Object { $_ -ne "127.0.0.1" -and $_ -ne "::1" })
    $DnsDoh    = @($DnsRemote | Where-Object { $DohAuto.ContainsKey($_) -or $DohManual.ContainsKey($_) })
    if ($DnsRemote.Count -gt 0 -and $DnsDoh.Count -eq $DnsRemote.Count) {
        Add-Result "Network" "Encrypted DNS (DoH)" "$($DnsDoh.Count) DNS server(s) use DoH" "OK" "Every configured DNS server resolves over DoH: $($DnsDoh -join ', ')"
    } elseif ($DnsDoh.Count -gt 0) {
        Add-Result "Network" "Encrypted DNS (DoH)" "$($DnsDoh.Count) of $($DnsRemote.Count) DNS server(s) use DoH" "INFO" "DoH: $($DnsDoh -join ', ') — in the clear: $((@($DnsRemote | Where-Object { $DnsDoh -notcontains $_ })) -join ', ')"
    } elseif ($DnsLocal.Count -gt 0 -and $DnsRemote.Count -eq 0) {
        Add-Result "Network" "Encrypted DNS (DoH)" "Local DNS resolver ($($DnsLocal -join ', '))" "INFO" "Windows sends its queries to a local resolver (DNS proxy / filter); whether they leave the machine encrypted depends on that resolver"
    } else {
        Add-Result "Network" "Encrypted DNS (DoH)" "No DoH in use" "INFO" "Classic DNS queries (port 53) travel in the clear to: $($DnsRemote -join ', '). Windows supports DoH for known providers (Settings > Network & internet > DNS server assignment) — a hardening and privacy choice."
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
    # NOTE v5.5.0: wrapped in @() so $ExtConns.Count is reliable. With exactly one
    # connection, Windows PowerShell 5.1 returns a single CIM object that has no
    # Count property: the value then read " connection(s)" with no number.
    $ExtConns = @(Get-NetTCPConnection -State Established -ErrorAction Stop |
        Where-Object {
            $_.RemoteAddress -ne "127.0.0.1" -and
            $_.RemoteAddress -ne "::1" -and
            $_.RemoteAddress -notmatch "^fe80:" -and
            $_.RemoteAddress -ne "0.0.0.0"
        })

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
        # NOTE v5.0.1: post-real-machine-run additions — legitimate
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
            "NisSrv","SecurityHealthService","SgrmBroker","spoolsv","lsass","wininit")
        # NOTE v5.6.0: (1) a name from this list is only trusted when the process IMAGE is verified
        # (Windows folder, valid signature, or protected Program Files location) — the former
        # substring match ("*steam*", "*explorer*", "*svchost*") accepted any process whose name
        # merely contained one of these words; (2) PowerShell is no longer in the list: a PowerShell
        # process holding a public connection is exactly what must be looked at. Only the process
        # running THIS audit is ignored.
        $ConnPathMap  = @{}
        try { foreach ($cp in @(Get-CimInstance -ClassName Win32_Process -ErrorAction Stop)) { if ($cp.ExecutablePath) { $ConnPathMap[[int]$cp.ProcessId] = $cp.ExecutablePath } } } catch { }
        $ConnSigCache = @{}

        $PublicConns = @($ExtConns | Where-Object {
            $addr = $_.RemoteAddress
            # Exclude RFC-1918 + link-local + APIPA
            -not ($addr -match '^10\.' -or
                  $addr -match '^192\.168\.' -or
                  $addr -match '^172\.(1[6-9]|2[0-9]|3[01])\.' -or
                  $addr -match '^169\.254\.' -or
                  $addr -match '^fc|^fd' -or
                  $addr -eq '::')
        })

        if ($PublicConns.Count -gt 0) {
            $PubKnown   = [System.Collections.Generic.List[string]]::new()
            $PubUnknown = [System.Collections.Generic.List[string]]::new()

            foreach ($pc in ($PublicConns | Select-Object -First 20)) {
                $procName = if ($ProcMap.ContainsKey([int]$pc.OwningProcess)) { $ProcMap[[int]$pc.OwningProcess] } else { "PID $($pc.OwningProcess)" }
                $entry = "$procName → $($pc.RemoteAddress):$($pc.RemotePort)"
                $isKnown = $false
                if ([int]$pc.OwningProcess -eq $PID) {
                    $isKnown = $true
                } elseif ($SystemProcsAllowlist -contains ($procName -replace '\.exe$','')) {
                    $pcPath  = if ($ConnPathMap.ContainsKey([int]$pc.OwningProcess)) { $ConnPathMap[[int]$pc.OwningProcess] } else { $null }
                    $pcTrust = Get-ProcessTrustClass $pcPath $ConnSigCache -Name $procName
                    $isKnown = ($pcTrust -ne "Unverified")
                    if (-not $isKnown) { $entry = "$entry [name matches a known process but its image could not be verified]" }
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
# NOTE v5.6.0: only the DEFAULT administrative shares are ignored (Special flag, or the default
# names IPC$ / ADMIN$ / print$ / <drive>$). Excluding every name ending in "$" hid any hidden share
# created by an attacker (e.g. "backup$").
$Shares = @(Get-SmbShare -ErrorAction SilentlyContinue | Where-Object { -not $_.Special -and $_.Name -notmatch '^(IPC|ADMIN|print|[A-Za-z])\$$' })
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
            "Configured listeners: " + (@($WinRMListeners | ForEach-Object { $_.PSChildName }) -join ", ")
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

    $ActiveIPv6 = @($IPv6Adapters | Where-Object {
        # Filter loopback and virtual interfaces with no real traffic
        $_.Name -notmatch "Loopback|Local Area Connection\* \d+|isatap|teredo" -and
        (Get-NetAdapter -Name $_.Name -ErrorAction SilentlyContinue).Status -eq "Up"
    })

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
    $ListenConns = @(Get-NetTCPConnection -State Listen -ErrorAction Stop |
        Where-Object {
            $_.LocalAddress -ne "127.0.0.1" -and
            $_.LocalAddress -ne "::1" -and
            $_.LocalAddress -notmatch "^fe80:"
        })

    if ($ListenConns.Count -eq 0) {
        Add-Result "Network" "Listening TCP ports (non-loopback)" "0" "OK" "No TCP port listening on non-loopback interfaces"
    } else {
        $ProcMapListen = @{}
        Get-Process -ErrorAction SilentlyContinue | ForEach-Object { $ProcMapListen[$_.Id] = $_.Name }
        # NOTE v5.6.0: the owning process image is verified (see Get-ProcessTrustClass). A port is
        # only "normal" when a verified Windows/Microsoft process owns it: the port NUMBER alone says
        # nothing (a backdoor can listen on 445 or 49668), and any port >= 1024 opened on every
        # interface by an unverified process is now a WARN instead of "normal".
        $ListenPathMap = @{}
        try { foreach ($lp in @(Get-CimInstance -ClassName Win32_Process -ErrorAction Stop)) { if ($lp.ExecutablePath) { $ListenPathMap[[int]$lp.ProcessId] = $lp.ExecutablePath } } } catch { }
        $ListenSigCache = @{}

        $failPorts  = [System.Collections.Generic.List[string]]::new()
        $warnPorts  = [System.Collections.Generic.List[string]]::new()
        $infoPorts  = [System.Collections.Generic.List[string]]::new()

        foreach ($c in $ListenConns) {
            $procName  = if ($ProcMapListen.ContainsKey([int]$c.OwningProcess)) { $ProcMapListen[[int]$c.OwningProcess] } else { "PID $($c.OwningProcess)" }
            $portNum   = [int]$c.LocalPort
            $isAllIf   = ($c.LocalAddress -eq "0.0.0.0" -or $c.LocalAddress -eq "::")
            $lPath     = if ($ListenPathMap.ContainsKey([int]$c.OwningProcess)) { $ListenPathMap[[int]$c.OwningProcess] } else { $null }
            $lTrust    = Get-ProcessTrustClass $lPath $ListenSigCache -Name $procName
            $isNormal  = ($NormalWindowsPorts -contains $portNum) -and ($lTrust -eq "Windows" -or $lTrust -eq "Microsoft")
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
            } elseif ($isAllIf -and $lTrust -eq "Unverified") {
                $warnPorts.Add("$label [unverified process: $(if($lPath){$lPath}else{'image path unknown'})]")
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
# NOTE v5.6.0: the former filter excluded every path containing "system32", "Microsoft" or
# "Windows" as a SUBSTRING, so "C:\Windows\Temp\x.exe" or "C:\ProgramData\Microsoft\x.exe" were
# never reviewed (63 services out of 67 were skipped on a standard machine), and the "standard
# location" test was a substring match too. Every automatic running service is now evaluated:
#   - image under System32 / SysWOW64 / WinSxS / servicing / Microsoft.NET -> Windows component
#     (folders only an administrator can write to, anchored comparison);
#   - Microsoft-signed (valid) and not modifiable by a non-administrator -> Microsoft component;
#   - everything else is reviewed: location writable by a non-administrator, missing file,
#     unsigned outside Program Files, unquoted path with spaces, or a user account.
$SvcOsRoots = @("$env:SystemRoot\System32", "$env:SystemRoot\SysWOW64", "$env:SystemRoot\WinSxS", "$env:SystemRoot\servicing", "$env:SystemRoot\Microsoft.NET")
$SvcPfRoots = @($env:ProgramFiles, ${env:ProgramFiles(x86)}) | Where-Object { $_ }
$SvcSigCache = @{}
$SvcAll = @(Get-CimInstance -ClassName Win32_Service -ErrorAction SilentlyContinue |
    Where-Object { $_.StartMode -eq "Auto" -and $_.State -eq "Running" -and $_.PathName })

$svcSuspect = [System.Collections.Generic.List[string]]::new()
$svcNormal  = [System.Collections.Generic.List[string]]::new()
$svcWindows = 0
$svcMicrosoft = 0
$SuspiciousServices = [System.Collections.Generic.List[object]]::new()

foreach ($svc in $SvcAll) {
    # %SystemRoot% & co. may appear unexpanded in the registry value: expand before touching the disk.
    $pathClean = [Environment]::ExpandEnvironmentVariables((Get-ServiceImagePath $svc.PathName))
    if (Test-PathUnderRoot $pathClean $SvcOsRoots) { $svcWindows++; continue }

    $prot = Test-FileLocationProtected $pathClean
    $sigKey = (ConvertTo-NormalizedWinPath $pathClean).ToLowerInvariant()
    if ($SvcSigCache.ContainsKey($sigKey)) { $sig = $SvcSigCache[$sigKey] }
    else {
        $sig = $null
        try { $sig = Get-AuthenticodeSignature -FilePath $pathClean -ErrorAction Stop } catch { }
        $SvcSigCache[$sigKey] = $sig
    }
    $sigValid = ($sig -and $sig.Status -eq "Valid")
    $isMs     = ($sigValid -and (Test-MicrosoftSigner $sig.SignerCertificate.Subject))
    if ($isMs -and $prot -ne $false) { $svcMicrosoft++; continue }

    $SuspiciousServices.Add($svc)
    $reasons = @()
    if ($prot -eq $false) { $reasons += "binary or folder modifiable by a non-administrator" }
    if ($null -eq $prot)  { $reasons += "image file not found or ACL unreadable" }
    if (-not $sigValid -and -not (Test-PathUnderRoot $pathClean $SvcPfRoots)) { $reasons += "no valid signature outside Program Files" }
    if (Test-UnquotedServicePath $svc.PathName) { $reasons += "unquoted path containing spaces" }
    if ($svc.StartName -and $svc.StartName -notmatch "(?i)LocalSystem|LocalService|NetworkService|NT AUTHORITY|NT SERVICE") { $reasons += "runs under account $($svc.StartName)" }

    $signer = if ($sigValid -and $sig.SignerCertificate.Subject -match 'CN=("[^"]+"|[^,]+)') { " [$($Matches[1].Trim('"'))]" } elseif (-not $sigValid) { " [unsigned]" } else { "" }
    $label = "$($svc.Name) ($($svc.DisplayName)) — $pathClean$signer"
    if ($reasons.Count -gt 0) { $svcSuspect.Add("$label <$($reasons -join '; ')>") } else { $svcNormal.Add($label) }
}

$svcStatus = if ($svcSuspect.Count -gt 0) { "WARN" } elseif ($SuspiciousServices.Count -gt 10) { "WARN" } else { "INFO" }
$svcVerified = "$svcWindows Windows component(s) and $svcMicrosoft Microsoft-signed service(s) verified"
$svcDetail = if ($svcSuspect.Count -gt 0) {
    "Services to review: $($svcSuspect -join ' | ')$(if($svcNormal.Count -gt 0){" — Standard third-party services: $($svcNormal -join ' | ')"}). $svcVerified."
} elseif ($SuspiciousServices.Count -gt 0) {
    "Third-party services with automatic startup (signed or in Program Files, location protected): $($svcNormal -join ' | '). $svcVerified."
} else {
    "No third-party service with automatic startup. $svcVerified."
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

# NOTE v5.7.1: process creation auditing (event 4688). The 5 categories above do not include
# "Detailed Tracking". Queried by subcategory GUID; the setting text is shown as Windows returns it
# (localized) and never interpreted. Command-line capture is a separate policy (registry value
# ProcessCreationIncludeCmdLine_Enabled), which only applies when Audit Process Creation is on
# (Microsoft Learn: Policy CSP ADMX_AuditSettings, Command line process auditing). Informational.
try {
    $PcRaw = auditpol /get /subcategory:"{0CCE922B-69AE-11D9-BED3-505054503030}" /r 2>&1
    if ($LASTEXITCODE -ne 0) { throw "auditpol returned an error (code $LASTEXITCODE): $($PcRaw -join ' ')" }
    $PcInc = Get-AuditpolInclusion $PcRaw
    if ([string]::IsNullOrWhiteSpace($PcInc)) { throw "auditpol output not recognised" }
    $PcCmd = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -Name ProcessCreationIncludeCmdLine_Enabled -ErrorAction SilentlyContinue).ProcessCreationIncludeCmdLine_Enabled
    $PcCmdTxt = if ("$PcCmd" -eq "1") { "command line included in events" } else { "command line not included" }
    Add-Result "Audit" "Process creation auditing (event 4688)" "$PcInc | $PcCmdTxt" "INFO" "Event 4688 records every program that starts. The setting above is the Windows audit setting for 'Process Creation' as returned by auditpol; the command line is only added when the policy 'Include command line in process creation events' is on and Audit Process Creation is enabled. Capturing command lines can expose sensitive data to anyone who can read the Security log."
} catch {
    Add-Result "Audit" "Process creation auditing (event 4688)" "Unable to read" "INFO" "Error: $($_.Exception.Message)"
}

# Recent security events (failed logons)
try {
    # NOTE v5.6.0: -ErrorAction SilentlyContinue turned an unreadable Security log into "0 events"
    # (reported OK). "No matching event" is now told apart from a real read error, which is reported as
    # "Unable to read" (left out of the score) instead of a clean result.
    $FailedLogons = $null
    try {
        $FailedLogons = Get-WinEvent -FilterHashtable @{
            LogName   = "Security"
            Id        = 4625
            StartTime = (Get-Date).AddHours(-24)
        } -MaxEvents 100 -ErrorAction Stop
    } catch {
        if ($_.FullyQualifiedErrorId -notmatch 'NoMatchingEventsFound|NoMatchingRecordsFound') { throw }
    }
    $FailedLogons = @($FailedLogons | Where-Object { $_ })

    Add-Result "Audit" "Failed logons (24h)" $FailedLogons.Count $(
        if ($FailedLogons.Count -gt 50) { "FAIL" }
        elseif ($FailedLogons.Count -gt 10) { "WARN" }
        else { "OK" }
    ) $(if($FailedLogons.Count -gt 50){"Possible brute-force attack!"})
} catch {
    Add-Result "Audit" "Failed logons (24h)" "Unable to read" "INFO" "The Security log could not be read: $($_.Exception.Message)"
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
        $evts = $null
        try {
            $evts = Get-WinEvent -FilterHashtable @{
                LogName   = "Security"
                Id        = $evDef.Id
                StartTime = (Get-Date).AddHours(-24)
            } -MaxEvents 200 -ErrorAction Stop
        } catch {
            if ($_.FullyQualifiedErrorId -notmatch 'NoMatchingEventsFound|NoMatchingRecordsFound') { throw }
        }
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

# NOTE v5.6.0: an event log that was CLEARED (Security 1102 / any log 104 in System) is a classic
# way to erase traces after an intrusion. Looked at over the last 90 days.
foreach ($lc in @(
        @{ Log = "Security"; Id = 1102; Label = "Security log cleared (90 days)" },
        @{ Log = "System";   Id = 104;  Label = "Event log cleared, System channel (90 days)" })) {
    try {
        $clr = $null
        try {
            $clr = @(Get-WinEvent -FilterHashtable @{ LogName = $lc.Log; ProviderName = "Microsoft-Windows-Eventlog"; Id = $lc.Id; StartTime = (Get-Date).AddDays(-90) } -MaxEvents 20 -ErrorAction Stop)
        } catch {
            if ($_.FullyQualifiedErrorId -notmatch 'NoMatchingEventsFound|NoMatchingRecordsFound') { throw }
        }
        $clrN = if ($null -eq $clr) { 0 } else { @($clr).Count }
        Add-Result "Audit" $lc.Label $clrN $(if ($clrN -gt 0) { "WARN" } else { "OK" }) $(
            if ($clrN -gt 0) { "An event log was cleared $clrN time(s) in the last 90 days (latest: $(Format-AuditDate $clr[0].TimeCreated) — $((("$($clr[0].Message)" -replace '\s+',' ').Trim()) -replace '^(.{0,140}).*$','$1')). Clearing logs is a classic way to erase traces; check that it was intentional." }
        )
    } catch {
        Add-Result "Audit" $lc.Label "Unable to read" "INFO" "Error: $($_.Exception.Message)"
    }
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
# NOTE v5.5.0: a task script with a VALID Authenticode signature whose signer is
# in the Trusted Publishers store (CurrentUser or LocalMachine) is now recognized
# automatically. Trusting a publisher is an explicit decision of the user, so no
# setting has to be edited in this script. $TrustedSignerSubjectMatch stays
# available as an optional extra.
# NOTE v5.5.0: Winhance (a Windows tweaking tool) registers its cleanup tasks in the
# folder \Winhance\ and runs a script stored in %ProgramData%\Winhance\Scripts. Such a
# task is recognized only if ALL of these hold: it sits in \Winhance\, every action
# runs a .ps1 under that folder, the file's owner is SYSTEM/Administrators/TrustedInstaller,
# and neither the file nor its folder grants a non-administrator the right to modify,
# replace, delete or re-permission it. Otherwise it stays flagged. SIDs are compared,
# never account names, so it works whatever the Windows language.
# NOTE v5.6.0: the ACL helpers ($script:AdminLikeSids, Get-NonAdminWriteGrants) now live in the
# helper block at the top, because the services check (section 9) uses them too.

function Test-WinhanceTaskTrusted {
    param($Task)
    if ("$($Task.TaskPath)" -ine "\Winhance\") { return $false }
    $actions = @($Task.Actions)
    if ($actions.Count -eq 0) { return $false }
    $base = Join-Path $env:ProgramData "Winhance\Scripts"
    $rx   = [regex]::Escape($base) + '\\[^\\''"\s]+\.ps1'
    foreach ($a in $actions) {
        $m = [regex]::Match("$($a.Execute) $($a.Arguments)", $rx, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
        if (-not $m.Success) { return $false }
        $file = $m.Value
        if (-not (Test-Path -LiteralPath $file -PathType Leaf)) { return $false }
        try {
            $fileAcl = Get-Acl -LiteralPath $file -ErrorAction Stop
            $dirAcl  = Get-Acl -LiteralPath (Split-Path $file -Parent) -ErrorAction Stop
            $ownerSid = $fileAcl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
        } catch { return $false }
        if ($script:AdminLikeSids -notcontains $ownerSid) { return $false }
        if (@(Get-NonAdminWriteGrants $fileAcl $script:FileWriteMask).Count -gt 0) { return $false }
        if (@(Get-NonAdminWriteGrants $dirAcl  $script:DirWriteMask).Count  -gt 0) { return $false }
    }
    return $true
}

$TrustedPublisherThumbs = @(Get-ChildItem -Path "Cert:\CurrentUser\TrustedPublisher","Cert:\LocalMachine\TrustedPublisher" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Thumbprint)
# NOTE v5.6.0: (1) the folder of a task (\Microsoft\...) is chosen by whoever creates it, so it is
# no longer a reason to skip a task: for tasks in \Microsoft\ only the BINARY counts (it must be a
# Windows file or carry a valid Microsoft signature). (2) interpreters are recognised by FILE NAME
# (the former substring regex missed pwsh and matched any path containing "cmd"), and the list
# grew (pwsh, msiexec, certutil, bitsadmin, curl, wmic, msbuild, python, node, wsl...). (3) running
# tasks are no longer skipped (only Disabled ones are), and (4) a task that runs a binary from a
# user-writable location without a valid signature, or whose arguments contain an encoded command /
# download / hidden window, is reviewed even if it is not an interpreter.
$TaskOsRoots   = @("$env:SystemRoot\System32", "$env:SystemRoot\SysWOW64")
$TaskUserRoots = @("$env:SystemDrive\Users", "$env:ProgramData", "$env:SystemRoot\Temp", "$env:SystemRoot\Tasks", "$env:SystemRoot\Debug")
$TaskInterpRx  = '^(powershell|pwsh|cmd|wscript|cscript|mshta|rundll32|regsvr32|msiexec|bitsadmin|certutil|curl|wmic|msbuild|installutil|python|pythonw|node|wsl|bash)(\.exe)?$'
$TaskSigCache  = @{}
$TaskReasons   = @{}
$SuspTasksRaw  = foreach ($t in @(Get-ScheduledTask -ErrorAction SilentlyContinue)) {
    if ("$($t.State)" -eq "Disabled") { continue }
    $isMsFolder = ("$($t.TaskPath)" -like "\Microsoft\*")
    $why = $null
    foreach ($a in @($t.Actions)) {
        if (-not $a.Execute) { continue }
        $exe   = ConvertTo-NormalizedWinPath (Get-ServiceImagePath "$($a.Execute)")
        # A bare file name ("sc.exe", "BthUdTask.exe") is resolved by Windows from its system folders:
        # looking it up there avoids flagging Microsoft's own tasks (found on the first real run of v5.6.0).
        if ($exe -and $exe -notmatch '\\') {
            foreach ($sd in @("$env:SystemRoot\System32", "$env:SystemRoot\SysWOW64", "$env:SystemRoot")) {
                $cand = Join-Path $sd $exe
                if (Test-Path -LiteralPath $cand -PathType Leaf) { $exe = ConvertTo-NormalizedWinPath $cand; break }
            }
        }
        $leaf  = ($exe -split '\\')[-1]
        $isOs  = Test-PathUnderRoot $exe $TaskOsRoots
        $susArgs = Test-SuspiciousTaskArgs "$($a.Arguments)"
        if ($susArgs) { $why = "encoded command / download / hidden window in the arguments"; break }
        if ($isMsFolder) {
            if ($isOs) { continue }
            $sk = $exe.ToLowerInvariant()
            if (-not $TaskSigCache.ContainsKey($sk)) {
                $s = $null; try { $s = Get-AuthenticodeSignature -FilePath $exe -ErrorAction Stop } catch { }
                $TaskSigCache[$sk] = $s
            }
            $s = $TaskSigCache[$sk]
            if (-not ($s -and $s.Status -eq "Valid" -and (Test-MicrosoftSigner $s.SignerCertificate.Subject))) {
                $why = "task placed in \Microsoft\ but its binary is not a Windows file / Microsoft-signed"; break
            }
            continue
        }
        if ($leaf -match $TaskInterpRx) { $why = "runs an interpreter ($leaf)"; break }
        if (Test-PathUnderRoot $exe $TaskUserRoots) {
            $sk = $exe.ToLowerInvariant()
            if (-not $TaskSigCache.ContainsKey($sk)) {
                $s = $null; try { $s = Get-AuthenticodeSignature -FilePath $exe -ErrorAction Stop } catch { }
                $TaskSigCache[$sk] = $s
            }
            $s = $TaskSigCache[$sk]
            if (-not ($s -and $s.Status -eq "Valid")) { $why = "binary in a user-writable location without a valid signature"; break }
        }
    }
    if ($why) { $TaskReasons["$($t.TaskPath)$($t.TaskName)"] = $why; $t }
}

$SuspTasksReal    = [System.Collections.Generic.List[object]]::new()
$SuspTasksTrusted = [System.Collections.Generic.List[object]]::new()

foreach ($task in $SuspTasksRaw) {
    $isTrusted = $false

    # NOTE v3.3 — priority 1: match by task NAME ($TrustedTaskNames).
    # Checked first since it's independent of the argument format. Covers
    # cmd, .bat tasks, or ones whose script path can't be extracted.
    if (($TrustedTaskNames -contains $task.TaskName) -or (Test-WinhanceTaskTrusted $task)) {
        $isTrusted = $true
    }

    if (-not $isTrusted) {
        foreach ($action in $task.Actions) {
            if ($isTrusted) { break }
            $argLine = "$($action.Execute) $($action.Arguments)"

            # NOTE v3.3 — priority 2: extracting the .ps1 path.
            # Old regex: [A-Za-z]:\\[^\s"]+\.ps1 — stopped at the first
            # space, so it never captured a path like
            # "C:\Users\username\Desktop\My Scripts\Script.ps1".
            # New logic: tries the quoted path first (which can contain
            # spaces), then the unquoted path (no spaces). First match wins.
            $scriptPath = $null
            $quotedMatch   = [regex]::Match($argLine, '"([A-Za-z]:\\[^"]+\.ps1)"')
            $unquotedMatch = [regex]::Match($argLine,  '([A-Za-z]:\\[^\s"]+\.ps1)')
            if    ($quotedMatch.Success)   { $scriptPath = $quotedMatch.Groups[1].Value }
            elseif ($unquotedMatch.Success) { $scriptPath = $unquotedMatch.Groups[1].Value }
            if (-not $scriptPath) { continue }

            # NOTE v5.6.0: the script path must be what the task actually RUNS (only PowerShell
            # switches before it, nothing suspicious around it); a path that merely appears somewhere
            # in the arguments (after an encoded command, in a comment...) proves nothing.
            if (-not (Test-TaskScriptInvocation "$($action.Arguments)" $scriptPath)) { continue }

            # NOTE v5.6.0: trust by PATH applies to the normalised path (no "..\" tricks) and no
            # longer covers an ELEVATED task (Highest run level, SYSTEM or service account) that
            # runs a script a non-administrator can modify: whoever can edit the script then
            # gets administrator rights. Such a task stays flagged unless the script is signed by a
            # trusted publisher (checked below) or protected by its ACL.
            $normScript = ConvertTo-NormalizedWinPath $scriptPath
            $pathMatch  = $false
            foreach ($pattern in $TrustedScriptPathPatterns) {
                if ($normScript -like $pattern) { $pathMatch = $true }
            }
            if ($pathMatch) {
                $princ    = $task.Principal
                $elevated = ("$($princ.RunLevel)" -eq "Highest") -or ("$($princ.UserId)" -match '(?i)^(SYSTEM|S-1-5-18)$') -or ("$($princ.LogonType)" -eq "ServiceAccount")
                if ($elevated -and ((Test-FileLocationProtected $scriptPath) -ne $true)) {
                    $TaskReasons["$($task.TaskPath)$($task.TaskName)"] = "elevated task running a script that a non-administrator can modify (privilege-escalation route)"
                } else {
                    $isTrusted = $true
                }
            }

            if (-not $isTrusted -and (Test-Path $scriptPath -ErrorAction SilentlyContinue)) {
                try {
                    $sig = Get-AuthenticodeSignature -FilePath $scriptPath -ErrorAction Stop
                    if ($sig.Status -eq "Valid" -and (
                            ($TrustedPublisherThumbs -contains $sig.SignerCertificate.Thumbprint) -or
                            ($sig.SignerCertificate.Subject -match [regex]::Escape($TrustedSignerSubjectMatch)))) {
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
) $(if($SuspTasksReal.Count -gt 0){
    "Tasks to audit: " + (@($SuspTasksReal | ForEach-Object {
        $tk = "$($_.TaskPath)$($_.TaskName)"
        if ($TaskReasons.ContainsKey($tk)) { "$($_.TaskName) <$($TaskReasons[$tk])>" } else { "$($_.TaskName)" }
    }) -join ", ")
})

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

# NOTE v5.7.0: Secure Boot certificate renewal (Microsoft 2011 certificates -> 2023 certificates).
# Evidence, strongest first: the Windows UEFI CA 2023 / KEK 2K CA 2023 actually present in the
# firmware databases (db, KEK), the servicing status Windows keeps in the registry
# (Servicing\UEFICA2023Status) and, only when the status is not "Updated", the Secure Boot
# servicing events of the System log (event ids only: the message text is localized).
# AvailableUpdates is not used for the decision. The decision is made by Get-SecureBootCertAssessment.
try {
    $SbcEnabled = $null
    try { $SbcEnabled = [bool](Confirm-SecureBootUEFI -ErrorAction Stop) } catch { }
    $SbcSvc = $null
    try { $SbcSvc = Get-ItemProperty -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing" -ErrorAction Stop } catch { }
    $SbcStatus = if ($SbcSvc) { "$($SbcSvc.UEFICA2023Status)" } else { "" }
    $SbcErr    = if ($SbcSvc) { "$($SbcSvc.UEFICA2023Error)" } else { "" }
    $SbcErrEv  = if ($SbcSvc) { "$($SbcSvc.UEFICA2023ErrorEvent)" } else { "" }
    $SbcDb = $null; $SbcKek = $null
    if ($SbcEnabled -eq $true) {
        try { $SbcDbVar  = Get-SecureBootUEFI -Name db  -ErrorAction Stop; $SbcDb  = Test-UefiSignatureText $SbcDbVar.Bytes  "Windows UEFI CA 2023" } catch { }
        try { $SbcKekVar = Get-SecureBootUEFI -Name KEK -ErrorAction Stop; $SbcKek = Test-UefiSignatureText $SbcKekVar.Bytes "Microsoft Corporation KEK 2K CA 2023" } catch { }
    }
    $SbcEvents = @()
    if ($SbcEnabled -eq $true -and $SbcStatus -ne "Updated") {
        try {
            $SbcEvents = @(Get-WinEvent -FilterHashtable @{ LogName = "System"; Id = 1795, 1796, 1800, 1801, 1802, 1803, 1808 } -MaxEvents 50 -ErrorAction Stop |
                ForEach-Object { [int]$_.Id } | Select-Object -Unique)
        } catch {
            # No matching event is a normal answer (empty list); any other error = log unreadable.
            if ($_.FullyQualifiedErrorId -notmatch 'NoMatchingEventsFound') { $SbcEvents = $null }
        }
    }
    $Sbc = Get-SecureBootCertAssessment -SecureBootEnabled $SbcEnabled -Status $SbcStatus -ErrorValue $SbcErr -ErrorEvent $SbcErrEv `
        -DbHas2023 $SbcDb -KekHas2023 $SbcKek -EventIds $SbcEvents
    Add-Result "UEFI Security" "Secure Boot certificates (2023 renewal)" $Sbc.Value $Sbc.Status $Sbc.Detail
} catch {
    Add-Result "UEFI Security" "Secure Boot certificates (2023 renewal)" "Unable to read" "INFO" "Error: $($_.Exception.Message)"
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
    # NOTE v5.6.0: Microsoft states that the execution policy is NOT a security boundary (it only
    # prevents accidental launches), so a permissive policy is a hardening recommendation: WARN, no longer FAIL.
    if ($ep.ExecutionPolicy -match "Unrestricted|Bypass") { $st = "WARN" }
    if ($ep.Scope -match "LocalMachine|CurrentUser") {
        Add-Result "PowerShell" "ExecutionPolicy ($($ep.Scope))" $ep.ExecutionPolicy $st $(
            if ($st -eq "WARN") { "Execution policy is permissive. It is not a security boundary (it only prevents accidental script launches), but RemoteSigned or AllSigned is the recommended baseline." }
        )
    }
}

# NOTE v4.8: Smart App Control — three distinct states with CPU context.
# On an incompatible CPU (e.g. Kaby Lake, predates the SAC
# requirement), "not available" is normal -> neutral INFO.
# State 0 = permanently disabled (deliberate choice, often for
# compatibility with unsigned tools) -> contextual INFO, not WARN.
# State 1 = active -> OK.
# State 2 = evaluation mode -> INFO (Windows decides automatically).
$SacKey = "HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy"
$SacRaw = (Get-ItemProperty $SacKey -Name VerifiedAndReputablePolicyState -EA SilentlyContinue).VerifiedAndReputablePolicyState

# NOTE v5.6.0: the former CPU heuristic ("Tiger Lake+ / Zen 3+ required") is removed: no such
# requirement appears in the sources consulted (SAC depends on Windows 11 22H2+ and the system
# requirements of Windows 11, not on a CPU generation).
$SacCpuNote = ""

if ($null -eq $SacRaw) {
    Add-Result "PowerShell" "Smart App Control" "Not available$SacCpuNote" "INFO" "The Smart App Control state is not exposed by this build (policy value absent). It requires Windows 11 22H2 or later; availability and the way to switch it on or off depend on the build (older builds required a clean installation) — check Windows Security > App & browser control > Smart App Control settings"
} else {
    $SacLabel = switch ([int]$SacRaw) {
        0 { "Permanently disabled$SacCpuNote" }
        1 { "Enabled (enforcement mode)" }
        2 { "In evaluation mode (Windows decides automatically)" }
        default { "Unknown state ($SacRaw)" }
    }
    $SacStatus = if ([int]$SacRaw -eq 1) { "OK" } else { "INFO" }
    $SacDetail = switch ([int]$SacRaw) {
        0 { "SAC permanently disabled — likely disabled deliberately for compatibility with unsigned tools (npm, portable tools, etc.). On older builds it could not be re-enabled without a clean installation; recent builds let you switch it back on from Windows Security (verify for your build)." }
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

# NOTE v5.7.1: application control overview (AppLocker, WDAC, PowerShell language mode), informational.
# AppLocker cmdlets are absent on some editions (e.g. Windows Home): that is reported, not an error.
# WDAC status: Win32_DeviceGuard (0 off, 1 audit, 2 enforced). Decision/text: Get-AppControlAssessment.
try {
    $AcAlAvail = [bool](Get-Command Get-AppLockerPolicy -ErrorAction SilentlyContinue)
    $AcAl = $null
    if ($AcAlAvail) {
        try { $AcAl = Get-AppLockerSummary ([string](Get-AppLockerPolicy -Effective -Xml -ErrorAction Stop)) } catch { }
    }
    $AcDg = $null
    try { $AcDg = Get-CimInstance -Namespace "root\Microsoft\Windows\DeviceGuard" -ClassName Win32_DeviceGuard -ErrorAction Stop } catch { }
    $AcLm = ""
    try { $AcLm = "$($ExecutionContext.SessionState.LanguageMode)" } catch { }
    $Ac = Get-AppControlAssessment -AppLockerAvailable $AcAlAvail -AppLocker $AcAl `
        -WdacKernel $AcDg.CodeIntegrityPolicyEnforcementStatus -WdacUser $AcDg.UsermodeCodeIntegrityPolicyEnforcementStatus -LanguageMode $AcLm
    Add-Result "PowerShell" "Application control (AppLocker / WDAC / language mode)" $Ac.Value $Ac.Status $Ac.Detail
} catch {
    Add-Result "PowerShell" "Application control (AppLocker / WDAC / language mode)" "Unable to read" "INFO" "Error: $($_.Exception.Message)"
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

# NOTE v5.6.0: Winlogon\Shell and Winlogon\Userinit start programs at every sign-in. Windows ships
# "explorer.exe" and a single userinit.exe; anything else added there is a classic persistence trick.
try {
    $WlPers = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -ErrorAction Stop
    $WlTest = Test-WinlogonShellUserinit -Shell "$($WlPers.Shell)" -Userinit "$($WlPers.Userinit)"
    if ($WlTest.ShellOk -and $WlTest.UserinitOk) {
        Add-Result "Startup" "Winlogon Shell / Userinit" "Default values" "OK" "Shell is explorer.exe and Userinit is the Windows userinit.exe only"
    } else {
        Add-Result "Startup" "Winlogon Shell / Userinit" "Modified" "WARN" "A program other than the Windows defaults runs at every sign-in. Shell = '$($WlPers.Shell)' | Userinit = '$($WlPers.Userinit)' (defaults: explorer.exe and $env:SystemRoot\System32\userinit.exe,). Check that it is intentional."
    }
} catch {
    Add-Result "Startup" "Winlogon Shell / Userinit" "Unable to read" "INFO" "Error: $($_.Exception.Message)"
}

# NOTE v5.6.0: permanent WMI event subscriptions run a command or a script when an event occurs,
# surviving reboots with no file in any startup location: a known "fileless" persistence technique.
# Only the two consumer types able to execute something are listed (the event-log consumer Windows
# ships by default is harmless).
try {
    $WmiCmd = @(Get-CimInstance -Namespace "root\subscription" -ClassName CommandLineEventConsumer -ErrorAction Stop)
    $WmiScr = @(Get-CimInstance -Namespace "root\subscription" -ClassName ActiveScriptEventConsumer -ErrorAction Stop)
    $WmiAll = @($WmiCmd | ForEach-Object { "$($_.Name) [command: $($_.CommandLineTemplate)]" }) + @($WmiScr | ForEach-Object { "$($_.Name) [script: $(if($_.ScriptFileName){$_.ScriptFileName}else{$_.ScriptingEngine})]" })
    Add-Result "Startup" "WMI permanent event subscriptions (command/script)" $WmiAll.Count $(if ($WmiAll.Count -gt 0) { "WARN" } else { "OK" }) $(
        if ($WmiAll.Count -gt 0) { "Consumers able to run a command or script when a WMI event fires: $($WmiAll -join ' | '). Rare in legitimate use — verify each one." } else { "No command or script consumer is registered in root\subscription" }
    )
} catch {
    Add-Result "Startup" "WMI permanent event subscriptions (command/script)" "Unable to read" "INFO" "Error: $($_.Exception.Message)"
}

}

# ──────────────────────────────────────────────
#  16. WINDOWS DEFENDER EXCLUSIONS
# ──────────────────────────────────────────────
if (ShouldRunSection "16_Exclusions") {
Write-Log "=== 16. WINDOWS DEFENDER EXCLUSIONS ===" -Level SECTION

try {
    $Prefs = Get-MpPreference -ErrorAction Stop
    # NOTE v5.5.0: when there is no exclusion, Get-MpPreference returns $null (not an
    # empty array), and @($null) is an array with ONE empty element: the report then
    # showed "1:" for a list that is actually empty. Empty entries are filtered out.
    $PathExclusions = @($Prefs.ExclusionPath      | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    $ExtExclusions  = @($Prefs.ExclusionExtension | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    $ProcExclusions = @($Prefs.ExclusionProcess   | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })

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
    # NOTE v5.6.0: the breadth test is now done by Test-BroadDefenderExclusion (normalised path:
    # drive root, Windows, Users, a whole user profile, ProgramData, Program Files itself, Downloads, Temp,
    # AppData, trailing wildcard). The former pattern flagged EVERY folder under Program Files, including
    # a single application. Extension and process exclusions, which used to be listed without any
    # judgement, are also reviewed: excluding ".exe", ".ps1" or "powershell.exe" exempts everything that
    # matches, which is a classic way to blind an antivirus.
    foreach ($path in $PathExclusions) {
        if (Test-BroadDefenderExclusion $path) {
            Add-Result "Defender" "Broad exclusion detected" $path "WARN" "This exclusion covers a very broad folder — check that it's intentional and no broader than needed"
        }
    }
    foreach ($ext in $ExtExclusions) {
        if (Test-RiskyExclusionExtension $ext) {
            Add-Result "Defender" "Broad exclusion detected" "extension $ext" "WARN" "Every file with this extension is exempt from scanning, anywhere on the machine. An executable or script extension should not be excluded: exclude the specific folder or file instead."
        }
    }
    foreach ($proc in $ProcExclusions) {
        if (Test-RiskyExclusionProcess $proc) {
            Add-Result "Defender" "Broad exclusion detected" "process $proc" "WARN" "Excluding an interpreter or a wildcard process exempts everything it opens or runs. Malware commonly adds such an exclusion to avoid detection — check that it is intentional."
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
    # NOTE v5.6.0: AvailableSecurityProperties tells what the hardware / firmware can do
    # (1 = virtualization support, 2 = Secure Boot, 3 = DMA protection, 7 = MBEC/GMET...). When the
    # list is returned and does not contain 1, VBS cannot run on this machine: that is "not
    # supported" (INFO), not a setting left disabled (WARN).
    $VbsAvail       = @($DG.AvailableSecurityProperties)
    $VbsUnsupported = ($VbsAvail.Count -gt 0 -and $VbsAvail -notcontains 1)
    $VbsStatusCode  = [int]$DG.VirtualizationBasedSecurityStatus
    Add-Result "VBS" "Virtualization-based security" $(if ($VbsUnsupported -and $VbsStatusCode -ne 2) { "Not supported by this hardware/firmware" } else { $VBSStatus }) $(
        if ($VbsStatusCode -eq 2) { "OK" } elseif ($VbsUnsupported) { "INFO" } else { "WARN" }
    ) $(if ($VbsUnsupported -and $VbsStatusCode -ne 2) { "The firmware reports no virtualization support for VBS (AvailableSecurityProperties: $($VbsAvail -join ','))" } else { "Requires a compatible CPU (VT-x/AMD-V) + enabling at startup (Core Isolation)" })

    $RunningServices = @($DG.SecurityServicesRunning)
    $CredGuardRunning = $RunningServices -contains 1
    $HVCIRunning      = $RunningServices -contains 2

    Add-Result "VBS" "Credential Guard" $(if($CredGuardRunning){"Active"}else{"Inactive"}) $(
        if ($CredGuardRunning) { "OK" } else { "INFO" }
    ) "Protects credentials in memory against theft (pass-the-hash) — mainly relevant in a domain environment, optional on a personal machine"

    Add-Result "VBS" "Memory Integrity (HVCI)" $(if($HVCIRunning){"Active"}elseif($VbsUnsupported){"Not supported by this hardware/firmware"}else{"Inactive"}) $(
        if ($HVCIRunning) { "OK" } elseif ($VbsUnsupported) { "INFO" } else { "WARN" }
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
# NOTE v5.6.0: the registry value is the CONFIGURATION, not the effective state. Windows writes a
# Wininit event (ID 12, "LSASS.exe was started as a protected process") at each start when the
# protection is really applied; the event ID is language-independent. A missing RunAsPPL value is
# therefore only a WARN when no such event exists for the current boot.
$LsaEffective = $false
try {
    $LsaEv = @(Get-WinEvent -FilterHashtable @{ LogName = "System"; ProviderName = "Microsoft-Windows-Wininit"; Id = 12 } -MaxEvents 1 -ErrorAction Stop)
    if ($LsaEv.Count -gt 0) {
        $LsaBoot = $null
        try { $LsaBoot = $OS.LastBootUpTime } catch { }
        $LsaEffective = (-not $LsaBoot) -or ($LsaEv[0].TimeCreated -ge $LsaBoot.AddMinutes(-10))
    }
} catch { }
if ($null -eq $LsaPplRaw -and $LsaEffective) {
    Add-Result "VBS" "LSA Protection (RunAsPPL)" "Active (no registry value, confirmed by Wininit event 12)" "OK" "lsass.exe was started as a protected process at the last boot (Windows default on recent builds); no RunAsPPL value is stored in the registry"
} elseif ($null -eq $LsaPplRaw) {
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

# NOTE v4.4 / v5.6.0: Kernel-mode Hardware-enforced Stack Protection protects kernel driver
# stacks against ROP attacks at the hardware level (CPU with CET: Intel 11th gen+ / AMD Zen 3+,
# HVCI active, Windows 11 22H2+). v5.6.0: the former reading of "bit 3 of HVCIOptions" was not backed
# by Microsoft documentation and is dropped. Two sources are used instead: the services reported
# as RUNNING by Win32_DeviceGuard (value 5, "Kernel-mode Hardware-enforced Stack Protection"), and the
# CONFIGURATION key Scenarios\KernelShadowStacks\Enabled.
$KheKey = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\KernelShadowStacks"
$KheRunning = (@($RunningServices) -contains 5)
$KheConfigured = $null
try { $KheConfigured = (Get-ItemProperty -LiteralPath $KheKey -Name "Enabled" -ErrorAction Stop).Enabled } catch { }
if ($KheRunning) {
    Add-Result "VBS" "Kernel Hardware-enforced Stack Protection" "Active (reported running by Win32_DeviceGuard)" "OK" "Hardware protection of the kernel stack against ROP attacks is running"
} elseif ($null -ne $KheConfigured) {
    Add-Result "VBS" "Kernel Hardware-enforced Stack Protection" $(if ([int]$KheConfigured -eq 1) { "Configured but not running" } else { "Inactive (Enabled=$KheConfigured)" }) "INFO" "Hardware protection of the kernel stack against ROP attacks — requires an Intel 11th gen+/AMD Zen 3+ CPU (CET) and active HVCI$(if([int]$KheConfigured -eq 1){'; it is configured but not running: unsupported CPU, incompatible driver or restart pending'})"
} else {
    Add-Result "VBS" "Kernel Hardware-enforced Stack Protection" "Not available" "INFO" "Neither the running-services list nor the KernelShadowStacks configuration key reports this feature — probably unsupported on this CPU/configuration"
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
# NOTE v5.6.0: the former exclusion "Subject contains Microsoft" contradicted the principle above:
# a rogue root named "Microsoft ..." was silently skipped, and so was a non-Microsoft root whose
# subject happens to contain the word (e.g. "Symantec Enterprise Mobile Root for Microsoft").
# Roots that Windows itself ships are now recognised by THUMBPRINT. The list below was taken
# from a Windows 11 25H2 installation (Root store, certificates absent from the AuthRoot CTL) and
# the subjects match Microsoft's published roots; verify it against Microsoft's trusted root
# program documentation before relying on it. Anything else is judged like any other root, and
# $TrustedRootThumbprintAllowlist (CONFIGURATION) still lets you vouch for a root yourself.
$WindowsShippedRootThumbprints = @{
    "CDD4EEAE6000AC7F40C3802C171E30148030C072" = "Microsoft Root Certificate Authority (2001)"
    "A43489159A520F0D93D032CCAF37E7FE20A8B419" = "Microsoft Root Authority (1997)"
    "7F88CD7223F3C813818C994614A89C99FA3B5247" = "Microsoft Authenticode(tm) Root Authority"
    "245C97DF7514E7CF2DF8BE72AE957B9E04741E85" = "Microsoft Time Stamping Service Root"
    "3B1EFD3A66EA28B16697394703A72CA340A05BD5" = "Microsoft Root Certificate Authority 2010"
    "8F43288AD272F3103B6FB1428485EA3014C0BCFE" = "Microsoft Root Certificate Authority 2011"
    "06F1AA330B927B753A40E68CDF22E34BCBEF3352" = "Microsoft ECC Product Root Certificate Authority 2018"
    "31F9FC8BA3805986B721EA7295C65B3A44534274" = "Microsoft ECC TS Root Certificate Authority 2018"
    "0119E81BE9A14CD8E22F40AC118C687ECBA3F4D8" = "Microsoft Time Stamp Root Certificate Authority 2014"
    "45A0FA32604773C82433C3B7D59E7466B3AC0C67" = "Windows UEFI CA 2023"
    "92B46C76E13054E104F230517E6E504D43AB10B5" = "Symantec Enterprise Mobile Root for Microsoft (shipped with Windows)"
}
try {
    $RootCerts = Get-ChildItem -Path "Cert:\LocalMachine\Root" -ErrorAction Stop
    $AuthRootCerts = Get-ChildItem -Path "Cert:\LocalMachine\AuthRoot" -ErrorAction SilentlyContinue
    $AuthRootThumbprints = @($AuthRootCerts | Select-Object -ExpandProperty Thumbprint)

    Add-Result "Certificates" "Installed root certificates" $RootCerts.Count "INFO" "Cert:\LocalMachine\Root store"

    $UnknownRootCerts = $RootCerts | Where-Object {
        $AuthRootThumbprints -notcontains $_.Thumbprint -and -not $WindowsShippedRootThumbprints.ContainsKey($_.Thumbprint)
    }

    if ($UnknownRootCerts.Count -eq 0) {
        Add-Result "Certificates" "Root certificates outside the Microsoft list" "0" "OK" "Every root certificate present is aligned with Microsoft's trust list (AuthRoot CTL) or is a known Windows-shipped root (thumbprint)"
    } else {
        $VerifiedCerts   = $UnknownRootCerts | Where-Object { $TrustedRootThumbprintAllowlist.ContainsKey($_.Thumbprint) }
        $UnverifiedCerts = $UnknownRootCerts | Where-Object { -not $TrustedRootThumbprintAllowlist.ContainsKey($_.Thumbprint) }

        # NOTE v5.5.0: an unverified certificate only deserves a WARN when it is
        # a real CA (BasicConstraints CA:TRUE): that is the only kind able to
        # sign other certificates and intercept TLS traffic. An end-entity
        # certificate placed in Root (CA:FALSE) cannot do either, so it is INFO
        # (full score credit) and never requires editing the allowlist.
        $IsEndEntityRoot = {
            param($c)
            $bc = $c.Extensions | Where-Object { $_.Oid.Value -eq "2.5.29.19" }
            if (-not $bc) { return $false }
            # Typed property first: language-independent, no text parsing.
            if ($bc -is [System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]) {
                return (-not $bc.CertificateAuthority)
            }
            try {
                # Fallback on the text: "Subject Type=End Entity" or the localized French equivalent "Entité finale"
                return [bool]($bc.Format($false) -match "End Entity|Entité finale|Subject Type=End|CA:FALSE")
            } catch { return $false }
        }
        $UnverifiedCA = @($UnverifiedCerts | Where-Object { -not (& $IsEndEntityRoot $_) })
        $UnverifiedEE = @($UnverifiedCerts | Where-Object { & $IsEndEntityRoot $_ })

        Add-Result "Certificates" "Root certificates outside the Microsoft list" $UnknownRootCerts.Count $(
            if ($UnverifiedCA.Count -gt 0) { "WARN" } elseif ($UnverifiedEE.Count -gt 0) { "INFO" } else { "OK" }
        ) "$($VerifiedCerts.Count) manually verified (known thumbprint) | $($UnverifiedCA.Count) unverified CA, to review | $($UnverifiedEE.Count) unverified end-entity (cannot sign other certificates), informational. Detail below for each"

        $caReviewHint = " | To review: a CA in Root outside Microsoft's list is sometimes legitimate (antivirus with HTTPS scanning, corporate proxy or VPN, developer tools such as mkcert, Fiddler or mitmproxy). Check its thumbprint against the vendor's documentation; if you cannot link it to software you installed, treat it as suspect."
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
            $isEndEntity = [bool](& $IsEndEntityRoot $cert)

            # EKU detection to enrich the description
            $ekuLabel = ""
            $ekuExt = $cert.Extensions | Where-Object { $_.Oid.Value -eq "2.5.29.37" }
            if ($ekuExt) {
                try { $ekuLabel = " | EKU: $($ekuExt.Format($false))" } catch {}
            }

            $reviewHint = ""
            if ($isVerified) {
                $legitLabel = "Manually verified — $($TrustedRootThumbprintAllowlist[$cert.Thumbprint])"
                $riskLabel  = if ($isEndEntity) { "Very low (thumbprint confirmed + end-entity: can't sign other certificates or do MITM)" } else { "Low (thumbprint confirmed)" }
                $certStatus = "OK"
            } else {
                $legitLabel = "Unverified — absent from both the Microsoft CTL (AuthRoot) and the local allowlist"
                if ($isEndEntity) {
                    $riskLabel  = "Low (end-entity: cannot sign other certificates or intercept TLS; non-standard placement in Root, identify the origin if you want to be thorough)"
                    $certStatus = "INFO"
                } elseif ($isGuidLike -or -not $cnMatch.Success) {
                    $riskLabel  = "Review as a priority (possible CA + non-descriptive name + unverified)"
                    $certStatus = "WARN"
                    $reviewHint = $caReviewHint
                } else {
                    $riskLabel  = "Review (possible CA, unverified, readable name)"
                    $certStatus = "WARN"
                    $reviewHint = $caReviewHint
                }
            }

            $typeNote   = if ($isEndEntity) { "End entity — CANNOT sign other certificates" } else { "Certificate Authority (CA) — can sign other certificates" }
            # NOTE v5.5.0: the web links only help for certificates issued by a public CA.
            # For a locally created one, the useful facts are on the machine itself.
            if (-not $isVerified) {
                $reviewHint += " | To trace its origin run: certutil -store Root $($cert.Thumbprint) (creation date NotBefore, key provider, presence of a private key on this machine), then check what was installed or updated on that date."
            }
            $certDetail = "Name (CN): $displayName ($nameNote) | Type: $typeNote | Issuer: $($cert.Issuer) | Location: Cert:\LocalMachine\Root | Expiration: $(Format-AuditDate $cert.NotAfter -DateOnly) ($daysToExpiry days) | Thumbprint (SHA-1): $($cert.Thumbprint)$ekuLabel | Legitimacy: $legitLabel | Estimated danger: $riskLabel$reviewHint"

            Add-Result "Certificates" "Root certificate: $displayName" "$($cert.Subject)" $certStatus $certDetail
        }
    }
} catch {
    Add-Result "Certificates" "Reading root certificates" "Unable to read" "INFO" "Error: $($_.Exception.Message)"
}

# NOTE v5.6.0: a root certificate can also be installed for the CURRENT USER only, with no
# administrator rights (the user just has to accept a prompt). Cert:\CurrentUser\Root also shows
# the machine roots, so only certificates present in neither the machine Root store, the AuthRoot
# CTL nor the Windows-shipped list are examined.
try {
    $LmRootThumbs = @(Get-ChildItem -Path "Cert:\LocalMachine\Root" -ErrorAction Stop | ForEach-Object { $_.Thumbprint })
    $LmAuthThumbs = @(Get-ChildItem -Path "Cert:\LocalMachine\AuthRoot" -ErrorAction SilentlyContinue | ForEach-Object { $_.Thumbprint })
    $UserRootCerts = @(Get-ChildItem -Path "Cert:\CurrentUser\Root" -ErrorAction Stop | Where-Object {
        $LmRootThumbs -notcontains $_.Thumbprint -and $LmAuthThumbs -notcontains $_.Thumbprint -and
        -not $WindowsShippedRootThumbprints.ContainsKey($_.Thumbprint)
    })
    if ($UserRootCerts.Count -eq 0) {
        Add-Result "Certificates" "Root certificates added for the current user" "0" "OK" "Cert:\CurrentUser\Root holds nothing beyond the machine Root store and Microsoft's trust list"
    } else {
        $uUnverified = @($UserRootCerts | Where-Object { -not $TrustedRootThumbprintAllowlist.ContainsKey($_.Thumbprint) })
        $uCA         = @($uUnverified | Where-Object { -not (Test-CertEndEntity $_) })
        # The summary row is INFO when something is unverified: each unverified certificate gets its own
        # WARN row below, so a single finding is not counted twice in the score.
        Add-Result "Certificates" "Root certificates added for the current user" $UserRootCerts.Count $(
            if ($uUnverified.Count -gt 0) { "INFO" } else { "OK" }
        ) "$($UserRootCerts.Count - $uUnverified.Count) vouched for in the allowlist | $($uCA.Count) unverified CA, to review | $($uUnverified.Count - $uCA.Count) unverified end-entity. Detail below for each unverified one"
        foreach ($uc in $uUnverified) {
            $ucEE   = Test-CertEndEntity $uc
            $ucName = if ($uc.Subject -match '^CN=([^,]+)') { $Matches[1] } else { $uc.Subject }
            Add-Result "Certificates" "Current-user root certificate: $ucName" "$($uc.Subject)" $(if ($ucEE) { "INFO" } else { "WARN" }) "Type: $(if($ucEE){'End entity — cannot sign other certificates'}else{'Certificate Authority (CA) — can sign other certificates and intercept TLS for this user'}) | Issuer: $($uc.Issuer) | Expiration: $(Format-AuditDate $uc.NotAfter -DateOnly) | Thumbprint (SHA-1): $($uc.Thumbprint) | Legitimacy: Unverified — to trace its origin run: certutil -user -store Root $($uc.Thumbprint). If you created it yourself (for example to sign your own scripts), add its thumbprint to `$TrustedRootThumbprintAllowlist`."
        }
    }
} catch {
    Add-Result "Certificates" "Root certificates added for the current user" "Unable to read" "INFO" "Error: $($_.Exception.Message)"
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
    Add-Result "Startup" "HVCI Vulnerable Driver Blocklist" "Not forced (HVCI default)" "INFO" "VulnerableDriverBlocklistEnable key absent — Windows applies its own default for this build; check Windows Security > Device security > Core isolation > Microsoft Vulnerable Driver Blocklist"
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
        $suspDrivers   = [System.Collections.Generic.List[string]]::new()
        $okDrivers     = [System.Collections.Generic.List[string]]::new()
        $signedDrivers = [System.Collections.Generic.List[string]]::new()

        foreach ($ev in @($RecentDrivers)) {
            try {
                $svcName  = $ev.Properties[0].Value
                $svcPath  = "$($ev.Properties[1].Value)"
                # NOTE v5.6.0: the "kernel" flag now relies on the .sys extension as well (the service
                # type text is localised), and the standard-location test is an ANCHORED path
                # comparison: the former unanchored regex accepted "...\Temp\system32\drivers\x.sys".
                # Driver paths come as "System32\drivers\x.sys" (relative to the Windows folder),
                # "\SystemRoot\..." or "\??\C:\...": all are normalised first.
                $isKernel = ($ev.Properties[2].Value -match "kernel") -or ($svcPath -match '(?i)\.sys(\s|"|$)')
                $drvImage = Get-ServiceImagePath $svcPath
                if ($drvImage -and $drvImage -notmatch '^([A-Za-z]:|\\|%)') { $drvImage = "$env:SystemRoot\$drvImage" }
                $isSuspect = (-not (Test-PathUnderRoot $drvImage @("$env:SystemRoot\System32\drivers", "$env:SystemRoot\System32\DriverStore\FileRepository", "$env:SystemRoot\INF", "$env:ProgramFiles\WSL", "$env:ProgramFiles\WindowsApps"))) -and
                             $svcPath -ne "0"
                # NOTE v5.5.0: a user-mode service (.exe) with a VALID Authenticode
                # signature outside the Windows paths is normally an application
                # updater (Edge Update, vendor updaters...): listed as INFO with its
                # signer. Kernel drivers (.sys), unsigned or invalid executables keep
                # the WARN. Kernel detection relies on the extension, not on the
                # localized service-type text.
                $signerNote = $null
                $exeNote    = ""
                if ($isSuspect) {
                    $exePath = $null
                    $mq = [regex]::Match($svcPath, '(?i)^\s*"([^"]+\.exe)"')
                    if ($mq.Success) { $exePath = $mq.Groups[1].Value }
                    else {
                        $mu = [regex]::Match($svcPath, '(?i)^\s*(.+?\.exe)(\s|$)')
                        if ($mu.Success) { $exePath = $mu.Groups[1].Value }
                    }
                    if ($exePath) {
                        $exePath = [Environment]::ExpandEnvironmentVariables($exePath)
                        if (Test-Path -LiteralPath $exePath -PathType Leaf -ErrorAction SilentlyContinue) {
                            # Own try/catch: if the signature can't be read, the entry keeps its WARN
                            # (it must never fall through to the outer catch and disappear).
                            try {
                                $sigD = Get-AuthenticodeSignature -FilePath $exePath -ErrorAction Stop
                                if ($sigD.Status -eq "Valid") {
                                    $signerNote = if ($sigD.SignerCertificate.Subject -match 'CN=("[^"]+"|[^,]+)') { $Matches[1].Trim('"') } else { $sigD.SignerCertificate.Subject }
                                } else {
                                    $exeNote = " [signature: $($sigD.Status)]"
                                }
                            } catch { $signerNote = $null }
                        } else {
                            # A service registered in the last 24h whose executable no longer exists
                            # (removed afterwards by a cleanup tool, or by malware covering its tracks).
                            $exeNote = " [file not found on disk]"
                        }
                    }
                }
                if ($isSuspect -and $signerNote) {
                    $signedDrivers.Add("$svcName (signed by $signerNote) : $svcPath")
                } elseif ($isSuspect) {
                    $suspDrivers.Add("$svcName : $svcPath$(if($isKernel){' [kernel]'})$exeNote")
                } else {
                    $okDrivers.Add($svcName)
                }
            } catch {}
        }

        $status = if ($suspDrivers.Count -gt 0) { "WARN" } else { "INFO" }
        $detail = if ($suspDrivers.Count -gt 0) {
            "Drivers outside the normal Windows delivery channel: $($suspDrivers -join ' | ')"
        } elseif ($signedDrivers.Count -gt 0) {
            "Signed services outside the standard Windows paths (usually application updaters): $($signedDrivers -join ' | ')"
        } else {
            "All drivers are in standard Windows paths: $($okDrivers -join ', ')"
        }
        if ($suspDrivers.Count -gt 0 -and $signedDrivers.Count -gt 0) {
            $detail += " | Also, signed services (usually application updaters): $($signedDrivers -join ' | ')"
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

# 2. Existing shadow copies on the system drive
# NOTE v5.4.2: detection rewritten, locale-independent. Root cause of the
# false "0 shadow copies" FAIL found on a Win11 Home machine (Famille, French
# locale): the vssadmin text parsing used "ID de clich" while the real
# French output says "ID du cliché instantané" (-> 0 blocks counted), and
# the date regex was case-sensitive against "à la date de création :"
# (lowercase "date"). The old fallback (Get-ComputerRestorePoint) was also
# wrapped in an empty catch{}, so any failure there was silent and ended
# in a misleading FAIL "0".
# New order of detection:
#   1. CIM Win32_ShadowCopy filtered on the system volume's DeviceID —
#      no text parsing, InstallDate is already a [datetime], works on any
#      Windows language. Snapshots of other volumes (wbadmin images on E:/F:)
#      are NOT counted.
#   2. vssadmin list shadows with locale-tolerant, case-insensitive regexes —
#      only if the CIM query itself failed.
#   3. Get-ComputerRestorePoint — only if no shadow copy was found.
#   4. FAIL only if all of the above come back empty; the error messages of
#      the methods that failed are appended to the detail instead of being
#      swallowed.
try {
    $shadowDates      = @()
    $shadowBlockCount = 0
    $detectErrors     = New-Object System.Collections.Generic.List[string]
    $cimOk            = $false

    # --- Method 1: CIM (preferred, locale-independent) ---
    try {
        $sysVol  = Get-CimInstance -ClassName Win32_Volume -Filter "DriveLetter='$env:SystemDrive'" -ErrorAction Stop
        $shadows = @(Get-CimInstance -ClassName Win32_ShadowCopy -ErrorAction Stop |
            Where-Object { $_.VolumeName -ieq $sysVol.DeviceID })
        $shadowBlockCount = $shadows.Count
        $shadowDates = @($shadows | Where-Object { $_.InstallDate } |
            ForEach-Object { [datetime]$_.InstallDate } | Sort-Object -Descending)
        $cimOk = $true
    } catch { $detectErrors.Add("CIM: $($_.Exception.Message)") }

    # --- Method 2: vssadmin text parsing (only if CIM failed) ---
    if (-not $cimOk) {
        try {
            # vssadmin can produce UTF-16LE output on some configurations —
            # NULs stripped, same pattern as Check-Boot_Win11's SFC/DISM section.
            $vssOutput = & vssadmin list shadows /for=$env:SystemDrive 2>&1
            $vssText   = ($vssOutput -join "`n") -replace "`0",""
            # FR: "ID du cliché instantané" / EN: "Shadow Copy ID" (case-insensitive)
            $shadowBlockCount = ([regex]::Matches($vssText,
                "(?i)ID d[eu] clich|Shadow Copy ID|Snapshot ID")).Count
            # FR: "à la date de création : 20/10/2026 10:23:06" / EN: "creation time: ..."
            $shadowDates = @([regex]::Matches($vssText,
                '(?i)date (?:et heure )?de cr[ée]ation\s*:\s*(.+)|creation time\s*:\s*(.+)') |
                ForEach-Object {
                    $dateStr = ($_.Groups[1].Value + $_.Groups[2].Value).Trim()
                    if ($dateStr -ne "") { try { [datetime]::Parse($dateStr) } catch { $null } }
                } | Where-Object { $_ -ne $null } | Sort-Object -Descending)
        } catch { $detectErrors.Add("vssadmin: $($_.Exception.Message)") }
    }

    # --- Method 3: system restore points (only if no shadow copy found) ---
    $RestorePoints = @()
    if ($shadowBlockCount -eq 0) {
        try {
            $RestorePoints = @(Get-ComputerRestorePoint -ErrorAction Stop |
                Sort-Object -Property SequenceNumber -Descending)
        } catch { $detectErrors.Add("Get-ComputerRestorePoint: $($_.Exception.Message)") }
    }
    $errSuffix = if ($detectErrors.Count -gt 0) { " [Detection errors: $($detectErrors -join ' | ')]" } else { "" }

    if ($shadowBlockCount -gt 0) {
        if ($shadowDates.Count -gt 0) {
            $mostRecent = $shadowDates[0]
            $ageInDays  = [int]((Get-Date) - $mostRecent).TotalDays
            $lastStr    = Format-AuditDate $mostRecent
            if ($ageInDays -le 7) {
                Add-Result "Backup" "Shadow copies on $env:SystemDrive" "$shadowBlockCount snapshot(s) — last one $ageInDays day(s) ago" "OK" "VSS shadow copies present and recent — good ransomware resilience. Last snapshot: $lastStr. Local snapshots of $env:SystemDrive only: system image backups (wbadmin) are listed below and live on other disks."
            } elseif ($ageInDays -le 30) {
                Add-Result "Backup" "Shadow copies on $env:SystemDrive" "$shadowBlockCount snapshot(s) — last one $ageInDays day(s) ago" "WARN" "VSS shadow copies present but the most recent is $ageInDays days old. Last one: $lastStr — create a new one: Checkpoint-Computer -Description 'Manual' -RestorePointType MODIFY_SETTINGS"
            } else {
                Add-Result "Backup" "Shadow copies on $env:SystemDrive" "$shadowBlockCount snapshot(s) — last one $ageInDays day(s) ago" "WARN" "VSS shadow copies very old ($ageInDays days) — consider a new restore point: Checkpoint-Computer -Description 'Manual' -RestorePointType MODIFY_SETTINGS"
            }
        } else {
            Add-Result "Backup" "Shadow copies on $env:SystemDrive" "$shadowBlockCount snapshot(s) detected" "INFO" "$shadowBlockCount snapshot(s) detected but their date could not be read. Check: Get-CimInstance Win32_ShadowCopy | Select ID, InstallDate, VolumeName$errSuffix"
        }
    } elseif ($RestorePoints.Count -gt 0) {
        # No VSS snapshot visible but system restore points exist -> valid protection
        $rpDates = @($RestorePoints | ForEach-Object {
            try { [Management.ManagementDateTimeConverter]::ToDateTime($_.CreationTime) } catch { $null }
        } | Where-Object { $_ -ne $null } | Sort-Object -Descending)
        $rpNames = ($RestorePoints | Select-Object -First 3 | ForEach-Object {
            $dt = try { [Management.ManagementDateTimeConverter]::ToDateTime($_.CreationTime) } catch { $null }
            if ($dt) { "$($_.Description) ($(Format-AuditDate $dt -DateOnly))" } else { "$($_.Description)" }
        }) -join " | "
        if ($rpDates.Count -gt 0) {
            $rpAge = [int]((Get-Date) - $rpDates[0]).TotalDays
            if ($rpAge -le 30) {
                Add-Result "Backup" "Shadow copies on $env:SystemDrive" "0 VSS snapshot — $($RestorePoints.Count) restore point(s)" "OK" "No VSS snapshot returned for $env:SystemDrive but $($RestorePoints.Count) system restore point(s) present. Last one: $rpAge day(s) ago. Points: $rpNames$errSuffix"
            } else {
                Add-Result "Backup" "Shadow copies on $env:SystemDrive" "0 VSS snapshot — $($RestorePoints.Count) restore point(s) (last: $rpAge d)" "WARN" "Restore points present but old ($rpAge days). Points: $rpNames. Create a new one: Checkpoint-Computer -Description 'Manual' -RestorePointType MODIFY_SETTINGS$errSuffix"
            }
        } else {
            Add-Result "Backup" "Shadow copies on $env:SystemDrive" "0 VSS snapshot — $($RestorePoints.Count) restore point(s)" "INFO" "System restore point(s) present but their date could not be read. Points: $rpNames$errSuffix"
        }
    } elseif ($detectErrors.Count -ge 2) {
        # Every method errored out: we do not actually know -> WARN, not a false FAIL
        Add-Result "Backup" "Shadow copies on $env:SystemDrive" "Unable to read" "WARN" "No detection method could be executed, so the state of the shadow copies is unknown.$errSuffix"
    } else {
        # Genuinely no VSS protection — neither shadow copy nor restore point
        Add-Result "Backup" "Shadow copies on $env:SystemDrive" "0" "FAIL" "No shadow copy or restore point on $env:SystemDrive — in the event of ransomware, no VSS recovery is possible. Enable system protection on C: then: Checkpoint-Computer -Description 'Manual' -RestorePointType MODIFY_SETTINGS, or via Settings > System > About > System Protection$errSuffix"
    }
} catch {
    Add-Result "Backup" "Shadow copies" "Unable to read" "WARN" "Error while checking shadow copies: $($_.Exception.Message)"
}

# NOTE v5.4.2: VSS shadow storage (space reserved for snapshots), per volume.
# Win32_ShadowStorage via CIM — locale-independent, no vssadmin text parsing.
#  - Bounded limit >= 80% used: Windows deletes the OLDEST snapshots by itself to
#    make room, so the restore history on that volume is capped (seen on C:,
#    where the 4.75 GB limit keeps the count stuck around 5 snapshots).
#  - UNBOUNDED limit: snapshots can keep growing until the host disk is full
#    (seen on E:, stored on F:). Flagged WARN once they already use >= 20% of
#    the host disk, INFO below that.
try {
    $volMap = @{}
    foreach ($v in @(Get-CimInstance -ClassName Win32_Volume -ErrorAction Stop)) { $volMap[$v.DeviceID] = $v }
    $volName = {
        param($dev)
        $v = $volMap[$dev]
        if ($v -and $v.DriveLetter) { $v.DriveLetter }
        else { ($dev -replace '^\\\\\?\\Volume','').Trim('{','}','\') }
    }
    $storages = @(Get-CimInstance -ClassName Win32_ShadowStorage -ErrorAction Stop)
    if ($storages.Count -eq 0) {
        Add-Result "Backup" "VSS shadow storage" "No storage association" "INFO" "No volume has space reserved for shadow copies (System Protection is off everywhere)."
    } else {
        $stLines = New-Object System.Collections.Generic.List[string]
        $stFixes = New-Object System.Collections.Generic.List[string]
        $stWarn  = 0
        $stInfo  = 0
        $stFull  = 0
        # NOTE v5.5.0: a bounded limit always ends up full (VSS fills it, then recycles the
        # oldest snapshots), so a percentage alone says nothing about the protection. What
        # matters is how much history the volume keeps: a limit at 80% or more is a WARN only
        # when fewer than 3 snapshots are kept (or the count can't be read), otherwise INFO.
        $shadowAll = $null
        try { $shadowAll = @(Get-CimInstance -ClassName Win32_ShadowCopy -ErrorAction Stop) } catch { }
        foreach ($st in $storages) {
            $srcDev  = $st.Volume.DeviceID
            $hostDev = $st.DiffVolume.DeviceID
            $src     = & $volName $srcDev
            $hostN   = & $volName $hostDev
            $usedGB  = [math]::Round(([decimal]$st.UsedSpace) / 1GB, 1)
            $unbound = ([decimal]$st.MaxSpace -ge [decimal]9223372036854775807)
            $where   = if ($srcDev -ieq $hostDev) { "" } else { " (stored on $hostN)" }
            if ($unbound) {
                $hostCap = $volMap[$hostDev].Capacity
                $hostPct = if ($hostCap -gt 0) { [int][math]::Round(([decimal]$st.UsedSpace) / [decimal]$hostCap * 100) } else { -1 }
                $pctTxt  = if ($hostPct -ge 0) { ", $hostPct% of $hostN" } else { "" }
                if ($hostPct -ge 20) {
                    $stWarn++
                    $stLines.Add("${src}${where} — $usedGB GB used, NO LIMIT$pctTxt")
                    if ($src -match '^[A-Z]:$' -and $hostN -match '^[A-Z]:$') {
                        $stFixes.Add("vssadmin resize shadowstorage /for=$src /on=$hostN /maxsize=<size, e.g. 200GB>")
                    }
                } else {
                    $stInfo++
                    $stLines.Add("${src}${where} — $usedGB GB used, no limit set$pctTxt")
                }
            } else {
                $maxGB  = [math]::Round(([decimal]$st.MaxSpace) / 1GB, 1)
                $pctMax = if ($st.MaxSpace -gt 0) { [int][math]::Round(([decimal]$st.UsedSpace) / [decimal]$st.MaxSpace * 100) } else { 0 }
                $snapCount = if ($null -ne $shadowAll) { @($shadowAll | Where-Object { $_.VolumeName -ieq $srcDev }).Count } else { -1 }
                if ($pctMax -ge 80 -and $snapCount -ge 3) {
                    $stFull++
                    $stLines.Add("${src}${where} — $usedGB / $maxGB GB ($pctMax% of the limit), $snapCount snapshots kept — normal: the oldest are deleted automatically once the limit is reached")
                } elseif ($pctMax -ge 80) {
                    $stWarn++
                    $snapTxt = if ($snapCount -ge 0) { ", only $snapCount snapshot(s) kept" } else { ", snapshot count unreadable" }
                    $stLines.Add("${src}${where} — $usedGB / $maxGB GB ($pctMax% of the limit)$snapTxt — oldest snapshots are deleted automatically")
                    if ($src -match '^[A-Z]:$' -and $hostN -match '^[A-Z]:$') {
                        $stFixes.Add("vssadmin resize shadowstorage /for=$src /on=$hostN /maxsize=<larger size>")
                    }
                } else {
                    $stLines.Add("${src}${where} — $usedGB / $maxGB GB ($pctMax% of the limit)")
                }
            }
        }
        $stDetail = $stLines -join " | "
        if ($stFixes.Count -gt 0) { $stDetail += ". To adjust: " + ($stFixes -join " ; ") }
        if ($stWarn -gt 0) {
            Add-Result "Backup" "VSS shadow storage" "$stWarn volume(s) to review" "WARN" $stDetail
        } elseif (($stInfo + $stFull) -gt 0) {
            $stInfoTxt = @()
            if ($stInfo -gt 0) { $stInfoTxt += "$stInfo without a limit" }
            if ($stFull -gt 0) { $stInfoTxt += "$stFull at their limit with several snapshots kept" }
            Add-Result "Backup" "VSS shadow storage" "$($storages.Count) volume(s) — $($stInfoTxt -join ', ')" "INFO" $stDetail
        } else {
            Add-Result "Backup" "VSS shadow storage" "$($storages.Count) volume(s) — within limits" "OK" $stDetail
        }
    }
} catch {
    Add-Result "Backup" "VSS shadow storage" "Unable to read" "WARN" "Error while reading VSS shadow storage: $($_.Exception.Message)"
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
    # analyzing the actual output on a real machine). Date format: dd/MM/yyyy HH:mm,
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

    # Extract the target volume (e.g. "Disque dur étiqueté BackupDisk(E:)")
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
#  23. LEGACY NAME RESOLUTION & IPv6 TRANSITION TUNNELS
# ──────────────────────────────────────────────
if (ShouldRunSection "23_NameResolution") {
Write-Log "=== 23. LEGACY NAME RESOLUTION & IPv6 TUNNELS ===" -Level SECTION

# NOTE v5.5.0: LLMNR, mDNS and the NetBIOS name service are the fallback
# protocols Windows uses when DNS can't resolve a name: they shout the question
# on the local network, with NO authentication. Any device on the same network
# (shared Wi-Fi, a guest, a compromised smart gadget) can answer "it's me" and
# make Windows send the user's NTLM hash (Responder-type attacks). LLMNR and
# NetBIOS are enabled by default on virtually every Windows machine, so they
# are WARN rather than FAIL: the real exposure depends on the networks the
# machine joins. mDNS carries less risk and stays INFO.

# LLMNR — policy value, absent = Windows default (enabled)
try {
    $LlmnrValue = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name EnableMulticast -ErrorAction SilentlyContinue).EnableMulticast
    if ($LlmnrValue -eq 0) {
        Add-Result "Network" "LLMNR (multicast name resolution)" "Disabled" "OK" "LLMNR is turned off by policy (EnableMulticast = 0)"
    } else {
        Add-Result "Network" "LLMNR (multicast name resolution)" "Enabled" "WARN" ("When DNS fails, Windows asks every device on the local network to resolve the name, and trusts any answer. On a shared or untrusted network an attacker can answer and capture the user's NTLM hash. Turning it off doesn't affect DNS." + (Get-ToolboxHint "NameResolutionFix"))
    }
} catch {
    Add-Result "Network" "LLMNR (multicast name resolution)" "Unable to read" "INFO" "Error: $($_.Exception.Message)"
}

# mDNS — EnableMDNS = 0 turns it off, absent = Windows default (enabled)
try {
    $MdnsValue = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" -Name EnableMDNS -ErrorAction SilentlyContinue).EnableMDNS
    if ($MdnsValue -eq 0) {
        Add-Result "Network" "mDNS (multicast DNS)" "Disabled" "OK" "mDNS is turned off (EnableMDNS = 0)"
    } else {
        Add-Result "Network" "mDNS (multicast DNS)" "Enabled" "INFO" ("Same unauthenticated local-network lookup as LLMNR, used by printers and casting devices. Lower risk, but it can be turned off if you don't rely on it." + (Get-ToolboxHint "NameResolutionFix"))
    }
} catch {
    Add-Result "Network" "mDNS (multicast DNS)" "Unable to read" "INFO" "Error: $($_.Exception.Message)"
}

# NetBIOS over TCP/IP — per active IP adapter (TcpipNetbiosOptions: 0 = follow
# DHCP, usually enabled; 1 = enabled; 2 = disabled)
try {
    $NbAdapters = @(Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -Filter "IPEnabled = TRUE" -ErrorAction Stop)
    $NbActive   = @($NbAdapters | Where-Object { $_.TcpipNetbiosOptions -ne 2 })
    if ($NbAdapters.Count -eq 0) {
        Add-Result "Network" "NetBIOS over TCP/IP" "No active IP adapter" "INFO"
    } elseif ($NbActive.Count -eq 0) {
        Add-Result "Network" "NetBIOS over TCP/IP" "Disabled on all active adapters ($($NbAdapters.Count))" "OK" "NetBIOS name service is turned off on every active adapter"
    } else {
        $NbNames = ($NbActive | Select-Object -First 3 -ExpandProperty Description) -join ", "
        Add-Result "Network" "NetBIOS over TCP/IP" "Enabled or default on $($NbActive.Count) of $($NbAdapters.Count) adapter(s)" "WARN" ("The legacy NetBIOS name service (NBT-NS) answers unauthenticated local-network lookups, like LLMNR. Adapters: $NbNames." + (Get-ToolboxHint "NameResolutionFix"))
    }
} catch {
    Add-Result "Network" "NetBIOS over TCP/IP" "Unable to read" "INFO" "Error: $($_.Exception.Message)"
}

# IPv6 transition tunnels — NetworkTransition cmdlets (typed values, language
# independent), NOT netsh text output, which is localized (see v5.4.2).
# These tunnels carry IPv6 inside IPv4. With native IPv6 (or none needed) they
# only add attack surface: tunneled traffic can bypass a firewall or DNS
# filter, and Teredo lets inbound connections cross the router's NAT.
try {
    $TeredoCfg   = Get-NetTeredoConfiguration -ErrorAction Stop
    $TeredoState = $null
    try { $TeredoState = (Get-NetTeredoState -ErrorAction Stop).State } catch { }
    # NOTE v5.5.0: Get-NetTeredoConfiguration returns the CONFIGURED type, which stays
    # "Default" when Teredo was turned off with netsh (netsh interface teredo set state
    # disabled): the effective type "disabled" is then only reported by netsh. Only the
    # VALUE token of the netsh output is read (default / disabled / client / ...), never
    # its labels, which are localized (see v5.4.2). If it can't be read, nothing changes.
    $TeredoNetsh = $null
    try {
        foreach ($ln in @(& netsh.exe interface teredo show state 2>$null)) {
            if ("$ln" -match '^\s*[^:]+:\s*(default|disabled|client|enterpriseclient|natawareclient)\s*$') { $TeredoNetsh = $Matches[1]; break }
        }
    } catch { }
    if ("$($TeredoCfg.Type)" -eq "Disabled" -or "$TeredoNetsh" -eq "disabled") {
        $TeredoOffNote = "Teredo (IPv6 over UDP/IPv4 through the router's NAT) is turned off"
        if ("$($TeredoCfg.Type)" -ne "Disabled") {
            $TeredoOffNote += ": netsh reports the effective type 'disabled' (the configured type read by Get-NetTeredoConfiguration is still '$($TeredoCfg.Type)')"
        }
        Add-Result "Network" "Teredo tunnel" "Disabled" "OK" $TeredoOffNote
    } elseif ("$TeredoState" -eq "Qualified") {
        Add-Result "Network" "Teredo tunnel" "Active ($TeredoState)" "WARN" ("Teredo is active: it lets inbound connections cross the router's NAT and can bypass a firewall or DNS filter that only watches the normal path." + (Get-ToolboxHint "IPv6TunnelsFix"))
    } else {
        # Get-NetTeredoState can return no State at all when Windows keeps Teredo
        # inactive: don't print an empty "( / )", say what is known instead.
        $TeredoDesc = if ([string]::IsNullOrEmpty("$TeredoState")) { "$($TeredoCfg.Type), no active tunnel" } else { "$($TeredoCfg.Type) / $TeredoState" }
        Add-Result "Network" "Teredo tunnel" "Allowed, not active ($TeredoDesc)" "INFO" ("Teredo isn't currently in use but isn't disabled either. Useless with native IPv6." + (Get-ToolboxHint "IPv6TunnelsFix"))
    }
} catch {
    Add-Result "Network" "Teredo tunnel" "Unable to read" "INFO" "Error: $($_.Exception.Message)"
}

try {
    $Tunnel6to4 = "$((Get-Net6to4Configuration -ErrorAction Stop).State)"
    if ($Tunnel6to4 -eq "Disabled") {
        Add-Result "Network" "6to4 tunnel" "Disabled" "OK" "6to4 is turned off"
    } elseif ($Tunnel6to4 -eq "Enabled") {
        Add-Result "Network" "6to4 tunnel" "Enabled" "WARN" ("6to4 is explicitly enabled. It only works with a PUBLIC IPv4 address directly on the adapter and is an abandoned technique." + (Get-ToolboxHint "IPv6TunnelsFix"))
    } else {
        Add-Result "Network" "6to4 tunnel" "Default (Windows decides)" "INFO" ("6to4 only activates with a public IPv4 address directly on the adapter, which isn't the case behind a typical home router." + (Get-ToolboxHint "IPv6TunnelsFix"))
    }
} catch {
    Add-Result "Network" "6to4 tunnel" "Unable to read" "INFO" "Error: $($_.Exception.Message)"
}

try {
    $TunnelIsatap = "$((Get-NetIsatapConfiguration -ErrorAction Stop).State)"
    if ($TunnelIsatap -eq "Disabled") {
        Add-Result "Network" "ISATAP tunnel" "Disabled" "OK" "ISATAP is turned off"
    } elseif ($TunnelIsatap -eq "Enabled") {
        Add-Result "Network" "ISATAP tunnel" "Enabled" "WARN" ("ISATAP is explicitly enabled. It is meant for internal corporate IPv4 networks; a spoofed 'isatap' name can redirect traffic." + (Get-ToolboxHint "IPv6TunnelsFix"))
    } else {
        Add-Result "Network" "ISATAP tunnel" "Default (Windows decides)" "INFO" ("ISATAP only activates if the name 'isatap' resolves on the network (corporate networks), not on a home network." + (Get-ToolboxHint "IPv6TunnelsFix"))
    }
} catch {
    Add-Result "Network" "ISATAP tunnel" "Unable to read" "INFO" "Error: $($_.Exception.Message)"
}

# NOTE v5.7.0: UDP endpoints bound to a non-loopback address (Get-NetUDPEndpoint), the counterpart of
# the TCP listening-ports line of section 8. It sits here because the coherence rule needs the three
# settings read just above (LLMNR, mDNS, NetBIOS): a Windows process bound to UDP 5355 / 5353 / 137-138
# while the matching protocol is turned off is a real inconsistency. Endpoints are de-duplicated by
# (process, port): the IPv4 and IPv6 sockets of one service count once. A UDP port bound to an address
# is not necessarily reachable (the firewall can still drop the packets): see Get-UdpEndpointAssessment.
try {
    $UdpAll = @(Get-NetUDPEndpoint -ErrorAction Stop | Where-Object {
        $_.LocalAddress -ne "127.0.0.1" -and $_.LocalAddress -ne "::1" -and $_.LocalAddress -notmatch '^fe80:' })
    if ($UdpAll.Count -eq 0) {
        Add-Result "Network" "Listening UDP endpoints (non-loopback)" "0" "OK" "No UDP endpoint is bound to a non-loopback address"
    } else {
        $UdpProcName = @{}
        foreach ($up in @(Get-Process -ErrorAction SilentlyContinue)) { $UdpProcName[[int]$up.Id] = $up.Name }
        $UdpPath = @{}
        $UdpSvc  = @{}
        try {
            foreach ($up in @(Get-CimInstance -ClassName Win32_Process -ErrorAction Stop)) {
                if ($up.ExecutablePath) { $UdpPath[[int]$up.ProcessId] = $up.ExecutablePath }
            }
            foreach ($us in @(Get-CimInstance -ClassName Win32_Service -ErrorAction Stop)) {
                if ($us.ProcessId -and [int]$us.ProcessId -gt 0) {
                    $usKey = [int]$us.ProcessId
                    if ($UdpSvc.ContainsKey($usKey)) { $UdpSvc[$usKey] += $us.Name } else { $UdpSvc[$usKey] = @($us.Name) }
                }
            }
        } catch { }
        # "Protocol turned off" flags, from the variables of the three checks above (unknown = not off).
        $UdpDisabled = @{
            LLMNR   = ($LlmnrValue -eq 0)
            mDNS    = ($MdnsValue -eq 0)
            NetBIOS = ((@($NbAdapters | Where-Object { $_ }).Count -gt 0) -and (@($NbActive | Where-Object { $_ }).Count -eq 0))
        }
        $UdpEp = @{}
        foreach ($u in $UdpAll) {
            $uPid  = [int]$u.OwningProcess
            $uKey  = "$uPid|$($u.LocalPort)"
            $uIsAll = ($u.LocalAddress -eq "0.0.0.0" -or $u.LocalAddress -eq "::")
            if ($UdpEp.ContainsKey($uKey)) { if ($uIsAll) { $UdpEp[$uKey].All = $true } }
            else { $UdpEp[$uKey] = [PSCustomObject]@{ ProcId = $uPid; Port = [int]$u.LocalPort; All = $uIsAll } }
        }
        $UdpSigCache = @{}
        $UdpWarn   = [System.Collections.Generic.List[string]]::new()
        $UdpGroups = [ordered]@{}
        foreach ($e in ($UdpEp.Values | Sort-Object Port, ProcId)) {
            $pName  = if ($UdpProcName.ContainsKey($e.ProcId)) { $UdpProcName[$e.ProcId] } else { "PID $($e.ProcId)" }
            $pPath  = if ($UdpPath.ContainsKey($e.ProcId)) { $UdpPath[$e.ProcId] } else { $null }
            $pTrust = Get-ProcessTrustClass $pPath $UdpSigCache -Name $pName
            $pLabel = $pName
            if ($UdpSvc.ContainsKey($e.ProcId)) { $pLabel += " [" + (($UdpSvc[$e.ProcId] | Sort-Object) -join ",") + "]" }
            if ($pTrust -eq "Unverified") { $pLabel += " (unverified)" }
            $pAssess = Get-UdpEndpointAssessment -Port $e.Port -TrustClass $pTrust -AllInterfaces $e.All -Disabled $UdpDisabled
            if ($pAssess.Status -eq "WARN") { $UdpWarn.Add("UDP $($e.Port) ($pLabel): $($pAssess.Reason)") }
            if (-not $UdpGroups.Contains($pLabel)) { $UdpGroups[$pLabel] = [System.Collections.Generic.List[int]]::new() }
            $UdpGroups[$pLabel].Add($e.Port)
        }
        $UdpListTxt = (($UdpGroups.Keys | ForEach-Object { "$_ -> " + (($UdpGroups[$_] | Sort-Object) -join ", ") }) -join "; ")
        $UdpDetail  = "A UDP port bound to an address is not necessarily reachable from the network (the Windows Firewall may still drop the packets). Listening: $UdpListTxt."
        if ($UdpWarn.Count -gt 0) { $UdpDetail = "To review: " + ($UdpWarn -join " | ") + ". " + $UdpDetail }
        Add-Result "Network" "Listening UDP endpoints (non-loopback)" "$($UdpEp.Count) endpoint(s)" $(if ($UdpWarn.Count -gt 0) { "WARN" } else { "INFO" }) $UdpDetail
    }
} catch {
    Add-Result "Network" "Listening UDP endpoints (non-loopback)" "Unable to read" "INFO" "Error enumerating UDP endpoints: $($_.Exception.Message)"
}

}

# ──────────────────────────────────────────────
#  24. DEFENDER PROTECTIONS (TAMPER, PUA, NETWORK, CLOUD)
# ──────────────────────────────────────────────
if (ShouldRunSection "24_DefenderProtections") {
Write-Log "=== 24. DEFENDER PROTECTIONS ===" -Level SECTION

# NOTE v5.5.0: section 16 audits what Defender is told NOT to scan; this one
# audits the protections around it. Tamper Protection is the important one:
# without it, malware or a script running as administrator can switch Defender
# off. It can't be changed by script - only from the Windows Security app - so
# its hint points to the read-only Toolbox command instead of a "fix" command.
try {
    $MpStatus = Get-MpComputerStatus -ErrorAction Stop
    $MpPrefs  = Get-MpPreference -ErrorAction Stop
    $MpMode   = "$($MpStatus.AMRunningMode)"
    $DefenderActive = ($MpMode -eq "") -or ($MpMode -eq "Normal")

    if (-not $DefenderActive) {
        Add-Result "Defender" "Defender protections" "Not evaluated ($MpMode mode)" "INFO" "Defender isn't the active antivirus (passive / EDR block mode): Tamper Protection, PUA, Network Protection and cloud protection are managed by the active security product"
    } else {
        # NOTE v5.5.1: every row below keeps its label (so the comparison with a previous
        # audit still matches it) but now shows the plain-language name AND the raw value
        # exactly as Get-MpPreference prints it, e.g. "Advanced (2)". The explanation of the
        # current value comes from the $script:DefenderRef table; the full list of values,
        # the commands and the Microsoft links are in the expandable card of the HTML report.

        # Tamper Protection
        if ($null -eq $MpStatus.IsTamperProtected) {
            Add-Result "Defender" "Tamper Protection" "Unable to determine" "INFO" "IsTamperProtected isn't exposed by this Defender platform version"
        } elseif ($MpStatus.IsTamperProtected) {
            Add-DefenderSettingResult -Check "Tamper Protection" -Key "IsTamperProtected" -Current "True" -Status "OK" -Value "Enabled"
        } else {
            Add-DefenderSettingResult -Check "Tamper Protection" -Key "IsTamperProtected" -Current "False" -Status "FAIL" -Value "Disabled" -Hint
        }

        # PUA protection: 0 = off, 1 = block, 2 = audit
        $puaV = [int]$MpPrefs.PUAProtection
        Add-DefenderSettingResult -Check "PUA protection" -Key "PUAProtection" -Current $puaV -Hint `
            -Status $(if ($puaV -eq 1) { "OK" } else { "INFO" })

        # Network Protection: 0 = off, 1 = block, 2 = audit
        $netV = [int]$MpPrefs.EnableNetworkProtection
        Add-DefenderSettingResult -Check "Network Protection" -Key "EnableNetworkProtection" -Current $netV -Hint `
            -Status $(if ($netV -eq 1) { "OK" } else { "INFO" })

        # Cloud-delivered protection (MAPS): 0 = off, 1 = basic, 2 = advanced
        $mapsV = [int]$MpPrefs.MAPSReporting
        Add-DefenderSettingResult -Check "Cloud protection (MAPS)" -Key "MAPSReporting" -Current $mapsV -Hint `
            -Status $(if ($mapsV -eq 0) { "INFO" } else { "OK" })

        # The four settings below belong to the cloud protection: they do nothing while
        # MAPS is Disabled, which the Detail says. A property that this Defender platform
        # version doesn't expose is reported as such instead of being read as 0 / False.
        $cloudOff = if ($mapsV -eq 0) { "These cloud settings have no effect while cloud protection (MAPS) is Disabled." } else { "" }

        # Automatic sample submission: 0 = always prompt, 1 = safe samples, 2 = never, 3 = all.
        # 1 and 3 are OK; 0 and 2 are legitimate choices (privacy) reported as INFO, with the
        # consequence for block at first sight spelled out in the Detail.
        if ($null -eq $MpPrefs.SubmitSamplesConsent) {
            Add-Result "Defender" "Cloud sample submission" "Unable to determine" "INFO" "SubmitSamplesConsent isn't exposed by this Defender platform version"
        } else {
            $ssV = [int]$MpPrefs.SubmitSamplesConsent
            Add-DefenderSettingResult -Check "Cloud sample submission" -Key "SubmitSamplesConsent" -Current $ssV -Extra $cloudOff -Hint `
                -Status $(if ($ssV -in 1,3) { "OK" } else { "INFO" })
        }

        # Block at first sight: DisableBlockAtFirstSeen = False means the feature is ON.
        if ($null -eq $MpPrefs.DisableBlockAtFirstSeen) {
            Add-Result "Defender" "Block at first sight" "Unable to determine" "INFO" "DisableBlockAtFirstSeen isn't exposed by this Defender platform version"
        } else {
            $bafsV = [bool]$MpPrefs.DisableBlockAtFirstSeen
            Add-DefenderSettingResult -Check "Block at first sight" -Key "DisableBlockAtFirstSeen" -Current $bafsV -Extra $cloudOff -Hint `
                -Status $(if ($bafsV) { "INFO" } else { "OK" })
        }

        # Cloud block level: 0 default, 1 moderate, 2 high, 4 high+, 6 zero tolerance.
        # Default / High / High+ are OK; Moderate (less strict than the default) and Zero
        # tolerance (blocks every unknown executable) are choices worth a mention: INFO.
        if ($null -eq $MpPrefs.CloudBlockLevel) {
            Add-Result "Defender" "Cloud block level" "Unable to determine" "INFO" "CloudBlockLevel isn't exposed by this Defender platform version"
        } else {
            $cblV = [int]$MpPrefs.CloudBlockLevel
            Add-DefenderSettingResult -Check "Cloud block level" -Key "CloudBlockLevel" -Current $cblV -Extra $cloudOff `
                -Status $(if ($cblV -in 0,2,4) { "OK" } else { "INFO" })
        }

        # Cloud extended timeout: 0 to 50 seconds ADDED to the default 10 s (Microsoft Learn).
        # Information only: a longer wait is a trade-off, not a weakness.
        if ($null -eq $MpPrefs.CloudExtendedTimeout) {
            Add-Result "Defender" "Cloud extended timeout" "Unable to determine" "INFO" "CloudExtendedTimeout isn't exposed by this Defender platform version"
        } else {
            $cetV = [int]$MpPrefs.CloudExtendedTimeout
            Add-DefenderSettingResult -Check "Cloud extended timeout" -Key "CloudExtendedTimeout" -Current $cetV -Status "INFO" `
                -Value "+$cetV s (about $(10 + $cetV) s maximum wait)" `
                -Extra ("Currently up to about $(10 + $cetV) s in total (10 s default + $cetV s). $cloudOff")
        }

        # Controlled Folder Access (ransomware protection): 0 off, 1 on, 2 audit, 3 block disk
        # modification only, 4 audit disk modification only. v5.6.1: now one of the settings above
        # (same card in the HTML report), placed before the help line that closes the section.
        # It is OFF by default in Windows, so a disabled state is a hardening recommendation (WARN).
        if ($null -eq $MpPrefs.EnableControlledFolderAccess) {
            Add-Result "Defender" "Controlled Folder Access (ransomware protection)" "Unable to determine" "INFO" "EnableControlledFolderAccess isn't exposed by this Defender platform version"
        } else {
            $cfaV = [int]$MpPrefs.EnableControlledFolderAccess
            Add-DefenderSettingResult -Check "Controlled Folder Access (ransomware protection)" -Key "EnableControlledFolderAccess" -Current $cfaV `
                -Status $(if ($cfaV -eq 1) { "OK" } elseif ($cfaV -eq 0) { "WARN" } else { "INFO" })
        }

        # Console stays compact (one line per check): the explanations live in the HTML report.
        # v5.6.1: "»" instead of "↳" (missing from many console fonts, it showed as a box).
        if (-not $Silent) {
            Write-Host "                 » Where to change each Defender setting (Windows Security first), other possible values, PowerShell commands and Microsoft links: expand the row in the HTML report." -ForegroundColor DarkGray
        }
    }
} catch {
    Add-Result "Defender" "Defender protections" "Unable to read" "INFO" "Error: $($_.Exception.Message)"
}

}

# ──────────────────────────────────────────────
#  25. POWERSHELL 2.0 (DOWNGRADE ROUTE)
# ──────────────────────────────────────────────
if (ShouldRunSection "25_PowerShell2") {
Write-Log "=== 25. POWERSHELL 2.0 ===" -Level SECTION

# NOTE v5.5.0: the PowerShell 2.0 engine predates AMSI (antimalware scanning of
# scripts) and script logging; an attacker who can start "powershell -Version 2"
# bypasses both. Microsoft removed it from Windows 11 24H2 onwards (August 2025
# update), so "absent" is a normal, GOOD result on a recent build. The feature
# list is read once per run by Get-WinFeatures (shared with section 26).
$FeatList = Get-WinFeatures
if (-not $script:WinFeaturesOK) {
    Add-Result "PowerShell" "PowerShell 2.0 (downgrade route)" "Unable to read" "INFO" "Get-WindowsOptionalFeature failed — the optional-features list couldn't be read"
} else {
    $PS2All = @($FeatList | Where-Object { $_.FeatureName -like "MicrosoftWindowsPowerShellV2*" })
    $PS2On  = @($PS2All | Where-Object { $_.State -eq "Enabled" })
    if ($PS2On.Count -gt 0) {
        Add-Result "PowerShell" "PowerShell 2.0 (downgrade route)" "Enabled ($(($PS2On | ForEach-Object { $_.FeatureName }) -join ', '))" "WARN" ("The legacy engine can be launched with 'powershell -Version 2', which bypasses AMSI and script logging. Almost nothing legitimate needs it today." + (Get-ToolboxHint "PowerShell2Fix"))
    } elseif ($PS2All.Count -eq 0) {
        Add-Result "PowerShell" "PowerShell 2.0 (downgrade route)" "Removed from this Windows build" "OK" "The feature no longer exists (removed by Microsoft starting with Windows 11 24H2)"
    } else {
        Add-Result "PowerShell" "PowerShell 2.0 (downgrade route)" "Disabled" "OK" "The PowerShell 2.0 features are installed but turned off"
    }
}

}

# ──────────────────────────────────────────────
#  26. REMOTE-ACCESS SERVICES
# ──────────────────────────────────────────────
if (ShouldRunSection "26_RemoteServices") {
Write-Log "=== 26. REMOTE-ACCESS SERVICES ===" -Level SECTION

# NOTE v5.5.0: WinRM is already covered elsewhere (section 8). This section
# adds the services and features that open remote-access doors on a PC that
# doesn't need them. Severity follows exposure: Remote Registry running = FAIL
# (it is Disabled by default on Windows clients, so running means someone
# turned it on); WebClient / RemoteAccess running = WARN; the rest = INFO.
foreach ($Def in @(
    @{ Name = "RemoteRegistry"; Label = "Remote Registry service"; Level = "FAIL"; Why = "Remote Registry lets other machines read and modify this PC's registry. It is Disabled by default on Windows clients, so a running service means it was turned on." },
    @{ Name = "WebClient";      Label = "WebClient (WebDAV) service"; Level = "WARN"; Why = "WebClient enables WebDAV access and is abused in NTLM relay and credential-coercion attacks. It is only needed to map WebDAV drives or for some SharePoint setups." }
)) {
    try {
        $Svc = Get-Service -Name $Def.Name -ErrorAction SilentlyContinue
        if (-not $Svc) {
            Add-Result "Services" $Def.Label "Not installed" "OK" "The $($Def.Name) service isn't present"
        } elseif ($Svc.Status -eq "Running") {
            Add-Result "Services" $Def.Label "Running" $Def.Level ($Def.Why + (Get-ToolboxHint "RemoteServicesFix"))
        } else {
            Add-Result "Services" $Def.Label "$($Svc.Status) / $($Svc.StartType)" "OK" "The $($Def.Name) service isn't running"
        }
    } catch {
        Add-Result "Services" $Def.Label "Unable to read" "INFO" "Error: $($_.Exception.Message)"
    }
}

# sshd / SSDP / UPnP / RemoteAccess — running only matters if not intentional
try {
    $OtherRunning = @()
    foreach ($SvcName in "sshd", "SSDPSRV", "upnphost", "RemoteAccess") {
        $S = Get-Service -Name $SvcName -ErrorAction SilentlyContinue
        if ($S -and $S.Status -eq "Running") { $OtherRunning += $SvcName }
    }
    if ($OtherRunning -contains "RemoteAccess") {
        Add-Result "Services" "Other remote-access services" "Running: $($OtherRunning -join ', ')" "WARN" ("Routing and Remote Access (VPN server / router role) is running; it should be Disabled on a client PC. sshd and SSDP/UPnP are fine if you use them on purpose." + (Get-ToolboxHint "RemoteServicesState" -Mode Check))
    } elseif ($OtherRunning.Count -gt 0) {
        Add-Result "Services" "Other remote-access services" "Running: $($OtherRunning -join ', ')" "INFO" ("sshd (OpenSSH server) and SSDP/UPnP (device discovery) are legitimate when used on purpose; they widen what other devices on the network can see and reach." + (Get-ToolboxHint "RemoteServicesState" -Mode Check))
    } else {
        Add-Result "Services" "Other remote-access services" "None running" "OK" "sshd, SSDP, UPnP and Routing and Remote Access aren't running"
    }
} catch {
    Add-Result "Services" "Other remote-access services" "Unable to read" "INFO" "Error: $($_.Exception.Message)"
}

# Telnet client / TFTP — clear-text protocols, unusual to find enabled
$FeatList = Get-WinFeatures
if (-not $script:WinFeaturesOK) {
    Add-Result "Services" "Legacy clear-text features (Telnet client / TFTP)" "Unable to read" "INFO" "Get-WindowsOptionalFeature failed — the optional-features list couldn't be read"
} else {
    $LegacyOn = @($FeatList | Where-Object { $_.FeatureName -in @("TelnetClient", "TFTP") -and $_.State -eq "Enabled" } | ForEach-Object { $_.FeatureName })
    if ($LegacyOn.Count -gt 0) {
        Add-Result "Services" "Legacy clear-text features (Telnet client / TFTP)" "Enabled: $($LegacyOn -join ', ')" "WARN" ("Telnet and TFTP send everything, including credentials, in clear text. Disable them in Windows Features if you don't use them." + (Get-ToolboxHint "RemoteServicesState" -Mode Check))
    } else {
        Add-Result "Services" "Legacy clear-text features (Telnet client / TFTP)" "Not enabled" "OK" "Neither the Telnet client nor TFTP is enabled"
    }
}

# Remote Assistance — ENABLED by default on Windows; every session still needs
# an invitation, so this is INFO, never a warning
try {
    $RaValue = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name fAllowToGetHelp -ErrorAction SilentlyContinue).fAllowToGetHelp
    if ($RaValue -eq 1) {
        Add-Result "Services" "Remote Assistance" "Allowed" "INFO" "Remote Assistance invitations are allowed (the Windows default); a session still requires an invitation you send"
    } else {
        Add-Result "Services" "Remote Assistance" "Not allowed" "OK" "Remote Assistance connections are turned off"
    }
} catch {
    Add-Result "Services" "Remote Assistance" "Unable to read" "INFO" "Error: $($_.Exception.Message)"
}

}

# ──────────────────────────────────────────────
#  27. STORED CREDENTIALS & AUTOMATIC LOGON
# ──────────────────────────────────────────────
if (ShouldRunSection "27_Credentials") {
Write-Log "=== 27. STORED CREDENTIALS & AUTOLOGON ===" -Level SECTION

# NOTE v5.5.0: automatic logon configured the classic way stores the account
# password in CLEAR TEXT in the registry (Winlogon\DefaultPassword), where
# other software on the PC can read it. This check only tests whether the value
# EXISTS and is non-empty: the password itself is never read into the report.
# Tools such as Sysinternals Autologon keep it as an LSA secret instead, which
# can't be detected from here: AutoAdminLogon = 1 alone is therefore a WARN.
# Credential Manager (cmdkey /list) is deliberately not audited: its output is
# localized text, the trap that caused the v5.4.2 vssadmin false positive.
try {
    $Winlogon  = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -ErrorAction Stop
    $AutoOn    = ($Winlogon.AutoAdminLogon -eq "1")
    $PlainPw   = -not [string]::IsNullOrEmpty($Winlogon.DefaultPassword)
    $AutoUser  = $Winlogon.DefaultUserName
    if ($PlainPw) {
        Add-Result "Accounts" "Automatic logon (Winlogon)" "Plaintext password stored in the registry" "FAIL" ("A DefaultPassword value is stored in clear text under Winlogon (account: $AutoUser) — readable by other software on the PC. The value itself isn't shown here." + (Get-ToolboxHint "AutologonFix"))
    } elseif ($AutoOn) {
        Add-Result "Accounts" "Automatic logon (Winlogon)" "Enabled (account: $AutoUser)" "WARN" ("Windows signs in by itself at startup, so anyone with physical access gets a signed-in session. The password isn't in clear text under Winlogon (probably an LSA secret, e.g. Sysinternals Autologon)." + (Get-ToolboxHint "AutologonFix"))
    } else {
        Add-Result "Accounts" "Automatic logon (Winlogon)" "Disabled" "OK" "Windows asks for the password or PIN at startup, and no plaintext password is stored under Winlogon"
    }
} catch {
    Add-Result "Accounts" "Automatic logon (Winlogon)" "Unable to read" "INFO" "Error: $($_.Exception.Message)"
}

# NOTE v5.6.0: credential-exposure settings (read-only). WDigest UseLogonCredential=1 keeps the
# password in clear text in lsass memory; NoLMHash=0 stores the weak LM hash; EveryoneIncludesAnonymous=1
# gives anonymous users the rights of Everyone; RestrictAnonymousSAM=0 allows anonymous enumeration of
# local accounts. Windows defaults are safe, so a missing value is OK.
try {
    $WdVal = $null
    try { $WdVal = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name "UseLogonCredential" -ErrorAction Stop).UseLogonCredential } catch { }
    Add-Result "Accounts" "WDigest (clear-text password in memory)" $(if ($WdVal -eq 1) { "ENABLED (UseLogonCredential=1)" } elseif ($null -eq $WdVal) { "Not enabled (Windows default)" } else { "Disabled" }) $(if ($WdVal -eq 1) { "FAIL" } else { "OK" }) $(
        if ($WdVal -eq 1) { "WDigest keeps the signed-in user's password in CLEAR TEXT in lsass memory, where credential-dumping tools read it. It is off by default on supported Windows versions: set UseLogonCredential to 0 unless a legacy application requires it." }
    )
    $LsaP = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -ErrorAction Stop
    $NoLm = $LsaP.NoLMHash
    Add-Result "Accounts" "LM password hash storage (NoLMHash)" $(if ($null -ne $NoLm -and [int]$NoLm -eq 0) { "LM hashes ARE stored" } else { "Not stored (default)" }) $(if ($null -ne $NoLm -and [int]$NoLm -eq 0) { "FAIL" } else { "OK" }) $(
        if ($null -ne $NoLm -and [int]$NoLm -eq 0) { "The obsolete LM hash of each password is stored, and can be cracked in seconds. Set NoLMHash to 1." }
    )
    $EvAnon = $LsaP.EveryoneIncludesAnonymous
    Add-Result "Accounts" "Everyone includes Anonymous" $(if ($null -ne $EvAnon -and [int]$EvAnon -eq 1) { "YES" } else { "No (default)" }) $(if ($null -ne $EvAnon -and [int]$EvAnon -eq 1) { "FAIL" } else { "OK" }) $(
        if ($null -ne $EvAnon -and [int]$EvAnon -eq 1) { "Anonymous (unauthenticated) users receive the permissions granted to Everyone. Set EveryoneIncludesAnonymous to 0." }
    )
    $RaSam = $LsaP.RestrictAnonymousSAM
    Add-Result "Accounts" "Anonymous enumeration of local accounts (RestrictAnonymousSAM)" $(if ($null -ne $RaSam -and [int]$RaSam -eq 0) { "Allowed" } else { "Restricted (default)" }) $(if ($null -ne $RaSam -and [int]$RaSam -eq 0) { "WARN" } else { "OK" }) $(
        if ($null -ne $RaSam -and [int]$RaSam -eq 0) { "Anonymous users may list the local accounts. Set RestrictAnonymousSAM to 1 (the Windows default)." }
    )
} catch {
    Add-Result "Accounts" "Credential exposure settings" "Unable to read" "INFO" "Error: $($_.Exception.Message)"
}

# NOTE v5.6.0: the built-in Guest account (RID 501) must stay disabled. Found by its SID suffix, so it
# works whatever the language of Windows.
try {
    $GuestAcc = @(Get-LocalUser -ErrorAction Stop | Where-Object { $_.SID.Value -like "S-1-5-21-*-501" })
    foreach ($g in $GuestAcc) {
        Add-Result "Accounts" "Guest account (RID-501)" $(if ($g.Enabled) { "ENABLED" } else { "Disabled" }) $(if ($g.Enabled) { "FAIL" } else { "OK" }) $(
            if ($g.Enabled) { "The built-in Guest account is enabled: it allows access without a personal account. Disable it: Disable-LocalUser -Name '$($g.Name)'" }
        )
    }
} catch {
    Add-Result "Accounts" "Guest account (RID-501)" "Unable to read" "INFO" "Error: $($_.Exception.Message)"
}

}

# ──────────────────────────────────────────────
#  SUMMARY
# ──────────────────────────────────────────────
$TotalOK   = @($AuditResults | Where-Object { $_.Status -eq "OK" }).Count
$TotalWARN = @($AuditResults | Where-Object { $_.Status -eq "WARN" }).Count
$TotalFAIL = @($AuditResults | Where-Object { $_.Status -eq "FAIL" }).Count
$TotalINFO = @($AuditResults | Where-Object { $_.Status -eq "INFO" }).Count
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
    if ($result.Indeterminate) { continue }   # v5.6.0: not performed -> neutral, never a free point
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

# v5.6.0: the headline score comes from Get-AuditScoreRaw (same model as before,
# indeterminate checks ignored); $CatStats above feeds the per-category scores.
$ScoreRaw   = Get-AuditScoreRaw -Results $AuditResults -Weights $CategoryWeights
$ScoreExact = [math]::Round($ScoreRaw, 2)
$Score      = [int][math]::Round($ScoreRaw)
$ScoreColor = if ($Score -ge 80) { "#a8ce81" } elseif ($Score -ge 50) { "#ffb347" } else { "#ef7066" }

Write-Log "=== SUMMARY ===" -Level SECTION
Write-Log "Total checks: $Total | OK: $TotalOK | WARN: $TotalWARN | FAIL: $TotalFAIL | INFO: $TotalINFO" -Level INFO
Write-Log "Estimated security score (weighted by category): $Score / 100" -Level $(if($Score -ge 80){"OK"}elseif($Score -ge 50){"WARN"}else{"FAIL"})
$TotalIndeterminate = @($AuditResults | Where-Object { $_.Indeterminate }).Count
if ($TotalIndeterminate -gt 0) {
    Write-Log "$TotalIndeterminate check(s) could not be performed and are excluded from the score (see the 'Unable to read' / 'Not available' lines)" -Level INFO
}

# ──────────────────────────────────────────────
#  EVOLUTION SINCE THE LAST AUDIT (DELTAS)
# ──────────────────────────────────────────────
$Deltas = [System.Collections.Generic.List[object]]::new()

if ($PreviousAudit -and $PreviousAudit.Results) {
    # NOTE v5.6.0: several results can share the same Category|Check (one line per
    # exclusion, per rule...). A numeric suffix keeps each occurrence distinct so
    # the second one is no longer reported as "(new check)" on every run.
    $PrevMap  = @{}
    $prevSeen = @{}
    foreach ($p in @($PreviousAudit.Results)) {
        $bk = "$($p.Category)|$($p.Check)"
        if ($prevSeen.ContainsKey($bk)) { $prevSeen[$bk]++; $bk = "$bk#$($prevSeen[$bk])" } else { $prevSeen[$bk] = 0 }
        $PrevMap[$bk] = $p
    }

    $curSeen = @{}
    foreach ($cur in $AuditResults) {
        $key = "$($cur.Category)|$($cur.Check)"
        if ($curSeen.ContainsKey($key)) { $curSeen[$key]++; $key = "$key#$($curSeen[$key])" } else { $curSeen[$key] = 0 }
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
    # NOTE v5.6.0: checks and decision rules change between versions, so a score difference between two
    # versions of the script is not strictly a change of the machine: the report says so.
    $PrevVersion = "$($PreviousAudit.ScriptVersion)"
    $VersionNote = if ($PrevVersion -ne $ScriptVersion) { " — different script version ($(if($PrevVersion){$PrevVersion}else{'earlier than 5.6.0'}) -> $ScriptVersion): detection rules changed, compare with care" } else { "" }
    Write-Log "Score evolution since the last audit ($($PreviousAudit.Date)): $PrevScore -> $Score ($(if($ScoreDiff -ge 0){'+'})$ScoreDiff)$VersionNote" -Level $(if($ScoreDiff -ge 0){"OK"}else{"WARN"})

    # NOTE v4.0: regression alert — if the score drops by more than
    # $ScoreRegressionThreshold points, a FAIL is emitted in the console so
    # a scheduled run (-Silent) surfaces it in the logs.
    if ($ScoreDiff -le -$ScoreRegressionThreshold) {
        Write-Log "REGRESSION ALERT: the score dropped by $([math]::Abs($ScoreDiff)) points ($PrevScore -> $Score) — configured threshold: $ScoreRegressionThreshold pts" -Level FAIL
    }

    # NOTE v5.6.0: a category with many checks dilutes a single failure, so the
    # score alone can hide a serious regression. Any check that is FAIL now and
    # was not FAIL before raises its own alert, whatever the score does.
    $NewFailDeltas = @($Deltas | Where-Object { $_.After -eq "FAIL" -and ($_.Type -eq "New issue" -or $_.Type -eq "New check") })
    if ($NewFailDeltas.Count -gt 0) {
        Write-Log "NEW FAIL ALERT: $($NewFailDeltas.Count) check(s) newly in FAIL since the last audit: $(@($NewFailDeltas | ForEach-Object { "$($_.Category) | $($_.Check)" }) -join ' ; ')" -Level FAIL
    }
} elseif ($IsFilteredRun) {
    Write-Log "Filtered run (-Category): no comparison with the last full audit; baseline and history are left untouched" -Level INFO
} else {
    Write-Log "No previous audit found — first run or missing baseline, no comparison possible" -Level INFO
}

# Save the current run as the reference for the next run
# (v5.6.0: full runs only — a -Category run would replace the reference by a partial one)
try {
  if (-not $IsFilteredRun) {
    [PSCustomObject]@{
        Date          = Get-Date -Format "o"
        Score         = $Score
        ScoreExact    = $ScoreExact
        ScriptVersion = $ScriptVersion
        Results       = ($AuditResults | Select-Object Category, Check, Value, Status)
    } | ConvertTo-Json -Depth 5 | Out-File -FilePath $BaselineFile -Encoding UTF8 -Force
  }
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
        ScoreExact    = $ScoreExact
        FilteredRun   = $IsFilteredRun
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
    # NOTE v5.6.0: cells starting with = + - @ are neutralised (CSV formula injection)
    $AuditResults | ForEach-Object {
        [PSCustomObject]@{
            Category = ConvertTo-SafeCsvCell $_.Category
            Check    = ConvertTo-SafeCsvCell $_.Check
            Value    = ConvertTo-SafeCsvCell $_.Value
            Status   = $_.Status
            Detail   = ConvertTo-SafeCsvCell $_.Detail
        }
    } | Export-Csv -Path $ReportCSV -NoTypeInformation -Encoding UTF8 -Delimiter ";"
} catch {
    Write-Log "Unable to write the CSV export: $($_.Exception.Message)" -Level WARN
}

# NOTE v3.0: multi-run history, distinct from the baseline (which only
# keeps the previous run). Adds the current run, truncates to the most
# recent $MaxHistoryRuns, and rewrites the whole file (no incremental
# append, to avoid invalid JSON if writing is interrupted mid-way).
try {
  if (-not $IsFilteredRun) {
    $ScoreHistory.Add([PSCustomObject]@{ Date = Get-Date -Format "o"; Score = $Score; ScoreExact = $ScoreExact; ScriptVersion = $ScriptVersion })
    $HistoryToKeep = $ScoreHistory | Select-Object -Last $MaxHistoryRuns
    $HistoryToKeep | ConvertTo-Json -Depth 3 | Out-File -FilePath $HistoryFile -Encoding UTF8 -Force
    $ScoreHistory = [System.Collections.Generic.List[object]]::new()
    foreach ($h in @($HistoryToKeep)) { $ScoreHistory.Add($h) }
  }
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
    $moreNote = if (@($AuditResults | Where-Object { $_.Status -in "FAIL","WARN" }).Count -gt 10) {
        "<div class='exec-more'>... and $( @($AuditResults | Where-Object { $_.Status -in 'FAIL','WARN' }).Count - 10 ) more — see the full table below.</div>"
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
              <span>$(He $d.Category) — $(He $d.Check)</span>
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
    $items = @($AuditResults | Where-Object { $_.Category -eq $cat })
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

        # NOTE v5.5.0: Check / Value / Detail are HTML-escaped here. They used to be inserted
        # raw, so text between angle brackets (the "<larger size>" placeholder of the VSS fix
        # command) was swallowed by the browser, and a service, task or path name containing
        # markup would have been injected into the report instead of displayed.
        $detail = if ($item.Detail) { "<br><small class='detail'>$(He $item.Detail)</small>" } else { "" }

        # NOTE v3.2: contextual help links only on WARN/FAIL checks — an
        # OK/INFO check doesn't need remediation documentation, it would
        # just clutter the table for nothing.
        # Exception: two INFO categories still deserve links:
        # - Software: the CVE search (NVD) is useful even when the status
        #   is INFO (no real-time version comparison is done).
        # - Certificates: the crt.sh link (search by thumbprint) is useful
        #   even on individual detailed certificates classified as INFO.
        # - Defender PUA / Network Protection (v5.5.0): "off" is only INFO (these
        #   are optional layers), but the link explains how to turn them on.
        $helpLinks = ""
        $needsLinks = $item.Status -in @("WARN","FAIL") -or
                      ($item.Status -eq "INFO" -and $item.Category -eq "Software" -and $item.Check -like "Software to watch:*") -or
                      ($item.Status -eq "INFO" -and $item.Category -eq "Certificates" -and $item.Check -like "Root certificate:*") -or
                      ($item.Status -eq "INFO" -and $item.Category -eq "Defender" -and $item.Check -match "^(PUA protection|Network Protection)") -or
                      (Test-HelpLinksReferenceRow $item.Category $item.Check)
        if ($needsLinks) {
            $helpLinks = Get-HelpLinks -Category $item.Category -Check $item.Check -Value $item.Value -Detail $item.Detail
        }

        # NOTE v5.5.1: a row with a Defender settings card (see $script:DefenderRef) shows the
        # card's own links, visible whatever the status, instead of the generic WARN / FAIL
        # ones, so a link is never listed twice. The card is collapsed by default.
        $refObj  = Get-SettingRef -Category $item.Category -Check $item.Check
        $refHtml = ""
        $refKeyText = ""
        if ($refObj) {
            $refHtml    = Get-SettingRefHtml -Category $item.Category -Check $item.Check
            $helpLinks  = ""
            $refKeyText = " $($refObj.Key)"
        }

        $rowId = ""
        if ($item.Status -eq "FAIL") {
            $FailCounter++
            $rowId = "fail-$FailCounter"
            $FailAnchorsHTML += "<a href=`"#$rowId`" class=`"fail-link`">$(He $item.Category) — $(He $item.Check)</a>"
        }

        $searchText = (He "$($item.Category) $($item.Check) $($item.Value) $($item.Detail)$refKeyText").ToLower()

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

        # NOTE v5.6.0: an empty id="" attribute was emitted on every non-FAIL row (invalid HTML);
        # data-cat lets the filter script rebuild the category cell (see layoutCategories()).
        $rowIdAttr = if ($rowId) { "id=`"$rowId`" " } else { "" }
        $TableRows += @"
        <tr class="$rowClass" $($rowIdAttr)data-cat="$(He $cat)" data-status="$($item.Status)" data-search="$searchText">
            $catCell
            <td>$(He $item.Check)</td>
            <td>$(He $item.Value)$detail$helpLinks$refHtml</td>
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
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'">
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
  .meta-bar { display:flex; flex-wrap:wrap; gap:8px 24px; font-size:11.5px; color:#94a3b8; border-top:1px solid var(--border); padding-top:12px; margin-top:4px; position:relative; z-index:1; }
  .meta-bar span { display:flex; align-items:center; gap:6px; }
  .meta-bar b { color:var(--muted); }
  .meta-dot { width:5px; height:5px; border-radius:50%; background:var(--accent); display:inline-block; box-shadow:0 0 6px var(--accent); }

  .container { max-width: 1400px; margin: 0 auto; padding: 32px 40px; }

  .summary-grid { display: grid; grid-template-columns: repeat(5, 1fr); gap: 16px; margin-bottom: 32px; }
  /* NOTE v5.6.0: the report had no media query (fixed 5-column grid). Narrow screens now get fewer
     columns and a horizontally scrollable results table. */
  @media (max-width: 900px) { .summary-grid { grid-template-columns: repeat(2, 1fr); } }
  @media (max-width: 560px) { .summary-grid { grid-template-columns: 1fr; } #resultsTable { display: block; overflow-x: auto; } }
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

  /* v5.5.1: expandable explanation card under the Defender settings */
  .ref { margin-top: 8px; border: 1px solid var(--border); border-radius: 8px; background: var(--surface2); padding: 6px 12px; }
  .ref > summary { cursor: pointer; color: var(--accent); font-size: 12px; font-weight: 600; }
  .ref p { margin: 8px 0 4px; color: var(--muted); font-size: 12px; line-height: 1.5; }
  .ref .ref-label { margin-top: 12px; color: var(--text); font-weight: 600; }
  .ref .ref-warn { color: var(--warn); }
  .ref .ref-easy { color: var(--text); background: rgba(0,212,255,0.07); border-left: 3px solid var(--accent); padding: 6px 10px; border-radius: 4px; }
  .ref .ref-fr { color: var(--muted); font-size: 11.5px; }
  .ref table { margin: 6px 0 0 0; border-radius: 6px; background: var(--bg); }
  .ref thead th { padding: 6px 10px; }
  .ref tbody td { padding: 6px 10px; font-size: 12px; color: var(--muted); }
  .ref tbody td:first-child { white-space: nowrap; color: var(--text); }
  .ref tr.cur td { background: rgba(0,212,255,0.10); }
  .ref .ref-cur { color: var(--accent); font-weight: 600; font-size: 11px; }
  .ref code, .ref pre.cmd { font-family: 'Cascadia Code','Consolas','Courier New',monospace; }
  .ref pre.cmd { margin: 4px 0 0 0; padding: 8px 10px; background: var(--bg); border: 1px solid var(--border); border-radius: 6px; color: var(--text); font-size: 11.5px; line-height: 1.5; overflow-x: auto; }

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
  .help-link:hover { background: var(--accent); color: #04121f; border-color: var(--accent); }
  .help-link::before { content: "🔗 "; }
  .fail-link:hover { background: rgba(239,112,102,0.22); }

  .search-box { width: 100%; max-width: 420px; margin-bottom: 16px; padding: 10px 14px; border-radius: 8px; border: 1px solid var(--border); background: var(--surface); color: var(--text); font-size: 13px; }
  .search-box:focus { outline: none; border-color: var(--accent); }
  .filter-bar { display: flex; align-items: center; gap: 12px; margin-bottom: 12px; flex-wrap: wrap; }
  .filter-chip { font-size: 11px; padding: 5px 12px; border-radius: 20px; border: 1px solid var(--border); background: var(--surface2); color: var(--muted); cursor: pointer; user-select: none; }
  .filter-chip.active { background: var(--accent); color: #04121f; border-color: var(--accent); }
  .no-results { color: var(--muted); font-size: 13px; padding: 16px; text-align: center; display: none; }

  .regression-banner { display: flex; align-items: center; gap: 14px; background: rgba(239,112,102,0.12); border: 1px solid rgba(239,112,102,0.4); border-radius: 12px; padding: 16px 20px; margin-bottom: 16px; color: var(--fail); }
  .regression-icon { font-size: 22px; flex-shrink: 0; }

  .exec-summary { background: var(--surface); border: 1px solid var(--border); border-radius: 12px; padding: 18px 20px; margin-bottom: 20px; }
  .exec-summary.exec-ok { border-color: rgba(168,206,129,0.4); background: rgba(168,206,129,0.07); display: flex; align-items: center; gap: 12px; color: var(--ok); }
  .exec-icon { font-size: 20px; }
  .exec-title { font-weight: 600; font-size: 13px; color: var(--muted); text-transform: uppercase; letter-spacing: .05em; margin-bottom: 10px; }
  .exec-item { display: grid; grid-template-columns: 80px 130px 1fr auto; gap: 10px; align-items: center; padding: 8px 10px; border-radius: 8px; margin-bottom: 5px; font-size: 13px; }
  @media (max-width: 700px) { .exec-item { grid-template-columns: auto 1fr; } }
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
    // NOTE v5.6.0: only the audit rows (data-status) are filtered. The selector used to match every
    // <tr>, including the tables inside the expandable Defender cards, which vanished as soon as a
    // filter or a search was active.
    var rows = document.querySelectorAll('#resultsTable tbody tr[data-status]');
    var noResults = document.getElementById('noResults');
    var activeStatus = 'ALL';

    // The category cell is a rowspan cell attached to the first row of its group; when that row is
    // filtered out the cell disappeared and the other rows shifted left. It is rebuilt here on the
    // first visible row of each category, spanning down to the last visible one.
    function layoutCategories() {
      var groups = {}, order = [];
      rows.forEach(function (row) {
        var c = row.getAttribute('data-cat');
        if (!groups[c]) { groups[c] = []; order.push(c); }
        groups[c].push(row);
        var old = row.querySelector('td.cat-cell');
        if (old) { old.parentNode.removeChild(old); }
      });
      order.forEach(function (c) {
        var rs = groups[c], first = -1, last = -1;
        rs.forEach(function (r, i) { if (r.style.display !== 'none') { if (first < 0) { first = i; } last = i; } });
        if (first < 0) { return; }
        var td = document.createElement('td');
        td.className = 'cat-cell';
        td.setAttribute('rowspan', String(last - first + 1));
        td.textContent = c;
        rs[first].insertBefore(td, rs[first].firstChild);
      });
    }

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
      layoutCategories();
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
            # NOTE v5.6.0: the script runs elevated; starting the browser from it would open it with
            # administrator rights. explorer.exe hands the file to the user's normal (non-elevated) shell.
            try { Start-Process -FilePath "explorer.exe" -ArgumentList "`"$ReportHTML`"" -ErrorAction Stop }
            catch { Start-Process $ReportHTML }
        }
    }

    # NOTE v5.4.2: the right edge of this box was shifted by 2 columns — the
    # border was hard-coded at 51 "═" while the text line was padded to 53
    # characters by hand. Inner width is now a single variable and the text is
    # PadRight()-ed to exactly that width, so border and content can't diverge.
    $enterBoxWidth = 51
    Write-Host ""
    Write-Host ("  ╔" + ("═" * $enterBoxWidth) + "╗") -ForegroundColor Cyan
    Write-Host "  ║" -ForegroundColor Cyan -NoNewline
    Write-Host ("  Press ENTER to close this window...").PadRight($enterBoxWidth) -ForegroundColor Yellow -NoNewline
    Write-Host "║" -ForegroundColor Cyan
    Write-Host ("  ╚" + ("═" * $enterBoxWidth) + "╝") -ForegroundColor Cyan
    Read-Host | Out-Null
}

# SIG # Begin signature block
# MIIFwgYJKoZIhvcNAQcCoIIFszCCBa8CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCA9vgmzV6bSZgf0
# iRKISqND09Gf+CUn8Jhl7p09M1SVpaCCAygwggMkMIICDKADAgECAhB6X4r8AlBU
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
# ARUwLwYJKoZIhvcNAQkEMSIEICkVDMTgS6/RO4V/CCxAsNOSuUc09NEP9z7qG2xH
# C3vkMA0GCSqGSIb3DQEBAQUABIIBAJTm/VTssgzFTlVHQmZbzgZnDCJzOj4kHBxZ
# 574gxGyl7V8fyJJsnmqIJMv9JEPAfcmBbXszaq9eRw9JL8z3UDO8IqpNJbFh8NY1
# pBXpmlCW28IHgRT2B0zYA6wbtcOI80zuSJWL34RWuB6jzEm7ifNuhzRpGeNpOZlO
# H+mBryJCBGDR4uQ5JMuoyTWC3t00ARhI/OwOX3yw0XuOSN2W2bSprk1Obmtq9s9S
# 8688EXPyFaGbqFqHAuIhyZUjls6rsOEi1g2dmz4EDRmCyV1BFKUGl6xQvlSR4wU6
# X6QoRJGUKmhiYOocyBlEQiSyQCSteXtugWWAkAHxdQHYH/UbJXI=
# SIG # End signature block
