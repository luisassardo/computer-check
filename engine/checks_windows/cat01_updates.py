"""CAT-1: OS, Updates & System Integrity for Windows.

Mirrors macOS CAT-1 conceptually. Includes BitLocker/TPM/Secure Boot here
because they are foundational system state, not malware artifacts.

All checks are read-only. Several queries (BitLocker, scheduled-task changes,
WindowsUpdate COM) work better with elevation; we attempt them without admin
and surface ERROR/SKIP cleanly when access is denied.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from ..core import Finding, ScanContext, Severity, Status, run_cmd, run_ps, safe_check

CATEGORY = "CAT-1: OS & Updates"
CATEGORY_DE = "CAT-1: System & Updates"
CATEGORY_ES = "CAT-1: Sistema y actualizaciones"


def run(ctx: ScanContext) -> list[Finding]:
    """Each check is isolated so a crash in one does not kill the rest."""
    out: list[Finding] = []
    out.append(safe_check("WIN-CAT01-001", CATEGORY, _check_windows_version, ctx))
    out.append(safe_check("WIN-CAT01-002", CATEGORY, _check_pending_updates))
    out.append(safe_check("WIN-CAT01-003", CATEGORY, _check_auto_update_settings))
    out.append(safe_check("WIN-CAT01-004", CATEGORY, _check_defender_status))
    out.append(safe_check("WIN-CAT01-005", CATEGORY, _check_defender_signatures))
    out.append(safe_check("WIN-CAT01-006", CATEGORY, _check_tamper_protection))
    out.append(safe_check("WIN-CAT01-007", CATEGORY, _check_secure_boot))
    out.append(safe_check("WIN-CAT01-008", CATEGORY, _check_bitlocker))
    out.append(safe_check("WIN-CAT01-009", CATEGORY, _check_tpm))
    out.append(safe_check("WIN-CAT01-010", CATEGORY, _check_credential_guard))
    out.append(safe_check("WIN-CAT01-011", CATEGORY, _check_third_party_browsers))
    out.append(safe_check("WIN-CAT01-012", CATEGORY, _check_winget_outdated))
    return out


# --- 1.1 Windows version ----------------------------------------------------

# Builds still in mainstream support as of late 2026. Update as Microsoft
# rotates supported builds. Source: learn.microsoft.com/lifecycle.
SUPPORTED_BUILDS_MIN = {
    "11": 22631,   # Win11 23H2 minimum still receiving updates
    "10": 19045,   # Win10 22H2 (last Win10) — extended security updates only after EOL
}
WIN10_EOL_DATE = "2025-10-14"  # Microsoft's official Win10 end-of-support


def _check_windows_version(ctx: ScanContext) -> Finding:
    r = run_ps(
        "$o = [PSCustomObject]@{ "
        "  ProductName = (Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion').ProductName; "
        "  DisplayVersion = (Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion').DisplayVersion; "
        "  CurrentBuild = (Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion').CurrentBuild; "
        "  UBR = (Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion').UBR; "
        "}; $o | ConvertTo-Json -Compress"
    )
    if not r.ok:
        return Finding(
            id="WIN-CAT01-001",
            title="Could not determine Windows version",
            description="Verifies that Windows is on a build still receiving security updates.",
            category=CATEGORY,
            severity=Severity.HIGH,
            status=Status.ERROR,
            command=r.cmd,
            evidence=(r.stderr or r.exception)[:400],
            standards=("CIS Win11 1.1",),
            vector_ids=("O-01", "O-02"),
            remediation="Run `winver` from Start to read the version manually.",
            title_de="Windows-Version konnte nicht ermittelt werden",
            description_de="Prüft, ob Windows auf einem Build läuft, der noch Sicherheitsupdates erhält.",
            remediation_de="Öffne Start → `winver`, um die Version manuell abzulesen.",
            category_de=CATEGORY_DE,
            title_es="No se pudo determinar la versión de Windows",
            description_es="Verifica que Windows esté en un build que aún recibe actualizaciones de seguridad.",
            remediation_es="Abre Inicio → `winver` para leer la versión manualmente.",
            category_es=CATEGORY_ES,
        )

    try:
        d = json.loads(r.stdout.strip())
    except json.JSONDecodeError:
        d = {}

    product = d.get("ProductName", "Windows")
    display = d.get("DisplayVersion", "")
    build = int(d.get("CurrentBuild", 0)) if str(d.get("CurrentBuild", "")).isdigit() else 0
    ubr = d.get("UBR", "")

    is_win11 = build >= 22000
    major = "11" if is_win11 else "10"
    min_supported = SUPPORTED_BUILDS_MIN.get(major, 0)
    supported = build >= min_supported and is_win11  # only Win11 fully supported in 2026

    # Derive the display OS name from the build number, NOT from ProductName.
    # On Windows 11, HKLM ProductName still literally reads "Windows 10 Pro"
    # (a long-standing Microsoft quirk — the key was never updated for Win11),
    # which would otherwise print a confusing "Windows 10 Pro" line on a Win11
    # device. Preserve the SKU suffix (e.g. "Pro", "Home") from ProductName but
    # force the correct "Windows 11"/"Windows 10" prefix off the build number.
    edition = re.sub(r"^\s*Windows\s+1[01]\s*", "", product or "").strip()
    os_name = f"Windows {major}" + (f" {edition}" if edition else "")
    evidence = f"{os_name}\nVersion: {display}\nBuild: {build}.{ubr}"

    if supported:
        return Finding(
            id="WIN-CAT01-001",
            title=f"Windows {major} build {build}.{ubr} is on a supported version",
            description="Build is within Microsoft's mainstream support window for security updates.",
            category=CATEGORY,
            severity=Severity.HIGH,
            status=Status.PASS,
            command=r.cmd,
            evidence=evidence,
            standards=("CIS Win11 1.1",),
            vector_ids=("O-01", "O-02"),
            remediation="No action.",
            references=("https://learn.microsoft.com/en-us/lifecycle/products/windows-11",),
            title_de=f"Windows {major} Build {build}.{ubr} ist eine unterstützte Version",
            description_de="Der Build liegt im Mainstream-Support-Fenster von Microsoft für Sicherheitsupdates.",
            remediation_de="Keine Aktion nötig.",
            category_de=CATEGORY_DE,
            title_es=f"Windows {major} build {build}.{ubr} está en una versión con soporte",
            description_es="El build está dentro de la ventana de soporte general de Microsoft para actualizaciones de seguridad.",
            remediation_es="Sin acción necesaria.",
            category_es=CATEGORY_ES,
        )

    if not is_win11:
        return Finding(
            id="WIN-CAT01-001",
            title=f"Windows 10 detected — out of mainstream support since {WIN10_EOL_DATE}",
            description="Windows 10 reached end of mainstream support in October 2025. Security updates require ESU (Extended Security Updates) subscription. For high-risk users, plan migration to Windows 11 on supported hardware.",
            category=CATEGORY,
            severity=Severity.CRITICAL,
            status=Status.FAIL,
            command=r.cmd,
            evidence=evidence,
            standards=("CIS Win11 1.1",),
            vector_ids=("O-01", "O-02", "W-04"),
            remediation="Upgrade to Windows 11 if hardware supports it (TPM 2.0 + UEFI + supported CPU). Run the PC Health Check app to verify. If hardware is not supported, plan device replacement.",
            interim_mitigation="Until upgrade: enroll the device in Microsoft's ESU program (paid for consumers as of 2025), uninstall Internet Explorer and legacy Edge, use a current Chromium browser, avoid opening untrusted documents, ensure Defender + tamper protection are on.",
            references=("https://learn.microsoft.com/en-us/lifecycle/products/windows-10-home-and-pro",),
            title_de=f"Windows 10 erkannt — kein Mainstream-Support mehr seit {WIN10_EOL_DATE}",
            description_de="Windows 10 hat im Oktober 2025 das Ende des Mainstream-Supports erreicht. Sicherheitsupdates erfordern ein ESU-Abo (Extended Security Updates). Für Hochrisiko-Personen: Migration auf Windows 11 auf unterstützter Hardware planen.",
            remediation_de="Auf Windows 11 aktualisieren, wenn die Hardware es unterstützt (TPM 2.0 + UEFI + unterstützte CPU). Die App 'PC Health Check' bestätigt das. Wenn nicht unterstützt: Gerätewechsel planen.",
            interim_mitigation_de="Bis zum Upgrade: Gerät im ESU-Programm von Microsoft registrieren (für Privatkunden seit 2025 kostenpflichtig), Internet Explorer und legacy Edge deinstallieren, einen aktuellen Chromium-Browser nutzen, keine nicht vertrauenswürdigen Dokumente öffnen, sicherstellen dass Defender + Tamper Protection aktiv sind.",
            category_de=CATEGORY_DE,
            title_es=f"Windows 10 detectado — sin soporte general desde {WIN10_EOL_DATE}",
            description_es="Windows 10 llegó al fin del soporte general en octubre de 2025. Las actualizaciones de seguridad requieren una suscripción ESU (Extended Security Updates). Para personas en alto riesgo, planifica la migración a Windows 11 en hardware compatible.",
            remediation_es="Actualiza a Windows 11 si el hardware lo soporta (TPM 2.0 + UEFI + CPU compatible). La app 'PC Health Check' lo confirma. Si el hardware no es compatible, planifica el reemplazo del equipo.",
            interim_mitigation_es="Hasta el upgrade: inscribe el equipo en el programa ESU de Microsoft (de pago para usuarios particulares desde 2025), desinstala Internet Explorer y el Edge antiguo, usa un navegador Chromium actual, evita abrir documentos no confiables y asegúrate de que Defender + la protección contra manipulación (Tamper Protection) estén activos.",
            category_es=CATEGORY_ES,
        )

    return Finding(
        id="WIN-CAT01-001",
        title=f"Windows 11 build {build}.{ubr} is older than the minimum supported ({SUPPORTED_BUILDS_MIN['11']})",
        description="This Windows 11 build no longer receives security updates. Newer builds are available via Windows Update.",
        category=CATEGORY,
        severity=Severity.HIGH,
        status=Status.FAIL,
        command=r.cmd,
        evidence=evidence,
        standards=("CIS Win11 1.1",),
        vector_ids=("O-01", "O-02"),
        remediation="Settings → Windows Update → Check for updates → install the latest feature update (24H2 or later).",
        references=("https://learn.microsoft.com/en-us/lifecycle/products/windows-11",),
        title_de=f"Windows 11 Build {build}.{ubr} ist älter als der minimal unterstützte Build ({SUPPORTED_BUILDS_MIN['11']})",
        description_de="Dieser Windows-11-Build erhält keine Sicherheitsupdates mehr. Neuere Builds sind über Windows Update verfügbar.",
        remediation_de="Einstellungen → Windows Update → Nach Updates suchen → das neueste Feature-Update (24H2 oder neuer) installieren.",
        category_de=CATEGORY_DE,
        title_es=f"El build {build}.{ubr} de Windows 11 es más antiguo que el mínimo con soporte ({SUPPORTED_BUILDS_MIN['11']})",
        description_es="Este build de Windows 11 ya no recibe actualizaciones de seguridad. Hay builds más nuevos disponibles vía Windows Update.",
        remediation_es="Configuración → Windows Update → Buscar actualizaciones → instala la actualización de características más reciente (24H2 o posterior).",
        category_es=CATEGORY_ES,
    )


# --- 1.2 Pending updates ----------------------------------------------------

def _check_pending_updates() -> Finding:
    # Use the WindowsUpdate COM object — no admin required for read.
    # Note: PowerShell escapes single quotes inside single-quoted strings as
    # '' (doubled), NOT \' as in bash. Mixing the two breaks the parser.
    script = (
        "$session = New-Object -ComObject Microsoft.Update.Session; "
        "$searcher = $session.CreateUpdateSearcher(); "
        "try { "
        "  $r = $searcher.Search('IsInstalled=0 and Type=''Software'' and IsHidden=0'); "
        "  $r.Updates | Select-Object Title, @{N='KB';E={($_.KBArticleIDs -join ',')}}, MsrcSeverity | ConvertTo-Json -Compress -Depth 3 "
        "} catch { Write-Output ('SEARCH_FAILED: ' + $_.Exception.Message) }"
    )
    r = run_ps(script, timeout=120)
    if not r.ok or r.stdout.startswith("SEARCH_FAILED"):
        return Finding(
            id="WIN-CAT01-002",
            title="Could not query pending Windows Updates",
            description="The Windows Update Agent did not return results. Network blocked, WUA service stopped, or recent install in progress.",
            category=CATEGORY,
            severity=Severity.MEDIUM,
            status=Status.WARN,
            command=r.cmd,
            evidence=(r.stdout or r.stderr or r.exception)[:600],
            standards=("CIS Win11 1.2",),
            vector_ids=("O-01",),
            remediation="Settings → Windows Update → Check for updates manually.",
            title_de="Ausstehende Windows-Updates konnten nicht abgefragt werden",
            description_de="Der Windows Update Agent lieferte keine Ergebnisse. Netzwerk blockiert, WUA-Dienst gestoppt oder Installation in Bearbeitung.",
            remediation_de="Einstellungen → Windows Update → Manuell nach Updates suchen.",
            category_de=CATEGORY_DE,
            title_es="No se pudieron consultar las actualizaciones de Windows pendientes",
            description_es="El Agente de Windows Update no devolvió resultados. Red bloqueada, servicio WUA detenido o una instalación en curso.",
            remediation_es="Configuración → Windows Update → Buscar actualizaciones manualmente.",
            category_es=CATEGORY_ES,
        )

    txt = r.stdout.strip()
    if not txt or txt == "null":
        return Finding(
            id="WIN-CAT01-002",
            title="No pending Windows Updates",
            description="The Windows Update Agent reports no missing updates.",
            category=CATEGORY,
            severity=Severity.HIGH,
            status=Status.PASS,
            command=r.cmd,
            evidence="(empty result set)",
            standards=("CIS Win11 1.2",),
            vector_ids=("O-01",),
            remediation="No action.",
            title_de="Keine ausstehenden Windows-Updates",
            description_de="Der Windows Update Agent meldet keine fehlenden Updates.",
            remediation_de="Keine Aktion nötig.",
            category_de=CATEGORY_DE,
            title_es="No hay actualizaciones de Windows pendientes",
            description_es="El Agente de Windows Update no reporta actualizaciones faltantes.",
            remediation_es="Sin acción necesaria.",
            category_es=CATEGORY_ES,
        )

    try:
        data = json.loads(txt)
        if isinstance(data, dict):
            data = [data]
        items = data
    except json.JSONDecodeError:
        items = []

    critical = [i for i in items if str(i.get("MsrcSeverity", "")).lower() in ("critical", "important")]
    return Finding(
        id="WIN-CAT01-002",
        title=f"{len(items)} pending Windows Update(s), {len(critical)} rated Critical/Important",
        description="Targeted attacks rely on N-day exploits — slow patching directly increases exposure. Critical/Important updates should be installed within 24–72h.",
        category=CATEGORY,
        severity=Severity.HIGH if critical else Severity.MEDIUM,
        status=Status.FAIL,
        command=r.cmd,
        evidence="\n".join(
            f"[{i.get('MsrcSeverity') or 'Unrated'}] {i.get('Title','?')}  ({i.get('KB') or 'no KB'})"
            for i in items[:30]
        ) + (f"\n... +{len(items)-30} more" if len(items) > 30 else ""),
        standards=("CIS Win11 1.2",),
        vector_ids=("O-01", "W-04"),
        remediation="Settings → Windows Update → Install all available updates. Reboot when prompted. For high-risk profiles, install Critical/Important within 24h.",
        interim_mitigation="If a reboot now is impossible, at minimum install Defender platform/signature updates (no reboot required) and enable Lockdown-equivalent mitigations: turn on Defender Application Guard for Edge if available.",
        title_de=f"{len(items)} ausstehende Windows-Update(s), {len(critical)} als Kritisch/Wichtig eingestuft",
        description_de="Gezielte Angriffe nutzen N-Day-Exploits — langsames Patchen erhöht direkt deine Angriffsfläche. Kritische/Wichtige Updates sollten innerhalb von 24–72 h installiert werden.",
        remediation_de="Einstellungen → Windows Update → alle verfügbaren Updates installieren. Bei Aufforderung neu starten. Bei Hochrisiko-Profilen: Kritisch/Wichtig binnen 24 h installieren.",
        interim_mitigation_de="Wenn ein Neustart jetzt nicht möglich ist: zumindest Defender-Plattform/Signatur-Updates installieren (kein Neustart nötig) und Lockdown-ähnliche Maßnahmen aktivieren — Defender Application Guard für Edge einschalten, falls verfügbar.",
        category_de=CATEGORY_DE,
        title_es=f"{len(items)} actualización(es) de Windows pendiente(s), {len(critical)} clasificadas como Críticas/Importantes",
        description_es="Los ataques dirigidos aprovechan exploits N-day — parchear lento aumenta directamente tu superficie de exposición. Las actualizaciones Críticas/Importantes deben instalarse en 24–72 h.",
        remediation_es="Configuración → Windows Update → instala todas las actualizaciones disponibles. Reinicia cuando se te solicite. En perfiles de alto riesgo, instala las Críticas/Importantes dentro de 24 h.",
        interim_mitigation_es="Si reiniciar ahora es imposible, al menos instala las actualizaciones de plataforma/firmas de Defender (no requieren reinicio) y activa mitigaciones equivalentes a Lockdown: habilita Defender Application Guard para Edge si está disponible.",
        category_es=CATEGORY_ES,
    )


# --- 1.3 Auto-update settings ----------------------------------------------

def _check_auto_update_settings() -> Finding:
    # Modern Windows manages this via the Update Orchestrator + policy keys.
    # A common-but-not-complete signal: NoAutoUpdate must NOT be 1.
    script = (
        "$au = Get-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU' "
        "-ErrorAction SilentlyContinue; "
        "$wu = Get-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate' "
        "-ErrorAction SilentlyContinue; "
        "$muSvc = Get-Service -Name wuauserv -ErrorAction SilentlyContinue; "
        "[PSCustomObject]@{ "
        "  NoAutoUpdate = $au.NoAutoUpdate; "
        "  AUOptions = $au.AUOptions; "
        "  DisableWindowsUpdateAccess = $wu.DisableWindowsUpdateAccess; "
        "  WUAServiceStatus = if ($muSvc) { $muSvc.Status.ToString() } else { 'not-found' }; "
        "} | ConvertTo-Json -Compress"
    )
    r = run_ps(script)
    if not r.ok:
        return Finding(
            id="WIN-CAT01-003",
            title="Could not read Windows Update policy",
            description="Verifies that policies are not preventing automatic updates.",
            category=CATEGORY,
            severity=Severity.MEDIUM,
            status=Status.ERROR,
            command=r.cmd,
            evidence=(r.stderr or r.exception)[:300],
            standards=("CIS Win11 1.3",),
            vector_ids=("O-01",),
            remediation="Settings → Windows Update → Advanced options → confirm 'Receive updates for other Microsoft products' and 'Get me up to date' are enabled.",
            title_de="Windows-Update-Richtlinie konnte nicht gelesen werden",
            description_de="Prüft, dass keine Richtlinien automatische Updates verhindern.",
            remediation_de="Einstellungen → Windows Update → Erweiterte Optionen → bestätige, dass 'Updates für andere Microsoft-Produkte erhalten' und 'Auf dem aktuellen Stand bleiben' aktiviert sind.",
            category_de=CATEGORY_DE,
            title_es="No se pudo leer la directiva de Windows Update",
            description_es="Verifica que ninguna directiva esté impidiendo las actualizaciones automáticas.",
            remediation_es="Configuración → Windows Update → Opciones avanzadas → confirma que 'Recibir actualizaciones de otros productos de Microsoft' y 'Mantenerme al día' estén activadas.",
            category_es=CATEGORY_ES,
        )

    try:
        d = json.loads(r.stdout.strip()) if r.stdout.strip() else {}
    except json.JSONDecodeError:
        d = {}

    issues = []
    if d.get("NoAutoUpdate") == 1:
        issues.append("NoAutoUpdate=1 in policy (auto updates disabled by GPO)")
    if d.get("DisableWindowsUpdateAccess") == 1:
        issues.append("DisableWindowsUpdateAccess=1 (user blocked from WU)")
    wua = str(d.get("WUAServiceStatus", "")).lower()
    if wua and wua not in ("running", "stopped"):
        issues.append(f"wuauserv service in unusual state: {wua}")
    if wua == "stopped":
        issues.append("wuauserv (Windows Update service) is stopped")

    evidence = json.dumps(d, indent=2) if d else "(no policy keys present — defaults apply, which is OK)"

    if not issues:
        return Finding(
            id="WIN-CAT01-003",
            title="Windows Update settings are not blocking automatic patching",
            description="No policy keys disable Windows Update; the service is in a normal state.",
            category=CATEGORY,
            severity=Severity.HIGH,
            status=Status.PASS,
            command=r.cmd,
            evidence=evidence,
            standards=("CIS Win11 1.3",),
            vector_ids=("O-01",),
            remediation="No action.",
            title_de="Windows-Update-Einstellungen blockieren automatisches Patchen nicht",
            description_de="Keine Richtlinie deaktiviert Windows Update; der Dienst ist im Normalzustand.",
            remediation_de="Keine Aktion nötig.",
            category_de=CATEGORY_DE,
            title_es="La configuración de Windows Update no está bloqueando el parcheo automático",
            description_es="Ninguna directiva desactiva Windows Update; el servicio está en estado normal.",
            remediation_es="Sin acción necesaria.",
            category_es=CATEGORY_ES,
        )

    return Finding(
        id="WIN-CAT01-003",
        title=f"Windows Update is being blocked or restricted ({len(issues)} issue(s))",
        description="One or more policy/service settings prevent automatic patching. On a personal device this is almost always wrong.",
        category=CATEGORY,
        severity=Severity.HIGH,
        status=Status.FAIL,
        command=r.cmd,
        evidence=evidence + "\n\nIssues:\n" + "\n".join(f"  - {x}" for x in issues),
        standards=("CIS Win11 1.3",),
        vector_ids=("O-01",),
        remediation="If this is a personal device, remove the WindowsUpdate policy keys (regedit → HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate) and start the wuauserv service. If managed by an employer's MDM, contact IT — they may have a reason but you should know what it is.",
        title_de=f"Windows Update wird blockiert oder eingeschränkt ({len(issues)} Problem(e))",
        description_de="Eine oder mehrere Richtlinien-/Dienst-Einstellungen verhindern automatisches Patchen. Auf einem privaten Gerät ist das fast immer falsch.",
        remediation_de="Wenn dies ein privates Gerät ist: WindowsUpdate-Richtlinienschlüssel entfernen (regedit → HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate) und den Dienst wuauserv starten. Wenn vom MDM des Arbeitgebers verwaltet: IT kontaktieren — sie haben evtl. einen Grund, den du kennen solltest.",
        category_de=CATEGORY_DE,
        title_es=f"Windows Update está bloqueado o restringido ({len(issues)} problema(s))",
        description_es="Una o más opciones de directiva/servicio impiden el parcheo automático. En un equipo personal esto casi siempre es un error.",
        remediation_es="Si este es un equipo personal, elimina las claves de directiva de WindowsUpdate (regedit → HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate) e inicia el servicio wuauserv. Si lo gestiona el MDM de tu empleador, contacta a TI — pueden tener un motivo, pero deberías saber cuál es.",
        category_es=CATEGORY_ES,
    )


# --- 1.4 Defender status ---------------------------------------------------

def _check_defender_status() -> Finding:
    r = run_ps("Get-MpComputerStatus | ConvertTo-Json -Compress")
    if not r.ok:
        return Finding(
            id="WIN-CAT01-004",
            title="Could not read Microsoft Defender status",
            description="Verifies that Defender's real-time, behavior, and network protections are active.",
            category=CATEGORY,
            severity=Severity.HIGH,
            status=Status.ERROR,
            command=r.cmd,
            evidence=(r.stderr or r.exception)[:400],
            standards=("CIS Win11 18.10",),
            vector_ids=("M-01", "M-04"),
            remediation="Settings → Privacy & Security → Windows Security → Virus & threat protection — confirm Real-time protection is on.",
            title_de="Microsoft-Defender-Status konnte nicht gelesen werden",
            description_de="Prüft, dass Defenders Echtzeit-, Verhaltens- und Netzwerkschutz aktiv sind.",
            remediation_de="Einstellungen → Datenschutz & Sicherheit → Windows-Sicherheit → Viren- & Bedrohungsschutz — bestätige, dass Echtzeitschutz aktiv ist.",
            category_de=CATEGORY_DE,
            title_es="No se pudo leer el estado de Microsoft Defender",
            description_es="Verifica que las protecciones en tiempo real, de comportamiento y de red de Defender estén activas.",
            remediation_es="Configuración → Privacidad y seguridad → Seguridad de Windows → Protección contra virus y amenazas — confirma que la protección en tiempo real esté activada.",
            category_es=CATEGORY_ES,
        )

    try:
        d = json.loads(r.stdout.strip())
    except json.JSONDecodeError:
        d = {}

    failing = []
    for k in ("AntivirusEnabled", "RealTimeProtectionEnabled", "BehaviorMonitorEnabled",
              "OnAccessProtectionEnabled", "IoavProtectionEnabled", "NISEnabled"):
        if d.get(k) is False:
            failing.append(k)

    evidence_keys = ("AMServiceEnabled", "AntivirusEnabled", "RealTimeProtectionEnabled",
                     "BehaviorMonitorEnabled", "IoavProtectionEnabled", "NISEnabled",
                     "AntivirusSignatureLastUpdated", "QuickScanEndTime")
    evidence = "\n".join(f"{k} = {d.get(k)}" for k in evidence_keys if k in d)

    if not failing:
        return Finding(
            id="WIN-CAT01-004",
            title="Microsoft Defender is fully enabled",
            description="All core Defender protections are active.",
            category=CATEGORY,
            severity=Severity.HIGH,
            status=Status.PASS,
            command=r.cmd,
            evidence=evidence or "(no detail keys returned)",
            standards=("CIS Win11 18.10",),
            vector_ids=("M-01", "M-04"),
            remediation="No action.",
            title_de="Microsoft Defender ist vollständig aktiviert",
            description_de="Alle Kernschutzfunktionen von Defender sind aktiv.",
            remediation_de="Keine Aktion nötig.",
            category_de=CATEGORY_DE,
            title_es="Microsoft Defender está completamente activado",
            description_es="Todas las protecciones principales de Defender están activas.",
            remediation_es="Sin acción necesaria.",
            category_es=CATEGORY_ES,
        )

    return Finding(
        id="WIN-CAT01-004",
        title=f"Microsoft Defender has {len(failing)} protection(s) disabled",
        description="One or more Defender protections are off. This usually means a third-party AV is installed (which can be fine), or Defender has been intentionally weakened (which usually isn't).",
        category=CATEGORY,
        severity=Severity.HIGH,
        status=Status.FAIL,
        command=r.cmd,
        evidence=evidence + "\n\nDisabled: " + ", ".join(failing),
        standards=("CIS Win11 18.10",),
        vector_ids=("M-01", "M-04"),
        remediation="If you intentionally use another AV, verify it is reputable and up to date. If not, re-enable Defender: Settings → Privacy & Security → Windows Security → Virus & threat protection → manage settings → toggle protections on.",
        interim_mitigation="If the third-party AV is the cause, check that it shows green in its own UI and that its definitions are <7 days old.",
        title_de=f"Microsoft Defender hat {len(failing)} Schutz(e) deaktiviert",
        description_de="Eine oder mehrere Defender-Schutzfunktionen sind aus. Meist bedeutet das, dass ein Drittanbieter-AV installiert ist (kann OK sein), oder Defender wurde absichtlich geschwächt (meist nicht OK).",
        remediation_de="Wenn du absichtlich einen anderen AV nutzt: prüfe, dass er seriös und aktuell ist. Wenn nicht: Defender wieder aktivieren — Einstellungen → Datenschutz & Sicherheit → Windows-Sicherheit → Viren- & Bedrohungsschutz → Einstellungen verwalten → Schutz einschalten.",
        interim_mitigation_de="Wenn der Drittanbieter-AV der Grund ist: bestätige, dass seine Oberfläche grün zeigt und seine Definitionen jünger als 7 Tage sind.",
        category_de=CATEGORY_DE,
        title_es=f"Microsoft Defender tiene {len(failing)} protección(es) desactivada(s)",
        description_es="Una o más protecciones de Defender están apagadas. Normalmente significa que hay un antivirus de terceros instalado (lo cual puede estar bien), o que Defender fue debilitado a propósito (lo cual normalmente no está bien).",
        remediation_es="Si usas otro antivirus a propósito, verifica que sea confiable y esté actualizado. Si no, reactiva Defender: Configuración → Privacidad y seguridad → Seguridad de Windows → Protección contra virus y amenazas → administrar configuración → activa las protecciones.",
        interim_mitigation_es="Si la causa es el antivirus de terceros, comprueba que su propia interfaz muestre verde y que sus definiciones tengan menos de 7 días.",
        category_es=CATEGORY_ES,
    )


# --- 1.5 Defender signatures recent ----------------------------------------

def _check_defender_signatures() -> Finding:
    r = run_ps(
        "$s = Get-MpComputerStatus; "
        "[PSCustomObject]@{ "
        "  AntivirusSignatureVersion = $s.AntivirusSignatureVersion; "
        "  AntivirusSignatureLastUpdated = $s.AntivirusSignatureLastUpdated.ToString('o'); "
        "  AgeDays = ((Get-Date) - $s.AntivirusSignatureLastUpdated).Days; "
        "} | ConvertTo-Json -Compress"
    )
    if not r.ok:
        return Finding(
            id="WIN-CAT01-005",
            title="Could not read Defender signature freshness",
            description="Verifies that AV signatures have been updated recently.",
            category=CATEGORY,
            severity=Severity.MEDIUM,
            status=Status.ERROR,
            command=r.cmd,
            evidence=(r.stderr or r.exception)[:300],
            standards=("CIS Win11 18.10",),
            vector_ids=("M-01",),
            remediation="Open Windows Security → Virus & threat protection → check for updates.",
            title_de="Aktualität der Defender-Signaturen konnte nicht gelesen werden",
            description_de="Prüft, dass AV-Signaturen kürzlich aktualisiert wurden.",
            remediation_de="Windows-Sicherheit → Viren- & Bedrohungsschutz → nach Updates suchen.",
            category_de=CATEGORY_DE,
            title_es="No se pudo leer la antigüedad de las firmas de Defender",
            description_es="Verifica que las firmas del antivirus se hayan actualizado recientemente.",
            remediation_es="Seguridad de Windows → Protección contra virus y amenazas → buscar actualizaciones.",
            category_es=CATEGORY_ES,
        )

    try:
        d = json.loads(r.stdout.strip())
    except json.JSONDecodeError:
        d = {}

    age = d.get("AgeDays", 9999)
    if age <= 3:
        sev, status = Severity.MEDIUM, Status.PASS
        title = f"Defender signatures updated {age} day(s) ago"
        title_de = f"Defender-Signaturen vor {age} Tag(en) aktualisiert"
        title_es = f"Firmas de Defender actualizadas hace {age} día(s)"
    elif age <= 7:
        sev, status = Severity.MEDIUM, Status.WARN
        title = f"Defender signatures are {age} days old (acceptable but stale)"
        title_de = f"Defender-Signaturen sind {age} Tage alt (akzeptabel, aber alt)"
        title_es = f"Las firmas de Defender tienen {age} días (aceptable pero anticuadas)"
    else:
        sev, status = Severity.HIGH, Status.FAIL
        title = f"Defender signatures are {age} days old — too stale"
        title_de = f"Defender-Signaturen sind {age} Tage alt — zu veraltet"
        title_es = f"Las firmas de Defender tienen {age} días — demasiado anticuadas"

    return Finding(
        id="WIN-CAT01-005",
        title=title,
        description="Microsoft publishes new AV definitions multiple times per day. Stale signatures mean missed detections for recent malware families.",
        category=CATEGORY,
        severity=sev,
        status=status,
        command=r.cmd,
        evidence=json.dumps(d, indent=2),
        standards=("CIS Win11 18.10",),
        vector_ids=("M-01", "M-04"),
        remediation="Open Windows Security → Virus & threat protection → 'Check for updates'. If updates fail repeatedly: confirm internet connectivity and that the device is not behind an enterprise WSUS that is broken.",
        title_de=title_de,
        description_de="Microsoft veröffentlicht mehrmals täglich neue AV-Definitionen. Veraltete Signaturen bedeuten verpasste Erkennungen aktueller Malware.",
        remediation_de="Windows-Sicherheit → Viren- & Bedrohungsschutz → 'Nach Updates suchen'. Wenn Updates wiederholt fehlschlagen: Internetverbindung bestätigen und prüfen, dass das Gerät nicht hinter einem defekten Unternehmens-WSUS steht.",
        category_de=CATEGORY_DE,
        title_es=title_es,
        description_es="Microsoft publica nuevas definiciones de antivirus varias veces al día. Las firmas anticuadas significan detecciones perdidas de familias de malware recientes.",
        remediation_es="Seguridad de Windows → Protección contra virus y amenazas → 'Buscar actualizaciones'. Si las actualizaciones fallan repetidamente, confirma la conexión a internet y que el equipo no esté detrás de un WSUS corporativo averiado.",
        category_es=CATEGORY_ES,
    )


# --- 1.6 Tamper protection -------------------------------------------------

def _check_tamper_protection() -> Finding:
    r = run_ps("(Get-MpComputerStatus).IsTamperProtected")
    if not r.ok:
        return Finding(
            id="WIN-CAT01-006",
            title="Could not read Tamper Protection status",
            description="Tamper Protection prevents malware (or a misbehaving admin) from disabling Defender via registry/PowerShell.",
            category=CATEGORY,
            severity=Severity.MEDIUM,
            status=Status.ERROR,
            command=r.cmd,
            evidence=(r.stderr or r.exception)[:300],
            standards=("CIS Win11 18.10.42",),
            vector_ids=("M-04",),
            remediation="Windows Security → Virus & threat protection → manage settings → Tamper Protection → On.",
            title_de="Tamper-Protection-Status konnte nicht gelesen werden",
            description_de="Tamper Protection verhindert, dass Malware (oder ein fehlerhafter Admin) Defender per Registry/PowerShell deaktiviert.",
            remediation_de="Windows-Sicherheit → Viren- & Bedrohungsschutz → Einstellungen verwalten → Manipulationsschutz → Ein.",
            category_de=CATEGORY_DE,
            title_es="No se pudo leer el estado de la protección contra manipulación (Tamper Protection)",
            description_es="La protección contra manipulación (Tamper Protection) impide que el malware (o un administrador con mal comportamiento) desactive Defender vía registro/PowerShell.",
            remediation_es="Seguridad de Windows → Protección contra virus y amenazas → administrar configuración → Protección contra manipulaciones → Activada.",
            category_es=CATEGORY_ES,
        )

    enabled = "true" in r.stdout.lower()
    if enabled:
        return Finding(
            id="WIN-CAT01-006",
            title="Tamper Protection is enabled",
            description="Defender's anti-tampering protection is on.",
            category=CATEGORY,
            severity=Severity.HIGH,
            status=Status.PASS,
            command=r.cmd,
            evidence=r.stdout.strip(),
            standards=("CIS Win11 18.10.42",),
            vector_ids=("M-04",),
            remediation="No action.",
            title_de="Tamper Protection ist aktiviert",
            description_de="Der Manipulationsschutz von Defender ist eingeschaltet.",
            remediation_de="Keine Aktion nötig.",
            category_de=CATEGORY_DE,
            title_es="La protección contra manipulación (Tamper Protection) está activada",
            description_es="La protección antimanipulación de Defender está encendida.",
            remediation_es="Sin acción necesaria.",
            category_es=CATEGORY_ES,
        )

    return Finding(
        id="WIN-CAT01-006",
        title="Tamper Protection is DISABLED",
        description="Without Tamper Protection, malware with admin can silently turn off Defender's real-time protection. This is a known precursor in many ransomware playbooks.",
        category=CATEGORY,
        severity=Severity.HIGH,
        status=Status.FAIL,
        command=r.cmd,
        evidence=r.stdout.strip() or "(empty)",
        standards=("CIS Win11 18.10.42",),
        vector_ids=("M-04", "M-01"),
        remediation="Windows Security → Virus & threat protection → manage settings → toggle Tamper Protection on. (No reboot needed.)",
        title_de="Tamper Protection ist DEAKTIVIERT",
        description_de="Ohne Tamper Protection kann Malware mit Admin-Rechten Defenders Echtzeitschutz still abschalten. Bekannter Vorläufer in vielen Ransomware-Playbooks.",
        remediation_de="Windows-Sicherheit → Viren- & Bedrohungsschutz → Einstellungen verwalten → Manipulationsschutz einschalten. (Kein Neustart nötig.)",
        category_de=CATEGORY_DE,
        title_es="La protección contra manipulación (Tamper Protection) está DESACTIVADA",
        description_es="Sin la protección contra manipulación, el malware con permisos de administrador puede apagar silenciosamente la protección en tiempo real de Defender. Es un precursor conocido en muchos manuales de ransomware.",
        remediation_es="Seguridad de Windows → Protección contra virus y amenazas → administrar configuración → activa la Protección contra manipulaciones. (No requiere reinicio.)",
        category_es=CATEGORY_ES,
    )


# --- 1.7 Secure Boot --------------------------------------------------------

def _check_secure_boot() -> Finding:
    r = run_ps("try { (Confirm-SecureBootUEFI) } catch { 'NOT_UEFI: ' + $_.Exception.Message }")
    if not r.ok:
        return Finding(
            id="WIN-CAT01-007",
            title="Could not query Secure Boot",
            description="Confirms that the device boots only with firmware-trusted code.",
            category=CATEGORY,
            severity=Severity.MEDIUM,
            status=Status.ERROR,
            command=r.cmd,
            evidence=(r.stderr or r.exception)[:300],
            standards=("CIS Win11 18.10.5",),
            vector_ids=("F-01", "H-01"),
            remediation="Run `msinfo32` from Start; under System Summary look for 'Secure Boot State'. Should be 'On'.",
            title_de="Secure Boot konnte nicht abgefragt werden",
            description_de="Bestätigt, dass das Gerät nur mit firmware-vertrauten Code bootet.",
            remediation_de="Start → `msinfo32` → unter Systemübersicht nach 'Sicherer Startzustand' suchen. Sollte 'Ein' sein.",
            category_de=CATEGORY_DE,
            title_es="No se pudo consultar Secure Boot",
            description_es="Confirma que el equipo solo arranca con código de confianza del firmware.",
            remediation_es="Inicio → `msinfo32` → en Resumen del sistema busca 'Estado de arranque seguro'. Debería estar en 'Activado'.",
            category_es=CATEGORY_ES,
        )

    txt = r.stdout.strip()
    if "true" in txt.lower():
        return Finding(
            id="WIN-CAT01-007",
            title="Secure Boot is enabled",
            description="Firmware-level boot integrity is in place.",
            category=CATEGORY,
            severity=Severity.HIGH,
            status=Status.PASS,
            command=r.cmd,
            evidence=txt,
            standards=("CIS Win11 18.10.5",),
            vector_ids=("F-01", "H-01"),
            remediation="No action.",
            title_de="Secure Boot ist aktiviert",
            description_de="Boot-Integrität auf Firmware-Ebene ist gewährleistet.",
            remediation_de="Keine Aktion nötig.",
            category_de=CATEGORY_DE,
            title_es="Secure Boot está activado",
            description_es="La integridad de arranque a nivel de firmware está garantizada.",
            remediation_es="Sin acción necesaria.",
            category_es=CATEGORY_ES,
        )

    if "NOT_UEFI" in txt or "false" in txt.lower():
        is_legacy = "NOT_UEFI" in txt
        return Finding(
            id="WIN-CAT01-007",
            title="Secure Boot is DISABLED" + (" (system is using legacy BIOS, not UEFI)" if is_legacy else ""),
            description="Without Secure Boot, the device can be booted from compromised media (Evil Maid, malicious USB) loading code that runs before Windows.",
            category=CATEGORY,
            severity=Severity.HIGH,
            status=Status.FAIL,
            command=r.cmd,
            evidence=txt,
            standards=("CIS Win11 18.10.5",),
            vector_ids=("F-01", "H-01", "F-02"),
            remediation=("Reboot to UEFI (Settings → System → Recovery → Advanced startup → UEFI Firmware Settings) and enable Secure Boot. "
                         + ("This system appears to be in legacy BIOS mode — converting to UEFI requires repartitioning to GPT and is non-trivial." if is_legacy else "")),
            interim_mitigation="Until enabled: do not leave the device unattended in untrusted locations. Use a strong UEFI/BIOS password.",
            title_de="Secure Boot ist DEAKTIVIERT" + (" (System nutzt legacy BIOS, nicht UEFI)" if is_legacy else ""),
            description_de="Ohne Secure Boot kann das Gerät von kompromittierten Medien gebootet werden (Evil Maid, bösartiger USB), die Code laden, der vor Windows läuft.",
            remediation_de=("In UEFI neu starten (Einstellungen → System → Wiederherstellung → Erweiterter Start → UEFI-Firmware-Einstellungen) und Secure Boot aktivieren. "
                            + ("Dieses System scheint im legacy-BIOS-Modus zu sein — die Umstellung auf UEFI erfordert Repartitionierung auf GPT und ist nicht trivial." if is_legacy else "")),
            interim_mitigation_de="Bis zur Aktivierung: Gerät nicht unbeaufsichtigt an unsicheren Orten lassen. Starkes UEFI/BIOS-Passwort verwenden.",
            category_de=CATEGORY_DE,
            title_es="Secure Boot está DESACTIVADO" + (" (el sistema usa BIOS heredada, no UEFI)" if is_legacy else ""),
            description_es="Sin Secure Boot, el equipo puede arrancar desde medios comprometidos (Evil Maid, USB malicioso) que cargan código antes que Windows.",
            remediation_es=("Reinicia en UEFI (Configuración → Sistema → Recuperación → Inicio avanzado → Configuración de firmware UEFI) y activa Secure Boot. "
                            + ("Este sistema parece estar en modo BIOS heredada — convertirlo a UEFI requiere reparticionar a GPT y no es trivial." if is_legacy else "")),
            interim_mitigation_es="Hasta activarlo: no dejes el equipo sin vigilancia en lugares no confiables. Usa una contraseña fuerte de UEFI/BIOS.",
            category_es=CATEGORY_ES,
        )

    return Finding(
        id="WIN-CAT01-007",
        title="Secure Boot status: inconclusive",
        description="The Secure Boot query returned an unexpected value.",
        category=CATEGORY,
        severity=Severity.MEDIUM,
        status=Status.WARN,
        command=r.cmd,
        evidence=txt or "(empty)",
        standards=("CIS Win11 18.10.5",),
        vector_ids=("F-01",),
        remediation="Verify manually with `msinfo32` → Secure Boot State.",
        title_de="Secure-Boot-Status: nicht eindeutig",
        description_de="Die Secure-Boot-Abfrage lieferte einen unerwarteten Wert.",
        remediation_de="Manuell mit `msinfo32` → Sicherer Startzustand prüfen.",
        category_de=CATEGORY_DE,
        title_es="Estado de Secure Boot: no concluyente",
        description_es="La consulta de Secure Boot devolvió un valor inesperado.",
        remediation_es="Verifica manualmente con `msinfo32` → Estado de arranque seguro.",
        category_es=CATEGORY_ES,
    )


# --- 1.8 BitLocker ----------------------------------------------------------

def _check_bitlocker() -> Finding:
    # Try Get-BitLockerVolume first (richest data), then fall back to the WMI
    # Win32_EncryptableVolume class which is readable without admin on most
    # Win10/11 builds. Force enums to strings for clean parsing.
    r = run_ps(
        "$out = $null; "
        "try { "
        "  $out = Get-BitLockerVolume -ErrorAction Stop | "
        "    Select-Object MountPoint, "
        "      @{N='VolumeStatus';E={$_.VolumeStatus.ToString()}}, "
        "      @{N='ProtectionStatus';E={$_.ProtectionStatus.ToString()}}, "
        "      @{N='EncryptionMethod';E={$_.EncryptionMethod.ToString()}}, "
        "      EncryptionPercentage "
        "} catch { "
        "  $out = Get-CimInstance -Namespace 'root/cimv2/security/microsoftvolumeencryption' "
        "    -ClassName Win32_EncryptableVolume -ErrorAction SilentlyContinue | "
        "    Select-Object @{N='MountPoint';E={$_.DriveLetter}}, "
        "      @{N='ProtectionStatus';E={ if ($_.ProtectionStatus -eq 1) { 'On' } elseif ($_.ProtectionStatus -eq 0) { 'Off' } else { 'Unknown' } }}, "
        "      @{N='VolumeStatus';E={ if ($_.ConversionStatus -eq 1) { 'FullyEncrypted' } elseif ($_.ConversionStatus -eq 0) { 'FullyDecrypted' } else { 'Partial' } }}, "
        "      @{N='EncryptionMethod';E={$_.EncryptionMethod}} "
        "}; "
        "$out | ConvertTo-Json -Compress"
    )
    if not r.ok or not r.stdout.strip():
        return Finding(
            id="WIN-CAT01-008",
            title="BitLocker status unavailable (likely needs elevation)",
            description="Verifies that the OS volume is encrypted at rest.",
            category=CATEGORY,
            severity=Severity.HIGH,
            status=Status.ERROR,
            command=r.cmd,
            evidence=(r.stderr or r.exception or "(empty)")[:300],
            standards=("CIS Win11 18.9.13",),
            vector_ids=("F-03", "F-05"),
            remediation="Open Settings → Privacy & Security → Device encryption (or Control Panel → BitLocker Drive Encryption) — confirm the OS drive shows 'On'.",
            title_de="BitLocker-Status nicht abrufbar (vermutlich Adminrechte nötig)",
            description_de="Prüft, dass das OS-Volume verschlüsselt ist.",
            remediation_de="Einstellungen → Datenschutz & Sicherheit → Geräteverschlüsselung (oder Systemsteuerung → BitLocker-Laufwerkverschlüsselung) — bestätige, dass das OS-Laufwerk 'Ein' zeigt.",
            category_de=CATEGORY_DE,
            title_es="Estado de BitLocker no disponible (probablemente requiere elevación)",
            description_es="Verifica que el volumen del sistema operativo esté cifrado en reposo.",
            remediation_es="Configuración → Privacidad y seguridad → Cifrado de dispositivo (o Panel de control → Cifrado de unidad BitLocker) — confirma que la unidad del sistema muestre 'Activado'.",
            category_es=CATEGORY_ES,
        )

    try:
        data = json.loads(r.stdout.strip())
        if isinstance(data, dict):
            data = [data]
    except json.JSONDecodeError:
        data = []

    os_vol = next((v for v in data if str(v.get("MountPoint", "")).upper().startswith("C:")), None)
    if not os_vol:
        return Finding(
            id="WIN-CAT01-008",
            title="No OS volume returned by BitLocker query",
            description="Could not identify the OS volume in BitLocker output.",
            category=CATEGORY,
            severity=Severity.MEDIUM,
            status=Status.WARN,
            command=r.cmd,
            evidence=json.dumps(data, indent=2)[:600],
            standards=("CIS Win11 18.9.13",),
            vector_ids=("F-03",),
            remediation="Open Control Panel → BitLocker Drive Encryption manually.",
            title_de="Kein OS-Volume in BitLocker-Ausgabe",
            description_de="OS-Volume in BitLocker-Ausgabe nicht identifizierbar.",
            remediation_de="Systemsteuerung → BitLocker-Laufwerkverschlüsselung manuell öffnen.",
            category_de=CATEGORY_DE,
            title_es="La consulta de BitLocker no devolvió un volumen del sistema",
            description_es="No se pudo identificar el volumen del sistema operativo en la salida de BitLocker.",
            remediation_es="Abre manualmente Panel de control → Cifrado de unidad BitLocker.",
            category_es=CATEGORY_ES,
        )

    protected = os_vol.get("ProtectionStatus") in (1, "On")
    fully_encrypted = str(os_vol.get("VolumeStatus", "")).lower() == "fullyencrypted"

    if protected and fully_encrypted:
        return Finding(
            id="WIN-CAT01-008",
            title="BitLocker is enabled and protecting the OS volume",
            description="OS volume is fully encrypted with active key protectors.",
            category=CATEGORY,
            severity=Severity.HIGH,
            status=Status.PASS,
            command=r.cmd,
            evidence=json.dumps(os_vol, indent=2),
            standards=("CIS Win11 18.9.13",),
            vector_ids=("F-03", "F-05"),
            remediation="No action. Verify your recovery key is stored somewhere YOU control (not just in your Microsoft account, if account is shared).",
            title_de="BitLocker ist aktiviert und schützt das OS-Volume",
            description_de="OS-Volume ist vollständig verschlüsselt mit aktiven Schlüsselschutz.",
            remediation_de="Keine Aktion nötig. Bestätige, dass dein Wiederherstellungsschlüssel an einem Ort gespeichert ist, den DU kontrollierst (nicht nur im Microsoft-Konto, falls es geteilt wird).",
            category_de=CATEGORY_DE,
            title_es="BitLocker está activado y protege el volumen del sistema",
            description_es="El volumen del sistema está completamente cifrado con protectores de clave activos.",
            remediation_es="Sin acción necesaria. Confirma que tu clave de recuperación esté guardada en un lugar que TÚ controlas (no solo en tu cuenta de Microsoft, si esa cuenta es compartida).",
            category_es=CATEGORY_ES,
        )

    return Finding(
        id="WIN-CAT01-008",
        title=f"BitLocker not fully protecting the OS volume (Protection={os_vol.get('ProtectionStatus')}, Volume={os_vol.get('VolumeStatus')})",
        description="The OS volume is either not encrypted, partially encrypted, or has protection suspended. Anyone with physical access can read your files.",
        category=CATEGORY,
        severity=Severity.CRITICAL,
        status=Status.FAIL,
        command=r.cmd,
        evidence=json.dumps(os_vol, indent=2),
        standards=("CIS Win11 18.9.13",),
        vector_ids=("F-03", "F-05"),
        remediation="Control Panel → BitLocker Drive Encryption → Turn on BitLocker for the OS drive. Save the recovery key to a location ONLY you control (printout in safe + password manager — NOT in plain text on the same device).",
        interim_mitigation="If you cannot enable BitLocker right now (e.g. no TPM, edition limitation): keep the device powered off when not in use, never leave it unlocked unattended, and back up everything important to an encrypted external drive.",
        title_de=f"BitLocker schützt das OS-Volume nicht vollständig (Protection={os_vol.get('ProtectionStatus')}, Volume={os_vol.get('VolumeStatus')})",
        description_de="Das OS-Volume ist entweder nicht verschlüsselt, teilweise verschlüsselt oder der Schutz ist ausgesetzt. Jede Person mit physischem Zugriff kann deine Dateien lesen.",
        remediation_de="Systemsteuerung → BitLocker-Laufwerkverschlüsselung → BitLocker für das OS-Laufwerk aktivieren. Wiederherstellungsschlüssel an einem Ort speichern, den NUR du kontrollierst (Ausdruck im Tresor + Passwort-Manager — NICHT im Klartext auf demselben Gerät).",
        interim_mitigation_de="Wenn BitLocker jetzt nicht aktivierbar ist (kein TPM, Editions-Einschränkung): Gerät bei Nichtnutzung ausgeschaltet halten, nie entsperrt unbeaufsichtigt lassen, alles Wichtige auf einer verschlüsselten externen Festplatte sichern.",
        category_de=CATEGORY_DE,
        title_es=f"BitLocker no protege completamente el volumen del sistema (Protection={os_vol.get('ProtectionStatus')}, Volume={os_vol.get('VolumeStatus')})",
        description_es="El volumen del sistema no está cifrado, está cifrado parcialmente o tiene la protección suspendida. Cualquier persona con acceso físico puede leer tus archivos.",
        remediation_es="Panel de control → Cifrado de unidad BitLocker → Activa BitLocker para la unidad del sistema. Guarda la clave de recuperación en un lugar que SOLO tú controlas (impresión en una caja fuerte + gestor de contraseñas — NUNCA en texto plano en el mismo equipo).",
        interim_mitigation_es="Si no puedes activar BitLocker ahora mismo (sin TPM, limitación de edición): mantén el equipo apagado cuando no lo uses, nunca lo dejes desbloqueado sin vigilancia, y respalda todo lo importante en un disco externo cifrado.",
        category_es=CATEGORY_ES,
    )


# --- 1.9 TPM ----------------------------------------------------------------

def _check_tpm() -> Finding:
    r = run_ps("Get-Tpm | Select-Object TpmPresent, TpmReady, TpmEnabled, TpmActivated, ManufacturerVersion, ManufacturerVersionInfo | ConvertTo-Json -Compress")
    if not r.ok:
        return Finding(
            id="WIN-CAT01-009",
            title="Could not query TPM",
            description="TPM (Trusted Platform Module) anchors BitLocker, Credential Guard, and Windows Hello.",
            category=CATEGORY,
            severity=Severity.HIGH,
            status=Status.ERROR,
            command=r.cmd,
            evidence=(r.stderr or r.exception)[:300],
            standards=("CIS Win11 18.9",),
            vector_ids=("F-03", "H-01"),
            remediation="Run `tpm.msc` from Start to inspect TPM state manually.",
            title_de="TPM konnte nicht abgefragt werden",
            description_de="TPM (Trusted Platform Module) ist die Vertrauensbasis für BitLocker, Credential Guard und Windows Hello.",
            remediation_de="Start → `tpm.msc` ausführen, um den TPM-Status manuell zu prüfen.",
            category_de=CATEGORY_DE,
            title_es="No se pudo consultar el TPM",
            description_es="El TPM (Trusted Platform Module) es la base de confianza para BitLocker, Credential Guard y Windows Hello.",
            remediation_es="Ejecuta `tpm.msc` desde Inicio para inspeccionar el estado del TPM manualmente.",
            category_es=CATEGORY_ES,
        )

    try:
        d = json.loads(r.stdout.strip())
    except json.JSONDecodeError:
        d = {}

    present = d.get("TpmPresent") in (True, "True")
    ready = d.get("TpmReady") in (True, "True")
    enabled = d.get("TpmEnabled") in (True, "True")

    if present and ready and enabled:
        return Finding(
            id="WIN-CAT01-009",
            title="TPM is present, enabled and ready",
            description="The TPM is in a usable state to anchor disk encryption and credential protection.",
            category=CATEGORY,
            severity=Severity.HIGH,
            status=Status.PASS,
            command=r.cmd,
            evidence=json.dumps(d, indent=2),
            standards=("CIS Win11 18.9",),
            vector_ids=("F-03", "H-01"),
            remediation="No action.",
            title_de="TPM ist vorhanden, aktiviert und einsatzbereit",
            description_de="Der TPM ist in nutzbarem Zustand als Vertrauensbasis für Festplattenverschlüsselung und Credential-Schutz.",
            remediation_de="Keine Aktion nötig.",
            category_de=CATEGORY_DE,
            title_es="El TPM está presente, activado y listo",
            description_es="El TPM está en un estado utilizable como base de confianza para el cifrado de disco y la protección de credenciales.",
            remediation_es="Sin acción necesaria.",
            category_es=CATEGORY_ES,
        )

    if not present:
        return Finding(
            id="WIN-CAT01-009",
            title="No TPM detected",
            description="Without a TPM, BitLocker has to rely on a USB key or password (less convenient, easier to mishandle), and Credential Guard cannot run.",
            category=CATEGORY,
            severity=Severity.HIGH,
            status=Status.FAIL,
            command=r.cmd,
            evidence=json.dumps(d, indent=2),
            standards=("CIS Win11 18.9",),
            vector_ids=("F-03", "H-01"),
            remediation="If hardware has a TPM but it is disabled, enable it in UEFI Setup (often labelled 'TPM', 'PTT' for Intel, 'fTPM' for AMD). If hardware lacks TPM entirely, plan device replacement for a model with TPM 2.0.",
            title_de="Kein TPM erkannt",
            description_de="Ohne TPM muss BitLocker auf USB-Schlüssel oder Passwort zurückgreifen (weniger bequem, fehleranfälliger), und Credential Guard kann nicht laufen.",
            remediation_de="Wenn die Hardware einen TPM hat, aber deaktiviert ist: In UEFI-Setup aktivieren (oft als 'TPM', 'PTT' bei Intel, 'fTPM' bei AMD bezeichnet). Wenn keine TPM-Hardware vorhanden ist: Gerätewechsel zu einem Modell mit TPM 2.0 planen.",
            category_de=CATEGORY_DE,
            title_es="No se detectó ningún TPM",
            description_es="Sin TPM, BitLocker tiene que depender de una llave USB o contraseña (menos cómodo, más propenso a errores), y Credential Guard no puede ejecutarse.",
            remediation_es="Si el hardware tiene un TPM pero está desactivado, actívalo en la configuración UEFI (a menudo etiquetado como 'TPM', 'PTT' en Intel, 'fTPM' en AMD). Si el hardware carece de TPM por completo, planifica el reemplazo del equipo por un modelo con TPM 2.0.",
            category_es=CATEGORY_ES,
        )

    return Finding(
        id="WIN-CAT01-009",
        title="TPM present but not in a fully ready state",
        description=f"TpmPresent={present} TpmReady={ready} TpmEnabled={enabled} — the TPM exists but is not fully operational.",
        category=CATEGORY,
        severity=Severity.HIGH,
        status=Status.WARN,
        command=r.cmd,
        evidence=json.dumps(d, indent=2),
        standards=("CIS Win11 18.9",),
        vector_ids=("F-03", "H-01"),
        remediation="Run `tpm.msc` and click 'Prepare the TPM'. If it fails, check UEFI for TPM enablement.",
        title_de="TPM vorhanden, aber nicht voll einsatzbereit",
        description_de=f"TpmPresent={present} TpmReady={ready} TpmEnabled={enabled} — der TPM existiert, ist aber nicht voll funktionsfähig.",
        remediation_de="`tpm.msc` ausführen und 'TPM vorbereiten' klicken. Wenn es fehlschlägt: UEFI auf TPM-Aktivierung prüfen.",
        category_de=CATEGORY_DE,
        title_es="TPM presente, pero no completamente listo",
        description_es=f"TpmPresent={present} TpmReady={ready} TpmEnabled={enabled} — el TPM existe, pero no está completamente operativo.",
        remediation_es="Ejecuta `tpm.msc` y haz clic en 'Preparar el TPM'. Si falla, revisa en la UEFI que el TPM esté habilitado.",
        category_es=CATEGORY_ES,
    )


# --- 1.10 Credential Guard / VBS -------------------------------------------

def _check_credential_guard() -> Finding:
    # SecurityServicesRunning: 1 = Credential Guard, 2 = HVCI, 3 = SystemGuard
    r = run_ps(
        "$d = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\\Microsoft\\Windows\\DeviceGuard -ErrorAction SilentlyContinue; "
        "if ($d) { [PSCustomObject]@{ "
        "  VirtualizationBasedSecurityStatus = $d.VirtualizationBasedSecurityStatus; "
        "  SecurityServicesConfigured = ($d.SecurityServicesConfigured -join ','); "
        "  SecurityServicesRunning = ($d.SecurityServicesRunning -join ','); "
        "} | ConvertTo-Json -Compress } else { 'NOT_AVAILABLE' }"
    )
    if not r.ok or "NOT_AVAILABLE" in r.stdout:
        return Finding(
            id="WIN-CAT01-010",
            title="VBS / Credential Guard query unavailable",
            description="Verifies that Virtualization-Based Security and Credential Guard are running. Requires Win10/11 Pro or Enterprise.",
            category=CATEGORY,
            severity=Severity.MEDIUM,
            status=Status.SKIP,
            command=r.cmd,
            evidence=(r.stderr or r.stdout or "(no DeviceGuard CIM class — likely Home edition)")[:300],
            standards=("CIS Win11 18.9.5",),
            vector_ids=("A-01", "A-04"),
            remediation="VBS and Credential Guard are Pro/Enterprise features. On Home edition, this check does not apply.",
            title_de="VBS/Credential Guard nicht abfragbar",
            description_de="Prüft, ob Virtualization-Based Security und Credential Guard laufen. Erfordert Win10/11 Pro oder Enterprise.",
            remediation_de="VBS und Credential Guard sind Pro/Enterprise-Funktionen. Bei Home-Edition trifft diese Prüfung nicht zu.",
            category_de=CATEGORY_DE,
            title_es="Consulta de VBS / Credential Guard no disponible",
            description_es="Verifica que la Seguridad basada en virtualización (VBS) y Credential Guard estén en ejecución. Requiere Win10/11 Pro o Enterprise.",
            remediation_es="VBS y Credential Guard son funciones de Pro/Enterprise. En la edición Home, esta verificación no aplica.",
            category_es=CATEGORY_ES,
        )

    try:
        d = json.loads(r.stdout.strip())
    except json.JSONDecodeError:
        d = {}

    vbs_status = int(d.get("VirtualizationBasedSecurityStatus", 0))
    running_csv = str(d.get("SecurityServicesRunning", ""))
    cred_guard_running = "1" in running_csv.split(",")

    if vbs_status == 2 and cred_guard_running:
        return Finding(
            id="WIN-CAT01-010",
            title="VBS and Credential Guard are running",
            description="Hypervisor-protected isolation is active and protecting credentials from in-memory theft.",
            category=CATEGORY,
            severity=Severity.HIGH,
            status=Status.PASS,
            command=r.cmd,
            evidence=json.dumps(d, indent=2),
            standards=("CIS Win11 18.9.5",),
            vector_ids=("A-01", "A-04"),
            remediation="No action.",
            title_de="VBS und Credential Guard laufen",
            description_de="Hypervisor-geschützte Isolation ist aktiv und schützt Credentials vor In-Memory-Diebstahl.",
            remediation_de="Keine Aktion nötig.",
            category_de=CATEGORY_DE,
            title_es="VBS y Credential Guard están en ejecución",
            description_es="El aislamiento protegido por el hipervisor está activo y protege las credenciales del robo en memoria.",
            remediation_es="Sin acción necesaria.",
            category_es=CATEGORY_ES,
        )

    return Finding(
        id="WIN-CAT01-010",
        title=f"VBS/Credential Guard not fully active (VBS={vbs_status}, running={running_csv or 'none'})",
        description="Without Credential Guard, in-memory credential theft (Mimikatz-style) is much easier for an attacker who reaches your machine.",
        category=CATEGORY,
        severity=Severity.MEDIUM,
        status=Status.WARN,
        command=r.cmd,
        evidence=json.dumps(d, indent=2),
        standards=("CIS Win11 18.9.5",),
        vector_ids=("A-01", "A-04"),
        remediation="Settings → Privacy & Security → Windows Security → Device security → Core isolation → enable Memory integrity and Credential Guard. Reboot. Requires VT-x/AMD-V enabled in UEFI.",
        title_de=f"VBS/Credential Guard nicht voll aktiv (VBS={vbs_status}, läuft={running_csv or 'keine'})",
        description_de="Ohne Credential Guard ist In-Memory-Credential-Diebstahl (Mimikatz-Stil) für Angreifer mit Zugriff auf deine Maschine deutlich einfacher.",
        remediation_de="Einstellungen → Datenschutz & Sicherheit → Windows-Sicherheit → Gerätesicherheit → Kernisolierung → Speicherintegrität und Credential Guard aktivieren. Neu starten. Erfordert VT-x/AMD-V im UEFI aktiviert.",
        category_de=CATEGORY_DE,
        title_es=f"VBS/Credential Guard no completamente activos (VBS={vbs_status}, en ejecución={running_csv or 'ninguno'})",
        description_es="Sin Credential Guard, el robo de credenciales en memoria (estilo Mimikatz) es mucho más fácil para un atacante que llega a tu máquina.",
        remediation_es="Configuración → Privacidad y seguridad → Seguridad de Windows → Seguridad del dispositivo → Aislamiento del núcleo → activa Integridad de memoria y Credential Guard. Reinicia. Requiere VT-x/AMD-V habilitado en la UEFI.",
        category_es=CATEGORY_ES,
    )


# --- 1.11 Third-party browsers ---------------------------------------------

_BROWSER_PATHS = [
    (r"C:\Program Files\Google\Chrome\Application\chrome.exe", "Google Chrome"),
    (r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe", "Google Chrome (x86)"),
    (r"C:\Program Files\Mozilla Firefox\firefox.exe", "Firefox"),
    (r"C:\Program Files (x86)\Mozilla Firefox\firefox.exe", "Firefox (x86)"),
    (r"C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe", "Brave"),
    (r"C:\Program Files\Microsoft\Edge\Application\msedge.exe", "Microsoft Edge"),
    (r"C:\Users\*\AppData\Local\Programs\Tor Browser\Browser\firefox.exe", "Tor Browser"),
]


def _check_third_party_browsers() -> Finding:
    found = []
    for path, name in _BROWSER_PATHS:
        # Use PowerShell to check existence + read FileVersionInfo
        ps = (
            f"$p = '{path}'; "
            "if ($p -like '*\\*\\*' -and $p.Contains('*')) { "
            "  $items = Get-ChildItem $p -ErrorAction SilentlyContinue "
            "} else { "
            "  $items = if (Test-Path $p) { Get-Item $p } else { @() } "
            "}; "
            "$items | ForEach-Object { "
            "  [PSCustomObject]@{ Path = $_.FullName; Version = $_.VersionInfo.FileVersion } "
            "} | ConvertTo-Json -Compress -Depth 3"
        )
        r = run_ps(ps, timeout=10)
        if r.ok and r.stdout.strip() and r.stdout.strip() != "null":
            try:
                data = json.loads(r.stdout.strip())
                if isinstance(data, dict):
                    data = [data]
                for it in data:
                    found.append((name, it.get("Version", "?"), it.get("Path", path)))
            except json.JSONDecodeError:
                pass

    if not found:
        return Finding(
            id="WIN-CAT01-011",
            title="No third-party browsers detected",
            description="Only the system-shipped browser (Microsoft Edge) appears to be installed.",
            category=CATEGORY,
            severity=Severity.LOW,
            status=Status.PASS,
            command="(filesystem inspection)",
            evidence="No matches in known browser install paths.",
            standards=("CIS Win11 1.4",),
            vector_ids=("W-02", "W-04"),
            remediation="No action.",
            title_de="Keine Drittanbieter-Browser erkannt",
            description_de="Nur der mitgelieferte Browser (Microsoft Edge) scheint installiert.",
            remediation_de="Keine Aktion nötig.",
            category_de=CATEGORY_DE,
            title_es="No se detectaron navegadores de terceros",
            description_es="Solo parece estar instalado el navegador que viene con el sistema (Microsoft Edge).",
            remediation_es="Sin acción necesaria.",
            category_es=CATEGORY_ES,
        )

    return Finding(
        id="WIN-CAT01-011",
        title=f"{len(found)} third-party browser install(s) — verify each is current",
        description="Browsers are the most common entry point for drive-by exploits. Each must be updated independently of Windows.",
        category=CATEGORY,
        severity=Severity.MEDIUM,
        status=Status.WARN,
        command="(filesystem inspection)",
        evidence="\n".join(f"{n}: {v}  ({p})" for n, v, p in found),
        standards=("CIS Win11 1.4", "NIST CSF"),
        vector_ids=("W-02", "W-04", "W-06"),
        remediation="Open each browser → About → confirm latest stable. Enable auto-update in each (Chrome/Edge/Brave do this by default; Firefox needs Settings → Updates).",
        interim_mitigation="If a browser cannot be updated immediately, switch to Edge (which updates with Windows) for sensitive browsing until you can.",
        title_de=f"{len(found)} Drittanbieter-Browser-Installation(en) — bitte aktuelle Version prüfen",
        description_de="Browser sind der häufigste Einstiegspunkt für Drive-by-Exploits. Jeder muss unabhängig von Windows aktualisiert werden.",
        remediation_de="Jeden Browser öffnen → Über/About → die aktuellste Stable-Version bestätigen. Auto-Updates in jedem aktivieren (Chrome/Edge/Brave standardmäßig; Firefox braucht Einstellungen → Updates).",
        interim_mitigation_de="Wenn ein Browser nicht sofort aktualisierbar ist: für sensibles Browsing vorübergehend Edge nutzen (wird mit Windows aktualisiert).",
        category_de=CATEGORY_DE,
        title_es=f"{len(found)} instalación(es) de navegadores de terceros — verifica que cada uno esté actualizado",
        description_es="Los navegadores son el punto de entrada más común para los exploits drive-by. Cada uno debe actualizarse de forma independiente a Windows.",
        remediation_es="Abre cada navegador → Acerca de → confirma la última versión estable. Activa la actualización automática en cada uno (Chrome/Edge/Brave lo hacen por defecto; Firefox requiere Configuración → Actualizaciones).",
        interim_mitigation_es="Si un navegador no se puede actualizar de inmediato, cambia a Edge (que se actualiza con Windows) para la navegación sensible mientras tanto.",
        category_es=CATEGORY_ES,
    )


# --- 1.12 winget outdated --------------------------------------------------

def _check_winget_outdated() -> Finding:
    r = run_cmd(["winget", "--version"], timeout=10)
    if not r.ok:
        return Finding(
            id="WIN-CAT01-012",
            title="winget not available — third-party app updates not auditable",
            description="winget is the modern Windows package manager. Without it we cannot list outdated third-party apps automatically.",
            category=CATEGORY,
            severity=Severity.INFO,
            status=Status.SKIP,
            command=r.cmd,
            evidence=(r.stderr or r.exception or "command not found")[:300],
            standards=("NIST CSF",),
            vector_ids=("C-03",),
            remediation="winget ships with Windows 11 and recent Win10. If missing, install 'App Installer' from Microsoft Store.",
            title_de="winget nicht verfügbar — Updates für Drittanbieter-Apps nicht prüfbar",
            description_de="winget ist der moderne Windows-Paketmanager. Ohne ihn können wir veraltete Drittanbieter-Apps nicht automatisch auflisten.",
            remediation_de="winget ist bei Windows 11 und neueren Win10 dabei. Falls fehlend: 'App-Installer' aus dem Microsoft Store installieren.",
            category_de=CATEGORY_DE,
            title_es="winget no disponible — no se pueden auditar las actualizaciones de apps de terceros",
            description_es="winget es el gestor de paquetes moderno de Windows. Sin él no podemos listar automáticamente las apps de terceros desactualizadas.",
            remediation_es="winget viene con Windows 11 y con Win10 recientes. Si falta, instala 'Instalador de aplicaciones' desde Microsoft Store.",
            category_es=CATEGORY_ES,
        )

    r2 = run_cmd(["winget", "upgrade", "--accept-source-agreements"], timeout=120)
    txt = (r2.stdout + r2.stderr).strip()
    # Header line + each app
    lines = [ln for ln in txt.splitlines() if ln.strip()]
    # Heuristic: count lines after the table header that don't start with 'Name'
    pkg_lines = []
    seen_header = False
    for ln in lines:
        if ln.lower().startswith("name") and "version" in ln.lower():
            seen_header = True
            continue
        if seen_header and not ln.startswith("-") and "upgrades available" not in ln.lower():
            pkg_lines.append(ln)

    if not pkg_lines:
        return Finding(
            id="WIN-CAT01-012",
            title="All winget-tracked apps are up to date",
            description="winget reports no available upgrades.",
            category=CATEGORY,
            severity=Severity.MEDIUM,
            status=Status.PASS,
            command=r2.cmd,
            evidence=txt[:600],
            standards=("NIST CSF",),
            vector_ids=("C-03",),
            remediation="No action.",
            title_de="Alle von winget verwalteten Apps sind aktuell",
            description_de="winget meldet keine verfügbaren Upgrades.",
            remediation_de="Keine Aktion nötig.",
            category_de=CATEGORY_DE,
            title_es="Todas las apps gestionadas por winget están actualizadas",
            description_es="winget no reporta upgrades disponibles.",
            remediation_es="Sin acción necesaria.",
            category_es=CATEGORY_ES,
        )

    return Finding(
        id="WIN-CAT01-012",
        title=f"~{len(pkg_lines)} winget-tracked app(s) have updates available",
        description="Outdated third-party apps may include security-relevant packages (browsers, runtimes, comms tools).",
        category=CATEGORY,
        severity=Severity.MEDIUM,
        status=Status.FAIL,
        command=r2.cmd,
        evidence=txt[:2000],
        standards=("NIST CSF", "CIS Win11"),
        vector_ids=("C-03",),
        remediation="Run `winget upgrade --all --accept-source-agreements --accept-package-agreements` in PowerShell. For high-risk profiles, prioritize: any browser, Zoom, Slack, Signal, OpenSSL, .NET runtime, VPN clients.",
        title_de=f"~{len(pkg_lines)} von winget verwaltete App(s) haben Updates verfügbar",
        description_de="Veraltete Drittanbieter-Apps können sicherheitsrelevante Pakete enthalten (Browser, Laufzeitumgebungen, Kommunikationstools).",
        remediation_de="`winget upgrade --all --accept-source-agreements --accept-package-agreements` in PowerShell ausführen. Bei Hochrisiko-Profilen priorisieren: Browser, Zoom, Slack, Signal, OpenSSL, .NET-Laufzeit, VPN-Clients.",
        category_de=CATEGORY_DE,
        title_es=f"~{len(pkg_lines)} app(s) gestionada(s) por winget tienen actualizaciones disponibles",
        description_es="Las apps de terceros desactualizadas pueden incluir paquetes relevantes para la seguridad (navegadores, entornos de ejecución, herramientas de comunicación).",
        remediation_es="Ejecuta `winget upgrade --all --accept-source-agreements --accept-package-agreements` en PowerShell. En perfiles de alto riesgo, prioriza: cualquier navegador, Zoom, Slack, Signal, OpenSSL, runtime de .NET, clientes VPN.",
        category_es=CATEGORY_ES,
    )
