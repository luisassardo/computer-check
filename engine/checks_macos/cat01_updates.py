"""CAT-1: OS & Updates checks for macOS.

Mirrors items 1.1–1.10 of Luis's Marco de Seguridad MACOS v1.0, with adaptations
for full automation and high-risk user defaults.

All checks are read-only and do not require sudo.
Items needing sudo or recoveryOS access (e.g. bputil for Secure Boot detail)
return Status.SKIP with clear instructions.
"""
from __future__ import annotations

import os
import re
from pathlib import Path

from ..core import Finding, ScanContext, Severity, Status, run_cmd, safe_check

CATEGORY = "CAT-1: OS & Updates"
CATEGORY_DE = "CAT-1: System & Updates"
CATEGORY_ES = "CAT-1: Sistema y actualizaciones"


def run(ctx: ScanContext) -> list[Finding]:
    """Each check is isolated so a crash in one does not kill the rest."""
    out: list[Finding] = []
    out.append(safe_check("MACOS-CAT01-001", CATEGORY, _check_macos_version, ctx))
    out.append(safe_check("MACOS-CAT01-002", CATEGORY, _check_auto_security_updates))
    out.append(safe_check("MACOS-CAT01-003", CATEGORY, _check_sip))
    out.append(safe_check("MACOS-CAT01-004", CATEGORY, _check_gatekeeper))
    out.append(safe_check("MACOS-CAT01-005", CATEGORY, _check_xprotect_signatures))
    out.append(safe_check("MACOS-CAT01-006", CATEGORY, _check_kernel_extensions))
    out.append(safe_check("MACOS-CAT01-007", CATEGORY, _check_system_extensions))
    out.append(safe_check("MACOS-CAT01-008", CATEGORY, _check_pending_software_updates))
    out.append(safe_check("MACOS-CAT01-009", CATEGORY, _check_brew_outdated))
    out.append(safe_check("MACOS-CAT01-010", CATEGORY, _check_third_party_browsers))
    out.append(safe_check("MACOS-CAT01-011", CATEGORY, _check_secure_boot_note, ctx))
    return out


# --- 1.1 macOS version ------------------------------------------------------

# Minimum versions still receiving full security support from Apple as of 2026.
# When this changes, update this constant. Apple supports current + 2 prior majors.
MACOS_SUPPORTED_MAJORS = {26, 25, 15}  # Tahoe (26), Sequoia (15), Sonoma (14 unsupported)


def _check_macos_version(ctx: ScanContext) -> Finding:
    r_prod = run_cmd(["sw_vers", "-productVersion"])
    r_build = run_cmd(["sw_vers", "-buildVersion"])
    version = r_prod.stdout.strip() or "unknown"
    build = r_build.stdout.strip() or "unknown"
    major = _major(version)

    if major is None:
        return Finding(
            id="MACOS-CAT01-001",
            title="macOS version: could not parse",
            description="Determines whether macOS is on a version still receiving security updates.",
            category=CATEGORY,
            severity=Severity.MEDIUM,
            status=Status.ERROR,
            command=r_prod.cmd,
            evidence=f"productVersion={version!r} buildVersion={build!r}",
            standards=("CIS L1 1.1", "Apple Platform Security"),
            vector_ids=("O-01", "O-02"),
            remediation="Run `sw_vers` manually and report the output.",
            title_es="Versión de macOS: no se pudo determinar",
            description_es="Determina si macOS está en una versión que aún recibe actualizaciones de seguridad.",
            remediation_es="Ejecuta `sw_vers` manualmente y reporta el resultado.",
            category_es=CATEGORY_ES,
        )

    if major in MACOS_SUPPORTED_MAJORS:
        return Finding(
            id="MACOS-CAT01-001",
            title=f"macOS {version} is on a supported major version",
            description="Apple typically provides security updates for the current macOS plus the two prior majors. Your version is within that window.",
            category=CATEGORY,
            severity=Severity.HIGH,
            status=Status.PASS,
            command=r_prod.cmd,
            evidence=f"productVersion={version}\nbuildVersion={build}",
            standards=("CIS L1 1.1", "Apple Platform Security"),
            vector_ids=("O-01", "O-02"),
            remediation="No action. Continue to install point releases as Apple publishes them.",
            references=("https://support.apple.com/en-us/100100",),
            title_de=f"macOS {version} ist eine unterstützte Hauptversion",
            description_de="Apple liefert Sicherheitsupdates für die aktuelle macOS-Version sowie die beiden vorherigen Hauptversionen. Deine Version liegt in diesem Fenster.",
            remediation_de="Keine Aktion nötig. Installiere weiterhin Point-Releases, sobald Apple sie veröffentlicht.",
            category_de=CATEGORY_DE,
            title_es=f"macOS {version} está en una versión principal con soporte",
            description_es="Apple entrega actualizaciones de seguridad para la versión actual de macOS y las dos anteriores. Tu versión está dentro de ese rango.",
            remediation_es="Sin acción necesaria. Sigue instalando las versiones menores conforme Apple las publique.",
            category_es=CATEGORY_ES,
        )

    # Representative recent CVEs that affect older macOS majors and are commonly
    # exploited in the wild. Comprehensive matching arrives in v0.2 with the feed.
    representative_cves = (
        "CVE-2024-23222",   # WebKit type confusion, exploited in the wild Jan 2024
        "CVE-2024-44308",   # JavaScriptCore RCE, exploited Nov 2024
        "CVE-2025-24201",   # WebKit sandbox escape, exploited Mar 2025
    )
    return Finding(
        id="MACOS-CAT01-001",
        title=f"macOS {version} is on an UNSUPPORTED major version",
        description="This macOS major no longer receives security updates from Apple. Known CVEs in WebKit, kernel, and system frameworks remain unpatched. The CVEs listed below are recent zero-days that received fixes only in supported macOS majors.",
        category=CATEGORY,
        severity=Severity.CRITICAL,
        status=Status.FAIL,
        command=r_prod.cmd,
        evidence=f"productVersion={version}\nbuildVersion={build}",
        standards=("CIS L1 1.1", "Apple Platform Security"),
        vector_ids=("O-01", "O-02", "W-04"),
        remediation="Upgrade to the latest macOS the hardware supports. If hardware does not support a supported major, plan device replacement.",
        interim_mitigation="Until upgrade: enable Lockdown Mode, use a non-Safari browser that still receives updates (Firefox), keep all browsers updated weekly, avoid opening untrusted documents.",
        references=("https://support.apple.com/en-us/100100",),
        cve_ids=representative_cves,
        title_de=f"macOS {version} ist eine NICHT MEHR UNTERSTÜTZTE Hauptversion",
        description_de="Diese macOS-Hauptversion erhält keine Sicherheitsupdates mehr von Apple. Bekannte CVEs in WebKit, Kernel und System-Frameworks bleiben ungepatcht. Die unten gelisteten CVEs sind aktuelle Zero-Days, die nur in unterstützten macOS-Versionen behoben wurden.",
        remediation_de="Aktualisiere auf die neueste macOS-Version, die deine Hardware unterstützt. Wenn die Hardware keine unterstützte Hauptversion mehr trägt, plane einen Gerätewechsel.",
        interim_mitigation_de="Bis zum Upgrade: Aktiviere Lockdown Mode, nutze einen nicht-Safari-Browser, der noch Updates erhält (Firefox), aktualisiere alle Browser wöchentlich, öffne keine nicht vertrauenswürdigen Dokumente.",
        category_de=CATEGORY_DE,
        title_es=f"macOS {version} está en una versión principal SIN SOPORTE",
        description_es="Esta versión principal de macOS ya no recibe actualizaciones de seguridad de Apple. CVE conocidos en WebKit, el kernel y los frameworks del sistema siguen sin parche. Los CVE listados abajo son zero-days recientes que solo se corrigieron en versiones de macOS con soporte.",
        remediation_es="Actualiza a la última versión de macOS que admita tu hardware. Si el hardware ya no admite una versión con soporte, planifica el reemplazo del equipo.",
        interim_mitigation_es="Hasta poder actualizar: activa el Modo de Aislamiento (Lockdown Mode), usa un navegador que no sea Safari y que siga recibiendo actualizaciones (Firefox), actualiza todos los navegadores cada semana y evita abrir documentos no confiables.",
        category_es=CATEGORY_ES,
    )


def _major(version: str) -> int | None:
    m = re.match(r"^(\d+)", version)
    return int(m.group(1)) if m else None


# --- 1.2 Auto security updates ---------------------------------------------

def _check_auto_security_updates() -> Finding:
    keys = [
        ("AutomaticCheckEnabled", "Check for updates"),
        ("AutomaticDownload", "Download new updates when available"),
        ("CriticalUpdateInstall", "Install Security Responses & system files"),
        ("AutomaticallyInstallMacOSUpdates", "Install macOS updates automatically"),
    ]
    plist = "/Library/Preferences/com.apple.SoftwareUpdate"
    results = []
    failing = []
    for key, label in keys:
        r = run_cmd(["defaults", "read", plist, key])
        val = r.stdout.strip()
        results.append(f"{key} = {val or '(unset)'}  // {label}")
        # 1 == enabled. Anything else (including unset) is treated as not enabled.
        if val != "1":
            failing.append(label)

    evidence = "\n".join(results)
    if not failing:
        return Finding(
            id="MACOS-CAT01-002",
            title="Automatic security updates fully enabled",
            description="macOS Software Update preferences confirm automatic checks, downloads, security responses, and macOS updates are all enabled.",
            category=CATEGORY,
            severity=Severity.HIGH,
            status=Status.PASS,
            command=f"defaults read {plist} <keys>",
            evidence=evidence,
            standards=("CIS L1 1.2",),
            vector_ids=("O-01", "W-04", "C-02"),
            remediation="No action.",
            title_de="Automatische Sicherheitsupdates vollständig aktiviert",
            description_de="Die macOS-Softwareupdate-Einstellungen bestätigen: automatische Prüfung, Download, Security Responses und macOS-Updates sind alle aktiviert.",
            remediation_de="Keine Aktion nötig.",
            category_de=CATEGORY_DE,
            title_es="Actualizaciones de seguridad automáticas totalmente activadas",
            description_es="Las preferencias de Actualización de software de macOS confirman que la verificación automática, la descarga, las respuestas de seguridad y las actualizaciones de macOS están todas activadas.",
            remediation_es="Sin acción necesaria.",
            category_es=CATEGORY_ES,
        )

    return Finding(
        id="MACOS-CAT01-002",
        title=f"Automatic updates not fully enabled ({len(failing)}/{len(keys)} settings)",
        description="Targeted attacks against journalists rely on N-day exploits — slow patching directly increases exposure.",
        category=CATEGORY,
        severity=Severity.HIGH,
        status=Status.FAIL,
        command=f"defaults read {plist} <keys>",
        evidence=evidence,
        standards=("CIS L1 1.2",),
        vector_ids=("O-01", "W-04", "C-02"),
        remediation="System Settings → General → Software Update → Automatic Updates → enable all four toggles, especially 'Install Security Responses and system files'.",
        interim_mitigation="If full auto-install is not acceptable, at minimum enable 'Install Security Responses and system files' (delivers RSR patches without user friction).",
        title_de=f"Automatische Updates nicht vollständig aktiviert ({len(failing)}/{len(keys)} Einstellungen)",
        description_de="Gezielte Angriffe gegen Journalist:innen nutzen N-Day-Exploits — langsames Patchen erhöht direkt deine Angriffsfläche.",
        remediation_de="Systemeinstellungen → Allgemein → Softwareupdate → Automatische Updates → aktiviere alle vier Schalter, besonders 'Sicherheits-Responses und Systemdateien installieren'.",
        interim_mitigation_de="Wenn vollständige Auto-Installation nicht akzeptabel ist, aktiviere mindestens 'Sicherheits-Responses und Systemdateien installieren' (liefert RSR-Patches ohne Reibung für dich).",
        category_de=CATEGORY_DE,
        title_es=f"Actualizaciones automáticas no del todo activadas ({len(failing)}/{len(keys)} ajustes)",
        description_es="Los ataques dirigidos contra periodistas se apoyan en exploits N-day: parchear lento aumenta directamente tu exposición.",
        remediation_es="Ajustes del Sistema → General → Actualización de software → Actualizaciones automáticas → activa los cuatro interruptores, sobre todo 'Instalar respuestas de seguridad y archivos del sistema'.",
        interim_mitigation_es="Si no puedes aceptar la autoinstalación completa, activa al menos 'Instalar respuestas de seguridad y archivos del sistema' (entrega parches RSR sin fricción para ti).",
        category_es=CATEGORY_ES,
    )


# --- 1.3 SIP -----------------------------------------------------------------

def _check_sip() -> Finding:
    r = run_cmd(["csrutil", "status"])
    txt = r.stdout.strip()
    enabled = "enabled" in txt.lower() and "disabled" not in txt.lower()
    if enabled:
        return Finding(
            id="MACOS-CAT01-003",
            title="System Integrity Protection (SIP) is enabled",
            description="SIP prevents even root from modifying protected system locations. Disabling it is a major weakening of macOS security.",
            category=CATEGORY,
            severity=Severity.CRITICAL,
            status=Status.PASS,
            command=r.cmd,
            evidence=txt,
            standards=("CIS L1 5.1", "Apple Platform Security"),
            vector_ids=("O-03", "O-07"),
            remediation="No action.",
            title_de="System Integrity Protection (SIP) ist aktiviert",
            description_de="SIP verhindert, dass selbst root geschützte Systembereiche modifizieren kann. Eine Deaktivierung schwächt die macOS-Sicherheit erheblich.",
            remediation_de="Keine Aktion nötig.",
            category_de=CATEGORY_DE,
            title_es="La Protección de Integridad del Sistema (SIP) está activada",
            description_es="SIP impide que incluso root modifique ubicaciones protegidas del sistema. Desactivarla debilita seriamente la seguridad de macOS.",
            remediation_es="Sin acción necesaria.",
            category_es=CATEGORY_ES,
        )
    return Finding(
        id="MACOS-CAT01-003",
        title="System Integrity Protection (SIP) is DISABLED",
        description="Without SIP, malware with root access can modify /System, /usr, and bundled Apple binaries to achieve persistent kernel-level compromise.",
        category=CATEGORY,
        severity=Severity.CRITICAL,
        status=Status.FAIL,
        command=r.cmd,
        evidence=txt or "(empty output)",
        standards=("CIS L1 5.1", "Apple Platform Security"),
        vector_ids=("O-03", "O-07"),
        remediation="Reboot into recoveryOS (hold power on Apple Silicon, or Cmd+R on Intel), open Terminal, run `csrutil enable`, reboot. Confirm with `csrutil status`.",
        title_de="System Integrity Protection (SIP) ist DEAKTIVIERT",
        description_de="Ohne SIP kann Malware mit Root-Rechten /System, /usr und mitgelieferte Apple-Binaries modifizieren — und so persistente Kernel-Kompromittierung erreichen.",
        remediation_de="Boote in recoveryOS (Power-Taste gedrückt halten auf Apple Silicon, oder Cmd+R auf Intel), öffne Terminal, führe `csrutil enable` aus, starte neu. Bestätige mit `csrutil status`.",
        category_de=CATEGORY_DE,
        title_es="La Protección de Integridad del Sistema (SIP) está DESACTIVADA",
        description_es="Sin SIP, un malware con acceso root puede modificar /System, /usr y los binarios de Apple incluidos para lograr un compromiso persistente a nivel de kernel.",
        remediation_es="Reinicia en recoveryOS (mantén pulsado el botón de encendido en Apple Silicon, o Cmd+R en Intel), abre Terminal, ejecuta `csrutil enable` y reinicia. Confirma con `csrutil status`.",
        category_es=CATEGORY_ES,
    )


# --- 1.4 Gatekeeper ---------------------------------------------------------

def _check_gatekeeper() -> Finding:
    r = run_cmd(["spctl", "--status"])
    txt = r.stdout.strip()
    enabled = "assessments enabled" in txt.lower()
    if enabled:
        return Finding(
            id="MACOS-CAT01-004",
            title="Gatekeeper is enabled",
            description="Gatekeeper enforces code-signing and notarization on launched binaries.",
            category=CATEGORY,
            severity=Severity.HIGH,
            status=Status.PASS,
            command=r.cmd,
            evidence=txt,
            standards=("CIS L1 2.5",),
            vector_ids=("O-02", "M-09"),
            remediation="No action.",
            title_de="Gatekeeper ist aktiviert",
            description_de="Gatekeeper erzwingt Code-Signierung und Notarisierung bei gestarteten Binaries.",
            remediation_de="Keine Aktion nötig.",
            category_de=CATEGORY_DE,
            title_es="Gatekeeper está activado",
            description_es="Gatekeeper exige firma de código y notarización en los binarios que se ejecutan.",
            remediation_es="Sin acción necesaria.",
            category_es=CATEGORY_ES,
        )
    return Finding(
        id="MACOS-CAT01-004",
        title="Gatekeeper is DISABLED",
        description="With Gatekeeper off, unsigned and non-notarized binaries can launch without warning. Common compromise vector for trojanized installers.",
        category=CATEGORY,
        severity=Severity.HIGH,
        status=Status.FAIL,
        command=r.cmd,
        evidence=txt or "(empty output)",
        standards=("CIS L1 2.5",),
        vector_ids=("O-02", "M-09"),
        remediation="Run `sudo spctl --master-enable` in Terminal. Confirm with `spctl --status`.",
        title_de="Gatekeeper ist DEAKTIVIERT",
        description_de="Ohne Gatekeeper können unsignierte und nicht notarisierte Binaries ohne Warnung gestartet werden. Häufiger Einfallsvektor für trojanisierte Installer.",
        remediation_de="Führe `sudo spctl --master-enable` im Terminal aus. Bestätige mit `spctl --status`.",
        category_de=CATEGORY_DE,
        title_es="Gatekeeper está DESACTIVADO",
        description_es="Con Gatekeeper apagado, los binarios sin firma y sin notarizar pueden ejecutarse sin advertencia. Es un vector de compromiso habitual con instaladores troyanizados.",
        remediation_es="Ejecuta `sudo spctl --master-enable` en Terminal. Confirma con `spctl --status`.",
        category_es=CATEGORY_ES,
    )


# --- 1.5 XProtect / MRT signatures versions --------------------------------

def _check_xprotect_signatures() -> Finding:
    # Modern macOS (12+) uses XProtectRemediator and updates via background tasks.
    # Two info sources are useful: bundle versions and last install history.
    plists = [
        ("/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist", "XProtect.bundle"),
        ("/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist", "XProtect.bundle (Apple)"),
    ]
    versions = []
    for path, label in plists:
        if Path(path).exists():
            r = run_cmd(["defaults", "read", path[:-6], "CFBundleShortVersionString"])
            v = r.stdout.strip()
            if v:
                versions.append(f"{label}: {v}  ({path})")

    # Also: recent install history filtered to XProtect / MRT
    r2 = run_cmd("system_profiler SPInstallHistoryDataType 2>/dev/null | grep -B1 -A3 -E 'XProtect|MRT|Malware' | head -40", shell=True)
    history = r2.stdout.strip()

    evidence_parts = []
    if versions:
        evidence_parts.append("\n".join(versions))
    if history:
        evidence_parts.append("Recent install history:\n" + history)
    evidence = "\n\n".join(evidence_parts) or "(no XProtect data found)"

    if not versions:
        return Finding(
            id="MACOS-CAT01-005",
            title="Could not determine XProtect signatures version",
            description="Verifies that Apple's built-in malware signature database is recent.",
            category=CATEGORY,
            severity=Severity.MEDIUM,
            status=Status.WARN,
            command="defaults read XProtect.bundle/Contents/Info CFBundleShortVersionString",
            evidence=evidence,
            standards=("Apple Platform Security",),
            vector_ids=("M-01", "M-04", "M-09"),
            remediation="System Settings → General → Software Update → ensure 'Install Security Responses and system files' is on. Then run `softwareupdate --background` to force a check.",
            title_de="XProtect-Signaturversion konnte nicht ermittelt werden",
            description_de="Prüft, ob Apples eingebaute Malware-Signaturdatenbank aktuell ist.",
            remediation_de="Systemeinstellungen → Allgemein → Softwareupdate → stelle sicher, dass 'Sicherheits-Responses und Systemdateien installieren' aktiviert ist. Dann `softwareupdate --background` ausführen, um eine Prüfung zu erzwingen.",
            category_de=CATEGORY_DE,
            title_es="No se pudo determinar la versión de las firmas de XProtect",
            description_es="Verifica que la base de firmas de malware integrada de Apple esté actualizada.",
            remediation_es="Ajustes del Sistema → General → Actualización de software → asegúrate de que 'Instalar respuestas de seguridad y archivos del sistema' esté activado. Luego ejecuta `softwareupdate --background` para forzar una verificación.",
            category_es=CATEGORY_ES,
        )

    return Finding(
        id="MACOS-CAT01-005",
        title="XProtect signatures present",
        description="XProtect bundle is installed. Manual review of the version against Apple's latest is recommended for high-risk profiles.",
        category=CATEGORY,
        severity=Severity.MEDIUM,
        status=Status.PASS,
        command="defaults read XProtect.bundle/Contents/Info CFBundleShortVersionString",
        evidence=evidence,
        standards=("Apple Platform Security",),
        vector_ids=("M-01", "M-04", "M-09"),
        remediation="No action if version is recent. To force update: `softwareupdate --background`.",
        title_de="XProtect-Signaturen vorhanden",
        description_de="Das XProtect-Bundle ist installiert. Bei Hochrisiko-Profilen empfiehlt sich eine manuelle Prüfung gegen Apples aktuelle Version.",
        remediation_de="Keine Aktion nötig, wenn die Version aktuell ist. Update erzwingen: `softwareupdate --background`.",
        category_de=CATEGORY_DE,
        title_es="Firmas de XProtect presentes",
        description_es="El paquete XProtect está instalado. En perfiles de alto riesgo se recomienda revisar manualmente la versión frente a la más reciente de Apple.",
        remediation_es="Sin acción necesaria si la versión es reciente. Para forzar la actualización: `softwareupdate --background`.",
        category_es=CATEGORY_ES,
    )


# --- 1.6 Kernel extensions --------------------------------------------------

def _check_kernel_extensions() -> Finding:
    # `kmutil showloaded` works on Apple Silicon and recent Intel macOS.
    # Falls back to `kextstat` if not available.
    r = run_cmd(["kmutil", "showloaded"])
    if not r.ok:
        r = run_cmd(["kextstat"])

    if not r.ok:
        return Finding(
            id="MACOS-CAT01-006",
            title="Could not enumerate kernel extensions",
            description="Verifies no third-party kernel extensions are loaded (rare and high-risk on modern macOS).",
            category=CATEGORY,
            severity=Severity.MEDIUM,
            status=Status.ERROR,
            command=r.cmd,
            evidence=(r.stderr or r.exception)[:500],
            standards=("CIS L2",),
            vector_ids=("O-07",),
            remediation="Run `kmutil showloaded` manually.",
            title_de="Kernel-Erweiterungen konnten nicht aufgelistet werden",
            description_de="Prüft, dass keine Drittanbieter-Kernel-Erweiterungen geladen sind (selten und hochriskant auf modernem macOS).",
            remediation_de="Führe `kmutil showloaded` manuell aus.",
            category_de=CATEGORY_DE,
            title_es="No se pudieron enumerar las extensiones del kernel",
            description_es="Verifica que no haya extensiones de kernel de terceros cargadas (raras y de alto riesgo en macOS moderno).",
            remediation_es="Ejecuta `kmutil showloaded` manualmente.",
            category_es=CATEGORY_ES,
        )

    lines = r.stdout.splitlines()
    # Filter out Apple-signed entries; keep third party.
    third_party = [ln for ln in lines if "com.apple" not in ln and ln.strip() and not ln.startswith("Index")]

    if not third_party:
        return Finding(
            id="MACOS-CAT01-006",
            title="No third-party kernel extensions loaded",
            description="On Apple Silicon, third-party kexts require lowering security level — their absence is the safe default.",
            category=CATEGORY,
            severity=Severity.MEDIUM,
            status=Status.PASS,
            command=r.cmd,
            evidence=f"{len(lines)} kernel extensions loaded, all Apple-signed.",
            standards=("CIS L2",),
            vector_ids=("O-07",),
            remediation="No action.",
            title_de="Keine Drittanbieter-Kernel-Erweiterungen geladen",
            description_de="Auf Apple Silicon erfordern Drittanbieter-Kexts eine Absenkung des Sicherheitslevels — ihre Abwesenheit ist die sichere Voreinstellung.",
            remediation_de="Keine Aktion nötig.",
            category_de=CATEGORY_DE,
            title_es="No hay extensiones de kernel de terceros cargadas",
            description_es="En Apple Silicon, las kexts de terceros requieren bajar el nivel de seguridad: su ausencia es la opción segura por defecto.",
            remediation_es="Sin acción necesaria.",
            category_es=CATEGORY_ES,
        )

    return Finding(
        id="MACOS-CAT01-006",
        title=f"{len(third_party)} third-party kernel extension(s) loaded",
        description="Third-party kexts run with kernel privileges and are a known persistence and compromise vector. Modern macOS prefers DriverKit/System Extensions.",
        category=CATEGORY,
        severity=Severity.MEDIUM,
        status=Status.WARN,
        command=r.cmd,
        evidence="\n".join(third_party[:30]),
        standards=("CIS L2", "MITRE T1547"),
        vector_ids=("O-07",),
        remediation="Identify each extension's vendor. Replace with DriverKit/System Extension equivalent if available, or remove the parent app.",
        interim_mitigation="If a kext is required for hardware (e.g., enterprise VPN client), document it as known and approved in your operator log so future scans don't re-flag it.",
        title_de=f"{len(third_party)} Drittanbieter-Kernel-Erweiterung(en) geladen",
        description_de="Drittanbieter-Kexts laufen mit Kernel-Rechten und sind ein bekannter Persistenz- und Kompromittierungsvektor. Modernes macOS bevorzugt DriverKit/System Extensions.",
        remediation_de="Identifiziere für jede Erweiterung den Hersteller. Ersetze durch ein DriverKit-/System-Extension-Äquivalent wenn verfügbar, oder entferne die zugehörige App.",
        interim_mitigation_de="Wenn eine Kext für Hardware notwendig ist (z. B. Enterprise-VPN-Client), dokumentiere sie als bekannt und genehmigt in deinem Operator-Log, damit zukünftige Scans sie nicht erneut markieren.",
        category_de=CATEGORY_DE,
        title_es=f"{len(third_party)} extensión(es) de kernel de terceros cargada(s)",
        description_es="Las kexts de terceros se ejecutan con privilegios de kernel y son un vector conocido de persistencia y compromiso. El macOS moderno prefiere DriverKit/System Extensions.",
        remediation_es="Identifica el fabricante de cada extensión. Reemplázala por un equivalente DriverKit/System Extension si existe, o elimina la app que la instala.",
        interim_mitigation_es="Si una kext es necesaria para hardware (p. ej. un cliente VPN corporativo), documéntala como conocida y aprobada en tu bitácora para que los próximos análisis no la marquen de nuevo.",
        category_es=CATEGORY_ES,
    )


# --- 1.7 System extensions --------------------------------------------------

def _check_system_extensions() -> Finding:
    r = run_cmd(["systemextensionsctl", "list"])
    if not r.ok:
        return Finding(
            id="MACOS-CAT01-007",
            title="Could not enumerate system extensions",
            description="Lists installed System Extensions (network, endpoint security, drivers).",
            category=CATEGORY,
            severity=Severity.MEDIUM,
            status=Status.ERROR,
            command=r.cmd,
            evidence=(r.stderr or r.exception)[:500],
            standards=("Apple Platform Security",),
            vector_ids=("O-05", "N-06"),
            remediation="Run `systemextensionsctl list` manually.",
            title_de="System Extensions konnten nicht aufgelistet werden",
            description_de="Listet installierte System Extensions auf (Netzwerk, Endpoint Security, Treiber).",
            remediation_de="Führe `systemextensionsctl list` manuell aus.",
            category_de=CATEGORY_DE,
            title_es="No se pudieron enumerar las extensiones del sistema",
            description_es="Lista las System Extensions instaladas (red, seguridad de endpoint, controladores).",
            remediation_es="Ejecuta `systemextensionsctl list` manualmente.",
            category_es=CATEGORY_ES,
        )

    txt = r.stdout.strip()
    enabled = [ln for ln in txt.splitlines() if "enabled" in ln.lower() and "active" in ln.lower()]

    if not enabled:
        return Finding(
            id="MACOS-CAT01-007",
            title="No third-party system extensions active",
            description="No active System Extensions found. Common categories: NetworkExtension (VPN), EndpointSecurity (EDR/AV).",
            category=CATEGORY,
            severity=Severity.LOW,
            status=Status.PASS,
            command=r.cmd,
            evidence=txt[:500] or "(empty)",
            standards=("Apple Platform Security",),
            vector_ids=("O-05", "N-06"),
            remediation="No action.",
            title_de="Keine Drittanbieter-System-Extensions aktiv",
            description_de="Keine aktiven System Extensions gefunden. Übliche Kategorien: NetworkExtension (VPN), EndpointSecurity (EDR/AV).",
            remediation_de="Keine Aktion nötig.",
            category_de=CATEGORY_DE,
            title_es="No hay extensiones del sistema de terceros activas",
            description_es="No se encontraron System Extensions activas. Categorías habituales: NetworkExtension (VPN), EndpointSecurity (EDR/AV).",
            remediation_es="Sin acción necesaria.",
            category_es=CATEGORY_ES,
        )

    return Finding(
        id="MACOS-CAT01-007",
        title=f"System extensions active",
        description="System extensions can intercept network traffic or monitor file/process activity. Verify each is intentional and from a trusted vendor.",
        category=CATEGORY,
        severity=Severity.MEDIUM,
        status=Status.WARN,
        command=r.cmd,
        evidence=txt[:1500],
        standards=("Apple Platform Security",),
        vector_ids=("O-05", "N-06"),
        remediation="Review each extension. Common legitimate vendors: Cisco (AnyConnect), CrowdStrike, SentinelOne, Little Snitch, NordVPN. If unrecognized, identify the parent app via System Settings → General → Login Items → Extensions.",
        title_de="System Extensions aktiv",
        description_de="System Extensions können Netzwerkverkehr abfangen oder Datei-/Prozessaktivität überwachen. Stelle sicher, dass jede absichtlich installiert ist und von einem vertrauenswürdigen Hersteller stammt.",
        remediation_de="Prüfe jede Erweiterung. Bekannte legitime Hersteller: Cisco (AnyConnect), CrowdStrike, SentinelOne, Little Snitch, NordVPN. Wenn unbekannt, identifiziere die zugehörige App in Systemeinstellungen → Allgemein → Anmeldeobjekte → Erweiterungen.",
        category_de=CATEGORY_DE,
        title_es="Extensiones del sistema activas",
        description_es="Las extensiones del sistema pueden interceptar el tráfico de red o monitorear la actividad de archivos y procesos. Verifica que cada una sea intencional y de un fabricante confiable.",
        remediation_es="Revisa cada extensión. Fabricantes legítimos habituales: Cisco (AnyConnect), CrowdStrike, SentinelOne, Little Snitch, NordVPN. Si no la reconoces, identifica la app que la instala en Ajustes del Sistema → General → Ítems de inicio de sesión → Extensiones.",
        category_es=CATEGORY_ES,
    )


# --- 1.8 Pending software updates -------------------------------------------

def _check_pending_software_updates() -> Finding:
    r = run_cmd(["softwareupdate", "-l"], timeout=60)
    txt = (r.stdout + r.stderr).strip()
    no_updates = "no new software" in txt.lower() or "no updates available" in txt.lower()

    if no_updates:
        return Finding(
            id="MACOS-CAT01-008",
            title="No pending macOS software updates",
            description="`softwareupdate -l` reports no available updates.",
            category=CATEGORY,
            severity=Severity.HIGH,
            status=Status.PASS,
            command=r.cmd,
            evidence=txt[:1000],
            standards=("CIS L1 1.1",),
            vector_ids=("O-01", "W-04"),
            remediation="No action.",
            title_de="Keine ausstehenden macOS-Softwareupdates",
            description_de="`softwareupdate -l` meldet keine verfügbaren Updates.",
            remediation_de="Keine Aktion nötig.",
            category_de=CATEGORY_DE,
            title_es="No hay actualizaciones de macOS pendientes",
            description_es="`softwareupdate -l` indica que no hay actualizaciones disponibles.",
            remediation_es="Sin acción necesaria.",
            category_es=CATEGORY_ES,
        )

    # Try to detect entries that look like updates
    update_lines = [ln for ln in txt.splitlines() if ln.strip().startswith("*") or "Recommended:" in ln]

    if update_lines:
        return Finding(
            id="MACOS-CAT01-008",
            title=f"Pending macOS / Apple software updates: {len(update_lines)} item(s)",
            description="Updates from Apple's catalog are available but not yet installed.",
            category=CATEGORY,
            severity=Severity.HIGH,
            status=Status.FAIL,
            command=r.cmd,
            evidence=txt[:2000],
            standards=("CIS L1 1.1",),
            vector_ids=("O-01", "W-04"),
            remediation="System Settings → General → Software Update → Update Now. For a high-risk profile, install within 24h of release.",
            interim_mitigation="If update requires reboot at an inconvenient moment, at minimum install Safety/RSR-only updates first (they don't require reboot).",
            title_de=f"Ausstehende macOS-/Apple-Updates: {len(update_lines)} Eintrag/Einträge",
            description_de="Updates aus Apples Katalog sind verfügbar, aber noch nicht installiert.",
            remediation_de="Systemeinstellungen → Allgemein → Softwareupdate → Jetzt aktualisieren. Bei einem Hochrisiko-Profil binnen 24 Stunden nach Veröffentlichung installieren.",
            interim_mitigation_de="Wenn ein Neustart gerade nicht passt, installiere zumindest die Safety/RSR-Updates zuerst — die brauchen keinen Neustart.",
            category_de=CATEGORY_DE,
            title_es=f"Actualizaciones de macOS/Apple pendientes: {len(update_lines)} elemento(s)",
            description_es="Hay actualizaciones del catálogo de Apple disponibles pero aún sin instalar.",
            remediation_es="Ajustes del Sistema → General → Actualización de software → Actualizar ahora. En un perfil de alto riesgo, instálalas dentro de las 24 horas tras su publicación.",
            interim_mitigation_es="Si la actualización exige reiniciar en un momento inoportuno, instala al menos primero las actualizaciones de seguridad/RSR (no requieren reinicio).",
            category_es=CATEGORY_ES,
        )

    return Finding(
        id="MACOS-CAT01-008",
        title="Pending updates check inconclusive",
        description="`softwareupdate -l` did not return a clear answer. Possible network issue or rate-limiting.",
        category=CATEGORY,
        severity=Severity.MEDIUM,
        status=Status.WARN,
        command=r.cmd,
        evidence=txt[:1500] or "(no output)",
        standards=("CIS L1 1.1",),
        vector_ids=("O-01",),
        remediation="Open System Settings → General → Software Update and verify visually.",
        title_de="Update-Prüfung nicht eindeutig",
        description_de="`softwareupdate -l` lieferte keine klare Antwort. Möglicherweise Netzwerkproblem oder Rate-Limit.",
        remediation_de="Öffne Systemeinstellungen → Allgemein → Softwareupdate und prüfe visuell.",
        category_de=CATEGORY_DE,
        title_es="Verificación de actualizaciones no concluyente",
        description_es="`softwareupdate -l` no devolvió una respuesta clara. Posible problema de red o limitación de peticiones.",
        remediation_es="Abre Ajustes del Sistema → General → Actualización de software y verifica visualmente.",
        category_es=CATEGORY_ES,
    )


# --- 1.9 Brew outdated ------------------------------------------------------

def _check_brew_outdated() -> Finding:
    r = run_cmd(["brew", "--version"])
    if not r.ok:
        return Finding(
            id="MACOS-CAT01-009",
            title="Homebrew not installed",
            description="Homebrew is not present on this device. No third-party CLI packages to audit via brew.",
            category=CATEGORY,
            severity=Severity.INFO,
            status=Status.SKIP,
            command=r.cmd,
            evidence=r.stderr[:300] or "command not found",
            standards=("NIST CSF",),
            vector_ids=("C-03",),
            remediation="No action.",
            title_de="Homebrew nicht installiert",
            description_de="Homebrew ist auf diesem Gerät nicht vorhanden. Keine Drittanbieter-CLI-Pakete via brew zu prüfen.",
            remediation_de="Keine Aktion nötig.",
            category_de=CATEGORY_DE,
            title_es="Homebrew no está instalado",
            description_es="Homebrew no está presente en este equipo. No hay paquetes CLI de terceros que auditar mediante brew.",
            remediation_es="Sin acción necesaria.",
            category_es=CATEGORY_ES,
        )

    r2 = run_cmd(["brew", "outdated", "--quiet"], timeout=60)
    outdated = [ln for ln in r2.stdout.splitlines() if ln.strip()]

    if not outdated:
        return Finding(
            id="MACOS-CAT01-009",
            title="All Homebrew packages up to date",
            description="No outdated packages reported by `brew outdated`.",
            category=CATEGORY,
            severity=Severity.MEDIUM,
            status=Status.PASS,
            command=r2.cmd,
            evidence="(no outdated packages)",
            standards=("NIST CSF", "CIS L1"),
            vector_ids=("C-03",),
            remediation="No action.",
            title_de="Alle Homebrew-Pakete aktuell",
            description_de="`brew outdated` meldet keine veralteten Pakete.",
            remediation_de="Keine Aktion nötig.",
            category_de=CATEGORY_DE,
            title_es="Todos los paquetes de Homebrew están actualizados",
            description_es="`brew outdated` no reporta paquetes desactualizados.",
            remediation_es="Sin acción necesaria.",
            category_es=CATEGORY_ES,
        )

    return Finding(
        id="MACOS-CAT01-009",
        title=f"{len(outdated)} outdated Homebrew package(s)",
        description="Outdated CLI tools may include security-relevant packages (openssl, curl, git, ssh).",
        category=CATEGORY,
        severity=Severity.MEDIUM,
        status=Status.FAIL,
        command=r2.cmd,
        evidence="\n".join(outdated[:50]) + (f"\n... +{len(outdated)-50} more" if len(outdated) > 50 else ""),
        standards=("NIST CSF", "CIS L1"),
        vector_ids=("C-03",),
        remediation="Run `brew update && brew upgrade` in Terminal.",
        interim_mitigation="If upgrading might break a project pinned to an older version, prioritize: openssl, curl, git, openssh, libssh, libcurl, python.",
        title_de=f"{len(outdated)} veraltete(s) Homebrew-Paket(e)",
        description_de="Veraltete CLI-Werkzeuge können sicherheitsrelevante Pakete enthalten (openssl, curl, git, ssh).",
        remediation_de="Führe `brew update && brew upgrade` im Terminal aus.",
        interim_mitigation_de="Wenn ein Upgrade ein Projekt mit gepinnten älteren Versionen brechen könnte, priorisiere: openssl, curl, git, openssh, libssh, libcurl, python.",
        category_de=CATEGORY_DE,
        title_es=f"{len(outdated)} paquete(s) de Homebrew desactualizado(s)",
        description_es="Las herramientas CLI desactualizadas pueden incluir paquetes relevantes para la seguridad (openssl, curl, git, ssh).",
        remediation_es="Ejecuta `brew update && brew upgrade` en Terminal.",
        interim_mitigation_es="Si actualizar pudiera romper un proyecto fijado a una versión anterior, prioriza: openssl, curl, git, openssh, libssh, libcurl, python.",
        category_es=CATEGORY_ES,
    )


# --- 1.10 Third-party browsers ---------------------------------------------

_BROWSER_APPS = [
    ("/Applications/Google Chrome.app", "Google Chrome", "https://chromereleases.googleblog.com/"),
    ("/Applications/Firefox.app", "Firefox", "https://www.mozilla.org/en-US/security/advisories/"),
    ("/Applications/Brave Browser.app", "Brave", "https://brave.com/latest/"),
    ("/Applications/Microsoft Edge.app", "Microsoft Edge", "https://learn.microsoft.com/en-us/deployedge/microsoft-edge-relnotes-stable-channel"),
    ("/Applications/Arc.app", "Arc", "https://releases.arc.net/release/"),
    ("/Applications/Tor Browser.app", "Tor Browser", "https://blog.torproject.org/"),
]


def _check_third_party_browsers() -> Finding:
    found = []
    for path, name, advisory in _BROWSER_APPS:
        if Path(path).exists():
            v = _app_version(path)
            found.append((name, v, advisory, path))

    if not found:
        return Finding(
            id="MACOS-CAT01-010",
            title="No third-party browsers installed",
            description="Only Apple-shipped browsers detected.",
            category=CATEGORY,
            severity=Severity.LOW,
            status=Status.PASS,
            command="(filesystem inspection)",
            evidence="No /Applications/<browser>.app entries from the known list.",
            standards=("CIS L1",),
            vector_ids=("W-02", "W-04"),
            remediation="No action.",
            title_de="Keine Drittanbieter-Browser installiert",
            description_de="Nur von Apple mitgelieferte Browser erkannt.",
            remediation_de="Keine Aktion nötig.",
            category_de=CATEGORY_DE,
            title_es="No hay navegadores de terceros instalados",
            description_es="Solo se detectaron navegadores incluidos por Apple.",
            remediation_es="Sin acción necesaria.",
            category_es=CATEGORY_ES,
        )

    lines = [f"{name}: {v}  ({path})\n  Advisories: {advisory}" for name, v, advisory, path in found]
    return Finding(
        id="MACOS-CAT01-010",
        title=f"{len(found)} third-party browser(s) installed — verify each is current",
        description="Browsers are the most common entry point for drive-by exploits. Each must be updated independently of macOS.",
        category=CATEGORY,
        severity=Severity.MEDIUM,
        status=Status.WARN,
        command="(filesystem inspection)",
        evidence="\n".join(lines),
        standards=("CIS L1", "NIST CSF"),
        vector_ids=("W-02", "W-04", "W-06"),
        remediation="Open each browser → About → confirm latest stable. Enable auto-update in each.",
        interim_mitigation="If you can't update immediately, switch to Safari (which updates with macOS) or use a non-vulnerable browser temporarily.",
        references=tuple(advisory for _, _, advisory, _ in found),
        title_de=f"{len(found)} Drittanbieter-Browser installiert — bitte jede Version prüfen",
        description_de="Browser sind der häufigste Einstiegspunkt für Drive-by-Exploits. Jeder muss unabhängig von macOS aktualisiert werden.",
        remediation_de="Öffne jeden Browser → Über/About → bestätige die aktuellste Stable-Version. Aktiviere Auto-Updates in jedem.",
        interim_mitigation_de="Wenn du nicht sofort aktualisieren kannst, wechsle vorübergehend zu Safari (wird mit macOS aktualisiert) oder zu einem nicht betroffenen Browser.",
        category_de=CATEGORY_DE,
        title_es=f"{len(found)} navegador(es) de terceros instalado(s) — verifica que cada uno esté al día",
        description_es="Los navegadores son el punto de entrada más común para exploits drive-by. Cada uno debe actualizarse de forma independiente de macOS.",
        remediation_es="Abre cada navegador → Acerca de → confirma la última versión estable. Activa la actualización automática en cada uno.",
        interim_mitigation_es="Si no puedes actualizar de inmediato, cambia a Safari (que se actualiza con macOS) o usa temporalmente un navegador no vulnerable.",
        category_es=CATEGORY_ES,
    )


def _app_version(app_path: str) -> str:
    plist = Path(app_path) / "Contents" / "Info.plist"
    if not plist.exists():
        return "(unknown)"
    r = run_cmd(["defaults", "read", str(plist)[:-6], "CFBundleShortVersionString"])
    return r.stdout.strip() or "(unknown)"


# --- 1.11 Secure Boot (informational) --------------------------------------

def _check_secure_boot_note(ctx: ScanContext) -> Finding:
    """Secure Boot status requires recoveryOS access. We provide guidance only."""
    if ctx.arch == "arm64":
        return Finding(
            id="MACOS-CAT01-011",
            title="Secure Boot status: requires manual check from recoveryOS",
            description="On Apple Silicon, Secure Boot policy can only be read while booted into recoveryOS via `bputil -d`. Default at factory is 'Full Security'.",
            category=CATEGORY,
            severity=Severity.MEDIUM,
            status=Status.SKIP,
            command="(skipped — requires recoveryOS)",
            evidence="Apple Silicon detected. To verify: shut down → press and hold the power button until startup options appear → click Options → Continue → Utilities menu → Startup Security Utility.",
            standards=("Apple Platform Security",),
            vector_ids=("F-01", "H-01"),
            remediation="Verify Startup Security Utility shows 'Full Security' for the boot disk. If 'Reduced' or 'Permissive', restore to 'Full Security' unless you intentionally need legacy kexts.",
            title_de="Secure-Boot-Status: manuelle Prüfung in recoveryOS nötig",
            description_de="Auf Apple Silicon kann die Secure-Boot-Richtlinie nur in recoveryOS via `bputil -d` ausgelesen werden. Werkseinstellung ist 'Volle Sicherheit'.",
            remediation_de="Stelle sicher, dass das Startsicherheits-Dienstprogramm 'Volle Sicherheit' für das Boot-Volume zeigt. Falls 'Reduziert' oder 'Permissiv' eingestellt ist: zurück auf 'Volle Sicherheit', es sei denn du brauchst absichtlich Legacy-Kexts.",
            category_de=CATEGORY_DE,
            title_es="Estado de Arranque Seguro: requiere verificación manual desde recoveryOS",
            description_es="En Apple Silicon, la política de Arranque Seguro solo puede leerse desde recoveryOS mediante `bputil -d`. El valor de fábrica es 'Seguridad total'.",
            remediation_es="Verifica que la Utilidad de Seguridad de Arranque muestre 'Seguridad total' para el disco de arranque. Si está en 'Reducida' o 'Permisiva', vuelve a 'Seguridad total', salvo que necesites kexts heredadas a propósito.",
            category_es=CATEGORY_ES,
        )

    return Finding(
        id="MACOS-CAT01-011",
        title="Secure Boot status (Intel): requires manual check from recoveryOS",
        description="On Intel Macs with T2, Secure Boot policy is configured via Startup Security Utility in recoveryOS. Default is 'Full Security'.",
        category=CATEGORY,
        severity=Severity.MEDIUM,
        status=Status.SKIP,
        command="(skipped — requires recoveryOS)",
        evidence="Intel Mac detected. To verify: restart and hold Cmd+R → Utilities → Startup Security Utility.",
        standards=("Apple Platform Security",),
        vector_ids=("F-01", "H-01"),
        remediation="Verify 'Full Security' is selected and 'Disallow booting from external media' is enabled.",
        title_de="Secure-Boot-Status (Intel): manuelle Prüfung in recoveryOS nötig",
        description_de="Auf Intel-Macs mit T2 wird die Secure-Boot-Richtlinie über das Startsicherheits-Dienstprogramm in recoveryOS konfiguriert. Standard ist 'Volle Sicherheit'.",
        remediation_de="Stelle sicher, dass 'Volle Sicherheit' aktiv ist und 'Booten von externen Medien verhindern' eingeschaltet ist.",
        category_de=CATEGORY_DE,
        title_es="Estado de Arranque Seguro (Intel): requiere verificación manual desde recoveryOS",
        description_es="En Macs Intel con chip T2, la política de Arranque Seguro se configura desde la Utilidad de Seguridad de Arranque en recoveryOS. El valor por defecto es 'Seguridad total'.",
        remediation_es="Verifica que esté seleccionada 'Seguridad total' y que 'No permitir el arranque desde medios externos' esté activado.",
        category_es=CATEGORY_ES,
    )
