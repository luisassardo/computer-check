/* ComputerCheck landing — language toggle. Static, no network, no trackers. */
(function () {
  'use strict';

  const STRINGS = {
    es: {
      eyebrow: 'C-LAB · Herramienta · autoevaluación del equipo',
      role: 'Solo lectura · local · código abierto',
      hero_title: 'Revisa la seguridad de tu computadora en un clic.',
      hero_lead: 'Una autoevaluación de solo lectura para tu Mac o PC con Windows. Se ejecuta totalmente en tu dispositivo, te muestra en lenguaje claro qué está bien y qué corregir primero, y guarda un historial cifrado para que veas cómo mejora tu seguridad. No se envía nada a ningún lugar a menos que tú lo decidas.',
      cta_mac: 'Descargar para macOS',
      cta_win: 'Descargar para Windows',
      hero_note: 'macOS Intel + Apple Silicon, notarizada por Apple · Windows 10/11 · gratis y de código abierto · ',
      all_downloads: 'todas las descargas y sumas de verificación',
      f1_t: 'Solo lectura',
      f1_d: 'Observa e informa. Nunca cambia tu configuración ni toca tus archivos.',
      f2_t: 'Local y privada',
      f2_d: 'El análisis corre en tu dispositivo. Sin cuenta, sin subida, sin telemetría.',
      f3_t: 'Informe en lenguaje claro',
      f3_d: 'Una puntuación de seguridad y lo primero que debes corregir, cada cosa con pasos claros.',
      f4_t: 'Sigue tu progreso',
      f4_d: 'Un historial local cifrado muestra si tu seguridad mejora con el tiempo.',
      f5_t: 'Informes en EN / ES / DE',
      f5_d: 'Descarga un informe PDF imprimible en inglés, español o alemán.',
      f6_t: 'Compartir cifrado, opcional',
      f6_d: 'Ayuda a la red de investigación de C-LAB con un archivo cifrado, solo si tú quieres. Los hallazgos de spyware nunca van en una exportación de rutina.',
      prot_h: 'Qué detecta',
      prot_1: 'Sistemas operativos desactualizados y protecciones desactivadas (SIP, Gatekeeper, Defender, BitLocker, FileVault).',
      prot_2: 'Configuración riesgosa, mecanismos de persistencia y extensiones sospechosas del navegador o del sistema.',
      prot_3: 'Una lista clara y priorizada de correcciones, con pasos provisionales económicos cuando reemplazar no es posible.',
      no_h: 'Qué no es',
      no_1: 'No es un antivirus en tiempo real. Es una revisión periódica, no un monitor permanente.',
      no_2: 'No es una garantía contra spyware avanzado. Si aparece algo serio, te dirige a la línea de ayuda de Access Now.',
      no_3: 'No es un recolector de datos. Nunca lee tus mensajes, fotos ni documentos.',
      verify_note: 'Verifica cada descarga con su SHA-256 antes de abrirla. Las sumas se publican con cada versión.',
      foot_net: 'Parte de la red ARGUS'
    },
    en: {
      eyebrow: 'C-LAB · Tool · device self-assessment',
      role: 'Read-only · local · open source',
      hero_title: "Check your computer's security in one click.",
      hero_lead: 'A read-only self-assessment for your Mac or Windows PC. It runs entirely on your device, shows in plain language what is solid and what to fix first, and keeps an encrypted history so you can watch your security improve. Nothing is sent anywhere unless you choose to.',
      cta_mac: 'Download for macOS',
      cta_win: 'Download for Windows',
      hero_note: 'macOS Intel + Apple Silicon, notarized by Apple · Windows 10/11 · free & open source · ',
      all_downloads: 'all downloads & checksums',
      f1_t: 'Read-only',
      f1_d: 'It observes and reports. It never changes your settings or touches your files.',
      f2_t: 'Local & private',
      f2_d: 'The scan runs on your device. No account, no upload, no telemetry.',
      f3_t: 'Plain-language report',
      f3_d: 'A health score and the top things to fix first, each with clear steps.',
      f4_t: 'Track your progress',
      f4_d: 'An encrypted local history shows whether your security is improving over time.',
      f5_t: 'Reports in EN / ES / DE',
      f5_d: 'Download a printable PDF report in English, Spanish, or German.',
      f6_t: 'Optional encrypted sharing',
      f6_d: 'Help the C-LAB research network with an encrypted file, only if you choose. Spyware findings are never in a routine export.',
      prot_h: 'What it finds',
      prot_1: 'Outdated operating systems and disabled protections (SIP, Gatekeeper, Defender, BitLocker, FileVault).',
      prot_2: 'Risky configuration, persistence mechanisms, and suspicious browser or system extensions.',
      prot_3: "A clear, prioritized list of fixes, with budget-friendly interim steps when replacement isn't possible.",
      no_h: 'What it is not',
      no_1: 'Not real-time antivirus. It is a periodic check, not an always-on monitor.',
      no_2: 'Not a guarantee against advanced spyware. If something serious shows up, it points you to the Access Now helpline.',
      no_3: 'Not a data collector. It never reads your messages, photos, or documents.',
      verify_note: 'Verify every download against its SHA-256 before opening. Checksums are published with each release.',
      foot_net: 'Part of the ARGUS Defense Network'
    }
  };

  function applyLang(lang) {
    document.documentElement.lang = lang;
    const t = STRINGS[lang];
    document.querySelectorAll('[data-i18n]').forEach(el => {
      const key = el.getAttribute('data-i18n');
      if (t[key] !== undefined) el.textContent = t[key];
    });
    document.querySelectorAll('.lang-switch button').forEach(b => {
      b.classList.toggle('active', b.dataset.lang === lang);
    });
  }

  document.querySelectorAll('.lang-switch button').forEach(b => {
    b.addEventListener('click', () => applyLang(b.dataset.lang));
  });

  // Default to the browser's preferred language if it's English, else Spanish.
  const pref = (navigator.language || 'es').toLowerCase().startsWith('en') ? 'en' : 'es';
  applyLang(pref);
})();
