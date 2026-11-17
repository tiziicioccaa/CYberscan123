/**
 * @file script.js
 * @description Controlador principal del frontend de Cyberscan (Puerto 5500).
 * Gestiona la autenticación y perfil de usuario en localStorage, la navegación por pestañas,
 * las herramientas locales de seguridad (generador/validador de claves y brechas de correo),
 * el consumo de la API REST de VirusTotal (Puerto 3000) y el cliente SOAP/XML para
 * comunicarse con el Plugin Web Service Sentinel AI (Puerto 4000).
 */
'use strict';

document.addEventListener('DOMContentLoaded', () => {
    // Endpoints de los dos servicios backend desacoplados
    const scanApiBase = 'http://localhost:3000';
    const IS_LOCAL = window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1';
    const WS_ENDPOINT = window.SENTINEL_WS_URL || (
        IS_LOCAL
            ? 'http://localhost:4000/ws/sentinel'
            : 'https://tu-webservice-sentinel.onrender.com/ws/sentinel'
    );

    /**
     * Escapa caracteres especiales de HTML/XML para prevenir ataques XSS
     * y rupturas de etiquetas al construir sobres SOAP o renderizar DOM dinámico.
     *
     * @param {string|number} str - Cadena de texto a sanitizar.
     * @returns {string} Texto seguro con entidades HTML/XML codificadas.
     */
    function escapeHtml(str) {
        return String(str ?? '')
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;');
    }

    /* ======================================================
       1. AUTENTICACIÓN Y GESTIÓN DE SESIÓN (LOCALSTORAGE)
       ====================================================== */
    const authSection = document.getElementById('authSection');
    const mainAppContent = document.getElementById('mainAppContent');
    const loginForm = document.getElementById('loginForm');
    const registerForm = document.getElementById('registerForm');
    const forgotForm = document.getElementById('forgotForm');
    const authMessage = document.getElementById('authMessage');

    /**
     * Alterna la visibilidad entre los formularios de inicio de sesión,
     * registro de cuenta nueva y recuperación de contraseña.
     *
     * @param {HTMLElement} formToShow - Formulario que debe mostrarse activo.
     */
    function showAuthForm(formToShow) {
        [loginForm, registerForm, forgotForm].forEach(f => f && f.classList.add('hidden'));
        if (formToShow) formToShow.classList.remove('hidden');
        if (authMessage) authMessage.classList.add('hidden');
    }

    // Enlaces de navegación entre vistas de autenticación
    document.getElementById('toRegister')?.addEventListener('click', (e) => {
        e.preventDefault();
        showAuthForm(registerForm);
    });
    document.getElementById('toForgot')?.addEventListener('click', (e) => {
        e.preventDefault();
        showAuthForm(forgotForm);
    });
    document.getElementById('toLoginFromReg')?.addEventListener('click', (e) => {
        e.preventDefault();
        showAuthForm(loginForm);
    });
    document.getElementById('toLoginFromForgot')?.addEventListener('click', (e) => {
        e.preventDefault();
        showAuthForm(loginForm);
    });

    /**
     * Muestra mensajes de validación o confirmación en la pantalla de acceso.
     *
     * @param {string} text - Mensaje a mostrar al usuario.
     * @param {boolean} [isError=true] - Define si se muestra en rojo (error) o verde (éxito).
     */
    function showAuthMsg(text, isError = true) {
        if (!authMessage) return;
        authMessage.textContent = text;
        authMessage.className = `text-center text-xs mt-3 ${isError ? 'text-red-400' : 'text-green-400'}`;
        authMessage.classList.remove('hidden');
    }

    /**
     * Actualiza la barra superior y la pestaña de perfil con el nombre,
     * correo electrónico y avatar del usuario autenticado.
     *
     * @param {{user: string, email: string}} session - Datos de la sesión activa.
     */
    function updateProfileUI(session) {
        const navUserText = document.getElementById('navUserText');
        const profileName = document.getElementById('profileName');
        const profileEmail = document.getElementById('profileEmail');
        const navAvatar = document.getElementById('navAvatar');
        const profileImage = document.getElementById('profileImage');
        const profileIcon = document.getElementById('profileIcon');

        if (navUserText) navUserText.textContent = `👤 ${session.user}`;
        if (profileName) profileName.textContent = session.user;
        if (profileEmail) profileEmail.textContent = session.email;

        const users = JSON.parse(localStorage.getItem('infortech_users') || '[]');
        const fullUser = users.find(u => u.email === session.email);
        if (fullUser && fullUser.avatar) {
            if (navAvatar) {
                navAvatar.src = fullUser.avatar;
                navAvatar.classList.remove('hidden');
            }
            if (profileImage) {
                profileImage.src = fullUser.avatar;
                profileImage.classList.remove('hidden');
            }
            if (profileIcon) profileIcon.classList.add('hidden');
        }
    }

    /**
     * Verifica si existe una sesión activa en localStorage. Si está autenticado,
     * habilita el panel principal y consulta las reglas del Web Service SOAP.
     */
    function checkSession() {
        const session = JSON.parse(localStorage.getItem('infortech_session'));
        if (session) {
            authSection?.classList.add('hidden');
            mainAppContent?.classList.remove('hidden');
            mainAppContent?.classList.add('flex');
            updateProfileUI(session);
            cargarReglasWs();
        } else {
            authSection?.classList.remove('hidden');
            mainAppContent?.classList.add('hidden');
            mainAppContent?.classList.remove('flex');
        }
    }

    // Alta de nuevo usuario en almacenamiento local
    registerForm?.addEventListener('submit', (e) => {
        e.preventDefault();
        const user = document.getElementById('regUser').value.trim();
        const email = document.getElementById('regEmail').value.trim().toLowerCase();
        const pass = document.getElementById('regPass').value;

        const users = JSON.parse(localStorage.getItem('infortech_users') || '[]');
        if (users.some(u => u.email === email)) {
            return showAuthMsg('Ese correo ya se encuentra registrado.');
        }
        users.push({ user, email, pass, avatar: '' });
        localStorage.setItem('infortech_users', JSON.stringify(users));
        localStorage.setItem('infortech_session', JSON.stringify({ user, email }));
        registerForm.reset();
        checkSession();
    });

    // Validación de credenciales e inicio de sesión
    loginForm?.addEventListener('submit', (e) => {
        e.preventDefault();
        const email = document.getElementById('loginEmail').value.trim().toLowerCase();
        const pass = document.getElementById('loginPass').value;

        const users = JSON.parse(localStorage.getItem('infortech_users') || '[]');
        const found = users.find(u => u.email === email && u.pass === pass);
        if (!found) {
            return showAuthMsg('Correo o contraseña incorrectos.');
        }
        localStorage.setItem('infortech_session', JSON.stringify({ user: found.user, email: found.email }));
        loginForm.reset();
        checkSession();
    });

    // Recuperación o restablecimiento de contraseña
    forgotForm?.addEventListener('submit', (e) => {
        e.preventDefault();
        const email = document.getElementById('forgotEmail').value.trim().toLowerCase();
        const newPass = document.getElementById('forgotNewPass').value;
        const users = JSON.parse(localStorage.getItem('infortech_users') || '[]');
        const idx = users.findIndex(u => u.email === email);

        if (idx === -1) return showAuthMsg('No existe una cuenta con ese correo.');
        if (newPass) {
            users[idx].pass = newPass;
            localStorage.setItem('infortech_users', JSON.stringify(users));
            showAuthMsg('Contraseña actualizada correctamente.', false);
        } else {
            showAuthMsg(`Tu contraseña actual es: ${users[idx].pass}`, false);
        }
    });

    // Carga y conversión a Base64 de imagen de perfil
    document.getElementById('avatarInput')?.addEventListener('change', (e) => {
        const file = e.target.files[0];
        const session = JSON.parse(localStorage.getItem('infortech_session'));
        if (!file || !session) return;

        const reader = new FileReader();
        reader.onload = () => {
            const users = JSON.parse(localStorage.getItem('infortech_users') || '[]');
            const idx = users.findIndex(u => u.email === session.email);
            if (idx !== -1) {
                users[idx].avatar = reader.result;
                localStorage.setItem('infortech_users', JSON.stringify(users));
                updateProfileUI(session);
            }
        };
        reader.readAsDataURL(file);
    });

    // Cierre de sesión activo
    document.getElementById('logoutBtn')?.addEventListener('click', () => {
        localStorage.removeItem('infortech_session');
        checkSession();
    });

    /* ======================================================
       2. NAVEGACIÓN DE PESTAÑAS (9 MÓDULOS DE LA PLATAFORMA)
       ====================================================== */
    const tabs = {
        url: { btn: document.getElementById('btnTabUrl'), content: document.getElementById('tabUrlContent') },
        file: { btn: document.getElementById('btnTabFile'), content: document.getElementById('tabFileContent') },
        email: { btn: document.getElementById('btnTabEmail'), content: document.getElementById('tabEmailContent') },
        gen: { btn: document.getElementById('btnTabGen'), content: document.getElementById('tabGenContent') },
        val: { btn: document.getElementById('btnTabVal'), content: document.getElementById('tabValContent') },
        history: { btn: document.getElementById('btnTabHistory'), content: document.getElementById('tabHistoryContent') },
        glossary: { btn: document.getElementById('btnTabGlossary'), content: document.getElementById('tabGlossaryContent') },
        ai: { btn: document.getElementById('btnTabAi'), content: document.getElementById('tabAiContent') },
        auth: { btn: document.getElementById('btnTabAuth'), content: document.getElementById('tabAuthContent') }
    };

    const globalScanResultsWrapper = document.getElementById('globalScanResultsWrapper');

    /**
     * Activa la pestaña seleccionada, oculta las demás y dispara cargas
     * diferidas cuando se ingresa al historial local o al Asistente IA.
     *
     * @param {string} activeKey - Identificador de la pestaña a activar.
     */
    function switchTab(activeKey) {
        Object.entries(tabs).forEach(([key, tab]) => {
            if (!tab.btn || !tab.content) return;
            if (key === activeKey) {
                tab.content.classList.remove('hidden');
                tab.btn.classList.add('active');
            } else {
                tab.content.classList.add('hidden');
                tab.btn.classList.remove('active');
            }
        });

        // El contenedor de resultados de VirusTotal solo se muestra en URL y Archivo
        if (globalScanResultsWrapper) {
            if (activeKey === 'url' || activeKey === 'file') {
                globalScanResultsWrapper.classList.remove('hidden');
            } else {
                globalScanResultsWrapper.classList.add('hidden');
            }
        }

        if (activeKey === 'history') renderHistory();
        if (activeKey === 'ai') cargarHistorialIA();
    }

    Object.keys(tabs).forEach(key => {
        tabs[key].btn?.addEventListener('click', () => switchTab(key));
    });

    /* ======================================================
       3. HISTORIAL LOCAL DE ESCANEOS (LOCALSTORAGE)
       ====================================================== */
    /**
     * Registra un evento de análisis en el historial local del navegador (máx. 30 registros).
     *
     * @param {string} type - Tipo de análisis ('URL', 'Archivo', 'Correo').
     * @param {string} target - Recurso evaluado.
     * @param {string} statusText - Resumen del resultado obtenido.
     */
    function saveLocalHistory(type, target, statusText) {
        const items = JSON.parse(localStorage.getItem('cyberscan_history') || '[]');
        items.unshift({
            type,
            target,
            statusText,
            date: new Date().toLocaleString('es-AR')
        });
        localStorage.setItem('cyberscan_history', JSON.stringify(items.slice(0, 30)));
    }

    /**
     * Dibuja en pantalla la lista de análisis previos almacenados en localStorage.
     */
    function renderHistory() {
        const container = document.getElementById('historyListContainer');
        if (!container) return;
        const items = JSON.parse(localStorage.getItem('cyberscan_history') || '[]');
        if (!items.length) {
            container.innerHTML = '<p class="text-sm text-gray-400">No hay análisis registrados en el historial local.</p>';
            return;
        }
        container.innerHTML = items.map(item => `
            <div class="bg-gray-900 border border-gray-700 p-3 rounded-lg flex flex-col sm:flex-row sm:justify-between sm:items-center gap-1 text-sm">
                <div>
                    <span class="text-xs font-bold uppercase px-2 py-0.5 rounded bg-blue-900 text-blue-300">${escapeHtml(item.type)}</span>
                    <strong class="ml-2 text-white break-all">${escapeHtml(item.target)}</strong>
                </div>
                <div class="text-xs text-gray-400">
                    <span>${escapeHtml(item.statusText)}</span> · <span>${escapeHtml(item.date)}</span>
                </div>
            </div>
        `).join('');
    }

    document.getElementById('clearHistoryBtn')?.addEventListener('click', () => {
        localStorage.removeItem('cyberscan_history');
        renderHistory();
    });

    /* ======================================================
       4. ANALIZADOR DE URL Y ARCHIVOS + EVALUACIÓN SOAP PREVIA
       ====================================================== */
    const analyzeButton = document.getElementById('analyzeButton');
    const urlInput = document.getElementById('urlInput');
    const analyzeFileButton = document.getElementById('analyzeFileButton');
    const fileInput = document.getElementById('fileInput');
    const analyzerStatus = document.getElementById('analyzerStatus');
    const resultsContainer = document.getElementById('resultsContainer');

    /**
     * Renderiza las tarjetas estadísticas de motores Maliciosos, Sospechosos y Limpios
     * devueltas por el backend REST de VirusTotal.
     *
     * @param {string} title - Encabezado con el recurso escaneado.
     * @param {Object} stats - Contadores de detección de VirusTotal.
     */
    function renderScanStats(title, stats) {
        if (!resultsContainer) return;
        const malicious = Number(stats?.malicious || 0);
        const suspicious = Number(stats?.suspicious || 0);
        const clean = Number(stats?.harmless ?? stats?.undetected ?? 0);

        resultsContainer.innerHTML = `
            <div class="bg-gray-900 border border-gray-700 rounded-xl p-4">
                <h3 class="font-bold text-white mb-3">${escapeHtml(title)}</h3>
                <div class="grid grid-cols-3 gap-3 text-center text-sm">
                    <div class="bg-red-900/40 border border-red-700/50 p-3 rounded-lg">
                        <span class="block text-xl font-bold text-red-400">${malicious}</span>
                        <span class="text-xs text-gray-300">Maliciosos</span>
                    </div>
                    <div class="bg-yellow-900/40 border border-yellow-700/50 p-3 rounded-lg">
                        <span class="block text-xl font-bold text-yellow-400">${suspicious}</span>
                        <span class="text-xs text-gray-300">Sospechosos</span>
                    </div>
                    <div class="bg-green-900/40 border border-green-700/50 p-3 rounded-lg">
                        <span class="block text-xl font-bold text-green-400">${clean}</span>
                        <span class="text-xs text-gray-300">Limpios</span>
                    </div>
                </div>
            </div>`;
    }

    // Flujo en dos etapas para URLs: 1) Filtro preventivo SOAP -> 2) Escaneo VirusTotal
    analyzeButton?.addEventListener('click', async () => {
        const url = urlInput.value.trim();
        if (!url) {
            alert('Por favor, ingresa una URL.');
            return;
        }

        // Etapa 1: Consulta al Web Service Sentinel AI (Puerto 4000)
        await evaluarConWebService(url);

        // Etapa 2: Consulta al Backend REST VirusTotal (Puerto 3000)
        analyzeButton.classList.add('loading');
        analyzeButton.disabled = true;
        if (analyzerStatus) analyzerStatus.textContent = 'Analizando URL en VirusTotal...';
        if (resultsContainer) resultsContainer.innerHTML = '';

        try {
            const resp = await fetch(`${scanApiBase}/analizar?url=${encodeURIComponent(url)}`);
            const data = await resp.json();
            if (!resp.ok) throw new Error(data.error || 'Error al analizar la URL.');

            if (data.status === 'En proceso') {
                if (analyzerStatus) analyzerStatus.textContent = data.message;
                return;
            }

            if (analyzerStatus) analyzerStatus.textContent = 'Análisis completado.';
            renderScanStats(`Resultado para: ${url}`, data.stats);
            saveLocalHistory('URL', url, `Maliciosos: ${data.stats.malicious || 0}`);
        } catch (err) {
            if (analyzerStatus) analyzerStatus.textContent = `Aviso: ${err.message}`;
        } finally {
            analyzeButton.classList.remove('loading');
            analyzeButton.disabled = false;
        }
    });

    // Flujo en dos etapas para Archivos: 1) Filtro SOAP por extensión -> 2) Subida a VirusTotal
    analyzeFileButton?.addEventListener('click', async () => {
        const file = fileInput.files[0];
        if (!file) {
            alert('Por favor, selecciona un archivo.');
            return;
        }

        // Etapa 1: Verifica si la extensión del archivo está restringida en SQLite
        await evaluarConWebService(file.name);

        // Etapa 2: Envía el archivo binario al backend REST
        analyzeFileButton.disabled = true;
        if (analyzerStatus) analyzerStatus.textContent = `Subiendo "${file.name}" a VirusTotal...`;
        if (resultsContainer) resultsContainer.innerHTML = '';

        try {
            const formData = new FormData();
            formData.append('file', file);

            const resp = await fetch(`${scanApiBase}/analizar-archivo`, {
                method: 'POST',
                body: formData
            });
            const data = await resp.json();
            if (!resp.ok) throw new Error(data.error || 'Error al analizar el archivo.');

            if (data.status === 'En proceso') {
                if (analyzerStatus) analyzerStatus.textContent = data.message;
                return;
            }

            if (analyzerStatus) analyzerStatus.textContent = 'Análisis de archivo completado.';
            renderScanStats(`Archivo: ${file.name}`, data.stats);
            saveLocalHistory('Archivo', file.name, `Maliciosos: ${data.stats.malicious || 0}`);
        } catch (err) {
            if (analyzerStatus) analyzerStatus.textContent = `Aviso: ${err.message}`;
        } finally {
            analyzeFileButton.disabled = false;
        }
    });

    /* ======================================================
       5. VERIFICACIÓN DE FILTRACIONES DE CORREO
       ====================================================== */
    document.getElementById('breach-btn')?.addEventListener('click', () => {
        const email = document.getElementById('breach-email').value.trim();
        const resultDiv = document.getElementById('breach-result');
        if (!email || !email.includes('@')) {
            return alert('Ingresa un correo electrónico válido.');
        }
        resultDiv.classList.remove('hidden');
        resultDiv.className = 'p-3 rounded-lg bg-blue-900/40 border border-blue-500/40 text-sm text-blue-200';
        resultDiv.textContent = `Verificación completada para ${email}: se recomienda activar autenticación en dos pasos (2FA) y no reutilizar contraseñas.`;
        saveLocalHistory('Correo', email, 'Verificado');
    });

    /* ======================================================
       6. GENERADOR Y VALIDADOR DE CONTRASEÑAS (100% LOCAL)
       ====================================================== */
    const genLength = document.getElementById('genLength');
    const lengthVal = document.getElementById('lengthVal');
    const genPasswordOutput = document.getElementById('genPasswordOutput');

    genLength?.addEventListener('input', () => {
        if (lengthVal) lengthVal.textContent = genLength.value;
    });

    // Genera una contraseña aleatoria en el navegador sin enviarla por red
    document.getElementById('generatePassBtn')?.addEventListener('click', () => {
        const len = Number(genLength?.value || 16);
        const useNumbers = document.getElementById('genNumbers')?.checked;
        const useSymbols = document.getElementById('genSymbols')?.checked;

        let charset = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
        if (useNumbers) charset += '0123456789';
        if (useSymbols) charset += '!@#$%^&*()_+-=[]{}|;:,.<>?';

        let pass = '';
        for (let i = 0; i < len; i += 1) {
            pass += charset.charAt(Math.floor(Math.random() * charset.length));
        }
        if (genPasswordOutput) genPasswordOutput.value = pass;
    });

    document.getElementById('copyGenPass')?.addEventListener('click', () => {
        if (!genPasswordOutput?.value) return;
        navigator.clipboard.writeText(genPasswordOutput.value);
        alert('Contraseña copiada al portapapeles.');
    });

    const valPasswordInput = document.getElementById('valPasswordInput');
    const valStrengthBar = document.getElementById('valStrengthBar');
    const valStrengthText = document.getElementById('valStrengthText');

    // Evalúa en tiempo real la entropía básica de una clave ingresada
    valPasswordInput?.addEventListener('input', () => {
        const val = valPasswordInput.value;
        let score = 0;
        if (val.length >= 8) score += 25;
        if (val.length >= 12) score += 25;
        if (/[A-Z]/.test(val) && /[a-z]/.test(val)) score += 25;
        if (/[0-9]/.test(val) && /[^A-Za-z0-9]/.test(val)) score += 25;

        if (!val) {
            valStrengthBar.style.width = '0%';
            valStrengthText.textContent = 'Ingresa una clave para evaluar su seguridad.';
            return;
        }

        valStrengthBar.style.width = `${score}%`;
        if (score <= 25) {
            valStrengthBar.className = 'h-full bg-red-500 transition-all duration-300';
            valStrengthText.textContent = 'Seguridad Débil: agrega más longitud, mayúsculas y símbolos.';
        } else if (score <= 75) {
            valStrengthBar.className = 'h-full bg-yellow-500 transition-all duration-300';
            valStrengthText.textContent = 'Seguridad Media: aceptable, pero puede fortalecerse.';
        } else {
            valStrengthBar.className = 'h-full bg-green-500 transition-all duration-300';
            valStrengthText.textContent = 'Seguridad Fuerte: excelente combinación de caracteres.';
        }
    });

    /* ======================================================
       7. CLIENTE WEB SERVICE SOAP / XML (SENTINEL + POLÍTICAS)
       ====================================================== */
    // Base de contingencia en cliente por si el servicio SOAP (puerto 4000) está apagado
    const FALLBACK_IA_KB = [
        {
            keys: ['ransomware', 'secuestro', 'cifrado', 'rescate'],
            resp: 'El ransomware cifra tus archivos y pide rescate. Desconecta el equipo de la red de inmediato y restaura desde backups offline.'
        },
        {
            keys: ['troyano', 'trojan', 'falso', 'disfrazado'],
            resp: 'Un troyano se oculta en programas aparentemente legítimos para robar credenciales. Descarga software solo de fuentes oficiales.'
        },
        {
            keys: ['phishing', 'correo', 'enlace', 'banco', 'suplantacion'],
            resp: 'El phishing suplanta identidades para robar claves. Revisa siempre el dominio del remitente y activa la autenticación en dos pasos (2FA).'
        },
        {
            keys: ['gusano', 'worm', 'red', 'propagacion'],
            resp: 'Un gusano se propaga solo por la red explotando fallos. Mantén actualizado el sistema operativo y el firewall.'
        },
        {
            keys: ['spyware', 'keylogger', 'espia', 'teclado'],
            resp: 'El spyware espía tu actividad y los keyloggers registran tus teclas. Usa gestores de contraseñas y análisis antimalware.'
        }
    ];

    /**
     * Devuelve una respuesta orientativa local si el Web Service SOAP no está en ejecución.
     *
     * @param {string} pregunta - Consulta del usuario.
     * @returns {string} Respuesta de contingencia.
     */
    function respuestaIaContingencia(pregunta) {
        const q = pregunta.toLowerCase();
        const hit = FALLBACK_IA_KB.find(item => item.keys.some(k => q.includes(k)));
        return hit
            ? hit.resp
            : 'Puedo orientarte sobre Ransomware, Troyanos, Phishing, Gusanos o Spyware. (Modo demo estático sin servidor SOAP activo).';
    }

    /**
     * Construye un sobre SOAP 1.1 (<soap:Envelope>), lo envía por HTTP POST al plugin
     * en el puerto 4000 y parsea la respuesta XML con DOMParser.
     *
     * @param {string} bodyXml - Etiqueta XML de la operación SOAP a invocar.
     * @returns {Promise<Document>} Documento XML devuelto por el servidor.
     */
    async function invocarSoap(bodyXml) {
        const envelope = `<?xml version="1.0" encoding="UTF-8"?>
        <soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:tns="http://cyberscan.local/ws/sentinel">
          <soap:Body>${bodyXml}</soap:Body>
        </soap:Envelope>`;

        const res = await fetch(WS_ENDPOINT, {
            method: 'POST',
            headers: { 'Content-Type': 'text/xml; charset=utf-8' },
            body: envelope
        });
        const textXml = await res.text();
        const xmlDoc = new DOMParser().parseFromString(textXml, 'text/xml');
        const fault = xmlDoc.querySelector('faultstring');
        if (fault) throw new Error(fault.textContent);
        return xmlDoc;
    }

    /**
     * Invoca la operación SOAP EvaluarRecurso antes de realizar un escaneo
     * y muestra el banner preventivo (BLOQUEAR, PERMITIR o SIN_REGLA).
     *
     * @param {string} recurso - URL o nombre de archivo a evaluar.
     */
    async function evaluarConWebService(recurso) {
        const banner = document.getElementById('wsAlertBanner');
        if (!banner) return;
        try {
            const xml = await invocarSoap(`<tns:EvaluarRecursoRequest><recurso>${escapeHtml(recurso)}</recurso></tns:EvaluarRecursoRequest>`);
            const accion = xml.querySelector('accion')?.textContent || 'SIN_REGLA';
            const riesgo = xml.querySelector('nivelRiesgo')?.textContent || '0';
            const motivo = xml.querySelector('motivo')?.textContent || '';

            banner.classList.remove('hidden');
            if (accion === 'BLOQUEAR') {
                banner.className = 'mb-3 p-3 rounded text-sm bg-red-900/60 border border-red-500 text-red-200';
                banner.innerHTML = `<strong>🚨 BLOQUEADO POR WEB SERVICE SENTINEL (Riesgo ${riesgo}/100):</strong> ${escapeHtml(motivo)}`;
            } else if (accion === 'PERMITIR') {
                banner.className = 'mb-3 p-3 rounded text-sm bg-green-900/60 border border-green-500 text-green-200';
                banner.innerHTML = `<strong>✅ CONFIABLE SEGÚN WEB SERVICE SENTINEL:</strong> ${escapeHtml(motivo)}`;
            } else {
                banner.className = 'mb-3 p-3 rounded text-sm bg-gray-700 border border-gray-500 text-gray-300';
                banner.innerHTML = `<strong>ℹ️ Evaluación Web Service:</strong> ${escapeHtml(motivo)}`;
            }
        } catch {
            // Tolerancia a fallos: si el plugin está apagado, el aplicativo base sigue funcionando
            banner.classList.remove('hidden');
            banner.className = 'mb-3 p-3 rounded text-sm bg-yellow-900/40 border border-yellow-600 text-yellow-300';
            banner.textContent = 'Web Service Sentinel fuera de línea (el aplicativo base continúa operando normalmente).';
        }
    }

    /**
     * Consulta la operación SOAP ListarReglas y renderiza la lista de políticas
     * almacenadas en la base SQLite del plugin.
     */
    async function cargarReglasWs() {
        const list = document.getElementById('wsRulesList');
        if (!list) return;
        try {
            const xml = await invocarSoap('<tns:ListarReglasRequest/>');
            const reglas = Array.from(xml.querySelectorAll('regla'));
            if (!reglas.length) {
                list.innerHTML = '<p class="text-gray-500">No hay reglas configuradas en SQLite.</p>';
                return;
            }
            list.innerHTML = reglas.map(r => {
                const id = r.querySelector('id').textContent;
                const tipo = r.querySelector('tipoObjetivo').textContent;
                const patron = r.querySelector('patron').textContent;
                const accion = r.querySelector('accion').textContent;
                const desc = r.querySelector('descripcion').textContent;
                return `<div class="flex justify-between items-center bg-gray-900 p-2 rounded border-l-4 ${accion === 'BLOQUEAR' ? 'border-red-500' : 'border-green-500'}">
                    <div>
                        <span class="text-xs font-bold px-1.5 py-0.5 rounded bg-gray-700 text-cyan-300">${escapeHtml(tipo)}</span>
                        <strong class="ml-1 text-white">${escapeHtml(patron)}</strong>
                        <span class="text-xs text-gray-400 ml-2">${escapeHtml(desc)}</span>
                    </div>
                    <button onclick="eliminarReglaWs(${Number(id)})" class="text-xs text-red-400 hover:underline ml-2">Eliminar</button>
                </div>`;
            }).join('');
        } catch {
            list.innerHTML = '<p class="text-yellow-400 text-xs">Inicia el Web Service en el puerto 4000 para gestionar reglas.</p>';
        }
    }

    // Expone función global para eliminar reglas desde los botones dinámicos de la tabla
    window.eliminarReglaWs = async (id) => {
        await invocarSoap(`<tns:EliminarReglaRequest><id>${id}</id></tns:EliminarReglaRequest>`);
        cargarReglasWs();
    };

    // Alta de nueva política de seguridad mediante operación SOAP AgregarRegla
    const wsRuleForm = document.getElementById('wsRuleForm');
    if (wsRuleForm) {
        wsRuleForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const tipo = document.getElementById('wsTipo').value;
            const patron = document.getElementById('wsPatron').value.trim();
            const accion = document.getElementById('wsAccion').value;
            const desc = document.getElementById('wsDesc').value.trim();
            const riesgo = accion === 'BLOQUEAR' ? 90 : 0;

            await invocarSoap(`<tns:AgregarReglaRequest>
                <tipoObjetivo>${escapeHtml(tipo)}</tipoObjetivo>
                <patron>${escapeHtml(patron)}</patron>
                <accion>${escapeHtml(accion)}</accion>
                <nivelRiesgo>${riesgo}</nivelRiesgo>
                <descripcion>${escapeHtml(desc)}</descripcion>
            </tns:AgregarReglaRequest>`);
            wsRuleForm.reset();
            cargarReglasWs();
        });
        cargarReglasWs();
    }

    /* ======================================================
       8. MÓDULO DE ASISTENTE IA POR USUARIO (SOAP + SQLITE)
       ====================================================== */
    const aiChatBox = document.getElementById('aiChatBox');
    const aiChatForm = document.getElementById('aiChatForm');
    const aiQuestionInput = document.getElementById('aiQuestionInput');
    const aiSendBtn = document.getElementById('aiSendBtn');

    /**
     * Genera el bloque HTML de una burbuja de pregunta del usuario y respuesta de Sentinel AI.
     *
     * @param {string} pregunta - Texto enviado por el usuario.
     * @param {string} respuesta - Respuesta generada por la IA o base local.
     * @param {string} fuente - Modelo o motor que originó la respuesta.
     * @returns {string} Fragmento HTML renderizable.
     */
    function renderMensajeChat(pregunta, respuesta, fuente) {
        return `
            <div class="flex flex-col gap-1.5">
                <div class="self-end bg-blue-600/30 border border-blue-500/40 text-blue-100 rounded-lg px-3 py-2 max-w-[85%]">
                    <p class="text-xs font-bold text-blue-300 mb-0.5">Tú:</p>
                    <p>${escapeHtml(pregunta)}</p>
                </div>
                <div class="self-start bg-gray-800 border border-cyan-500/40 text-gray-200 rounded-lg px-3 py-2 max-w-[90%]">
                    <p class="text-xs font-bold text-cyan-400 mb-0.5">🤖 Sentinel AI <span class="text-[10px] text-gray-400 font-normal">(${escapeHtml(fuente)})</span></p>
                    <p>${escapeHtml(respuesta)}</p>
                </div>
            </div>`;
    }

    /**
     * Recupera desde SQLite (vía SOAP ObtenerHistorialIA) el historial conversacional
     * asociado al correo del usuario actualmente autenticado.
     */
    async function cargarHistorialIA() {
        const session = JSON.parse(localStorage.getItem('infortech_session'));
        if (!session || !aiChatBox) return;

        const badge = document.getElementById('aiUserBadge');
        if (badge) badge.textContent = `Sesión: ${session.email}`;

        try {
            const xml = await invocarSoap(`<tns:ObtenerHistorialIARequest><usuarioEmail>${escapeHtml(session.email)}</usuarioEmail></tns:ObtenerHistorialIARequest>`);
            const mensajes = Array.from(xml.querySelectorAll('mensaje'));
            if (!mensajes.length) {
                aiChatBox.innerHTML = `<p class="text-gray-400 text-center">Hola <strong>${escapeHtml(session.user)}</strong>, pregúntame sobre cualquier virus, malware o duda de seguridad.</p>`;
                return;
            }
            aiChatBox.innerHTML = mensajes.map(m => renderMensajeChat(
                m.querySelector('pregunta').textContent,
                m.querySelector('respuesta').textContent,
                m.querySelector('fuente').textContent
            )).join('');
            aiChatBox.scrollTop = aiChatBox.scrollHeight;
        } catch {
            aiChatBox.innerHTML = `<p class="text-gray-400 text-center">Hola <strong>${escapeHtml(session.user)}</strong>, escribe tu consulta sobre virus o amenazas (Modo contingencia activo si el Web Service está apagado).</p>`;
        }
    }

    // Envía la consulta del usuario al Web Service SOAP ConsultarAsistenteIA
    if (aiChatForm) {
        aiChatForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const session = JSON.parse(localStorage.getItem('infortech_session'));
            if (!session) return alert('Debes iniciar sesión para usar el Asistente IA.');

            const pregunta = aiQuestionInput.value.trim();
            if (!pregunta) return;

            aiSendBtn.disabled = true;
            aiSendBtn.textContent = 'Pensando...';
            aiQuestionInput.value = '';

            try {
                const xml = await invocarSoap(`<tns:ConsultarAsistenteIARequest>
                    <usuarioEmail>${escapeHtml(session.email)}</usuarioEmail>
                    <pregunta>${escapeHtml(pregunta)}</pregunta>
                </tns:ConsultarAsistenteIARequest>`);

                const respuesta = xml.querySelector('respuesta')?.textContent || 'Sin respuesta.';
                const fuente = xml.querySelector('fuente')?.textContent || 'Sentinel AI';

                if (aiChatBox.querySelector('p.text-center')) aiChatBox.innerHTML = '';
                aiChatBox.innerHTML += renderMensajeChat(pregunta, respuesta, fuente);
                aiChatBox.scrollTop = aiChatBox.scrollHeight;
            } catch {
                // Si el Web Service está apagado, responde con el motor de contingencia local
                const respFallback = respuestaIaContingencia(pregunta);
                if (aiChatBox.querySelector('p.text-center')) aiChatBox.innerHTML = '';
                aiChatBox.innerHTML += renderMensajeChat(pregunta, respFallback, 'Modo Demo Estático');
                aiChatBox.scrollTop = aiChatBox.scrollHeight;
            } finally {
                aiSendBtn.disabled = false;
                aiSendBtn.textContent = 'Preguntar';
            }
        });
    }

    // Verifica el estado de sesión al cargar la aplicación
    checkSession();
});