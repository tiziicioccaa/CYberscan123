/**
 * @file server.js
 * @description Servidor backend REST del aplicativo base Cyberscan (Puerto 3000).
 * Expone endpoints HTTP JSON para delegar el escaneo profundo de URLs y archivos
 * locales (de hasta 25 MB) a la API v3 de VirusTotal una vez superado el filtro
 * preventivo del Plugin Web Service Sentinel AI.
 */
'use strict';

// Carga automática del archivo .env local si existe (nativo en Node.js 20.12+)
try { process.loadEnvFile(); } catch (_) {}

const express = require('express');
const cors = require('cors');
const fetch = require('node-fetch');
const multer = require('multer');
const FormData = require('form-data');

const app = express();

// Habilita peticiones cross-origin desde el frontend (puerto 5500)
app.use(cors());
app.use(express.json({ limit: '16kb' }));

/**
 * Configuración de Multer en memoria RAM para recibir archivos adjuntos
 * sin escribir temporales en disco, estableciendo un límite máximo de 25 MB.
 */
const upload = multer({
    storage: multer.memoryStorage(),
    limits: { fileSize: 25 * 1024 * 1024 }
});

// Clave de autenticación para la API v3 de VirusTotal cargada desde entorno
const apiKey = process.env.VIRUSTOTAL_API_KEY || '';

if (!apiKey) {
    console.warn('[Cyberscan Base] VIRUSTOTAL_API_KEY no configurada: los escaneos responderán HTTP 503.');
}

// =============================================================================
// ENDPOINT 1: GET /analizar -> Escaneo de direcciones URL en VirusTotal
// =============================================================================
/**
 * Consulta el historial de análisis de una URL en VirusTotal v3 mediante su
 * identificador Base64URL. Si la URL nunca fue analizada (HTTP 404), solicita
 * un nuevo escaneo y aguarda 15 segundos antes de recuperar las estadísticas.
 */
app.get('/analizar', async (req, res) => {
    const urlToAnalyze = typeof req.query.url === 'string' ? req.query.url.trim() : '';

    // Validaciones de entrada: presencia, longitud máxima y formato sintáctico HTTP/HTTPS
    if (!urlToAnalyze) return res.status(400).json({ error: 'Falta la URL' });
    if (urlToAnalyze.length > 2048) return res.status(400).json({ error: 'La URL supera los 2048 caracteres.' });

    let parsedUrl;
    try {
        parsedUrl = new URL(urlToAnalyze);
    } catch {
        return res.status(400).json({ error: 'La URL no tiene un formato válido.' });
    }
    if (!['http:', 'https:'].includes(parsedUrl.protocol)) {
        return res.status(400).json({ error: 'Solo se admiten URLs http o https.' });
    }
    if (!apiKey) return res.status(503).json({ error: 'Configura VIRUSTOTAL_API_KEY en el servidor.' });

    try {
        // Codifica la URL en formato Base64URL sin relleno ('=') según especificación de VirusTotal v3
        const urlId = Buffer.from(urlToAnalyze)
            .toString('base64')
            .replace(/=/g, '')
            .replace(/\+/g, '-')
            .replace(/\//g, '_');

        const headers = { 'x-apikey': apiKey };
        let response = await fetch(`https://www.virustotal.com/api/v3/urls/${urlId}`, { headers });

        // Si la URL no existe aún en la base de VirusTotal, envía una solicitud POST para analizarla
        if (response.status === 404) {
            const form = new URLSearchParams({ url: urlToAnalyze });
            response = await fetch('https://www.virustotal.com/api/v3/urls', {
                method: 'POST',
                headers: { ...headers, 'Content-Type': 'application/x-www-form-urlencoded' },
                body: form.toString(),
            });
            if (!response.ok) return res.status(502).json({ error: 'VirusTotal no pudo iniciar el análisis de la URL.' });
            await response.json();

            // Espera 15 segundos para dar tiempo a los motores antivirus a completar el escaneo
            await new Promise(resolve => setTimeout(resolve, 15000));
            response = await fetch(`https://www.virustotal.com/api/v3/urls/${urlId}`, { headers });
        }
        if (!response.ok) return res.status(502).json({ error: 'No se pudo obtener el resultado de VirusTotal.' });

        const data = await response.json();
        const attributes = data.data.attributes;
        const stats = attributes.last_analysis_stats;

        // Suma el total de motores que ya emitieron veredicto
        const analyzedEngines = Object.values(stats || {}).reduce((total, count) => total + (Number(count) || 0), 0);

        if (!analyzedEngines) {
            return res.status(202).json({
                status: 'En proceso',
                message: 'VirusTotal todavía está analizando la URL. Inténtalo nuevamente en unos segundos.'
            });
        }

        // Devuelve el resumen estadístico y el detalle por motor al frontend
        return res.json({
            status: 'Encontrado',
            stats,
            results: attributes.last_analysis_results,
            meta: { title: attributes.title, url: attributes.url },
        });
    } catch (error) {
        console.error(`[Cyberscan Base] Error al analizar URL: ${error.message}`);
        return res.status(502).json({ error: 'No se pudo completar el análisis de la URL.' });
    }
});

// =============================================================================
// ENDPOINT 2: POST /analizar-archivo -> Subida y escaneo de archivos binarios
// =============================================================================
/**
 * Recibe un archivo binario en memoria mediante multipart/form-data, lo remite
 * a VirusTotal v3 y realiza hasta 4 intentos de consulta periódica (polling cada 20s)
 * hasta obtener el reporte completo de los motores antivirus.
 */
app.post('/analizar-archivo', upload.single('file'), async (req, res) => {
    if (!req.file) return res.status(400).json({ error: 'No se subió ningún archivo' });
    if (!apiKey) return res.status(503).json({ error: 'Configura VIRUSTOTAL_API_KEY en el servidor.' });

    try {
        // Construye el formulario multipart con el buffer en memoria y el nombre original del archivo
        const formData = new FormData();
        formData.append('file', req.file.buffer, req.file.originalname);

        const uploadResp = await fetch('https://www.virustotal.com/api/v3/files', {
            method: 'POST',
            headers: { 'x-apikey': apiKey, ...formData.getHeaders() },
            body: formData
        });
        if (!uploadResp.ok) return res.status(502).json({ error: 'VirusTotal no pudo recibir el archivo.' });

        const uploadData = await uploadResp.json();
        const analysisId = uploadData.data.id;
        let analysisResp;
        let analysisData;

        // Consulta el estado del análisis hasta 4 veces con intervalos de 20 segundos
        for (let attempt = 0; attempt < 4; attempt += 1) {
            if (attempt > 0) await new Promise(resolve => setTimeout(resolve, 20000));
            analysisResp = await fetch(`https://www.virustotal.com/api/v3/analyses/${analysisId}`, {
                headers: { 'x-apikey': apiKey }
            });
            if (!analysisResp.ok) return res.status(502).json({ error: 'No se pudo obtener el resultado en VirusTotal.' });
            analysisData = await analysisResp.json();
            if (analysisData.data.attributes.status === 'completed') break;
        }

        const attributes = analysisData.data.attributes;
        if (attributes.status !== 'completed') {
            return res.status(202).json({ status: 'En proceso', message: 'VirusTotal todavía está analizando el archivo.' });
        }

        return res.json({
            status: 'Encontrado',
            stats: attributes.stats,
            results: attributes.results,
        });
    } catch (error) {
        console.error(`[Cyberscan Base] Error al analizar archivo: ${error.message}`);
        return res.status(502).json({ error: 'No se pudo completar el análisis del archivo.' });
    }
});

// Inicia el servidor backend base en el puerto 3000
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`[Cyberscan Base] Servidor escuchando en http://localhost:${PORT}`));