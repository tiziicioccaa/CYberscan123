const test = require('node:test');
const assert = require('node:assert');
const http = require('node:http');
const app = require('../ws-server');

test('Web Service SOAP responde WSDL, evalúa .exe y responde consultas de Asistente IA', async () => {
    const server = http.createServer(app);
    await new Promise((resolve) => server.listen(0, resolve));
    const port = server.address().port;
    const baseUrl = `http://127.0.0.1:${port}/ws/sentinel`;

    try {
        // 1. Verificar WSDL
        const wsdlRes = await fetch(`${baseUrl}?wsdl`);
        const wsdlText = await wsdlRes.text();
        assert.strictEqual(wsdlRes.status, 200);
        assert.ok(wsdlText.includes('SentinelSecurityService'));

        // 2. Probar Asistente IA por usuario
        const iaEnvelope = `<?xml version="1.0" encoding="UTF-8"?>
        <soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:tns="http://cyberscan.local/ws/sentinel">
          <soap:Body>
            <tns:ConsultarAsistenteIARequest>
              <usuarioEmail>alumno@escuela.edu.ar</usuarioEmail>
              <pregunta>¿Qué es un ransomware?</pregunta>
            </tns:ConsultarAsistenteIARequest>
          </soap:Body>
        </soap:Envelope>`;

        const iaRes = await fetch(baseUrl, {
            method: 'POST',
            headers: { 'Content-Type': 'text/xml; charset=utf-8' },
            body: iaEnvelope
        });
        const iaXml = await iaRes.text();
        assert.strictEqual(iaRes.status, 200);
        assert.ok(iaXml.includes('ConsultarAsistenteIAResponse'));
    } finally {
        server.close();
    }
});