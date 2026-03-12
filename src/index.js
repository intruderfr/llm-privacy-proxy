/**
 * LLM Privacy Proxy - Main server module.
 *
 * Intercepts HTTP requests to LLM APIs, anonymizes PII in request bodies,
 * forwards sanitized requests, and de-anonymizes responses.
 */

const http = require('http');
const https = require('https');
const { URL } = require('url');
const { Anonymizer } = require('./anonymizer');

class PrivacyProxy {
  /**
   * @param {Object} options
   * @param {string} options.target - Target LLM API base URL
   * @param {number} [options.port=8080] - Proxy listen port
   * @param {string[]} [options.piiTypes] - PII types to detect
   * @param {Object[]} [options.customPatterns] - Custom detection patterns
   * @param {string[]} [options.allowlist] - Values to never anonymize
   * @param {boolean} [options.logAnonymizations=false] - Log anonymization events
   */
  constructor(options = {}) {
    this.target = options.target || 'https://api.openai.com';
    this.port = options.port || 8080;
    this.logAnonymizations = options.logAnonymizations || false;
    this.anonymizer = new Anonymizer({
      piiTypes: options.piiTypes,
      customPatterns: options.customPatterns,
      allowlist: options.allowlist,
    });
    this._server = null;
    this._auditLog = [];
  }

  /**
   * Start the proxy server.
   */
  start() {
    this._server = http.createServer((req, res) => this._handleRequest(req, res));
    this._server.listen(this.port, () => {
      console.log(`[PrivacyProxy] Listening on port ${this.port}`);
      console.log(`[PrivacyProxy] Forwarding to ${this.target}`);
    });
    return this._server;
  }

  /**
   * Stop the proxy server.
   */
  stop() {
    if (this._server) {
      this._server.close();
      this._server = null;
    }
  }

  /**
   * Handle incoming proxy request.
   */
  async _handleRequest(clientReq, clientRes) {
    let body = '';
    clientReq.on('data', chunk => { body += chunk; });
    clientReq.on('end', () => {
      try {
        // Anonymize request body
        const session = this.anonymizer.createSession();
        const sanitizedBody = session.anonymize(body);

        if (this.logAnonymizations && session.mappings.size > 0) {
          const entry = {
            timestamp: new Date().toISOString(),
            path: clientReq.url,
            replacements: session.mappings.size,
            types: [...new Set(Array.from(session.mappings.values()).map(m => m.type))],
          };
          this._auditLog.push(entry);
          console.log(`[PrivacyProxy] Anonymized ${entry.replacements} PII items`);
        }

        // Forward to target
        const targetUrl = new URL(clientReq.url, this.target);
        const isHttps = targetUrl.protocol === 'https:';
        const transport = isHttps ? https : http;

        const proxyReq = transport.request({
          hostname: targetUrl.hostname,
          port: targetUrl.port || (isHttps ? 443 : 80),
          path: targetUrl.pathname + targetUrl.search,
          method: clientReq.method,
          headers: {
            ...clientReq.headers,
            host: targetUrl.hostname,
            'content-length': Buffer.byteLength(sanitizedBody),
          },
        }, proxyRes => {
          let responseBody = '';
          proxyRes.on('data', chunk => { responseBody += chunk; });
          proxyRes.on('end', () => {
            // De-anonymize response
            const restoredBody = session.deanonymize(responseBody);

            clientRes.writeHead(proxyRes.statusCode, proxyRes.headers);
            clientRes.end(restoredBody);
          });
        });

        proxyReq.on('error', err => {
          console.error('[PrivacyProxy] Proxy error:', err.message);
          clientRes.writeHead(502);
          clientRes.end(JSON.stringify({ error: 'Proxy error', message: err.message }));
        });

        proxyReq.write(sanitizedBody);
        proxyReq.end();
      } catch (err) {
        console.error('[PrivacyProxy] Error:', err.message);
        clientRes.writeHead(500);
        clientRes.end(JSON.stringify({ error: 'Internal proxy error' }));
      }
    });
  }

  /**
   * Get audit log entries.
   */
  getAuditLog() {
    return [...this._auditLog];
  }
}

module.exports = { PrivacyProxy };

// Run directly
if (require.main === module) {
  const proxy = new PrivacyProxy({
    target: process.env.LLM_TARGET || 'https://api.openai.com',
    port: parseInt(process.env.PORT || '8080'),
    logAnonymizations: true,
  });
  proxy.start();
}
