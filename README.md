# 🔐 LLM Privacy Proxy

[![Node.js](https://img.shields.io/badge/node.js-18%2B-green.svg)](https://nodejs.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Tests](https://img.shields.io/badge/tests-passing-brightgreen.svg)]()
[![npm](https://img.shields.io/badge/npm-v0.1.0-red.svg)]()

A Node.js proxy server that intercepts requests to LLM APIs, detects and anonymizes PII (Personally Identifiable Information) before forwarding, and de-anonymizes responses before returning them to the client.

## Features

- 🕵️ **PII Detection** — Detects emails, phone numbers, SSNs, credit cards, names, addresses
- 🔄 **Reversible Anonymization** — Replaces PII with consistent tokens, restores in responses
- 🌐 **Proxy Any LLM API** — Works with OpenAI, Anthropic, Google, and custom endpoints
- 📊 **Audit Logging** — Track what was anonymized and when
- ⚙️ **Configurable Rules** — Choose which PII types to detect, add custom patterns

## Installation

```bash
npm install llm-privacy-proxy
```

## Quick Start

```javascript
const { PrivacyProxy } = require('llm-privacy-proxy');

const proxy = new PrivacyProxy({
  target: 'https://api.openai.com',
  port: 8080,
  piiTypes: ['email', 'phone', 'ssn', 'credit_card', 'name'],
  logAnonymizations: true,
});

proxy.start();
// Now point your LLM client to http://localhost:8080
```

## How It Works

```
Client → Privacy Proxy → LLM API
  1. Client sends request with PII
  2. Proxy detects and replaces PII with tokens
  3. Sanitized request forwarded to LLM
  4. LLM response received
  5. Tokens restored to original PII
  6. Clean response returned to client
```

## Supported PII Types

| Type | Example | Token Format |
|------|---------|-------------|
| `email` | john@example.com | `[EMAIL_001]` |
| `phone` | +1-555-123-4567 | `[PHONE_001]` |
| `ssn` | 123-45-6789 | `[SSN_001]` |
| `credit_card` | 4111-1111-1111-1111 | `[CC_001]` |
| `ip_address` | 192.168.1.1 | `[IP_001]` |

## Configuration

```javascript
const proxy = new PrivacyProxy({
  target: 'https://api.openai.com',
  port: 8080,
  piiTypes: ['email', 'phone', 'ssn'],
  customPatterns: [
    { name: 'employee_id', pattern: /EMP-\d{6}/g, token: 'EMPID' }
  ],
  allowlist: ['support@company.com'],
  logAnonymizations: true,
});
```

## License

MIT License — see [LICENSE](LICENSE) for details.
