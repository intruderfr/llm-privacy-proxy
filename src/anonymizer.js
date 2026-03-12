/**
 * Anonymizer - PII detection and replacement engine.
 *
 * Detects PII patterns in text and replaces them with consistent
 * tokens that can be reversed after LLM processing.
 */

// Built-in PII detection patterns
const PII_PATTERNS = {
  email: {
    regex: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g,
    token: 'EMAIL',
  },
  phone: {
    regex: /(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/g,
    token: 'PHONE',
  },
  ssn: {
    regex: /\b\d{3}-\d{2}-\d{4}\b/g,
    token: 'SSN',
  },
  credit_card: {
    regex: /\b(?:\d{4}[-\s]?){3}\d{4}\b/g,
    token: 'CC',
  },
  ip_address: {
    regex: /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g,
    token: 'IP',
  },
  date_of_birth: {
    regex: /\b(?:0[1-9]|1[0-2])\/(?:0[1-9]|[12]\d|3[01])\/(?:19|20)\d{2}\b/g,
    token: 'DOB',
  },
  passport: {
    regex: /\b[A-Z]{1,2}\d{6,9}\b/g,
    token: 'PASSPORT',
  },
};


class Anonymizer {
  /**
   * @param {Object} options
   * @param {string[]} [options.piiTypes] - PII types to detect (default: all)
   * @param {Object[]} [options.customPatterns] - Custom patterns [{name, pattern, token}]
   * @param {string[]} [options.allowlist] - Values to never anonymize
   */
  constructor(options = {}) {
    this.piiTypes = options.piiTypes || Object.keys(PII_PATTERNS);
    this.customPatterns = options.customPatterns || [];
    this.allowlist = new Set(options.allowlist || []);
    this._patterns = this._buildPatterns();
  }

  _buildPatterns() {
    const patterns = [];
    for (const type of this.piiTypes) {
      if (PII_PATTERNS[type]) {
        patterns.push({
          name: type,
          regex: PII_PATTERNS[type].regex,
          token: PII_PATTERNS[type].token,
        });
      }
    }
    for (const custom of this.customPatterns) {
      patterns.push({
        name: custom.name,
        regex: custom.pattern,
        token: custom.token || custom.name.toUpperCase(),
      });
    }
    return patterns;
  }

  /**
   * Create a new anonymization session with its own mapping table.
   */
  createSession() {
    return new AnonymizationSession(this._patterns, this.allowlist);
  }

  /**
   * Detect PII in text without replacing.
   */
  detect(text) {
    const findings = [];
    for (const pattern of this._patterns) {
      const regex = new RegExp(pattern.regex.source, pattern.regex.flags);
      let match;
      while ((match = regex.exec(text)) !== null) {
        if (!this.allowlist.has(match[0])) {
          findings.push({
            type: pattern.name,
            value: match[0],
            index: match.index,
            length: match[0].length,
          });
        }
      }
    }
    return findings;
  }
}


class AnonymizationSession {
  constructor(patterns, allowlist) {
    this._patterns = patterns;
    this._allowlist = allowlist;
    this.mappings = new Map(); // token -> { original, type }
    this._reverseMap = new Map(); // original -> token
    this._counters = {};
  }

  _getToken(type, tokenPrefix) {
    if (!this._counters[type]) this._counters[type] = 0;
    this._counters[type]++;
    return `[${tokenPrefix}_${String(this._counters[type]).padStart(3, '0')}]`;
  }

  /**
   * Anonymize PII in text, replacing with consistent tokens.
   */
  anonymize(text) {
    let result = text;
    for (const pattern of this._patterns) {
      const regex = new RegExp(pattern.regex.source, pattern.regex.flags);
      result = result.replace(regex, (match) => {
        if (this._allowlist.has(match)) return match;

        // Reuse existing token for same value
        if (this._reverseMap.has(match)) {
          return this._reverseMap.get(match);
        }

        const token = this._getToken(pattern.name, pattern.token);
        this.mappings.set(token, { original: match, type: pattern.name });
        this._reverseMap.set(match, token);
        return token;
      });
    }
    return result;
  }

  /**
   * Restore anonymized tokens back to original values.
   */
  deanonymize(text) {
    let result = text;
    for (const [token, { original }] of this.mappings) {
      // Replace all occurrences of the token
      while (result.includes(token)) {
        result = result.replace(token, original);
      }
    }
    return result;
  }
}


module.exports = { Anonymizer, AnonymizationSession, PII_PATTERNS };
