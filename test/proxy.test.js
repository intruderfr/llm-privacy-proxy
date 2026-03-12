/**
 * Tests for LLM Privacy Proxy - Anonymizer module.
 */

const { Anonymizer } = require('../src/anonymizer');
const assert = require('assert');

function test(name, fn) {
  try {
    fn();
    console.log(`  ✓ ${name}`);
  } catch (err) {
    console.log(`  ✗ ${name}: ${err.message}`);
    process.exitCode = 1;
  }
}

console.log('\nAnonymizer Tests\n');

test('detects email addresses', () => {
  const anon = new Anonymizer({ piiTypes: ['email'] });
  const findings = anon.detect('Contact john@example.com for details');
  assert.strictEqual(findings.length, 1);
  assert.strictEqual(findings[0].type, 'email');
  assert.strictEqual(findings[0].value, 'john@example.com');
});

test('detects phone numbers', () => {
  const anon = new Anonymizer({ piiTypes: ['phone'] });
  const findings = anon.detect('Call me at 555-123-4567');
  assert.strictEqual(findings.length, 1);
  assert.strictEqual(findings[0].type, 'phone');
});

test('detects SSN', () => {
  const anon = new Anonymizer({ piiTypes: ['ssn'] });
  const findings = anon.detect('SSN: 123-45-6789');
  assert.strictEqual(findings.length, 1);
  assert.strictEqual(findings[0].type, 'ssn');
});

test('detects credit card numbers', () => {
  const anon = new Anonymizer({ piiTypes: ['credit_card'] });
  const findings = anon.detect('Card: 4111 1111 1111 1111');
  assert.strictEqual(findings.length, 1);
  assert.strictEqual(findings[0].type, 'credit_card');
});

test('anonymizes and deanonymizes correctly', () => {
  const anon = new Anonymizer({ piiTypes: ['email', 'phone'] });
  const session = anon.createSession();

  const original = 'Email john@test.com or call 555-123-4567';
  const anonymized = session.anonymize(original);

  assert.ok(!anonymized.includes('john@test.com'));
  assert.ok(!anonymized.includes('555-123-4567'));
  assert.ok(anonymized.includes('[EMAIL_001]'));
  assert.ok(anonymized.includes('[PHONE_001]'));

  const restored = session.deanonymize(anonymized);
  assert.strictEqual(restored, original);
});

test('consistent tokens for same value', () => {
  const anon = new Anonymizer({ piiTypes: ['email'] });
  const session = anon.createSession();

  const text = 'From john@test.com to jane@test.com, CC: john@test.com';
  const anonymized = session.anonymize(text);

  // Same email should get same token
  const count = (anonymized.match(/\[EMAIL_001\]/g) || []).length;
  assert.strictEqual(count, 2); // john@test.com appears twice
});

test('respects allowlist', () => {
  const anon = new Anonymizer({
    piiTypes: ['email'],
    allowlist: ['admin@company.com'],
  });
  const session = anon.createSession();

  const text = 'Contact admin@company.com or user@test.com';
  const anonymized = session.anonymize(text);

  assert.ok(anonymized.includes('admin@company.com'));
  assert.ok(!anonymized.includes('user@test.com'));
});

test('custom patterns work', () => {
  const anon = new Anonymizer({
    piiTypes: [],
    customPatterns: [
      { name: 'employee_id', pattern: /EMP-\d{6}/g, token: 'EMPID' },
    ],
  });
  const session = anon.createSession();

  const text = 'Employee EMP-123456 reported an issue';
  const anonymized = session.anonymize(text);

  assert.ok(!anonymized.includes('EMP-123456'));
  assert.ok(anonymized.includes('[EMPID_001]'));
});

test('handles text with no PII', () => {
  const anon = new Anonymizer();
  const session = anon.createSession();

  const text = 'This is a normal message with no personal data.';
  const anonymized = session.anonymize(text);

  assert.strictEqual(anonymized, text);
  assert.strictEqual(session.mappings.size, 0);
});

test('detects IP addresses', () => {
  const anon = new Anonymizer({ piiTypes: ['ip_address'] });
  const findings = anon.detect('Server at 192.168.1.100 is down');
  assert.strictEqual(findings.length, 1);
  assert.strictEqual(findings[0].type, 'ip_address');
});

console.log('\nAll tests completed.\n');
