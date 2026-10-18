import test from 'node:test';
import assert from 'node:assert/strict';
import {
  SLH_DSA_SHA2_128S,
  SLH_DSA_SHA2_128F,
  SLH_DSA_SHA2_192S,
  SLH_DSA_SHA2_256S,
  SLH_DSA_SHAKE_128S,
  getSlhDsaParameters,
  validatePublicKey,
  validateSecretKey,
  validateSignature,
  constantTimeEqual
} from '../dist/index.js';

test('SLH-DSA FIPS 205 Parameter Definitions: SHA2-128s', () => {
  assert.equal(SLH_DSA_SHA2_128S.name, 'SLH-DSA-SHA2-128s');
  assert.equal(SLH_DSA_SHA2_128S.nistCategory, 1);
  assert.equal(SLH_DSA_SHA2_128S.publicKeyBytes, 32);
  assert.equal(SLH_DSA_SHA2_128S.secretKeyBytes, 64);
  assert.equal(SLH_DSA_SHA2_128S.signatureBytes, 7856);
  assert.equal(SLH_DSA_SHA2_128S.hashFunction, 'SHA2');
  assert.equal(SLH_DSA_SHA2_128S.optimization, 'small');
});

test('SLH-DSA FIPS 205 Parameter Definitions: SHA2-128f', () => {
  assert.equal(SLH_DSA_SHA2_128F.name, 'SLH-DSA-SHA2-128f');
  assert.equal(SLH_DSA_SHA2_128F.publicKeyBytes, 32);
  assert.equal(SLH_DSA_SHA2_128F.secretKeyBytes, 64);
  assert.equal(SLH_DSA_SHA2_128F.signatureBytes, 17088);
  assert.equal(SLH_DSA_SHA2_128F.optimization, 'fast');
});

test('SLH-DSA FIPS 205 Parameter Definitions: SHA2-192s and SHA2-256s', () => {
  assert.equal(SLH_DSA_SHA2_192S.publicKeyBytes, 48);
  assert.equal(SLH_DSA_SHA2_192S.secretKeyBytes, 96);
  assert.equal(SLH_DSA_SHA2_192S.signatureBytes, 16224);

  assert.equal(SLH_DSA_SHA2_256S.publicKeyBytes, 64);
  assert.equal(SLH_DSA_SHA2_256S.secretKeyBytes, 128);
  assert.equal(SLH_DSA_SHA2_256S.signatureBytes, 29792);
});

test('Registry Lookup and Error Handling', () => {
  const p128s = getSlhDsaParameters('SLH-DSA-SHA2-128s');
  assert.equal(p128s.name, 'SLH-DSA-SHA2-128s');

  assert.throws(
    () => getSlhDsaParameters('NON-EXISTENT-SLH-DSA'),
    /UNSUPPORTED_SLH_DSA_PARAMETER_SET/
  );
});

test('Buffer Validation Helpers', () => {
  const validPk = new Uint8Array(32);
  const invalidPk = new Uint8Array(31);
  assert.equal(validatePublicKey(validPk, SLH_DSA_SHA2_128S), true);
  assert.equal(validatePublicKey(invalidPk, SLH_DSA_SHA2_128S), false);

  const validSk = new Uint8Array(64);
  const invalidSk = new Uint8Array(65);
  assert.equal(validateSecretKey(validSk, SLH_DSA_SHA2_128S), true);
  assert.equal(validateSecretKey(invalidSk, SLH_DSA_SHA2_128S), false);

  const validSig = new Uint8Array(7856);
  const invalidSig = new Uint8Array(7855);
  assert.equal(validateSignature(validSig, SLH_DSA_SHA2_128S), true);
  assert.equal(validateSignature(invalidSig, SLH_DSA_SHA2_128S), false);
});

test('Constant-time Equality Helper', () => {
  const a = new Uint8Array([1, 2, 3, 4]);
  const b = new Uint8Array([1, 2, 3, 4]);
  const c = new Uint8Array([1, 2, 3, 5]);
  const d = new Uint8Array([1, 2, 3]);

  assert.equal(constantTimeEqual(a, b), true);
  assert.equal(constantTimeEqual(a, c), false);
  assert.equal(constantTimeEqual(a, d), false);
});
