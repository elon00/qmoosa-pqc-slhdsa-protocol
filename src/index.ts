/**
 * QMOOSA Post-Quantum Cryptography Specification
 * NIST FIPS 205: Stateless Hash-Based Digital Signature Standard (SLH-DSA)
 *
 * Parameter definitions, byte lengths, data structures, and mathematical validation
 * for SLH-DSA (formerly SPHINCS+), supporting SHA-2 and SHAKE instantiations.
 */

import { timingSafeEqual } from 'node:crypto';

export type SlhDsaParameterName =
  | 'SLH-DSA-SHA2-128s'
  | 'SLH-DSA-SHA2-128f'
  | 'SLH-DSA-SHA2-192s'
  | 'SLH-DSA-SHA2-192f'
  | 'SLH-DSA-SHA2-256s'
  | 'SLH-DSA-SHA2-256f'
  | 'SLH-DSA-SHAKE-128s'
  | 'SLH-DSA-SHAKE-128f';

export interface SlhDsaParameters {
  readonly name: SlhDsaParameterName;
  readonly nistCategory: number;
  readonly hashFunction: 'SHA2' | 'SHAKE';
  readonly optimization: 'small' | 'fast';
  readonly publicKeyBytes: number;
  readonly secretKeyBytes: number;
  readonly signatureBytes: number;
  readonly description: string;
}

/**
 * SLH-DSA-SHA2-128s: NIST Security Category 1 (small signature optimization)
 * Public key: 32 bytes, Secret key: 64 bytes, Signature: 7,856 bytes
 */
export const SLH_DSA_SHA2_128S: Readonly<SlhDsaParameters> = Object.freeze({
  name: 'SLH-DSA-SHA2-128s',
  nistCategory: 1,
  hashFunction: 'SHA2',
  optimization: 'small',
  publicKeyBytes: 32,
  secretKeyBytes: 64,
  signatureBytes: 7856,
  description: 'NIST Category 1, SHA-256 hash tree, optimized for small signature size (7,856 B)'
});

/**
 * SLH-DSA-SHA2-128f: NIST Security Category 1 (fast signing optimization)
 * Public key: 32 bytes, Secret key: 64 bytes, Signature: 17,088 bytes
 */
export const SLH_DSA_SHA2_128F: Readonly<SlhDsaParameters> = Object.freeze({
  name: 'SLH-DSA-SHA2-128f',
  nistCategory: 1,
  hashFunction: 'SHA2',
  optimization: 'fast',
  publicKeyBytes: 32,
  secretKeyBytes: 64,
  signatureBytes: 17088,
  description: 'NIST Category 1, SHA-256 hash tree, optimized for fast signing throughput (17,088 B)'
});

/**
 * SLH-DSA-SHA2-192s: NIST Security Category 3 (small signature optimization)
 * Public key: 48 bytes, Secret key: 96 bytes, Signature: 16,224 bytes
 */
export const SLH_DSA_SHA2_192S: Readonly<SlhDsaParameters> = Object.freeze({
  name: 'SLH-DSA-SHA2-192s',
  nistCategory: 3,
  hashFunction: 'SHA2',
  optimization: 'small',
  publicKeyBytes: 48,
  secretKeyBytes: 96,
  signatureBytes: 16224,
  description: 'NIST Category 3, SHA-384 hash tree, optimized for high security settlement (16,224 B)'
});

/**
 * SLH-DSA-SHA2-256s: NIST Security Category 5 (small signature optimization)
 * Public key: 64 bytes, Secret key: 128 bytes, Signature: 29,792 bytes
 */
export const SLH_DSA_SHA2_256S: Readonly<SlhDsaParameters> = Object.freeze({
  name: 'SLH-DSA-SHA2-256s',
  nistCategory: 5,
  hashFunction: 'SHA2',
  optimization: 'small',
  publicKeyBytes: 64,
  secretKeyBytes: 128,
  signatureBytes: 29792,
  description: 'NIST Category 5, SHA-512 hash tree, maximum security conservative anchor (29,792 B)'
});

/**
 * SLH-DSA-SHAKE-128s: NIST Security Category 1 (SHAKE-256 sponge, small)
 * Public key: 32 bytes, Secret key: 64 bytes, Signature: 7,856 bytes
 */
export const SLH_DSA_SHAKE_128S: Readonly<SlhDsaParameters> = Object.freeze({
  name: 'SLH-DSA-SHAKE-128s',
  nistCategory: 1,
  hashFunction: 'SHAKE',
  optimization: 'small',
  publicKeyBytes: 32,
  secretKeyBytes: 64,
  signatureBytes: 7856,
  description: 'NIST Category 1, SHAKE-256 sponge permutation, small signature size (7,856 B)'
});

export const SLH_DSA_REGISTRY: ReadonlyMap<SlhDsaParameterName, Readonly<SlhDsaParameters>> = new Map([
  [SLH_DSA_SHA2_128S.name, SLH_DSA_SHA2_128S],
  [SLH_DSA_SHA2_128F.name, SLH_DSA_SHA2_128F],
  [SLH_DSA_SHA2_192S.name, SLH_DSA_SHA2_192S],
  [SLH_DSA_SHA2_256S.name, SLH_DSA_SHA2_256S],
  [SLH_DSA_SHAKE_128S.name, SLH_DSA_SHAKE_128S]
]);

export function getSlhDsaParameters(name: SlhDsaParameterName): Readonly<SlhDsaParameters> {
  const params = SLH_DSA_REGISTRY.get(name);
  if (!params) {
    throw new Error(`UNSUPPORTED_SLH_DSA_PARAMETER_SET: Parameter set "${name}" is not registered in FIPS 205`);
  }
  return params;
}

export interface SlhDsaKeyPair {
  readonly publicKey: Uint8Array;
  readonly secretKey: Uint8Array;
  readonly parameterSet: SlhDsaParameterName;
}

export interface SlhDsaSignatureResult {
  readonly signature: Uint8Array;
  readonly parameterSet: SlhDsaParameterName;
}

export interface Web4SignedTransactionEnvelope {
  readonly chainId: string;
  readonly nonce: number;
  readonly fromAddress: string;
  readonly toAddress: string;
  readonly value: string;
  readonly payloadHex: string;
  readonly contextString: string;
  readonly parameterSet: SlhDsaParameterName;
  readonly publicKeyHex: string;
  readonly signatureHex: string;
  readonly timestamp: number;
}

export function validatePublicKey(pk: Uint8Array, params: SlhDsaParameters): boolean {
  return pk instanceof Uint8Array && pk.length === params.publicKeyBytes;
}

export function validateSecretKey(sk: Uint8Array, params: SlhDsaParameters): boolean {
  return sk instanceof Uint8Array && sk.length === params.secretKeyBytes;
}

export function validateSignature(sig: Uint8Array, params: SlhDsaParameters): boolean {
  return sig instanceof Uint8Array && sig.length === params.signatureBytes;
}

/**
 * Constant-time byte comparison using node:crypto timingSafeEqual.
 */
export function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  return timingSafeEqual(Buffer.from(a), Buffer.from(b));
}
