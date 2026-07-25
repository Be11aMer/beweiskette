/**
 * RFC 3161 trusted timestamps: request construction and token verification.
 *
 * WHY THIS EXISTS
 *
 * A chain's own `timestamp_registered` comes from the machine that made the
 * records, so the person making them controls it. Fetching the time from an
 * API would not help: the verifier still cannot tell "the app fetched this"
 * from "the producer typed it in". Only a value *signed by the time source* is
 * checkable by someone who does not trust the producer. That is what a
 * Time Stamping Authority provides — it signs your hash together with its
 * clock reading, and anyone can check that signature.
 *
 * WHAT IS SENT
 *
 * Only a 32-byte SHA-256 digest of the chain head. Never file contents, file
 * names, custody fields or metadata. The TSA learns that someone timestamped
 * *something*, and nothing else about it.
 *
 * THE VERDICT IS THREE-VALUED, ON PURPOSE
 *
 *   VERIFIED    every check below passed
 *   UNVERIFIED  we could not check — unknown signer, unsupported algorithm.
 *               NOT a statement that the token is good.
 *   INVALID     a check actively failed. Treat as tampered.
 *
 * Collapsing UNVERIFIED into either neighbour is the dangerous mistake: a
 * verifier that reports "valid" when it merely failed to look launders a
 * forged token into apparent proof. Every unhandled case therefore lands on
 * UNVERIFIED or INVALID, never VERIFIED.
 *
 * WHAT THE SIGNATURE ACTUALLY COVERS
 *
 * Not the whole file. In CMS the signature is computed over the DER of
 * `SignedAttributes`, which in turn commits to the encapsulated content
 * (the TSTInfo) through its `messageDigest` attribute. So these are protected:
 *
 *   - TSTInfo in full: the message imprint, genTime, serial, policy, nonce
 *   - the signed attributes themselves
 *
 * and these are NOT, by design:
 *
 *   - the `PKIStatusInfo` wrapper of a TimeStampResp
 *   - `SignedData.version` and `SignedData.digestAlgorithms`
 *
 * Altering an unprotected field changes nothing about what was attested, so a
 * token whose wrapper has been edited can still legitimately verify. Anything
 * that changes the *meaning* — the data attested to, the time, the signer —
 * lives in the protected region and does break verification. Worth stating
 * plainly, because "the signature covers the file" is the intuitive but wrong
 * mental model, and it is the sort of assumption that produces a verifier with
 * a hole in it.
 *
 * TRUST IS PINNED, DELIBERATELY
 *
 * Signatures are checked against explicitly pinned signer keys rather than by
 * building an X.509 path to a root store. Path building — name constraints,
 * policy mapping, revocation — is a much larger problem, and a partial
 * implementation of it that returns "valid" is worse than not attempting it.
 * Pinning is a narrower claim that can actually be honoured. It is stated in
 * the UI and docs rather than hidden, and docs/ANCHORING.md keeps the
 * independent `openssl ts -verify` procedure so nobody has to take this
 * module's word for anything.
 */

import {
  parseOnly, readOID, readInteger, readTime, readBitString,
  encode, encodeSequence, encodeInteger, encodeIntegerFromBytes,
  encodeOctetString, encodeOID, encodeBoolean, toHex, TAG, Asn1Error,
} from './asn1.js';

export const VERDICT = {
  VERIFIED: 'VERIFIED',
  UNVERIFIED: 'UNVERIFIED',
  INVALID: 'INVALID',
};

const OID = {
  signedData: '1.2.840.113549.1.7.2',
  tstInfo: '1.2.840.113549.1.9.16.1.4',
  contentTypeAttr: '1.2.840.113549.1.9.3',
  messageDigestAttr: '1.2.840.113549.1.9.4',
  sha256: '2.16.840.1.101.3.4.2.1',
  sha384: '2.16.840.1.101.3.4.2.2',
  sha512: '2.16.840.1.101.3.4.2.3',
  rsaEncryption: '1.2.840.113549.1.1.1',
  sha256WithRSA: '1.2.840.113549.1.1.11',
  sha384WithRSA: '1.2.840.113549.1.1.12',
  sha512WithRSA: '1.2.840.113549.1.1.13',
  rsassaPss: '1.2.840.113549.1.1.10',
  ecPublicKey: '1.2.840.10045.2.1',
  ecdsaWithSHA256: '1.2.840.10045.4.3.2',
  ecdsaWithSHA384: '1.2.840.10045.4.3.3',
  ecdsaWithSHA512: '1.2.840.10045.4.3.4',
  extKeyUsage: '2.5.29.37',
  timeStamping: '1.3.6.1.5.5.7.3.8',
};

const DIGEST_BY_OID = {
  [OID.sha256]: 'SHA-256',
  [OID.sha384]: 'SHA-384',
  [OID.sha512]: 'SHA-512',
};

const EC_CURVE_BY_HASH = { 'SHA-256': 'P-256', 'SHA-384': 'P-384', 'SHA-512': 'P-521' };

/** Maximum token size we will look at, to bound work on hostile input. */
const MAX_TOKEN_BYTES = 256 * 1024;

class VerificationFailure extends Error {
  constructor(verdict, reason) {
    super(reason);
    this.verdict = verdict;
    this.reason = reason;
  }
}

const invalid = (reason) => { throw new VerificationFailure(VERDICT.INVALID, reason); };
const unverified = (reason) => { throw new VerificationFailure(VERDICT.UNVERIFIED, reason); };

// ── Request construction ───────────────────────────────────────────

/**
 * Build a DER `TimeStampReq` over a SHA-256 digest.
 *
 * `certReq: true` asks the TSA to include its certificate in the response,
 * without which the token cannot be verified offline later.
 *
 * @param {Uint8Array} digest - 32-byte SHA-256 of the data being timestamped
 * @returns {{der: Uint8Array, nonce: Uint8Array}}
 */
export function buildTimestampRequest(digest) {
  if (!(digest instanceof Uint8Array) || digest.length !== 32) {
    throw new Error('buildTimestampRequest expects a 32-byte SHA-256 digest');
  }

  // The nonce ties this response to this request, so a recorded response
  // cannot be replayed as if it were fresh.
  const nonce = new Uint8Array(8);
  crypto.getRandomValues(nonce);

  const der = encodeSequence([
    encodeInteger(1),
    encodeSequence([
      encodeSequence([encodeOID(OID.sha256), encode(TAG.NULL, [])]),
      encodeOctetString(digest),
    ]),
    encodeIntegerFromBytes(nonce),
    encodeBoolean(true),
  ]);

  return { der, nonce };
}

/**
 * Send a timestamp request to a TSA.
 *
 * The only outbound request this application makes, and only when the user
 * asks for it. Carries the digest and nothing else.
 *
 * @returns {Promise<{token: Uint8Array, nonce: Uint8Array}>}
 */
export async function requestTimestamp(tsaUrl, digest, { fetchImpl = fetch, signal } = {}) {
  const { der, nonce } = buildTimestampRequest(digest);

  const response = await fetchImpl(tsaUrl, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/timestamp-query',
      Accept: 'application/timestamp-reply',
    },
    body: der,
    signal,
    // No credentials, no cookies: this is an anonymous request for a signature.
    credentials: 'omit',
    referrerPolicy: 'no-referrer',
    cache: 'no-store',
  });

  if (!response.ok) {
    throw new Error(`Timestamp authority returned HTTP ${response.status}`);
  }

  const token = new Uint8Array(await response.arrayBuffer());
  if (token.length === 0) throw new Error('Timestamp authority returned an empty response');
  if (token.length > MAX_TOKEN_BYTES) throw new Error('Timestamp response is implausibly large');

  return { token, nonce };
}

// ── Parsing ────────────────────────────────────────────────────────

/**
 * Accept either a full `TimeStampResp` or a bare `ContentInfo` token.
 * A stored token is usually the response as returned; some tools strip it.
 */
function locateContentInfo(root) {
  const first = root.at(0);

  // TimeStampResp starts with PKIStatusInfo ::= SEQUENCE { status INTEGER, ... }
  if (first.is(TAG.SEQUENCE) && first.children.length > 0 && first.children[0].is(TAG.INTEGER)) {
    const status = readInteger(first.at(0));
    // 0 granted, 1 grantedWithMods; anything else is a refusal.
    if (status !== 0n && status !== 1n) {
      invalid(`the timestamp authority refused the request (PKIStatus ${status})`);
    }
    if (root.children.length < 2) invalid('response reports success but carries no token');
    return root.at(1);
  }

  // Otherwise assume the root is already a ContentInfo.
  if (first.is(TAG.OID)) return root;

  invalid('not a recognisable RFC 3161 response or token');
}

function findAttribute(signedAttrs, oid) {
  return (signedAttrs.children || []).find((attr) => {
    try {
      return readOID(attr.at(0)) === oid;
    } catch {
      return false;
    }
  }) || null;
}

/** Pull the parts of a certificate the verifier needs. */
function readCertificate(cert) {
  const tbs = cert.at(0);
  // The optional [0] EXPLICIT version shifts every later field.
  const hasVersion = tbs.children.length > 0 && tbs.at(0).isContext(0);
  const base = hasVersion ? 1 : 0;

  const serialNumber = readInteger(tbs.at(base));
  const issuer = tbs.at(base + 2);
  const validity = tbs.at(base + 3);
  const subject = tbs.at(base + 4);
  const spki = tbs.at(base + 5);

  const extensionsNode = (tbs.children || []).find((c) => c.isContext(3));
  const extendedKeyUsage = [];
  if (extensionsNode) {
    for (const ext of extensionsNode.at(0).children || []) {
      let extOid;
      try {
        extOid = readOID(ext.at(0));
      } catch {
        continue;
      }
      if (extOid !== OID.extKeyUsage) continue;
      // extnValue is the last element (an OCTET STRING wrapping the DER value).
      const value = ext.children[ext.children.length - 1];
      try {
        for (const purpose of parseOnly(value.content).children || []) {
          extendedKeyUsage.push(readOID(purpose));
        }
      } catch {
        // A malformed EKU leaves the list empty, which fails the check below.
      }
    }
  }

  return {
    serialNumber,
    issuerBytes: issuer.bytes,
    subjectBytes: subject.bytes,
    spkiBytes: spki.bytes,
    spkiAlgorithm: readOID(spki.path(0, 0)),
    notBefore: readTime(validity.at(0)),
    notAfter: readTime(validity.at(1)),
    extendedKeyUsage,
  };
}

function bytesEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

/** Convert a DER ECDSA signature (SEQUENCE of r, s) to the raw r||s Web Crypto wants. */
function ecdsaDerToRaw(der, size) {
  const seq = parseOnly(der);
  const toFixed = (node) => {
    let bytes = node.content;
    // Strip the sign byte DER adds, then left-pad to the field size.
    while (bytes.length > 1 && bytes[0] === 0x00) bytes = bytes.subarray(1);
    if (bytes.length > size) invalid('ECDSA signature component is too large for the curve');
    const out = new Uint8Array(size);
    out.set(bytes, size - bytes.length);
    return out;
  };
  const r = toFixed(seq.at(0));
  const s = toFixed(seq.at(1));
  const raw = new Uint8Array(size * 2);
  raw.set(r, 0);
  raw.set(s, size);
  return raw;
}

async function importVerificationKey(cert, signatureOid, hashName) {
  if (cert.spkiAlgorithm === OID.rsaEncryption) {
    if (signatureOid === OID.rsassaPss) {
      unverified('RSASSA-PSS signatures are not supported by this verifier');
    }
    return {
      key: await crypto.subtle.importKey(
        'spki', cert.spkiBytes, { name: 'RSASSA-PKCS1-v1_5', hash: hashName }, false, ['verify'],
      ),
      params: { name: 'RSASSA-PKCS1-v1_5' },
      kind: 'RSASSA-PKCS1-v1_5',
    };
  }

  if (cert.spkiAlgorithm === OID.ecPublicKey) {
    const namedCurve = EC_CURVE_BY_HASH[hashName];
    if (!namedCurve) unverified(`unsupported ECDSA hash ${hashName}`);
    return {
      key: await crypto.subtle.importKey(
        'spki', cert.spkiBytes, { name: 'ECDSA', namedCurve }, false, ['verify'],
      ),
      params: { name: 'ECDSA', hash: hashName },
      kind: 'ECDSA',
      curveSize: namedCurve === 'P-521' ? 66 : Number(namedCurve.slice(2)) / 8,
    };
  }

  unverified(`unsupported public key algorithm ${cert.spkiAlgorithm}`);
}

// ── Verification ───────────────────────────────────────────────────

/**
 * Verify a timestamp token.
 *
 * @param {Uint8Array} tokenDer - TimeStampResp or ContentInfo, as stored
 * @param {Object} options
 * @param {Uint8Array} options.expectedDigest - the hash the token must attest to
 * @param {string[]} [options.pinnedSpki] - accepted signer keys, as SHA-256 hex of the SPKI
 * @param {Uint8Array} [options.expectedNonce] - required for a freshly requested token
 * @param {string} [options.now] - ISO time, for validity-window checks
 * @returns {Promise<Object>} { verdict, reason, genTime, ... }
 */
export async function verifyToken(tokenDer, {
  expectedDigest,
  pinnedSpki = [],
  expectedNonce = null,
  now = new Date().toISOString(),
} = {}) {
  const info = {
    verdict: VERDICT.UNVERIFIED,
    reason: '',
    genTime: null,
    serialNumber: null,
    policy: null,
    signerSpkiSha256: null,
    signatureAlgorithm: null,
    digestAlgorithm: null,
  };

  try {
    if (!(tokenDer instanceof Uint8Array) || tokenDer.length === 0) {
      invalid('no token data');
    }
    if (tokenDer.length > MAX_TOKEN_BYTES) invalid('token is implausibly large');
    if (!(expectedDigest instanceof Uint8Array) || expectedDigest.length === 0) {
      throw new Error('verifyToken requires the digest the token should attest to');
    }

    const root = parseOnly(tokenDer);
    const contentInfo = locateContentInfo(root);

    if (readOID(contentInfo.at(0)) !== OID.signedData) {
      invalid('token content is not a CMS SignedData');
    }
    const signedData = contentInfo.path(1, 0);

    // -- encapsulated content must be a TSTInfo -------------------------
    const encap = signedData.at(2);
    if (readOID(encap.at(0)) !== OID.tstInfo) {
      invalid('signed content is not a TSTInfo');
    }
    const eContentNode = encap.at(1).at(0);
    const eContent = eContentNode.content;

    const tst = parseOnly(eContent);
    if (readInteger(tst.at(0)) !== 1n) invalid('unsupported TSTInfo version');
    info.policy = readOID(tst.at(1));

    // -- the binding check ----------------------------------------------
    // Without this, a perfectly valid token for unrelated data could be
    // attached to a chain and would sail through every signature check.
    const imprint = tst.at(2);
    const imprintAlg = readOID(imprint.path(0, 0));
    const imprintHash = imprint.at(1).content;
    if (!DIGEST_BY_OID[imprintAlg]) unverified(`unsupported imprint digest ${imprintAlg}`);
    if (!bytesEqual(imprintHash, expectedDigest)) {
      invalid('the token attests to different data than the value being checked');
    }

    info.serialNumber = readInteger(tst.at(3)).toString();
    info.genTime = readTime(tst.at(4));

    // Optional fields after genTime vary, so locate the nonce by type rather
    // than by position.
    if (expectedNonce) {
      const nonceNode = (tst.children || []).slice(5).find((n) => n.is(TAG.INTEGER));
      if (!nonceNode) invalid('response omits the nonce that was requested');
      const expected = readInteger(parseOnly(encodeIntegerFromBytes(expectedNonce)));
      if (readInteger(nonceNode) !== expected) {
        invalid('response nonce does not match the request — possible replay');
      }
    }

    // -- signer ----------------------------------------------------------
    const signerInfos = signedData.children[signedData.children.length - 1];
    if (!signerInfos.is(TAG.SET) || signerInfos.children.length !== 1) {
      unverified('expected exactly one signer');
    }
    const signerInfo = signerInfos.at(0);

    const digestOid = readOID(signerInfo.path(2, 0));
    const hashName = DIGEST_BY_OID[digestOid];
    if (!hashName) unverified(`unsupported digest algorithm ${digestOid}`);
    info.digestAlgorithm = hashName;

    const signedAttrs = (signerInfo.children || []).find((c) => c.isContext(0));
    if (!signedAttrs) {
      // CMS requires signed attributes whenever the content is not id-data.
      // Without them there is no messageDigest binding to verify.
      invalid('signer info carries no signed attributes');
    }

    const contentTypeAttr = findAttribute(signedAttrs, OID.contentTypeAttr);
    if (!contentTypeAttr || readOID(contentTypeAttr.path(1, 0)) !== OID.tstInfo) {
      invalid('signed contentType attribute does not identify a TSTInfo');
    }

    const messageDigestAttr = findAttribute(signedAttrs, OID.messageDigestAttr);
    if (!messageDigestAttr) invalid('signed attributes omit the messageDigest');
    const declaredDigest = messageDigestAttr.path(1, 0).content;
    const actualDigest = new Uint8Array(await crypto.subtle.digest(hashName, eContent));
    if (!bytesEqual(declaredDigest, actualDigest)) {
      invalid('signed messageDigest does not match the TSTInfo content');
    }

    // -- certificate -----------------------------------------------------
    const certSet = (signedData.children || []).find((c) => c.isContext(0));
    if (!certSet || !certSet.children || certSet.children.length === 0) {
      unverified('the token carries no certificate, so its signer is unknown');
    }

    const sid = signerInfo.at(1);
    let signerCert = null;
    for (const candidate of certSet.children) {
      let parsed;
      try {
        parsed = readCertificate(candidate);
      } catch {
        continue;
      }
      // SignerIdentifier is IssuerAndSerialNumber for these tokens.
      if (sid.is(TAG.SEQUENCE) && sid.children.length === 2) {
        if (bytesEqual(parsed.issuerBytes, sid.at(0).bytes)
            && parsed.serialNumber === readInteger(sid.at(1))) {
          signerCert = parsed;
          break;
        }
      }
    }
    if (!signerCert) unverified('no certificate in the token matches the signer identifier');

    info.signerSpkiSha256 = toHex(new Uint8Array(await crypto.subtle.digest('SHA-256', signerCert.spkiBytes)));

    if (!signerCert.extendedKeyUsage.includes(OID.timeStamping)) {
      invalid('signing certificate is not authorised for timestamping');
    }
    if (info.genTime < signerCert.notBefore || info.genTime > signerCert.notAfter) {
      invalid('the stated time falls outside the signing certificate validity period');
    }

    // -- pinned trust ----------------------------------------------------
    // Deliberately before the signature check, so an unpinned signer is
    // reported as "not checked" rather than as a cryptographic result that
    // might read as an endorsement.
    if (!pinnedSpki.includes(info.signerSpkiSha256)) {
      unverified('the signing key is not one of the pinned timestamp authorities');
    }

    // -- signature -------------------------------------------------------
    const signatureOid = readOID(signerInfo.path(4, 0));
    info.signatureAlgorithm = signatureOid;
    const signature = signerInfo.at(5).content;

    const { key, params, kind, curveSize } = await importVerificationKey(signerCert, signatureOid, hashName);

    // CMS signs the DER of SignedAttributes with the IMPLICIT [0] tag replaced
    // by SET OF. Signing the bytes as they appear would verify nothing.
    const signedBytes = encode(0x31, signedAttrs.content);

    const signatureBytes = kind === 'ECDSA'
      ? ecdsaDerToRaw(signature, curveSize)
      : signature;

    const ok = await crypto.subtle.verify(params, key, signatureBytes, signedBytes);
    if (!ok) invalid('the signature does not verify against the signing certificate');

    info.verdict = VERDICT.VERIFIED;
    info.reason = `Timestamp signed by a pinned authority at ${info.genTime}.`;
    return info;
  } catch (err) {
    if (err instanceof VerificationFailure) {
      info.verdict = err.verdict;
      info.reason = err.reason;
      return info;
    }
    if (err instanceof Asn1Error) {
      // Malformed structure. Not an endorsement, and not proof of tampering
      // either — but it is certainly not verified.
      info.verdict = VERDICT.INVALID;
      info.reason = `the token could not be parsed: ${err.message}`;
      return info;
    }
    // An unexpected fault must never surface as a pass.
    info.verdict = VERDICT.UNVERIFIED;
    info.reason = `verification could not be completed: ${err.message}`;
    return info;
  }
}

/**
 * Compute the pin for a certificate: SHA-256 of its SubjectPublicKeyInfo.
 *
 * Pinning the key rather than the whole certificate means a TSA reissuing the
 * same key with a new validity period does not silently stop verifying, while
 * a change of key still does — which is the event that should require a human
 * decision.
 *
 * @param {Uint8Array} certDer - a DER-encoded X.509 certificate
 * @returns {Promise<string>} lowercase hex SHA-256 of the SPKI
 */
export async function spkiPin(certDer) {
  const cert = readCertificate(parseOnly(certDer));
  return toHex(new Uint8Array(await crypto.subtle.digest('SHA-256', cert.spkiBytes)));
}

/** Decode a PEM certificate to DER. */
export function pemToDer(pem) {
  const body = String(pem).replace(/-----BEGIN [^-]+-----|-----END [^-]+-----|\s+/g, '');
  if (body.length === 0 || body.length % 4 !== 0 || !/^[A-Za-z0-9+/]+={0,2}$/.test(body)) {
    throw new Error('not a valid PEM certificate');
  }

  let der;
  try {
    const binary = atob(body);
    der = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) der[i] = binary.charCodeAt(i);
  } catch {
    throw new Error('not a valid PEM certificate');
  }

  // Decoding to bytes is not enough — confirm it really is a certificate, so a
  // user pinning the wrong file is told so rather than pinning a digest of
  // arbitrary data.
  try {
    readCertificate(parseOnly(der));
  } catch {
    throw new Error('not a valid PEM certificate');
  }
  return der;
}

/**
 * Read a token's claims without verifying anything.
 *
 * For display only — never for deciding whether to believe a token. Returns
 * null if the structure is unreadable.
 */
export async function inspectToken(tokenDer) {
  try {
    const root = parseOnly(tokenDer);
    const contentInfo = locateContentInfo(root);
    const signedData = contentInfo.path(1, 0);
    const tst = parseOnly(signedData.path(2, 1, 0).content);
    return {
      genTime: readTime(tst.at(4)),
      policy: readOID(tst.at(1)),
      messageImprint: toHex(tst.path(2, 1).content),
      serialNumber: readInteger(tst.at(3)).toString(),
    };
  } catch {
    return null;
  }
}
