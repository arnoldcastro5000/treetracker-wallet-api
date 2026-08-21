/* ________________________________________________________________________
 * JWT Issuance upon prior authorization, login
 * ________________________________________________________________________
 */
const JWTTools = require('jsonwebtoken');
const axios = require('axios');
const log = require('loglevel');
const HttpError = require('../utils/HttpError');

// PRIVATE and PUBLIC key. Default to '' so the module still loads under the LOCAL Keycloak-auth path
// (KEYCLOAK_REALM_URL set), which needs neither key; sign()/verify() still require them if used.
const privateKEY = (process.env.PRIVATE_KEY || '').replace(/\\n/g, '\n'); // FS.readFileSync(path.resolve(__dirname, '../../config/jwtRS256.key'), 'utf8');
const publicKEY = (process.env.PUBLIC_KEY || '').replace(/\\n/g, '\n'); // FS.readFileSync(path.resolve(__dirname, '../../config/jwtRS256.key.pub'), 'utf8');

// LOCAL dev accommodation: verify a shared-realm Keycloak token instead of the greenstand-signed one.
// Enabled when KEYCLOAK_REALM_URL is set (e.g. http://keycloak...:8080/realms/treetracker). The realm's
// active RS256 public key is fetched from that URL (`public_key`, an SPKI DER wrapped as PEM) and
// cached. The Keycloak `sub` maps to the wallet id (the stand-up seed sets wallet.id == sub), so the
// returned object carries `.id = sub` and the rest of the app is unchanged. Only ACCESS tokens are
// accepted (`typ === 'Bearer'`, so refresh/ID tokens are rejected); signature + expiry are checked.
// Issuer/audience are NOT pinned (a local convenience: tokens may be minted through several base URLs).
//
// The cache holds the fetch PROMISE, so concurrent cold-start requests share ONE realm round-trip; a
// failed fetch drops the cache so the next request retries. On a verify miss the cache is dropped and
// the key re-fetched once, so a realm key rotation or Keycloak restart self-heals without a restart.
let keycloakPemPromise = null;
async function fetchRealmPem() {
  const realmUrl = process.env.KEYCLOAK_REALM_URL;
  if (!realmUrl)
    throw new HttpError(500, 'ERROR: Authentication, KEYCLOAK_REALM_URL not configured');
  let data;
  try {
    ({ data } = await axios.get(realmUrl, { timeout: 5000 }));
  } catch (err) {
    log.debug(err);
    throw new HttpError(503, 'ERROR: Authentication, Keycloak realm unreachable');
  }
  if (!data || !data.public_key)
    throw new HttpError(503, 'ERROR: Authentication, Keycloak realm returned no public key');
  return `-----BEGIN PUBLIC KEY-----\n${data.public_key}\n-----END PUBLIC KEY-----\n`;
}
function keycloakPublicKeyPem() {
  if (!keycloakPemPromise)
    keycloakPemPromise = fetchRealmPem().catch((err) => {
      keycloakPemPromise = null; // do not cache a failed fetch
      throw err;
    });
  return keycloakPemPromise;
}
function bearerToken(authorization) {
  if (!authorization)
    throw new HttpError(
      401,
      'ERROR: Authentication, no token supplied for protected path',
    );
  const [scheme, token] = authorization.split(' ');
  if (scheme !== 'Bearer' || !token)
    throw new HttpError(401, 'ERROR: Authentication, token not verified');
  return token;
}

const signingOptions = {
  issuer: 'greenstand',
  expiresIn: '365d',
  algorithm: 'RS256',
};

const verifyOptions = {
  issuer: 'greenstand',
  expiresIn: '365d',
  algorithms: ['RS256'],
};

class JWTService {
  static sign(payload) {
    return JWTTools.sign(payload, privateKEY, signingOptions);
  }

  // LOCAL: verify a Keycloak realm access token and map its `sub` to the wallet id (`.id`).
  static async verifyKeycloak(authorization) {
    const token = bearerToken(authorization);
    let decoded;
    try {
      decoded = JWTTools.verify(token, await keycloakPublicKeyPem(), {
        algorithms: ['RS256'],
      });
    } catch (err) {
      // The realm may have rotated its signing key; drop the cache, re-fetch once, retry.
      keycloakPemPromise = null;
      try {
        decoded = JWTTools.verify(token, await keycloakPublicKeyPem(), {
          algorithms: ['RS256'],
        });
      } catch (err2) {
        log.debug(err2);
        throw new HttpError(401, 'ERROR: Authentication, token not verified');
      }
    }
    if (decoded.typ !== 'Bearer')
      throw new HttpError(
        401,
        'ERROR: Authentication, not an access token',
      );
    if (!decoded.sub)
      throw new HttpError(401, 'ERROR: Authentication, invalid token received');
    return { ...decoded, id: decoded.sub };
  }

  static verify(authorization) {
    if (!authorization) {
      throw new HttpError(
        401,
        'ERROR: Authentication, no token supplied for protected path',
      );
    }
    // accounts for the "Bearer" string before the token
    const tokenArray = authorization.split(' ');
    const token = tokenArray[1];
    let result;
    if (token) {
      // Decode the token
      JWTTools.verify(token, publicKEY, verifyOptions, (err, decod) => {
        if (err || tokenArray[0] !== 'Bearer') {
          log.debug(err);
          throw new HttpError(401, 'ERROR: Authentication, token not verified');
        }
        result = decod;
        if (!result.id)
          throw new HttpError(
            401,
            'ERROR: Authentication, invalid token received',
          );
      });
    } else {
      throw new HttpError(401, 'ERROR: Authentication, token not verified');
    }
    return result;
  }
}

module.exports = JWTService;
