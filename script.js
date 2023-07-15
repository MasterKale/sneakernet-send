const elemMessage = document.getElementById('message');
const elemDebugConsole = document.getElementById('debug');
const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

// `salt` can be static for your site or unique per credential depending on your needs.
// crypto.getRandomValues(new Uint8Array(new Array(32)));
const firstSalt = new Uint8Array([
  0x4a, 0x18, 0xa1, 0xe7, 0x4b, 0xfb, 0x3d, 0x3f, 0x2a, 0x5d, 0x1f, 0x0c,
  0xcc, 0xe3, 0x96, 0x5e, 0x00, 0x61, 0xd1, 0x20, 0x82, 0xdc, 0x2a, 0x65,
  0x8a, 0x18, 0x10, 0xc0, 0x0f, 0x26, 0xbe, 0x1e,
]).buffer;

document.getElementById('btnPrepare').addEventListener('click', handlePrepareKey);
document.getElementById('btnProtect').addEventListener('click', handleProtectMessage);
document.getElementById('btnRead').addEventListener('click', handleReadMessage);

/**
 *
 * Functions
 *
 */

/**
 * Output a message to the on-page console
 *
 * @param {string} text
 */
function writeToDebug(text) {
  elemDebugConsole.innerHTML = elemDebugConsole.innerHTML + `<br>\[${Date.now()}\] ${text}`;
}

/**
 * Generate random bytes
 *
 * @param {number} length The number of bytes to return
 * @returns Uint8Array
 */
function getRandomBytes(length = 16) {
  const arrayBuffer = new Uint8Array(new Array(length));
  return crypto.getRandomValues(arrayBuffer);
}

/**
 * Create a symmetric encryption key from the provided bytes
 *
 * @param {Uint8Array} inputKeyMaterial
 * @returns {Promise<CryptoKey>}
 */
async function deriveEncryptionKey(inputKeyMaterial) {
  const keyDerivationKey = await crypto.subtle.importKey(
    'raw',
    inputKeyMaterial,
    'HKDF',
    false,
    ['deriveKey']
  );

  // Never forget what you set this value to or the key can't be
  // derived later
  const label = 'figbar encryption key';
  const info = textEncoder.encode(label);
  // `salt` is a required argument for `deriveKey()`, but should
  // be empty
  const salt = new Uint8Array();

  const encryptionKey = await crypto.subtle.deriveKey(
    { name: 'HKDF', info, salt, hash: 'SHA-256' },
    keyDerivationKey,
    { name: 'AES-GCM', length: 256 },
    // No need for exportability because we can deterministically
    // recreate this key
    false,
    ['encrypt', 'decrypt'],
  );

  return encryptionKey;
}

/**
 * Click handlers
 */

/**
 * Set up a security key to use the `prf` extension to protect messages
 */
async function handlePrepareKey() {
  const userID = getRandomBytes();
  const userName = `Figbar Key (${Date.now()})`;

  writeToDebug(userName);

  const regCredential = await navigator.credentials.create({
    publicKey: {
      challenge: getRandomBytes(),
      rp: {
        name: 'Project Figbar',
      },
      user: {
        id: userID,
        name: userName,
        displayName: userName,
      },
      pubKeyCredParams: [
        { alg: -8, type: 'public-key' }, // Ed25519
        { alg: -7, type: 'public-key' }, // ES256
        { alg: -257, type: 'public-key' }, // RS256
      ],
      authenticatorSelection: {
        userVerification: 'required',
        residentKey: 'required',
        authenticatorAttachment: 'cross-platform',
      },
      extensions: {
        prf: { eval: { first: firstSalt } },
      },
    },
  });

  // Hoping for `{ prf: { enabled: true } }`
  const extResults = regCredential.getClientExtensionResults();

  if (!extResults.prf?.enabled) {
    writeToDebug(`extResults: ${JSON.stringify(extResults)}`);
    const message = 'The authenticator could not be prepared.';
    writeToDebug(message);
    throw Error(message);
  }

  writeToDebug('Key can now be used to protect messages');
}

/**
 * Encrypt a message using a prepared security key
 */
async function handleProtectMessage() {
  const authCredential = await navigator.credentials.get({
    publicKey: {
      challenge: getRandomBytes(),
      userVerification: 'required',
      extensions: {
        prf: { eval: { first: firstSalt } },
      },
    },
  });

  // Hoping for `{ prf: { results: { first: Uint8Array } } },`
  const extResults = authCredential.getClientExtensionResults();

  if (!extResults.prf?.results?.first) {
    const message = 'The authenticator could not be used to protect this message. Try preparing it?';
    writeToDebug(`extResults: ${JSON.stringify(extResults)}`);
    writeToDebug(message);
    throw Error(message);
  }

  const inputKeyMaterial = new Uint8Array(extResults.prf.results.first);
  const encryptionKey = await deriveEncryptionKey(inputKeyMaterial);

  // Keep track of this `nonce`, you'll need it to decrypt later!
  // FYI it's not a secret so you don't have to protect it.
  const nonce = crypto.getRandomValues(new Uint8Array(12));

  const data = elemMessage.value ?? '';
  const encrypted = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: nonce },
    encryptionKey,
    textEncoder.encode(data),
  );

  const b64urlEncrypted = bufferToBase64URLString(encrypted);
  const b64urlNonce = bufferToBase64URLString(nonce);
  const b64urlCredentialID = authCredential.id;

  const toReturn = `${b64urlEncrypted}:${b64urlNonce}:${b64urlCredentialID}`;

  writeToDebug(toReturn);
}

async function handleReadMessage() {
  const message = elemMessage.value ?? '';

  const messageParts = message.split(':');

  if (messageParts.length < 2) {
    const message = 'The protected message is not in the expected format';
    writeToDebug(message);
    throw new Error(message);
  }

  const [
    b64urlEncrypted,
    b64urlNonce,
    credentialID,
  ] = messageParts;

  console.log({
    b64urlEncrypted,
    b64urlNonce,
    credentialID,
  });

  const authOptions = {
    publicKey: {
      challenge: getRandomBytes(),
      rpId: 'localhost',
      userVerification: 'required',
      extensions: {
        prf: { eval: { first: firstSalt } },
      },
      allowCredentials: undefined,
    },
  };

  // Provide a hint as to which authenticator would be usable to decrypt the message
  if (credentialID) {
    authOptions.publicKey.allowCredentials = [
      { id: base64URLStringToBuffer(credentialID), type: 'public-key' },
    ];
  }

  const authCredential = await navigator.credentials.get(authOptions);

  // Hoping for `{ prf: { results: { first: Uint8Array } } },`
  const extResults = authCredential.getClientExtensionResults();

  if (!extResults.prf?.results?.first) {
    const message = 'The authenticator could not be used to read this message.';
    writeToDebug(`extResults: ${JSON.stringify(extResults)}`);
    writeToDebug(message);
    throw Error(message);
  }

  const inputKeyMaterial = new Uint8Array(extResults.prf.results.first);
  const encryptionKey = await deriveEncryptionKey(inputKeyMaterial);

  try {
    const decrypted = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: base64URLStringToBuffer(b64urlNonce) },
      encryptionKey,
      base64URLStringToBuffer(b64urlEncrypted)
    );

    const toReturn = textDecoder.decode(decrypted);

    writeToDebug(toReturn);
  } catch (err) {
    console.error(err);
    writeToDebug(err);
  }
}
