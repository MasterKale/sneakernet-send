const elemMessage = document.getElementById('message');
const elemDebugContainer = document.querySelector('#debug');
const elemDebugConsole = document.querySelector('#debug p');
const elemOutput = document.querySelector('#output p');
const dialogFirstTime = document.getElementById('dialogFirstTime');

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

// `salt` can be static for your site or unique per credential depending on your needs.
// crypto.getRandomValues(new Uint8Array(new Array(32)));
const firstSalt = new Uint8Array([
  0x4a, 0x18, 0xa1, 0xe7, 0x4b, 0xfb, 0x3d, 0x3f, 0x2a, 0x5d, 0x1f, 0x0c,
  0xcc, 0xe3, 0x96, 0x5e, 0x00, 0x61, 0xd1, 0x20, 0x82, 0xdc, 0x2a, 0x65,
  0x8a, 0x18, 0x10, 0xc0, 0x0f, 0x26, 0xbe, 0x1e,
]).buffer;

// Event handlers
elemMessage.addEventListener('input', handleMessageChange);
document.getElementById('btnPrepare').addEventListener('click', handlePrepareKey);
document.getElementById('btnProtect').addEventListener('click', handleProtectMessage);
document.getElementById('btnRead').addEventListener('click', handleReadMessage);
document.getElementById('btnShowFirstTime').addEventListener('click', handleShowFirstTime);
document.getElementById('btnCloseFirstTime').addEventListener('click', handleCloseFirstTime);
document.addEventListener('keyup', handleDocumentKeyUp);

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
 * Display text that outputs from a protect or read operation
 *
 * @param {string} text
 */
function writeToOutput(text) {
  elemOutput.innerText = text;
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
 * Show or hide the debug console, opposite of its current visibility
 */
function toggleDebugConsoleVisibility() {
  if (elemDebugContainer.classList.contains('hide')) {
    elemDebugContainer.classList.remove('hide');
  } else {
    elemDebugContainer.classList.add('hide');
  }
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
  const userName = `Sneakernet Send (${Date.now()})`;

  writeToDebug(`WebAuthn user.name: "${userName}"`);

  const regCredential = await navigator.credentials.create({
    publicKey: {
      challenge: getRandomBytes(),
      rp: { name: 'Sneakernet Send' },
      user: {
        id: userID,
        name: userName,
        displayName: userName,
      },
      pubKeyCredParams: [
        { alg: -7, type: 'public-key' }, // ES256
        { alg: -257, type: 'public-key' }, // RS256
      ],
      authenticatorSelection: {
        userVerification: 'required',
        residentKey: 'required',
      },
      extensions: {
        prf: { eval: { first: firstSalt } },
      },
      hints: ['security-key', 'client-device', 'hybrid']
    },
  });

  // Hoping for `{ prf: { enabled: true } }`
  const extResults = regCredential.getClientExtensionResults();

  if (!extResults.prf?.enabled) {
    writeToDebug(`extResults: ${JSON.stringify(extResults)}`);
    const message = 'Your current OS, browser, and security key combination cannot be used with this site.';
    writeToDebug(message);
    alert(message);
    throw Error(message);
  }

  const message = 'Your security key can now be used to protect messages with this site.';
  writeToDebug(message);
  alert(message);

  handleCloseFirstTime();
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
    const message = 'The security key could not be used to protect this message. Try preparing it?';
    writeToDebug(`extResults: ${JSON.stringify(extResults)}`);
    writeToDebug(message);
    writeToOutput(`Error: ${message}`);
    throw Error(message);
  }


  try {
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

    writeToDebug(`Protected Message: ${toReturn}`);
    writeToOutput(toReturn.trim());
  } catch (err) {
    console.error(err);
    writeToDebug(err);
    writeToOutput(`Error: ${err}`);
  }
}

/**
 * Decrypt a protected message using a prepared security key
 */
async function handleReadMessage() {
  let message = elemMessage.value ?? '';
  // Normalize the message a bit
  message = message.trim();

  const messageParts = message.split(':');

  // TODO: Allow for credential ID to be omitted at the end to make it tougher to find the
  // authenticator that can decrypt a message?
  if (messageParts.length < 2) {
    const message = 'The protected message is not in the expected format';
    writeToDebug(message);
    writeToOutput(`Error: ${message}`);
    throw new Error(message);
  }

  const [
    b64urlEncrypted,
    b64urlNonce,
    credentialID,
  ] = messageParts;

  const authOptions = {
    publicKey: {
      challenge: getRandomBytes(),
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
    const message = 'The security key could not be used to read this message.';
    writeToDebug(`extResults: ${JSON.stringify(extResults)}`);
    writeToDebug(message);
    writeToOutput(`Error: ${message}`);
    throw Error(message);
  }

  try {
    // Prepare to decrypt
    const inputKeyMaterial = new Uint8Array(extResults.prf.results.first);
    const encryptionKey = await deriveEncryptionKey(inputKeyMaterial);

    const decrypted = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: base64URLStringToBuffer(b64urlNonce) },
      encryptionKey,
      base64URLStringToBuffer(b64urlEncrypted)
    );

    const toReturn = textDecoder.decode(decrypted);

    writeToDebug(`Original Message: ${toReturn}`);
    writeToOutput(toReturn);
  } catch (err) {
    console.error(err);
    writeToDebug(err);
    writeToOutput(`Error: ${err}`);
  }
}

/**
 * Handle global keypresses for shortcut configuration
 * @param {KeyboardEvent} event
 */
function handleDocumentKeyUp(event) {
  // Toggle debug console visibility
  if (event.ctrlKey && event.shiftKey && event.key === 'D') {
    toggleDebugConsoleVisibility()
  }
}
/**
 * Support use of typing the toolbox emoji to reveal the debug console (for mobile)
 * @param {Event} event
 */
function handleMessageChange(event) {
  // Toggle debug console visibility
  if (event.data === '🧰') {
    toggleDebugConsoleVisibility();
  }
}

/**
 * Show informational modal for setting up a key
 */
async function handleShowFirstTime() {
  dialogFirstTime.showModal();
}

async function handleCloseFirstTime() {
  dialogFirstTime.close();
}
