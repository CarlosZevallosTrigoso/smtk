// 🔽🔽🔽 Pega aquí la URL de tu servidor de Render 🔽🔽🔽
const socket = io('https://smtk-server.onrender.com');

// --- Referencias a elementos del DOM ---
const messagesDiv = document.getElementById('messages');
const messageInput = document.getElementById('message-input');
const passwordInput = document.getElementById('password-input');
const sendButton = document.getElementById('send-button');

let peer;
const isInitiator = location.hash === '#fa';

// --- Lógica de conexión ---
socket.on('connect', () => {
  displayMessage('System: Conectado al servidor de señalización...');
  if (isInitiator) {
    setupPeer();
  }
});

socket.on('signal', (data) => {
  if (!peer) {
    setupPeer();
  }
  peer.signal(data);
});

function setupPeer(initiator = isInitiator) {
  peer = new SimplePeer({
    initiator: initiator,
    trickle: false
  });

  peer.on('signal', (data) => {
    socket.emit('signal', data);
  });

  peer.on('connect', () => {
    const user = isInitiator ? 'fa' : 'fb';
    displayMessage(`System: Conexión P2P establecida. [user: ${user}]`);
  });

  peer.on('data', async (data) => {
    try {
      const payload = JSON.parse(new TextDecoder().decode(data));
      displayMessage('System: Mensaje encriptado recibido. Introduce la contraseña para verlo.');
      const password = window.prompt('Introduce la contraseña para el mensaje entrante:');
      if (!password) {
        displayMessage('Error: No se introdujo contraseña. No se puede desencriptar.');
        return;
      }
      const decrypted = await decryptMessage(payload, password);
      displayMessage(`Otro: ${decrypted}`);
    } catch (e) {
      displayMessage('Error: La contraseña es incorrecta o el mensaje está corrupto.');
    }
  });
}

// --- Lógica de Encriptación/Desencriptación por Mensaje ---
async function deriveKey(password, salt) {
  const encoder = new TextEncoder();
  const baseKey = await window.crypto.subtle.importKey(
    'raw', encoder.encode(password), { name: 'PBKDF2' }, false, ['deriveKey']
  );
  return window.crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: salt, iterations: 100000, hash: 'SHA-256' },
    baseKey, { name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']
  );
}

async function encryptMessage(message, password) {
  const salt = window.crypto.getRandomValues(new Uint8Array(16));
  const iv = window.crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKey(password, salt);
  const encryptedData = await window.crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: iv }, key, new TextEncoder().encode(message)
  );
  const payload = {
    salt: Array.from(salt),
    iv: Array.from(iv),
    ciphertext: Array.from(new Uint8Array(encryptedData))
  };
  return new TextEncoder().encode(JSON.stringify(payload));
}

async function decryptMessage(payload, password) {
  const salt = new Uint8Array(payload.salt);
  const iv = new Uint8Array(payload.iv);
  const ciphertext = new Uint8Array(payload.ciphertext);
  const key = await deriveKey(password, salt);
  const decryptedData = await window.crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: iv }, key, ciphertext
  );
  return new TextDecoder().decode(decryptedData);
}

// --- Lógica de Envío de Mensajes ---
sendButton.addEventListener('click', async () => {
  const message = messageInput.value;
  const password = passwordInput.value;
  if (message && password && peer && peer.connected) {
    displayMessage(`Tú: ${message}`);
    const encryptedPayload = await encryptMessage(message, password);
    peer.send(encryptedPayload);
    messageInput.value = '';
    passwordInput.value = '';
  }
});

function displayMessage(message) {
  const p = document.createElement('p');
  p.textContent = message;
  messagesDiv.appendChild(p);
  messagesDiv.scrollTop = messagesDiv.scrollHeight;
}
