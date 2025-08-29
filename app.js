// 🔽🔽🔽 Pega aquí la URL de tu servidor de Render 🔽🔽🔽
const socket = io('https://smtk-server.onrender.com', { autoConnect: false });

// --- Referencias a elementos del DOM ---
const messagesDiv = document.getElementById('messages');
const mainInput = document.getElementById('main-input');
const promptSpan = document.getElementById('prompt');
const inputContainer = document.getElementById('input-container');

// --- Variables de estado de la aplicación ---
let myRole = null; // 'emisor' o 'receptor'
let appState = 'AWAITING_ROLE'; // Controla el flujo de la aplicación
let tempMessage = ''; // Almacena el mensaje del emisor temporalmente
let peer;
let currentEncryptedPayload = null;
let currentPayloadId = null;

// --- Contraseñas de rol (hardcoded) ---
const SENDER_PASSWORD = 'carlos123';
const RECEIVER_PASSWORD = 'carlosxyz';

// --- Inicio de la aplicación ---
window.onload = () => {
    inputContainer.style.display = 'none'; // Ocultar input al inicio
    authenticateUser();
};

async function authenticateUser() {
    // 1. Preguntar el rol
    const roleInput = window.prompt("emites o recibes (e/r)");
    if (roleInput && roleInput.toLowerCase() === 'e') {
        myRole = 'emisor';
    } else if (roleInput && roleInput.toLowerCase() === 'r') {
        myRole = 'receptor';
    } else {
        displayMessage('Error: rol no válido. Recarga la página.', 'error-message');
        return;
    }

    // 2. Pedir contraseña de rol
    const passwordInput = window.prompt(`Ingresa la contraseña para el rol '${myRole}':`);
    if (myRole === 'emisor' && passwordInput === SENDER_PASSWORD) {
        displayMessage('Autenticación de emisor exitosa.', 'system-message');
    } else if (myRole === 'receptor' && passwordInput === RECEIVER_PASSWORD) {
        displayMessage('Autenticación de receptor exitosa.', 'system-message');
    } else {
        displayMessage('Error: contraseña de rol incorrecta. Recarga la página.', 'error-message');
        return;
    }

    // 3. Si la autenticación es exitosa, conectar al servidor
    socket.connect();
    connectToServer();
}

function connectToServer() {
    socket.on('connect', () => {
        displayMessage('Conectado al servidor de señalización...', 'system-message');
        if (myRole === 'receptor') {
            socket.emit('receptor_is_ready');
        }
    });

    if (myRole === 'emisor') {
        socket.on('receptor_is_ready', () => {
            displayMessage('Receptor está en línea. Iniciando conexión P2P...', 'system-message');
            setupPeer(true);
        });
    }

    socket.on('signal', (data) => {
        if (!peer || peer.destroyed) {
            setupPeer(false);
        }
        peer.signal(data);
    });
}

function setupPeer(initiator) {
    if (peer && !peer.destroyed) return;
    peer = new SimplePeer({ initiator, trickle: false });

    peer.on('connect', () => {
        displayMessage('Conexión P2P establecida. Terminal lista.', 'confirmation-message');
        inputContainer.style.display = 'flex';
        if (myRole === 'emisor') {
            appState = 'AWAITING_MESSAGE';
            promptSpan.textContent = 'mensaje:';
        } else {
            appState = 'IDLE_RECEIVER';
            promptSpan.textContent = 'esperando...';
            mainInput.disabled = true;
        }
    });

    peer.on('data', (data) => {
        const parsedData = JSON.parse(new TextDecoder().decode(data));
        if (parsedData.type === 'message' && myRole === 'receptor') {
            displayMessage('paquete recibido', 'system-message');
            promptSpan.textContent = 'ingresa llave de decodificación:';
            mainInput.disabled = false;
            mainInput.focus();
            appState = 'AWAITING_DECRYPTION_KEY';
            currentEncryptedPayload = parsedData.payload;
            currentPayloadId = parsedData.id;
        } else if (parsedData.type === 'read_confirmation' && myRole === 'emisor') {
            displayMessage(`confirmación de lectura [${parsedData.id.substring(0, 8)}]`, 'confirmation-message');
        }
    });

    peer.on('close', () => {
        displayMessage('El otro usuario se ha desconectado.', 'error-message');
        inputContainer.style.display = 'none';
    });
}

// --- Manejo del input de la terminal ---
mainInput.addEventListener('keydown', (event) => {
    if (event.key === 'Enter') {
        const inputValue = mainInput.value;
        mainInput.value = ''; // Limpiar input

        switch (appState) {
            case 'AWAITING_MESSAGE':
                tempMessage = inputValue;
                displayMessage(`> ${tempMessage}`);
                promptSpan.textContent = 'contraseña del mensaje:';
                appState = 'AWAITING_MSG_PASSWORD';
                break;

            case 'AWAITING_MSG_PASSWORD':
                const messagePassword = inputValue;
                encryptAndSendMessage(tempMessage, messagePassword);
                promptSpan.textContent = 'mensaje:';
                appState = 'AWAITING_MESSAGE';
                break;

            case 'AWAITING_DECRYPTION_KEY':
                const decryptionKey = inputValue;
                decryptAndShowMessage(decryptionKey);
                promptSpan.textContent = 'esperando...';
                mainInput.disabled = true;
                appState = 'IDLE_RECEIVER';
                break;
        }
    }
});

async function encryptAndSendMessage(message, password) {
    const uniqueId = crypto.randomUUID();
    const encryptedPayload = await encryptMessage(message, password);
    peer.send(new TextEncoder().encode(JSON.stringify({
        type: 'message',
        id: uniqueId,
        payload: encryptedPayload
    })));
}

async function decryptAndShowMessage(password) {
    try {
        const decrypted = await decryptMessage(currentEncryptedPayload, password);
        displayMessage(`> ${decrypted}`);
        peer.send(new TextEncoder().encode(JSON.stringify({
            type: 'read_confirmation',
            id: currentPayloadId
        })));
    } catch (e) {
        displayMessage('Error: llave de decodificación incorrecta.', 'error-message');
    } finally {
        currentEncryptedPayload = null;
        currentPayloadId = null;
    }
}

// --- Lógica de Encriptación y Utilidades (sin cambios, pero necesarias) ---
function displayMessage(message, className = '') {
  const p = document.createElement('p');
  if (className) p.classList.add(className);
  // Simular el prompt en el historial de mensajes
  if (!className) {
    p.textContent = message;
  } else {
    p.textContent = `[System] ${message}`;
  }
  messagesDiv.appendChild(p);
  messagesDiv.scrollTop = messagesDiv.scrollHeight;
}
async function deriveKey(password, salt) {
  const encoder = new TextEncoder();
  const baseKey = await window.crypto.subtle.importKey('raw', encoder.encode(password), { name: 'PBKDF2' }, false, ['deriveKey']);
  return window.crypto.subtle.deriveKey({ name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' }, baseKey, { name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
}
async function encryptMessage(message, password) {
  const salt = window.crypto.getRandomValues(new Uint8Array(16));
  const iv = window.crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKey(password, salt);
  const encryptedData = await window.crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(message));
  return { salt: Array.from(salt), iv: Array.from(iv), ciphertext: Array.from(new Uint8Array(encryptedData)) };
}
async function decryptMessage(payload, password) {
  const salt = new Uint8Array(payload.salt);
  const iv = new Uint8Array(payload.iv);
  const ciphertext = new Uint8Array(payload.ciphertext);
  const key = await deriveKey(password, salt);
  const decryptedData = await window.crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ciphertext);
  return new TextDecoder().decode(decryptedData);
}
