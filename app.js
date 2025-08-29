// --- Conexión al servidor de señalización ---
const socket = io('https-:-//smtk-server.onrender.com', { autoConnect: false });

// --- Referencias a elementos del DOM ---
const messagesDiv = document.getElementById('messages');
const mainInput = document.getElementById('main-input');
const promptSpan = document.getElementById('prompt');

// --- Variables de estado de la aplicación ---
let myRole = null;
let appState = 'AWAITING_ROLE'; // Controla el flujo de la aplicación
let tempMessage = '';
let peer;
let currentEncryptedPayload = null;
let currentPayloadId = null;

// --- Contraseñas de rol ---
const SENDER_PASSWORD = 'carlos123';
const RECEIVER_PASSWORD = 'carlosxyz';

// --- Inicio de la aplicación ---
window.onload = () => {
    displayMessage('Bienvenido a smtk.');
    updatePrompt(); // Configurar el primer prompt
};

function updatePrompt() {
    mainInput.type = 'text'; // Por defecto
    switch (appState) {
        case 'AWAITING_ROLE':
            promptSpan.textContent = 'emites o recibes (e/r):';
            break;
        case 'AWAITING_ROLE_AUTH':
            promptSpan.textContent = `contraseña para '${myRole}':`;
            mainInput.type = 'password';
            break;
        case 'AWAITING_MESSAGE':
            promptSpan.textContent = 'mensaje:';
            break;
        case 'AWAITING_MSG_PASSWORD':
            promptSpan.textContent = `contraseña para el mensaje:`;
            mainInput.type = 'password';
            break;
        case 'IDLE_RECEIVER':
            promptSpan.textContent = 'esperando paquete...';
            mainInput.disabled = true;
            break;
        case 'AWAITING_DECRYPTION_KEY':
            promptSpan.textContent = 'ingresa llave de decodificación:';
            mainInput.type = 'password';
            mainInput.disabled = false;
            break;
    }
    mainInput.focus();
}

// --- Manejo del input de la terminal ---
mainInput.addEventListener('keydown', (event) => {
    if (event.key === 'Enter' && mainInput.value.trim() !== '') {
        const inputValue = mainInput.value.trim();
        mainInput.value = ''; // Limpiar input

        // Mostrar el input del usuario en la terminal (excepto contraseñas)
        if (appState !== 'AWAITING_ROLE_AUTH' && appState !== 'AWAITING_MSG_PASSWORD' && appState !== 'AWAITING_DECRYPTION_KEY') {
            displayMessage(`> ${inputValue}`);
        } else {
            displayMessage(`> ********`);
        }

        handleInput(inputValue);
    }
});

function handleInput(value) {
    switch (appState) {
        case 'AWAITING_ROLE':
            if (value.toLowerCase() === 'e') myRole = 'emisor';
            else if (value.toLowerCase() === 'r') myRole = 'receptor';
            else {
                displayMessage('Error: rol no válido. Usa "e" o "r".', 'error-message');
                return;
            }
            appState = 'AWAITING_ROLE_AUTH';
            break;

        case 'AWAITING_ROLE_AUTH':
            const isAuth = (myRole === 'emisor' && value === SENDER_PASSWORD) || (myRole === 'receptor' && value === RECEIVER_PASSWORD);
            if (isAuth) {
                displayMessage(`Autenticación de ${myRole} exitosa.`, 'system-message');
                appState = 'CONNECTING';
                socket.connect();
                connectToServer();
            } else {
                displayMessage('Error: contraseña de rol incorrecta. Recarga la página para reintentar.', 'error-message');
                mainInput.disabled = true;
            }
            break;

        case 'AWAITING_MESSAGE':
            tempMessage = value;
            appState = 'AWAITING_MSG_PASSWORD';
            break;

        case 'AWAITING_MSG_PASSWORD':
            encryptAndSendMessage(tempMessage, value);
            appState = 'AWAITING_MESSAGE';
            break;

        case 'AWAITING_DECRYPTION_KEY':
            decryptAndShowMessage(value);
            appState = 'IDLE_RECEIVER';
            break;
    }
    updatePrompt();
}

function connectToServer() {
    displayMessage('Conectando al servidor de señalización...', 'system-message');
    socket.on('connect', () => {
        displayMessage('Conexión con servidor establecida.', 'system-message');
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
        if (!peer || peer.destroyed) setupPeer(false);
        peer.signal(data);
    });
}

function setupPeer(initiator) {
    if (peer && !peer.destroyed) return;
    peer = new SimplePeer({ initiator, trickle: false });

    peer.on('connect', () => {
        displayMessage('Conexión P2P establecida. Terminal lista.', 'confirmation-message');
        if (myRole === 'emisor') appState = 'AWAITING_MESSAGE';
        else appState = 'IDLE_RECEIVER';
        updatePrompt();
    });

    peer.on('data', (data) => {
        const parsedData = JSON.parse(new TextDecoder().decode(data));
        if (parsedData.type === 'message' && myRole === 'receptor') {
            displayMessage('paquete recibido', 'system-message');
            appState = 'AWAITING_DECRYPTION_KEY';
            currentEncryptedPayload = parsedData.payload;
            currentPayloadId = parsedData.id;
            updatePrompt();
        } else if (parsedData.type === 'read_confirmation' && myRole === 'emisor') {
            displayMessage(`confirmación de lectura [${parsedData.id.substring(0, 8)}]`, 'confirmation-message');
        }
    });

    peer.on('close', () => {
        displayMessage('El otro usuario se ha desconectado.', 'error-message');
        mainInput.disabled = true;
    });
}

async function encryptAndSendMessage(message, password) {
    const uniqueId = crypto.randomUUID();
    const encryptedPayload = await encryptMessage(message, password);
    peer.send(new TextEncoder().encode(JSON.stringify({
        type: 'message',
        id: uniqueId,
        payload: encryptedPayload
    })));
    displayMessage('Paquete encriptado y enviado.', 'system-message');
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

// --- Funciones de Utilidad y Criptografía (sin cambios conceptuales) ---
function displayMessage(message, className = '') {
  const p = document.createElement('p');
  if (className) p.classList.add(className);
  p.textContent = message;
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
