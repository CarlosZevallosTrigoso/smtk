// 🔽🔽🔽 Pega aquí la URL de tu servidor de Render 🔽🔽🔽
const socket = io('https://smtk-server.onrender.com');

// --- Referencias a elementos del DOM ---
const messagesDiv = document.getElementById('messages');
const senderInputDiv = document.getElementById('sender-input');
const readerInputDiv = document.getElementById('reader-input');
const messageInput = document.getElementById('message-input');
const passwordInput = document.getElementById('password-input');
const sendButton = document.getElementById('send-button');
const decryptPasswordInput = document.getElementById('decrypt-password-input');
const decryptButton = document.getElementById('decrypt-button');

let peer;
let myRole; // Guardará si somos 'fa' o 'fb'
let currentEncryptedPayload = null; // Para almacenar el último mensaje encriptado recibido
let currentPayloadId = null; // ID único para el payload

// --- Inicialización y manejo de roles ---
window.onload = () => {
    const hash = location.hash.substring(1); // Obtiene 'fa' o 'fb' de la URL
    if (hash === 'fa') {
        myRole = 'fa';
        senderInputDiv.style.display = 'flex'; // Mostrar interfaz de emisor
        displayMessage('System: Rol asignado: fa (Emisor). Esperando conexión...');
    } else if (hash === 'fb') {
        myRole = 'fb';
        readerInputDiv.style.display = 'flex'; // Mostrar interfaz de receptor
        displayMessage('System: Rol asignado: fb (Receptor). Esperando conexión...');
    } else {
        displayMessage('System: URL inválida. Usa #fa o #fb al final para asignar un rol.');
        return;
    }

    // Conectar al servidor de señalización
    socket.on('connect', () => {
        displayMessage('System: Conectado al servidor de señalización...');
        setupPeer(myRole === 'fa'); // fa inicia la conexión
    });

    socket.on('signal', (data) => {
        if (!peer) {
            setupPeer(myRole === 'fa');
        }
        peer.signal(data);
    });
};


function setupPeer(initiator) {
    peer = new SimplePeer({
        initiator: initiator,
        trickle: false
    });

    peer.on('signal', (data) => {
        socket.emit('signal', data);
    });

    peer.on('connect', () => {
        displayMessage(`System: Conexión P2P establecida. [user: ${myRole}]`);
        // Limpiar los campos de input al conectar
        messageInput.value = '';
        passwordInput.value = '';
        decryptPasswordInput.value = '';
    });

    // Manejo de datos entrantes
    peer.on('data', async (data) => {
        const parsedData = JSON.parse(new TextDecoder().decode(data));

        if (parsedData.type === 'message') {
            if (myRole === 'fa') {
                // fa no recibe mensajes encriptados, esto no debería pasar
                displayMessage('System: Error - fa recibió un mensaje encriptado inesperado.');
            } else if (myRole === 'fb') {
                // fb recibe un mensaje encriptado
                displayMessage('System: Mensaje encriptado recibido. Introduce la contraseña para leerlo.');
                currentEncryptedPayload = parsedData.payload; // Guardar el payload encriptado
                currentPayloadId = parsedData.id; // Guardar el ID para la confirmación
                decryptPasswordInput.focus(); // Enfocar el campo de contraseña
            }
        } else if (parsedData.type === 'read_confirmation') {
            if (myRole === 'fa') {
                // fa recibe una confirmación de lectura
                displayMessage(`System: Mensaje [ID: ${parsedData.id.substring(0, 8)}...] leído por fb.`, 'read-confirmation');
            }
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
    return {
        salt: Array.from(salt),
        iv: Array.from(iv),
        ciphertext: Array.from(new Uint8Array(encryptedData))
    };
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

// --- Lógica de Envío (fa) ---
sendButton.addEventListener('click', async () => {
    if (myRole !== 'fa') {
        displayMessage('Error: Solo fa puede enviar mensajes.', 'system-message');
        return;
    }
    const message = messageInput.value;
    const password = passwordInput.value;
    if (message && password && peer && peer.connected) {
        displayMessage(`fa@smtk:~ $ ${message}`); // Muestra el mensaje localmente
        const uniqueId = crypto.randomUUID(); // Genera un ID único para el mensaje
        const encryptedPayload = await encryptMessage(message, password);

        // Enviar un objeto que indica que es un mensaje y lleva el payload
        peer.send(new TextEncoder().encode(JSON.stringify({
            type: 'message',
            id: uniqueId,
            payload: encryptedPayload
        })));

        messageInput.value = '';
        passwordInput.value = '';
    } else {
        displayMessage('System: Mensaje o contraseña vacíos, o no conectado.', 'system-message');
    }
});

// --- Lógica de Lectura (fb) ---
decryptButton.addEventListener('click', async () => {
    if (myRole !== 'fb') {
        displayMessage('Error: Solo fb puede leer mensajes.', 'system-message');
        return;
    }
    const password = decryptPasswordInput.value;
    if (password && currentEncryptedPayload && peer && peer.connected) {
        try {
            const decrypted = await decryptMessage(currentEncryptedPayload, password);
            displayMessage(`fb@smtk:~ $ ${decrypted}`); // Muestra el mensaje desencriptado
            currentEncryptedPayload = null; // Limpiar mensaje después de leer
            decryptPasswordInput.value = ''; // Limpiar el campo de contraseña

            // Enviar confirmación de lectura a fa
            peer.send(new TextEncoder().encode(JSON.stringify({
                type: 'read_confirmation',
                id: currentPayloadId
            })));
            displayMessage('System: Confirmación de lectura enviada.', 'read-confirmation');

        } catch (e) {
            displayMessage('Error: Contraseña incorrecta o mensaje corrupto.', 'system-message');
            console.error('Error al desencriptar:', e);
        }
    } else {
        displayMessage('System: No hay mensaje para leer o contraseña vacía.', 'system-message');
    }
});


// --- Utilidad para mostrar mensajes en la terminal ---
function displayMessage(message, type = '') {
  const p = document.createElement('p');
  p.textContent = message;
  if (type) {
    p.classList.add(type);
  }
  messagesDiv.appendChild(p);
  messagesDiv.scrollTop = messagesDiv.scrollHeight; // Auto-scroll
}
