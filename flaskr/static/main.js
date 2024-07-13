const socket = io({ autoConnect: false });
let privateKey, publicKey;
var clientKeys = {};
var username, chatClient;
var isCurrentUser = true;

document.addEventListener('DOMContentLoaded', async () => {
    //publicKey = await generateRSAKeyPair()   
    publicKey = "abc"
    document.getElementById("logout-btn").value = "Logout-"+userData.Username;

    document.getElementById("message-input").addEventListener("keypress", function (event) {
        if (event.key === "Enter") {
            sendMessage();
        }
    });

    socket.on('message', async (data) => {
        try {
            //const decryptedMessage = await decryptMessage(privateKey, data.message);
            //console.log(`Message from ${data.sender_sid}:`, decryptedMessage);
            isCurrentUser = false;
            console.log("Sender------------",data["sender"])
            console.log("Sender------------",data["message"])
            let ul = document.getElementById("chat-msg");
            let li = document.createElement("li");
            li.appendChild(document.createTextNode(data["sender"] + " : " + data["message"]));
            li.classList.add("left-align");
            ul.appendChild(li);
            ul.scrolltop = ul.scrollHeight;
        } catch(error) {
            console.error("Error message error:", error);
        }
        
    });
    
    socket.on("allUsers", function (data) {
        clientKeys = data["allUserKeys"];
        console.log(userData.Username);
        delete clientKeys[userData.Username];
        loadFriends();
    })

    socket.on('logout_redirect', function() {
        logout()
    });

    document.getElementById('send').onclick = () => {
        sendMessage();
    };
    
    document.getElementById('logout-btn').onclick = () => {
        socket.emit('logout', { user_name:  username});
    };
});

async function initiateUser() {
    try {
        // Connect the socket
        username = userData.Username;
        socket.connect();

        // Generate RSA key pair and get the public key
        //const clientPublicKey = await generateRSAKeyPair();

        // Handle socket connection event
        socket.on("connect", function () {
            socket.emit('user_join', { recipient: userData.Username, publicKey: "abc_need to replace" });
        });
        
        
    } catch (error) {
        console.error("Error initiating user:", error);
    }
}



function loadFriends() {
    const friendsList = document.getElementById("friends-list");
    friendsList.innerHTML = "";

    let highlightedLi = null;

    for (const [user, key] of Object.entries(clientKeys)) {
        let li = document.createElement("li");
        li.innerHTML = `
            <div class="status-indicator"></div>
            <div class="username">${user}</div>
            <div class="last-active" id="last-active-${user}"></div>
        `;

        li.addEventListener("click", () => {
            chatClient = user;
        });

        friendsList.appendChild(li);
    }
}




function sendMessage() {
    const clientMessage = document.getElementById('message-input').value;
    if (chatClient && clientMessage.trim() !== "") {
        document.getElementById("message-input").value = "";
        socket.emit('message', { recipient_name: chatClient, message: clientMessage });

        isCurrentUser = true;
        let ul = document.getElementById("chat-msg");
        let li = document.createElement("li");
        li.appendChild(document.createTextNode("Me : " + clientMessage));
        li.classList.add("right-align");
        ul.appendChild(li);
        ul.scrollTop = ul.scrollHeight;
    } else if (clientMessage.trim() === "") {
        console.error('Empty message cannot be sent');
    } else {
        console.error('No chat client selected');
    }
}

function logout() {
    fetch('/logout', {
        method: 'GET',
        credentials: 'same-origin'
    }).then(response => {
        if (response.ok) {
            window.location.href = '/';
        } else {
            console.error("Logout failed");
        }
    }).catch(error => {
        console.error("Logout error:", error);
    });
}

async function generateRSAKeyPair() {
    const keyPair = await window.crypto.subtle.generateKey(
        {
            name: "RSA-OAEP",
            modulusLength: 2048,
            publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
            hash: "SHA-256"
        },
        true,
        ["encrypt", "decrypt"]
    );
    publicKey = await window.crypto.subtle.exportKey("spki", keyPair.publicKey);
    privateKey = keyPair.privateKey;
    return publicKey;
}

// Encrypting the client message
async function encryptMessage(publicKey, message) {
    const importedPublicKey = await window.crypto.subtle.importKey(
        "spki",
        base64ToArrayBuffer(publicKey),
        {
            name: "RSA-OAEP",
            hash: "SHA-256"
        },
        true,
        ["encrypt"]
    );
    const encryptedMessage = await window.crypto.subtle.encrypt(
        {
            name: "RSA-OAEP"
        },
        importedPublicKey,
        new TextEncoder().encode(message)
    );
    return arrayBufferToBase64(encryptedMessage);
}

// Decrypt the received encrypted message
async function decryptMessage(privateKey, encryptedMessage) {
    const decryptedMessage = await window.crypto.subtle.decrypt(
        {
            name: "RSA-OAEP"
        },
        privateKey,
        base64ToArrayBuffer(encryptedMessage)
    );
    return new TextDecoder().decode(decryptedMessage);
}

function base64ToArrayBuffer(base64) {
    const binaryString = window.atob(base64);
    const len = binaryString.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
        bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes.buffer;
}

function arrayBufferToBase64(buffer) {
    let binary = '';
    const bytes = new Uint8Array(buffer);
    const len = bytes.byteLength;
    for (let i = 0; i < len; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return window.btoa(binary);
}
