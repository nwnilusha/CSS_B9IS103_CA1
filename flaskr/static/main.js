const socket = io({ autoConnect: false });
let privateKey, publicKey;
var clientKeys = {};
var username, chatClient, chatClientPK;
var isCurrentUser = true;

document.addEventListener('DOMContentLoaded', async () => {
    //publicKey = await generateRSAKeyPair()   
    publicKey = "abc"
    document.getElementById("logout-btn").value = "Logout-"+userData.Username;

   

    socket.on('message', async (data) => {
        try {
            //const decryptedMessage = await decryptMessage(privateKey, data.message);
            //console.log(`Message from ${data.sender_sid}:`, decryptedMessage);
            isCurrentUser = false;
            console.log("Sender------------",data["sender"])
            console.log("Sender Encrypted Message------------",data["message"])
            const decryptMessage = await decryptMessage(privateKey,data["message"])
            console.log("Sender Decrypted Message------------",decryptMessage)
            let ul = document.getElementById("chat-msg");
            let li = document.createElement("li");
            li.appendChild(document.createTextNode(data["sender"] + " : " + decryptMessage));
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

    socket.on('error',function(errorData){
        console.log("Logout Error ------- ",errorData.message)
    });

    document.getElementById('send').onclick = async () => {
        await sendMessage();
    };

    document.getElementById("message-input").addEventListener("keypress", async function (event) {
        if (event.key === "Enter") {
            await sendMessage();
        }
    });
    
    document.getElementById('logout-btn').onclick = () => {
        socket.emit('logout', { user_name:  username});
    };
});

async function initiateUser() {
    try {
        // Connect the socket
        username = userData.Username;
        const clientPublicKey = await generateRSAKeyPair();

        socket.connect();

        // Handle socket connection event
        socket.on("connect", function () {
            socket.emit('user_join', { recipient: userData.Username, publicKey: clientPublicKey });
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
            chatClientPK = key
        });

        friendsList.appendChild(li);
    }
}


async function sendMessage() {
    const clientMessage = document.getElementById('message-input').value;
    console.log("Message before encrypt-----------",clientMessage)
    const encryptedMessage = await encryptMessage(chatClientPK,clientMessage)
    console.log("Message after encrypt-----------",encryptedMessage)
    if (chatClient && clientMessage.trim() !== "") {
        document.getElementById("message-input").value = "";
        socket.emit('message', { recipient_name: chatClient, message: encryptedMessage });

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
    console.log("Private Key-----------",privateKey)
    console.log("Public Key-----------",publicKey)
    return publicKey;
}

// Encrypting the client message
async function encryptMessage(publicKey, message) {
    try {
        const keyBuffer = base64ToArrayBuffer(publicKey);
        if (!keyBuffer) {
            throw new Error("Invalid public key format.");
        }

        const importedPublicKey = await window.crypto.subtle.importKey(
            "spki",
            keyBuffer,
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
        console.log("Encrypted Message-----------> ", encryptedMessage);
        return arrayBufferToBase64(encryptedMessage);
    } catch (error) {
        console.error("Error during encryption:", error.message);
        throw error;
    }
}

// Decrypt the received encrypted message
async function decryptMessage(privateKey, encryptedMessage) {
    try {
        const messageBuffer = base64ToArrayBuffer(encryptedMessage);
        if (!messageBuffer) {
            throw new Error("Invalid encrypted message format.");
        }

        const decryptedMessage = await window.crypto.subtle.decrypt(
            {
                name: "RSA-OAEP"
            },
            privateKey,
            messageBuffer
        );
        return new TextDecoder().decode(decryptedMessage);
    } catch (error) {
        console.error("Error during decryption:", error.message);
        throw error;
    }
}

function base64ToArrayBuffer(base64) {
    try {
        // Add padding if necessary
        const padLength = (4 - (base64.length % 4)) % 4;
        if (padLength > 0) {
            base64 += '='.repeat(padLength);
        }

        // Validate if the base64 string contains only valid Base64 characters
        const base64Pattern = /^[A-Za-z0-9+/]*={0,2}$/;
        if (!base64Pattern.test(base64)) {
            throw new Error("Invalid characters in Base64 string.");
        }

        const binaryString = window.atob(base64);
        const len = binaryString.length;
        const bytes = new Uint8Array(len);
        for (let i = 0; i < len; i++) {
            bytes[i] = binaryString.charCodeAt(i);
        }
        return bytes.buffer;
    } catch (error) {
        console.error("Failed to convert Base64 to ArrayBuffer:", error.message);
        return null;
    }
}


// Convert ArrayBuffer to Base64 string
function arrayBufferToBase64(buffer) {
    let binary = '';
    const bytes = new Uint8Array(buffer);
    const len = bytes.byteLength;
    for (let i = 0; i < len; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return window.btoa(binary);
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
