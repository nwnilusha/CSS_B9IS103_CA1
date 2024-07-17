const socket = io({ autoConnect: false });
let privateKey, publicKey;
var clientKeys = {};
var username, chatClient, chatClientPK;
var isCurrentUser = true;

/**
 * Function to load the email request
 */

function loadRequest() {
    const formContent = `
        <div class="email-form-container">
            <p>Send Connection Request</p>
            <form method="POST" action="{{ url_for('send_email') }}">
                <label for="email">Email:</label>
                <input type="email" id="email" name="email" required>
                
                <label for="subject">Subject:</label>
                <input type="text" id="subject" name="subject" required>
                
                <label for="body">Body:</label>
                <textarea id="body" name="body" required></textarea>
                
                <button type="submit">Send Email</button>
            </form>
        </div>
    `;
    // load to the div_connect_request
    document.getElementById('div_connect_request').innerHTML = formContent;
}

document.addEventListener('DOMContentLoaded', async () => {
    document.getElementById("logout-btn").value = "Logout-"+userData.Username;

   

    socket.on('message', async (data) => {
        try {
            isCurrentUser = false;
            console.log("Sender------------", data["sender"]);
            console.log("Sender Encrypted Message------------", data["message"]);

            const decryptedMessage = await decryptMessage(privateKey, data["message"]);
            console.log("Sender Decrypted Message------------", decryptedMessage);

            let ul = document.getElementById("chat-msg");
            let li = document.createElement("li");
            li.appendChild(document.createTextNode(data["sender"] + " : " + decryptedMessage));
            li.classList.add("left-align");
            ul.appendChild(li);
            ul.scrollTop = ul.scrollHeight;
        } catch (error) {
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
        username = userData.Username;
        const clientPublicKey = await generateRSAKeyPair();

        socket.connect();

        socket.on("connect", function () {
            socket.emit('user_join', { recipient: userData.Username, publicKey: clientPublicKey });
        });
        
        
        document.getElementById("chat_header_text").textContent = `Chat Website [${userData.Username}]`;
        
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
            <div class="action"><input type="button" name="connect" value="Invite to chat" onclick="loadRequest()"></div>
        `;

        li.addEventListener("click", () => {
            chatClient = user;
            chatClientPK = key

            let ul = document.getElementById("chat-msg");
            ul.innerHTML = "";
            let li = document.createElement("li");
            li.appendChild(document.createTextNode(`Chat with - ${chatClient}`));
            li.classList.add("center_user");
            ul.appendChild(li);
            ul.scrollTop = ul.scrollHeight;
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
            publicExponent: new Uint8Array([1, 0, 1]),
            hash: "SHA-256"
        },
        true,
        ["encrypt", "decrypt"]
    );

    const publicKeyArrayBuffer = await window.crypto.subtle.exportKey("spki", keyPair.publicKey);
    const publicKeyBase64 = arrayBufferToBase64(publicKeyArrayBuffer);
    
    console.log("Generated Public Key (Base64):", publicKeyBase64);
    privateKey = keyPair.privateKey;

    return publicKeyBase64;
}


async function encryptMessage(publicKeyBase64, message) {
    try {
        if (typeof publicKeyBase64 !== 'string' || !isBase64(publicKeyBase64)) {
            throw new Error("Public key is not a valid Base64 string.");
        }

        const publicKeyArrayBuffer = base64ToArrayBuffer(publicKeyBase64);

        const publicKey = await window.crypto.subtle.importKey(
            "spki",
            publicKeyArrayBuffer,
            {
                name: "RSA-OAEP",
                hash: "SHA-256"
            },
            true,
            ["encrypt"]
        );

        const encodedMessage = new TextEncoder().encode(message);

        const encryptedMessage = await window.crypto.subtle.encrypt(
            {
                name: "RSA-OAEP"
            },
            publicKey,
            encodedMessage
        );

        return arrayBufferToBase64(encryptedMessage);
    } catch (error) {
        console.error("Error during encryption:", error.message);
        throw error;
    }
}


async function decryptMessage(privateKey, encryptedMessage) {
    try {
        const decryptedMessage = await window.crypto.subtle.decrypt(
            {
                name: "RSA-OAEP"
            },
            privateKey,
            base64ToArrayBuffer(encryptedMessage)
        );
        return new TextDecoder().decode(decryptedMessage);
    } catch (error) {
        console.error("Error during decryption:", error.message);
        throw error;
    }
}

function base64ToArrayBuffer(base64) {
    try {
        if (!isBase64(base64)) {
            throw new Error("Invalid Base64 string.");
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
        throw error;
    }
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

function isBase64(str) {
    const base64Pattern = /^(?:[A-Za-z0-9+\/]{4})*(?:[A-Za-z0-9+\/]{2}==|[A-Za-z0-9+\/]{3}=)?$/;
    return base64Pattern.test(str);
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
