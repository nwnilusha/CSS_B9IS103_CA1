const socket = io({ autoConnect: false });
let privateKey, publicKey;
var clientKeys = {};
var username, chatClient;
var isCurrentUser = true;

document.addEventListener('DOMContentLoaded', async () => {
    //publicKey = await generateRSAKeyPair()
    publicKey = "abc"

    document.getElementById("join-btn").addEventListener("click", async function () {
        username = document.getElementById("username").value;

        socket.connect();
        // const clientPublicKey = await generateRSAKeyPair()
        const clientPublicKey = publicKey;

        socket.on("connect", function () {
            socket.emit('user_join', { recipient: username, publicKey: publicKey });

        })

        document.getElementById("chat").style.display = "block";
        document.getElementById("landing").style.display = "none";
    })

    document.getElementById("message-input").addEventListener("keyup", function (event) {
        //sendMessage()
    })

    socket.on('message', async (data) => {
        //const decryptedMessage = await decryptMessage(privateKey, data.message);
        //console.log(`Message from ${data.sender_sid}:`, decryptedMessage);
        isCurrentUser = false;
        let ul = document.getElementById("chat-msg");
        let li = document.createElement("li");
        li.appendChild(document.createTextNode(data["sender"] + " : " + data["message"]));
        if (isCurrentUser) {
            li.classList.add("right-align");
        } else {
            li.classList.add("left-align");
        }
        ul.appendChild(li);
        ul.scrolltop = ul.scrollHeight;
    });

    socket.on("allUsers", function (data) {

        clientKeys = data["allUserKeys"];
        console.log(username);
        delete clientKeys[username];
        loadFriends();
    })

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

    function loadFriends() {
        var availableClients = document.getElementById("clients");
        for (const [user, key] of Object.entries(clientKeys)) {
            console.log(key);
            var option = document.createElement('option');
            option.text = option.value = user;

            availableClients.add(option, 0);
        }
    }

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

    document.getElementById('send').onclick = async () => {
        sendMessage()
    };

    function sendMessage() {
        const clientMessage = document.getElementById('message-input').value;
        const recipient = document.getElementById('clients').value;
        const recipientPublicKey = clientKeys[recipient];

        if (recipientPublicKey) {
            document.getElementById("message-input").value = ""
            //const encryptedMessage = await encryptMessage(recipientPublicKey, clientMessage);
            socket.emit('message', { recipient_name: recipient, message: clientMessage });

            isCurrentUser = true;
            let ul = document.getElementById("chat-msg");
            let li = document.createElement("li");
            li.appendChild(document.createTextNode("Me : " + clientMessage));
            if (isCurrentUser) {
                li.classList.add("right-align");
            } else {
                li.classList.add("left-align");
            }
            ul.appendChild(li);
            ul.scrolltop = ul.scrollHeight;
        } else {
            console.error('Recipient public key not found');
        }
    }
})