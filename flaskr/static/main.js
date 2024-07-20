const socket = io({ autoConnect: false });
let privateKey, publicKey;
/**
 * Data structure to store client data
 * clientKeys[x] = {'username':uname, 'publicKey':'', 'email': email, 'status':'con_status'}
 * where status can have following values
 * 1. con_sent
 * 2. accepted
 * 3. con_recv
 * 4. available
 */
var clientKeys = {};
var username, chatClient, chatClientPK;
var isCurrentUser = true;


// Function to handle form events
document.addEventListener('DOMContentLoaded', function () {
    console.log("Page loaded. Initializing form event handlers...");

    // Select all forms
    const forms = document.querySelectorAll('form');

    // Add event listener to each form
    forms.forEach(form => {
        form.addEventListener('submit', function (event) {
            // Prevent default form submission, this is from the original form
            event.preventDefault();

            // Serialize form data
            const formData = new FormData(form);
            const email = formData.get('email');
            const subject = encodeURIComponent(formData.get('subject'));
            const body = encodeURIComponent(formData.get('body'));

            // Create mailto link
            const mailtoLink = `mailto:${email}?subject=${subject}&body=${body}`;

            // Open mailto link
            window.location.href = mailtoLink;

            // Reset the form values after submission
            form.reset();
        });
    });
});

document.addEventListener('DOMContentLoaded', async () => {
    document.getElementById("logout-btn").value = "Logout-"+userData.Username;

   socket.on('email_send_notify', function (data) {
        try {
            clientKeys[data['sender']].status = "con_recv"
            loadConReceiveFriends();
            loadAvailableFriends();
        } catch (error) {
            console.error("Error message error:", error);
        }
   })
   

   socket.on('email_reply_notify', function (data) {
        try {
            clientKeys[data['sender']].status = "con_reply_recv";
            loadAvailableFriends();
            loadConReceiveFriends();
        } catch (error) {
            console.error("Error message error:", error);
        }
    })

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
        //console.log('All clients----->',data['allClients'])
        for (const [key, email] of Object.entries(data["allClients"])) {
            console.log("-------start-------"); 
            console.log('Client key ------ > ',key)
            console.log('Username ------ > ',username)
            if ((!(key in clientKeys)) && (key != username)) {
                console.log("All Users------>",key);
                clientKeys[key] = {
                    'username':key,
                    'publicKey':'',
                    'email': email,
                    'status':'available'
                     }
            }
            console.log("-------end-------"); 
        }
        
        loadAvailableFriends();
    });

    socket.on('logoutUsers', function (data) {
        var clientKey = data['logoutUser']
        console.log('User logout========>', clientKey)
        console.log('Client keys========>', clientKeys)
        if (clientKey in clientKeys) {
            delete clientKeys[clientKey];
            console.log('Client keys after delete========>', clientKeys)
            loadAvailableFriends();
            loadConReceiveFriends();
            loadAccepetdFriends();
        }
    });

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
        socket.emit('logout', { user_name: username });
    };


});


async function initiateUser() {
    try {
        username = userData.Username;
        publicKey = await generateRSAKeyPair();

        socket.connect();
        console.log('Username------->',userData.Username)
        console.log('Email------->',userData.Email)
        socket.on("connect", function () {
            // socket.emit('user_join', { recipient: userData.Username, publicKey: clientPublicKey });
            socket.emit('user_join', { recipient: userData.Username, email: userData.Email});
        });
        
        
        document.getElementById("chat_header_text").textContent = `Chat Website [${userData.Username}]`;
        
    } catch (error) {
        console.error("Error initiating user:", error);
    }
}

/**
 * Function to load the chat list
 */
function loadAvailableFriends() {
    var friendsList = NaN;    

    let highlightedLi = null;
    let li = document.createElement("li");

    friendsList = document.getElementById("friends-list");
    friendsList.innerHTML = "";

    for (const [key, user] of Object.entries(clientKeys)) {
        console.log("user==" + user['username']);
        console.log("user==" + user['email']);
        console.log("user==" + user['status']);


        console.log("user['status'] available=====" + user['status']);

            if(user['status'] == 'con_sent')
            {
                li.innerHTML = `
                    <div class="status-indicator"></div>
                    <div class="username">${key}</div>
                    <div class="last-active" id="last-active-${key}"></div>
                    <div class="action"><input type="button" value="Invitation Sent" disabled></div>
                `;
            }
            else if (user['status'] == 'available')
            {
                li.innerHTML = `
                    <div class="status-indicator"></div>
                    <div class="username">${key}</div>
                    <div class="last-active" id="last-active-${key}"></div>
                    <div class="action"><input type="button" name="connect" value="Invite to chat" onclick='loadRequest(${JSON.stringify(user)})'></div>
                `;
            }

        friendsList.appendChild(li);
    }
}

/**
 * Function to load the chat list
 */
function loadConReceiveFriends() {
    var friendsList = NaN;    

    let li = document.createElement("li");

    friendsList = document.getElementById("received-list");
    friendsList.innerHTML = "";

    for (const [key, user] of Object.entries(clientKeys)) {
        console.log("user==" + user['username']);
        console.log("user==" + user['email']);
        console.log("user==" + user['status']);




        console.log("user['status'] loadConReceiveFriends=====" + user['status']);
        if ((user['status'] == 'con_recv' || user['status'] == 'con_reply_recv') && user['publicKey'] == "") {
            li.innerHTML = `
                    <div class="status-indicator"></div>
                    <div class="username">${key}</div>
                    <div class="last-active" id="last-active-${key}"></div>
                    <div class="action"><input type="button" name="add_friend" value="Add ParsePhase" onclick='loadReply(${JSON.stringify(user)})'></div>
                `;
            }
            else if(user['status'] == 'con_recv' && user['publicKey'] != "")
            {
                li.innerHTML = `
                    <div class="status-indicator"></div>
                    <div class="username">${key}</div>
                    <div class="last-active" id="last-active-${key}"></div>
                    <div class="action"><input type="button" name="add_friend" value="Send Confirmation" onclick='loadReply(${JSON.stringify(user)})'></div>
                `;
            }

        friendsList.appendChild(li);
    }
}

/**
 * onclick method for button click 
 * @param {*} friendObj 
 */
function OnAddParsePhaseClick(friendObj)
{
    //console.log("OnAddParsePhaseClick----:");
    var parsePhase = document.getElementById("body_parsephase").value;
    console.log("OnAddParsePhaseClick-parsePhase=", parsePhase);
    clientKeys[friendObj.username].publicKey=parsePhase;
    loadConReceiveFriends();
    loadAccepetdFriends();
}


/**
 * Function to load the chat list
 */
function loadAccepetdFriends() {
    var friendsList = NaN;    

    let highlightedLi = null;
    let li = document.createElement("li");

    friendsList = document.getElementById("connections-list");
    friendsList.innerHTML = "";

    for (const [key, user] of Object.entries(clientKeys)) {
        console.log("user==" + user['username']);
        console.log("user==" + user['email']);
        console.log("user==" + user['status']);


        console.log("user['status'] loadAccepetdFriends=====" + user['status']);
        if (user['status'] == 'accepted') {
            li.innerHTML = `
                    <div class="status-indicator"></div>
                    <div class="username">${key}</div>
                    <div class="last-active" id="last-active-${key}"></div>
                `;

                li.addEventListener("click", () => {
                    chatClient = key;
                    chatClientPK = user.publicKey

                let ul = document.getElementById("chat-msg");
                let li = document.createElement("li");
                li.appendChild(document.createTextNode(`Chat with - ${chatClient}`));
                li.classList.add("center_user");
                ul.appendChild(li);
                ul.scrollTop = ul.scrollHeight;
            });
        }

        friendsList.appendChild(li);
    }
}

/**
 * Button click function for sending connection request via an email
 * this will open the email client for sending the email.
 */
function OnRequestSend(obj) {

    clientKeys[obj.username].status = "con_sent"
    socket.emit('send_email_notification', { recipient_name: obj.username, notification: "Public Key Request Send" });
    loadAvailableFriends();

    // Get field data for email.
    const email = document.getElementById("email").value;
    const subject = document.getElementById('subject').value;
    const body = document.getElementById('body').value;

    // Create mailto link
    const mailtoLink = `mailto:${email}?subject=${subject}&body=${body}`;

    // Open mailto link
    window.location.href = mailtoLink;
}

/**
 * Function to load the email request
 */
function loadRequest(obj) {
    console.log('Load request-------->',obj)

    clientKeys[obj.username].status = "con_sent"
    socket.emit('send_email_notification', { recipient_name: obj.username, notification: "Public Key Request Send" });
    loadAvailableFriends();
    const formContent = `
        <div class="email-form-container">
            <label for="email">Email:</label>
            <input type="email" id="email" name="email" value="${obj.email}" required>            
            <label for="subject">Subject:</label>
            <input type="text" id="subject" name="subject" value="GOBUZZ Public Key For - ${obj.username}" required>            
            <label for="body">Body:</label>
            <textarea id="body" name="body" required>${publicKey}</textarea>            
            <button type="button" onclick="OnRequestSend()">Request To Connect</button>
        </div>
    `;
    // load to the div_connect_request
    //document.getElementById('div_connect_request').innerHTML = formContent;
    document.getElementById('email_request_form').innerHTML = formContent;
}

/**
 * Function to load the email request
 */
function loadReply(obj) {
    console.log('Load request-------->',obj)
    
    formContent = NaN;
    

    if(clientKeys[obj.username].status == "con_recv" && clientKeys[obj.username].publicKey != "")
    {
        console.log("TEST----1");
        formContent = `
        <div class="email-form-container">
            <label for="email">Email:</label>
            <input type="email" id="email" name="email" value="${obj.email}" required>            
            <label for="subject">Subject:</label>
            <input type="text" id="subject" name="subject" value="GOBUZZ Public Key For - ${obj.username}" required>            
            <label for="body">Body:</label>
            <textarea id="body" name="body" required>${publicKey}</textarea>            
            <button type="button" onclick="OnRequestSend()">Request To Connect</button>
        </div>
        `;
        clientKeys[obj.username].status = "accepted"
        socket.emit('reply_email_notification', { recipient_name: obj.username, notification: "Public Key Reply Send" });
        loadConReceiveFriends();
        loadAccepetdFriends();
    }
    else
    {
        //<div class="action"><input type="button" name="connect" value="Add ParsePhase" onclick='OnAddParsePhaseClick(${JSON.stringify(obj)})'></div>
        formContent = `
        <div class="email-form-container">
            <label for="body_parsephase">ParsePhase:</label>
            <textarea id="body_parsephase" name="body" required>Enter the ParsePhase received via the email. Please check email and enter the ParsePhase</textarea>
            <button type="button" name="connect" onclick='OnAddParsePhaseClick(${JSON.stringify(obj)})'>Add ParsePhase</button>
        </div>
        `;
        if(clientKeys[obj.username].status == "con_reply_recv"){
            clientKeys[obj.username].status = "accepted";
        }
    }
    
    // load to the div_connect_request
    //document.getElementById('div_connect_request').innerHTML = formContent;
    document.getElementById('email_reply_form').innerHTML = formContent;
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

function confirmLogout() {

    const modal = document.getElementById("confirmationModal");
    modal.style.display = "block";

    const confirmYes = document.getElementById("confirmYes");
    const confirmNo = document.getElementById("confirmNo");

    confirmYes.onclick = null;
    confirmNo.onclick = null;

    confirmYes.addEventListener('click', function() {
        socket.emit('logout', { user_name:  username});
    });

    confirmNo.addEventListener('click', function() {
        modal.style.display = "none";
    });

    const closeBtn = document.getElementsByClassName("close")[0];
    closeBtn.onclick = function() {
        modal.style.display = "none";
    };

    window.onclick = function(event) {
        if (event.target === modal) {
            modal.style.display = "none";
        }
    };

  
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