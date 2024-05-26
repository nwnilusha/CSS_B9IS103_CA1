const chatMessages = document.getElementById('chat-messages');
const messageInput = document.getElementById('message-input');

function sendMessage() {
    const messageText = messageInput.value.trim();
    if (messageText !== "") {
        const messageElement = document.createElement('div');
        messageElement.classList.add('message', 'user');
        messageElement.textContent = messageText;
        chatMessages.appendChild(messageElement);
        messageInput.value = '';
        chatMessages.scrollTop = chatMessages.scrollHeight; // Scroll to the bottom
    }
}

// Optional: Add event listener for Enter key
messageInput.addEventListener('keypress', function (e) {
    if (e.key === 'Enter') {
        sendMessage();
    }
});

            

        