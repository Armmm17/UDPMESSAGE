package com.armandoboaca17.encryptedmess;

import java.net.*;
import java.io.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.function.Consumer;
import org.json.JSONObject;

public class EnhancedUDPClient extends Thread {
    private DatagramSocket socket;
    private InetAddress remoteAddress;
    private int remotePort;
    private int localPort;
    private volatile boolean running;
    private Consumer<String> messageCallback;
    private String currentUser;
    private String currentUserPassword;
    private DatabaseManager dbManager;
    private Map<String, Timer> selfDestructTimers;
    private ScheduledExecutorService cleanupExecutor;

    // Statistics for debugging
    private int messagesSent = 0;
    private int messagesReceived = 0;

    public EnhancedUDPClient(int localPort, String remoteHost, int remotePort,
                             Consumer<String> messageCallback, String username, String password) throws Exception {
        this.localPort = localPort;
        this.remotePort = remotePort;
        this.messageCallback = messageCallback;
        this.currentUser = username;
        this.currentUserPassword = password;
        this.remoteAddress = InetAddress.getByName(remoteHost);
        this.socket = new DatagramSocket(localPort);
        this.socket.setSoTimeout(1000); // 1 second timeout for receive
        this.dbManager = DatabaseManager.getInstance();
        this.selfDestructTimers = new HashMap<>();
        this.cleanupExecutor = Executors.newScheduledThreadPool(1);

        System.out.println("\n🚀 UDP Client Configuration:");
        System.out.println("   Local Port: " + localPort);
        System.out.println("   Remote Host: " + remoteHost);
        System.out.println("   Remote Port: " + remotePort);
        System.out.println("   Username: " + username);

        startCleanupScheduler();
    }

    private void startCleanupScheduler() {
        cleanupExecutor.scheduleAtFixedRate(() -> {
            if (dbManager != null) {
                dbManager.cleanupExpiredMessages();
            }
        }, 0, 1, TimeUnit.MINUTES);
    }

    @Override
    public void run() {
        running = true;
        byte[] buffer = new byte[65507]; // Maximum UDP packet size

        System.out.println("📡 UDP Client started on port " + localPort + ". Listening for messages...");

        while (running) {
            try {
                DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
                socket.receive(packet);

                String received = new String(packet.getData(), 0, packet.getLength());
                messagesReceived++;

                // Log raw message (first 100 chars)
                String logMsg = received.length() > 100 ? received.substring(0, 100) + "..." : received;
                System.out.println("\n📥 Received message #" + messagesReceived + " (" + received.length() + " bytes)");
                System.out.println("   From: " + packet.getAddress().getHostAddress() + ":" + packet.getPort());
                System.out.println("   Preview: " + logMsg);

                processIncomingMessage(received);

            } catch (SocketTimeoutException e) {
                // Expected timeout, continue listening
                continue;
            } catch (IOException e) {
                if (running) {
                    System.err.println("❌ Error receiving UDP packet: " + e.getMessage());
                }
                break;
            }
        }

        // Cleanup
        if (socket != null && !socket.isClosed()) {
            socket.close();
        }
        if (cleanupExecutor != null) {
            cleanupExecutor.shutdown();
        }

        System.out.println("🛑 UDP Client stopped");
    }

    private void processIncomingMessage(String encryptedJson) {
        try {
            JSONObject messageObj = new JSONObject(encryptedJson);

            // Check if this is a delete request
            if (messageObj.has("type") && "DELETE".equals(messageObj.getString("type"))) {
                handleDeleteRequest(messageObj);
                return;
            }

            // Regular message processing
            String messageId = messageObj.getString("messageId");
            String encryptedContent = messageObj.getString("content");
            String iv = messageObj.getString("iv");
            String sender = messageObj.getString("sender");
            String encryptionType = messageObj.optString("encryptionType", "simple");
            boolean selfDestruct = messageObj.optBoolean("selfDestruct", false);
            int ttlMinutes = messageObj.optInt("ttl", 0);

            System.out.println("🔍 Processing message details:");
            System.out.println("   Message ID: " + messageId);
            System.out.println("   Sender: " + sender);
            System.out.println("   Encryption Type: " + encryptionType);
            System.out.println("   Self-Destruct: " + selfDestruct);
            System.out.println("   TTL: " + ttlMinutes + " minutes");

            String decryptedContent;

            if ("hybrid".equals(encryptionType)) {
                // Hybrid encryption: RSA for key exchange + AES for message
                System.out.println("   Using hybrid (RSA+AES) decryption");
                decryptedContent = decryptHybridMessage(encryptedContent, iv, sender);
            } else {
                // Simple shared secret encryption (fallback)
                System.out.println("   Using simple (shared secret) decryption");
                decryptedContent = decryptSimpleMessage(encryptedContent, iv, sender);
            }

            if (decryptedContent == null) {
                System.err.println("❌ Failed to decrypt message from " + sender);
                return;
            }

            System.out.println("✅ Successfully decrypted message: \"" +
                    (decryptedContent.length() > 50 ? decryptedContent.substring(0, 50) + "..." : decryptedContent) + "\"");

            // FIXED: Save message as RECEIVER (current user is the receiver)
            dbManager.saveMessageAsReceiver(messageId, sender, currentUser,
                    encryptedContent, iv, encryptionType, selfDestruct);

            // Schedule self-destruct if needed
            if (selfDestruct && ttlMinutes > 0) {
                dbManager.scheduleSelfDestruct(messageId, ttlMinutes);
                scheduleSelfDestruct(messageId, decryptedContent, ttlMinutes);
            }

            // Display message in UI
            if (messageCallback != null) {
                String displayText = sender + ": " + decryptedContent;
                if (selfDestruct) {
                    displayText += " [Self-destruct in " + ttlMinutes + " min]";
                }
                messageCallback.accept(displayText);
            }

        } catch (Exception e) {
            System.err.println("❌ Error processing incoming message: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private String decryptHybridMessage(String encryptedContent, String iv, String sender) {
        try {
            // Hybrid format: encryptedMessage::encryptedAESKey
            String[] parts = encryptedContent.split("::");
            if (parts.length != 2) {
                System.err.println("❌ Invalid hybrid encrypted format");
                return null;
            }

            String encryptedMessage = parts[0];
            String encryptedAESKey = parts[1];

            System.out.println("   Encrypted AES Key length: " + encryptedAESKey.length());
            System.out.println("   Encrypted Message length: " + encryptedMessage.length());

            // Get our private key
            String privateKey = dbManager.getPrivateKey(currentUser, currentUserPassword);
            if (privateKey == null) {
                System.err.println("❌ Could not retrieve private key for " + currentUser);
                System.err.println("   Make sure you're using the correct password");
                return null;
            }

            System.out.println("   Private key retrieved, length: " + privateKey.length());

            // Decrypt using hybrid method
            return SecurityUtils.decryptHybrid(encryptedMessage, encryptedAESKey, iv, privateKey);

        } catch (Exception e) {
            System.err.println("❌ Hybrid decryption failed: " + e.getMessage());
            return null;
        }
    }

    private String decryptSimpleMessage(String encryptedContent, String iv, String sender) {
        try {
            // Simple shared secret: currentUser:sender
            String sharedSecret = currentUser + ":" + sender;
            System.out.println("   Using shared secret: " + sharedSecret);
            return SecurityUtils.decryptSimple(encryptedContent, sharedSecret, iv);
        } catch (Exception e) {
            System.err.println("❌ Simple decryption failed: " + e.getMessage());
            return null;
        }
    }

    private void handleDeleteRequest(JSONObject deleteObj) {
        try {
            String messageId = deleteObj.getString("messageId");
            String sender = deleteObj.getString("sender");

            System.out.println("🗑️  Received delete request for message " + messageId + " from " + sender);

            // Mark as deleted for current user
            dbManager.markMessageDeletedForOwner(messageId, currentUser);

            // Cancel any scheduled self-destruct timer
            Timer timer = selfDestructTimers.remove(messageId);
            if (timer != null) {
                timer.cancel();
            }

            // Notify UI
            if (messageCallback != null) {
                messageCallback.accept("System: Message " + messageId + " was deleted by " + sender);
            }

        } catch (Exception e) {
            System.err.println("❌ Error handling delete request: " + e.getMessage());
        }
    }

    public void sendMessage(String receiverUsername, String message, boolean selfDestruct, int ttlMinutes) {
        try {
            String messageId = UUID.randomUUID().toString();
            messagesSent++;

            System.out.println("\n📤 Sending message #" + messagesSent);
            System.out.println("   To: " + receiverUsername);
            System.out.println("   Message: \"" + (message.length() > 50 ? message.substring(0, 50) + "..." : message) + "\"");
            System.out.println("   Self-Destruct: " + selfDestruct + " (" + ttlMinutes + " min)");

            String encryptedContent;
            String iv;
            String encryptionType;

            // Try to use hybrid encryption first (if we have receiver's public key)
            String receiverPublicKey = dbManager.getPublicKey(receiverUsername);
            if (receiverPublicKey != null && !receiverPublicKey.isEmpty()) {
                System.out.println("   Using hybrid encryption (RSA public key found)");

                try {
                    String[] hybridResult = SecurityUtils.encryptHybrid(message, receiverPublicKey);
                    encryptedContent = hybridResult[0] + "::" + hybridResult[1]; // Message::EncryptedKey
                    iv = hybridResult[2];
                    encryptionType = "hybrid";

                    System.out.println("   Hybrid encryption successful");
                    System.out.println("   Encrypted AES Key length: " + hybridResult[1].length());
                    System.out.println("   Encrypted Message length: " + hybridResult[0].length());

                } catch (Exception e) {
                    System.err.println("   Hybrid encryption failed, falling back to simple: " + e.getMessage());
                    // Fallback to simple encryption
                    String sharedSecret = currentUser + ":" + receiverUsername;
                    String[] simpleResult = SecurityUtils.encryptSimple(message, sharedSecret);
                    encryptedContent = simpleResult[0];
                    iv = simpleResult[1];
                    encryptionType = "simple";
                }
            } else {
                System.out.println("   No public key found, using simple encryption");
                // Use simple shared secret encryption
                String sharedSecret = currentUser + ":" + receiverUsername;
                String[] simpleResult = SecurityUtils.encryptSimple(message, sharedSecret);
                encryptedContent = simpleResult[0];
                iv = simpleResult[1];
                encryptionType = "simple";
            }

            // Create JSON message object
            JSONObject messageObj = new JSONObject();
            messageObj.put("messageId", messageId);
            messageObj.put("sender", currentUser);
            messageObj.put("receiver", receiverUsername);
            messageObj.put("content", encryptedContent);
            messageObj.put("iv", iv);
            messageObj.put("timestamp", System.currentTimeMillis());
            messageObj.put("selfDestruct", selfDestruct);
            messageObj.put("ttl", ttlMinutes);
            messageObj.put("encryptionType", encryptionType);

            String jsonString = messageObj.toString();
            System.out.println("   JSON message size: " + jsonString.length() + " bytes");

            // FIXED: Store message as SENDER (current user is the sender)
            dbManager.saveMessageAsSender(messageId, currentUser, receiverUsername,
                    encryptedContent, iv, encryptionType, selfDestruct);

            if (selfDestruct && ttlMinutes > 0) {
                dbManager.scheduleSelfDestruct(messageId, ttlMinutes);
            }

            // Send over UDP
            byte[] data = jsonString.getBytes();
            DatagramPacket packet = new DatagramPacket(
                    data, data.length, remoteAddress, remotePort
            );
            socket.send(packet);

            System.out.println("✅ Message sent successfully to " + remoteAddress.getHostAddress() + ":" + remotePort);

            // Display locally in UI
            if (messageCallback != null) {
                String displayText = "You to " + receiverUsername + ": " + message;
                if (selfDestruct) {
                    displayText += " [Self-destruct in " + ttlMinutes + " minutes]";
                }
                messageCallback.accept(displayText);
            }

        } catch (Exception e) {
            System.err.println("❌ Error sending message: " + e.getMessage());
            e.printStackTrace();
        }
    }

    public void deleteMessage(String messageId) {
        try {
            System.out.println("\n🗑️  Deleting message: " + messageId);

            // Mark as deleted for current user
            dbManager.markMessageDeletedForOwner(messageId, currentUser);

            // Send delete request to remote
            JSONObject deleteObj = new JSONObject();
            deleteObj.put("type", "DELETE");
            deleteObj.put("messageId", messageId);
            deleteObj.put("sender", currentUser);
            deleteObj.put("timestamp", System.currentTimeMillis());

            String jsonString = deleteObj.toString();
            byte[] data = jsonString.getBytes();
            DatagramPacket packet = new DatagramPacket(
                    data, data.length, remoteAddress, remotePort
            );
            socket.send(packet);

            // Cancel self-destruct timer if exists
            Timer timer = selfDestructTimers.remove(messageId);
            if (timer != null) {
                timer.cancel();
            }

            // Notify UI
            if (messageCallback != null) {
                messageCallback.accept("System: You deleted message: " + messageId);
            }

            System.out.println("✅ Delete request sent for message: " + messageId);

        } catch (Exception e) {
            System.err.println("❌ Error deleting message: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private void scheduleSelfDestruct(String messageId, String messageContent, int ttlMinutes) {
        Timer timer = new Timer(true);
        timer.schedule(new TimerTask() {
            @Override
            public void run() {
                System.out.println("⏰ Self-destruct timer expired for message: " + messageId);
                deleteMessage(messageId);

                if (messageCallback != null) {
                    String preview = messageContent.length() > 20 ?
                            messageContent.substring(0, 20) + "..." : messageContent;
                    messageCallback.accept("System: Message \"" + preview + "\" has self-destructed");
                }
            }
        }, ttlMinutes * 60 * 1000L); // Convert minutes to milliseconds

        selfDestructTimers.put(messageId, timer);
        System.out.println("⏰ Scheduled self-destruct for message " + messageId + " in " + ttlMinutes + " minutes");
    }

    public void stopClient() {
        System.out.println("\n🛑 Stopping UDP client...");
        running = false;

        // Cancel all self-destruct timers
        for (Timer timer : selfDestructTimers.values()) {
            timer.cancel();
        }
        selfDestructTimers.clear();

        if (socket != null && !socket.isClosed()) {
            socket.close();
        }

        if (cleanupExecutor != null) {
            cleanupExecutor.shutdown();
        }

        System.out.println("📊 Statistics:");
        System.out.println("   Messages Sent: " + messagesSent);
        System.out.println("   Messages Received: " + messagesReceived);
        System.out.println("   Active Timers: " + selfDestructTimers.size());
    }

    public boolean isRunning() {
        return running;
    }

    public int getLocalPort() {
        return localPort;
    }

    public String getCurrentUser() {
        return currentUser;
    }
}