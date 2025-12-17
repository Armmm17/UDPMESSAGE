package com.armandoboaca17.encryptedmess;

import java.sql.*;
import java.util.Properties;
import java.util.UUID;

public class DatabaseManager {
    private static DatabaseManager instance;
    private Connection connection;
    private String url = "jdbc:mysql://localhost:3306/secure_chat_db";
    private String user = "root";
    private String password = ""; // CHANGE THIS TO YOUR MYSQL PASSWORD

    private DatabaseManager() {
        initialize();
    }

    public static synchronized DatabaseManager getInstance() {
        if (instance == null) {
            instance = new DatabaseManager();
        }
        return instance;
    }

    private void initialize() {
        try {
            // Load MySQL driver
            Class.forName("com.mysql.cj.jdbc.Driver");
            System.out.println("MySQL Driver loaded successfully");

            // First, create database if it doesn't exist
            createDatabaseIfNotExists();

            // Connection properties
            Properties props = new Properties();
            props.setProperty("user", user);
            props.setProperty("password", this.password);
            props.setProperty("useSSL", "false");
            props.setProperty("serverTimezone", "UTC");
            props.setProperty("allowPublicKeyRetrieval", "true");

            // Connect to database
            connection = DriverManager.getConnection(url, props);
            System.out.println("✅ Connected to MySQL database: " + url);

            // Create tables
            createTables();

        } catch (ClassNotFoundException e) {
            System.err.println("❌ MySQL JDBC Driver not found!");
            e.printStackTrace();
        } catch (SQLException e) {
            System.err.println("❌ Database connection failed: " + e.getMessage());
            System.err.println("URL: " + url + ", User: " + user);
            e.printStackTrace();
        }
    }

    private void createDatabaseIfNotExists() {
        try {
            String tempUrl = "jdbc:mysql://localhost:3306/";
            Properties props = new Properties();
            props.setProperty("user", user);
            props.setProperty("password", this.password);
            props.setProperty("useSSL", "false");

            Connection tempConn = DriverManager.getConnection(tempUrl, props);
            Statement stmt = tempConn.createStatement();
            stmt.execute("CREATE DATABASE IF NOT EXISTS secure_chat_db "
                    + "CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci");
            stmt.close();
            tempConn.close();
            System.out.println("✅ Database 'secure_chat_db' created or already exists");
        } catch (SQLException e) {
            System.err.println("❌ Failed to create database: " + e.getMessage());
        }
    }

    private void createTables() {
        String[] createTables = {
                // Users table
                """
            CREATE TABLE IF NOT EXISTS users (
                id INT PRIMARY KEY AUTO_INCREMENT,
                username VARCHAR(50) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                salt VARCHAR(255) NOT NULL,
                public_key TEXT,
                private_key_encrypted TEXT,
                iv VARCHAR(255),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_active BOOLEAN DEFAULT TRUE,
                INDEX idx_username (username)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            """,

                // Messages table - FIXED: Added message_owner field
                """
            CREATE TABLE IF NOT EXISTS messages (
                id INT PRIMARY KEY AUTO_INCREMENT,
                message_id VARCHAR(36) NOT NULL,
                message_owner VARCHAR(50) NOT NULL,
                sender_username VARCHAR(50) NOT NULL,
                receiver_username VARCHAR(50) NOT NULL,
                encrypted_content TEXT NOT NULL,
                iv VARCHAR(255) NOT NULL,
                encryption_type VARCHAR(20) DEFAULT 'simple',
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                delete_timestamp TIMESTAMP NULL,
                is_deleted BOOLEAN DEFAULT FALSE,
                is_self_destruct BOOLEAN DEFAULT FALSE,
                self_destruct_minutes INT DEFAULT 0,
                UNIQUE KEY unique_message_per_user (message_id, message_owner),
                INDEX idx_message_id (message_id),
                INDEX idx_message_owner (message_owner),
                INDEX idx_sender_receiver (sender_username, receiver_owner),
                INDEX idx_timestamp (timestamp)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            """
        };

        try (Statement stmt = connection.createStatement()) {
            for (String sql : createTables) {
                stmt.execute(sql);
            }
            System.out.println("✅ Database tables created successfully");
        } catch (SQLException e) {
            System.err.println("❌ Error creating tables: " + e.getMessage());
            e.printStackTrace();
        }
    }

    // ========== USER OPERATIONS ==========
    public boolean registerUser(String username, String userPassword) {
        try {
            // Check if user exists
            if (userExists(username)) {
                System.out.println("❌ User '" + username + "' already exists");
                return false;
            }

            // Generate salt and hash password
            String salt = SecurityUtils.generateSalt();
            String hashedPassword = SecurityUtils.hashPassword(userPassword, salt);

            // Generate RSA key pair
            String[] rsaKeys;
            try {
                rsaKeys = SecurityUtils.generateRSAKeyPair();
            } catch (Exception e) {
                System.err.println("❌ Failed to generate RSA keys: " + e.getMessage());
                return false;
            }

            String publicKey = rsaKeys[0];
            String privateKey = rsaKeys[1];

            // Encrypt private key with user's password
            String encryptedPrivateKey;
            try {
                encryptedPrivateKey = SecurityUtils.encryptWithPassword(privateKey, userPassword);
            } catch (Exception e) {
                System.err.println("❌ Failed to encrypt private key: " + e.getMessage());
                return false;
            }

            // Insert user into database
            String sql = """
                INSERT INTO users (username, password_hash, salt, public_key, 
                                  private_key_encrypted, iv)
                VALUES (?, ?, ?, ?, ?, ?)
                """;

            try (PreparedStatement pstmt = connection.prepareStatement(sql)) {
                pstmt.setString(1, username);
                pstmt.setString(2, hashedPassword);
                pstmt.setString(3, salt);
                pstmt.setString(4, publicKey);
                pstmt.setString(5, encryptedPrivateKey);
                pstmt.setString(6, SecurityUtils.generateIV());

                int rowsAffected = pstmt.executeUpdate();
                if (rowsAffected > 0) {
                    System.out.println("✅ User '" + username + "' registered successfully");
                    System.out.println("   Public Key Length: " + publicKey.length());
                    System.out.println("   Encrypted Private Key Length: " + encryptedPrivateKey.length());
                    return true;
                }
            }

        } catch (SQLException e) {
            System.err.println("❌ SQL Error registering user: " + e.getMessage());
            e.printStackTrace();
        } catch (Exception e) {
            System.err.println("❌ Error registering user: " + e.getMessage());
            e.printStackTrace();
        }

        return false;
    }

    public boolean authenticateUser(String username, String userPassword) {
        String sql = "SELECT password_hash, salt FROM users WHERE username = ? AND is_active = TRUE";

        try (PreparedStatement pstmt = connection.prepareStatement(sql)) {
            pstmt.setString(1, username);
            ResultSet rs = pstmt.executeQuery();

            if (rs.next()) {
                String storedHash = rs.getString("password_hash");
                String salt = rs.getString("salt");
                String inputHash = SecurityUtils.hashPassword(userPassword, salt);

                boolean authenticated = storedHash.equals(inputHash);
                if (authenticated) {
                    System.out.println("✅ User '" + username + "' authenticated successfully");
                } else {
                    System.out.println("❌ Authentication failed for user '" + username + "'");
                }
                return authenticated;
            }

            System.out.println("❌ User '" + username + "' not found");
            return false;

        } catch (SQLException e) {
            System.err.println("❌ SQL Error authenticating user: " + e.getMessage());
            return false;
        }
    }

    public boolean userExists(String username) {
        String sql = "SELECT COUNT(*) FROM users WHERE username = ?";

        try (PreparedStatement pstmt = connection.prepareStatement(sql)) {
            pstmt.setString(1, username);
            ResultSet rs = pstmt.executeQuery();
            return rs.next() && rs.getInt(1) > 0;
        } catch (SQLException e) {
            System.err.println("❌ Error checking user existence: " + e.getMessage());
            return false;
        }
    }

    public String getPublicKey(String username) {
        String sql = "SELECT public_key FROM users WHERE username = ?";

        try (PreparedStatement pstmt = connection.prepareStatement(sql)) {
            pstmt.setString(1, username);
            ResultSet rs = pstmt.executeQuery();

            if (rs.next()) {
                String publicKey = rs.getString("public_key");
                if (publicKey != null && !publicKey.isEmpty()) {
                    System.out.println("✅ Retrieved public key for user '" + username + "'");
                    return publicKey;
                }
            }

            System.out.println("❌ No public key found for user '" + username + "'");
            return null;

        } catch (SQLException e) {
            System.err.println("❌ Error getting public key: " + e.getMessage());
            return null;
        }
    }

    public String getPrivateKey(String username, String userPassword) {
        String sql = "SELECT private_key_encrypted FROM users WHERE username = ?";

        try (PreparedStatement pstmt = connection.prepareStatement(sql)) {
            pstmt.setString(1, username);
            ResultSet rs = pstmt.executeQuery();

            if (rs.next()) {
                String encryptedPrivateKey = rs.getString("private_key_encrypted");
                if (encryptedPrivateKey != null && !encryptedPrivateKey.isEmpty()) {
                    System.out.println("🔐 Attempting to decrypt private key for user '" + username + "'");

                    try {
                        String privateKey = SecurityUtils.decryptWithPassword(encryptedPrivateKey, userPassword);
                        System.out.println("✅ Successfully decrypted private key for user '" + username + "'");
                        return privateKey;
                    } catch (Exception e) {
                        System.err.println("❌ Failed to decrypt private key for user '" + username + "': " + e.getMessage());
                        System.err.println("   This usually means the password is incorrect or the encrypted data is corrupted");
                        return null;
                    }
                }
            }

            System.out.println("❌ No encrypted private key found for user '" + username + "'");
            return null;

        } catch (SQLException e) {
            System.err.println("❌ SQL Error getting private key: " + e.getMessage());
            return null;
        }
    }

    // ========== MESSAGE OPERATIONS ==========
    // Save message from sender's perspective (sender is the owner)
    public void saveMessageAsSender(String messageId, String sender, String receiver,
                                    String encryptedContent, String iv, String encryptionType,
                                    boolean selfDestruct) {
        saveMessage(messageId, sender, sender, receiver, encryptedContent, iv, encryptionType, selfDestruct);
    }

    // Save message from receiver's perspective (receiver is the owner)
    public void saveMessageAsReceiver(String messageId, String sender, String receiver,
                                      String encryptedContent, String iv, String encryptionType,
                                      boolean selfDestruct) {
        saveMessage(messageId, receiver, sender, receiver, encryptedContent, iv, encryptionType, selfDestruct);
    }

    // Unified saveMessage method with message_owner
    private void saveMessage(String messageId, String messageOwner, String sender, String receiver,
                             String encryptedContent, String iv, String encryptionType, boolean selfDestruct) {
        // First check if message already exists for this owner
        if (messageExistsForOwner(messageId, messageOwner)) {
            System.out.println("⚠️  Message " + messageId + " already exists for owner " + messageOwner + ", skipping save");
            return;
        }

        String sql = """
            INSERT INTO messages (message_id, message_owner, sender_username, receiver_username, 
                                 encrypted_content, iv, encryption_type, is_self_destruct)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """;

        try (PreparedStatement pstmt = connection.prepareStatement(sql)) {
            pstmt.setString(1, messageId);
            pstmt.setString(2, messageOwner);
            pstmt.setString(3, sender);
            pstmt.setString(4, receiver);
            pstmt.setString(5, encryptedContent);
            pstmt.setString(6, iv);
            pstmt.setString(7, encryptionType);
            pstmt.setBoolean(8, selfDestruct);

            pstmt.executeUpdate();
            System.out.println("💾 Saved message: " + messageId +
                    " (owner: " + messageOwner + ", from: " + sender + " to: " + receiver + ")");

        } catch (SQLException e) {
            System.err.println("❌ Error saving message: " + e.getMessage());
            e.printStackTrace();
        }
    }

    // Check if message already exists for a specific owner
    private boolean messageExistsForOwner(String messageId, String messageOwner) {
        String sql = "SELECT COUNT(*) FROM messages WHERE message_id = ? AND message_owner = ?";

        try (PreparedStatement pstmt = connection.prepareStatement(sql)) {
            pstmt.setString(1, messageId);
            pstmt.setString(2, messageOwner);
            ResultSet rs = pstmt.executeQuery();
            return rs.next() && rs.getInt(1) > 0;
        } catch (SQLException e) {
            System.err.println("❌ Error checking message existence: " + e.getMessage());
            return false;
        }
    }

    // Legacy method for backward compatibility
    public void saveMessage(String messageId, String sender, String receiver,
                            String encryptedContent, String iv, String encryptionType, boolean selfDestruct) {
        // Determine owner based on current user context (this is a fallback)
        // In practice, you should use saveMessageAsSender or saveMessageAsReceiver
        System.out.println("⚠️  Using legacy saveMessage - please update to use saveMessageAsSender/Receiver");
        saveMessageAsSender(messageId, sender, receiver, encryptedContent, iv, encryptionType, selfDestruct);
    }

    public void markMessageDeleted(String messageId) {
        String sql = "UPDATE messages SET is_deleted = TRUE WHERE message_id = ?";

        try (PreparedStatement pstmt = connection.prepareStatement(sql)) {
            pstmt.setString(1, messageId);
            int rows = pstmt.executeUpdate();

            if (rows > 0) {
                System.out.println("🗑️  Marked message as deleted: " + messageId);
            } else {
                System.out.println("⚠️  No message found with ID: " + messageId);
            }

        } catch (SQLException e) {
            System.err.println("❌ Error marking message deleted: " + e.getMessage());
        }
    }

    public void markMessageDeletedForOwner(String messageId, String messageOwner) {
        String sql = "UPDATE messages SET is_deleted = TRUE WHERE message_id = ? AND message_owner = ?";

        try (PreparedStatement pstmt = connection.prepareStatement(sql)) {
            pstmt.setString(1, messageId);
            pstmt.setString(2, messageOwner);
            int rows = pstmt.executeUpdate();

            if (rows > 0) {
                System.out.println("🗑️  Marked message as deleted for owner " + messageOwner + ": " + messageId);
            } else {
                System.out.println("⚠️  No message found with ID: " + messageId + " for owner " + messageOwner);
            }

        } catch (SQLException e) {
            System.err.println("❌ Error marking message deleted: " + e.getMessage());
        }
    }

    public void scheduleSelfDestruct(String messageId, long delayMinutes) {
        String sql = """
            UPDATE messages 
            SET delete_timestamp = DATE_ADD(NOW(), INTERVAL ? MINUTE),
                self_destruct_minutes = ?
            WHERE message_id = ?
            """;

        try (PreparedStatement pstmt = connection.prepareStatement(sql)) {
            pstmt.setLong(1, delayMinutes);
            pstmt.setLong(2, delayMinutes);
            pstmt.setString(3, messageId);
            pstmt.executeUpdate();

            System.out.println("⏰ Scheduled self-destruct for message " + messageId + " in " + delayMinutes + " minutes");

        } catch (SQLException e) {
            System.err.println("❌ Error scheduling self-destruct: " + e.getMessage());
        }
    }

    public void cleanupExpiredMessages() {
        String sql = """
            UPDATE messages 
            SET is_deleted = TRUE 
            WHERE is_self_destruct = TRUE 
            AND delete_timestamp <= NOW()
            AND is_deleted = FALSE
            """;

        try (Statement stmt = connection.createStatement()) {
            int affected = stmt.executeUpdate(sql);
            if (affected > 0) {
                System.out.println("🧹 Cleaned up " + affected + " expired messages");
            }
        } catch (SQLException e) {
            System.err.println("❌ Error cleaning up expired messages: " + e.getMessage());
        }
    }

    // ========== DATABASE MAINTENANCE ==========
    public void close() {
        try {
            if (connection != null && !connection.isClosed()) {
                connection.close();
                System.out.println("🔒 Database connection closed");
            }
        } catch (SQLException e) {
            System.err.println("❌ Error closing database connection: " + e.getMessage());
        }
    }

    public void testConnection() {
        try {
            if (connection != null && !connection.isClosed()) {
                System.out.println("✅ Database connection is active");
            } else {
                System.out.println("❌ Database connection is not active");
            }
        } catch (SQLException e) {
            System.err.println("❌ Error testing connection: " + e.getMessage());
        }
    }

    // Utility method for debugging
    public void printAllUsers() {
        String sql = "SELECT username, created_at FROM users ORDER BY created_at";

        try (Statement stmt = connection.createStatement();
             ResultSet rs = stmt.executeQuery(sql)) {

            System.out.println("\n=== Registered Users ===");
            int count = 0;
            while (rs.next()) {
                count++;
                System.out.println(count + ". " + rs.getString("username") +
                        " (registered: " + rs.getTimestamp("created_at") + ")");
            }
            System.out.println("Total: " + count + " users\n");

        } catch (SQLException e) {
            System.err.println("❌ Error listing users: " + e.getMessage());
        }
    }

    // Drop and recreate messages table (for testing)
    public void recreateMessagesTable() {
        try (Statement stmt = connection.createStatement()) {
            stmt.execute("DROP TABLE IF EXISTS messages");
            System.out.println("🗑️  Dropped old messages table");

            String createMessagesTable = """
                CREATE TABLE messages (
                    id INT PRIMARY KEY AUTO_INCREMENT,
                    message_id VARCHAR(36) NOT NULL,
                    message_owner VARCHAR(50) NOT NULL,
                    sender_username VARCHAR(50) NOT NULL,
                    receiver_username VARCHAR(50) NOT NULL,
                    encrypted_content TEXT NOT NULL,
                    iv VARCHAR(255) NOT NULL,
                    encryption_type VARCHAR(20) DEFAULT 'simple',
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    delete_timestamp TIMESTAMP NULL,
                    is_deleted BOOLEAN DEFAULT FALSE,
                    is_self_destruct BOOLEAN DEFAULT FALSE,
                    self_destruct_minutes INT DEFAULT 0,
                    UNIQUE KEY unique_message_per_user (message_id, message_owner),
                    INDEX idx_message_id (message_id),
                    INDEX idx_message_owner (message_owner),
                    INDEX idx_sender_receiver (sender_username, receiver_username),
                    INDEX idx_timestamp (timestamp)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
                """;

            stmt.execute(createMessagesTable);
            System.out.println("✅ Recreated messages table with message_owner field");
        } catch (SQLException e) {
            System.err.println("❌ Error recreating messages table: " + e.getMessage());
            e.printStackTrace();
        }
    }
}