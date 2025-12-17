package com.armandoboaca17.encryptedmess;

import javafx.application.Application;
import javafx.geometry.Insets;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.layout.*;
import javafx.stage.Stage;
import javafx.application.Platform;
import java.util.Optional;

public class ChatWindow extends Application {
    private EnhancedUDPClient udpClient;
    private String currentUser;
    private String currentUserPassword;

    // UI Components
    private TextArea chatArea;
    private TextField messageField;
    private TextField receiverField;
    private TextField portField;
    private TextField remotePortField;
    private TextField remoteHostField;
    private TextField deleteMessageIdField;

    private Button connectButton;
    private Button sendButton;
    private Button deleteButton;

    private CheckBox selfDestructCheck;
    private Spinner<Integer> ttlSpinner;
    private Label statusLabel;

    public ChatWindow(String username, String password) {
        this.currentUser = username;
        this.currentUserPassword = password;
    }

    @Override
    public void start(Stage primaryStage) {
        primaryStage.setTitle("Secure UDP Chat - " + currentUser);

        // Create main layout with BorderPane
        BorderPane mainLayout = new BorderPane();
        mainLayout.setPadding(new Insets(10));

        // ========== TOP: Connection Panel ==========
        VBox topPanel = createConnectionPanel();
        mainLayout.setTop(topPanel);

        // ========== CENTER: Chat Area ==========
        VBox centerPanel = createChatPanel();
        mainLayout.setCenter(centerPanel);

        // ========== BOTTOM: Message Input Panel ==========
        VBox bottomPanel = createInputPanel();
        mainLayout.setBottom(bottomPanel);

        // ========== RIGHT: Message Management Panel ==========
        VBox rightPanel = createManagementPanel();
        mainLayout.setRight(rightPanel);

        // Create scene
        Scene scene = new Scene(mainLayout, 1200, 800);
        primaryStage.setScene(scene);

        // Set window close handler
        primaryStage.setOnCloseRequest(event -> {
            if (udpClient != null && udpClient.isRunning()) {
                udpClient.stopClient();
            }
            System.exit(0);
        });

        // Show window
        primaryStage.show();

        // Auto-connect with default settings
        Platform.runLater(() -> {
            appendToChat("Welcome, " + currentUser + "!");
            appendToChat("Configure your connection settings and click 'Connect' to start chatting.");
            appendToChat("Default ports: 12345 for first instance, 12346 for second instance.");
        });
    }

    private VBox createConnectionPanel() {
        VBox panel = new VBox(10);
        panel.setPadding(new Insets(10));
        panel.setStyle("-fx-border-color: #2c3e50; -fx-border-width: 0 0 2 0; -fx-background-color: #ecf0f1;");

        // Title
        Label titleLabel = new Label("Network Configuration");
        titleLabel.setStyle("-fx-font-size: 16px; -fx-font-weight: bold; -fx-text-fill: #2c3e50;");

        // Connection settings grid
        GridPane grid = new GridPane();
        grid.setHgap(10);
        grid.setVgap(10);
        grid.setPadding(new Insets(10, 0, 10, 0));

        // Local port
        Label localPortLabel = new Label("Local Port:");
        portField = new TextField("12345");
        portField.setPrefWidth(100);
        portField.setStyle("-fx-background-color: white; -fx-border-color: #bdc3c7;");

        // Remote host
        Label remoteHostLabel = new Label("Remote Host:");
        remoteHostField = new TextField("localhost");
        remoteHostField.setPrefWidth(150);
        remoteHostField.setStyle("-fx-background-color: white; -fx-border-color: #bdc3c7;");

        // Remote port
        Label remotePortLabel = new Label("Remote Port:");
        remotePortField = new TextField("12346");
        remotePortField.setPrefWidth(100);
        remotePortField.setStyle("-fx-background-color: white; -fx-border-color: #bdc3c7;");

        // Connect button
        connectButton = new Button("Connect");
        connectButton.setStyle("-fx-background-color: #27ae60; -fx-text-fill: white; -fx-font-weight: bold;");
        connectButton.setPrefWidth(100);

        // Status label
        statusLabel = new Label("Status: Disconnected");
        statusLabel.setStyle("-fx-text-fill: #e74c3c; -fx-font-weight: bold;");

        // Add to grid
        grid.add(localPortLabel, 0, 0);
        grid.add(portField, 1, 0);
        grid.add(remoteHostLabel, 2, 0);
        grid.add(remoteHostField, 3, 0);
        grid.add(remotePortLabel, 4, 0);
        grid.add(remotePortField, 5, 0);
        grid.add(connectButton, 6, 0);
        grid.add(statusLabel, 7, 0);

        // Receiver field
        HBox receiverBox = new HBox(10);
        receiverBox.setPadding(new Insets(10, 0, 0, 0));

        Label receiverLabel = new Label("Chat with:");
        receiverLabel.setStyle("-fx-font-weight: bold;");

        receiverField = new TextField();
        receiverField.setPromptText("Enter username of person to chat with");
        receiverField.setPrefWidth(300);
        receiverField.setStyle("-fx-background-color: white; -fx-border-color: #bdc3c7;");

        receiverBox.getChildren().addAll(receiverLabel, receiverField);

        panel.getChildren().addAll(titleLabel, grid, receiverBox);

        // Event handler
        connectButton.setOnAction(e -> toggleConnection());

        return panel;
    }

    private VBox createChatPanel() {
        VBox panel = new VBox();

        chatArea = new TextArea();
        chatArea.setEditable(false);
        chatArea.setWrapText(true);
        chatArea.setPrefHeight(500);
        chatArea.setStyle("""
            -fx-font-family: 'Consolas', 'Monaco', monospace;
            -fx-font-size: 14px;
            -fx-background-color: #2c3e50;
            -fx-text-fill: #ecf0f1;
            -fx-border-color: #34495e;
            -fx-border-width: 2;
            -fx-control-inner-background: #2c3e50;
        """);

        // Make chat area expand
        VBox.setVgrow(chatArea, Priority.ALWAYS);
        panel.getChildren().add(chatArea);

        return panel;
    }

    private VBox createInputPanel() {
        VBox panel = new VBox(10);
        panel.setPadding(new Insets(10));
        panel.setStyle("-fx-border-color: #2c3e50; -fx-border-width: 2 0 0 0; -fx-background-color: #ecf0f1;");

        // Message input area
        HBox messageBox = new HBox(10);

        messageField = new TextField();
        messageField.setPromptText("Type your encrypted message here...");
        messageField.setPrefWidth(600);
        messageField.setStyle("-fx-background-color: white; -fx-border-color: #3498db; -fx-border-width: 2;");

        sendButton = new Button("Send Encrypted");
        sendButton.setStyle("-fx-background-color: #2980b9; -fx-text-fill: white; -fx-font-weight: bold; -fx-font-size: 14px;");
        sendButton.setPrefWidth(150);

        HBox.setHgrow(messageField, Priority.ALWAYS);
        messageBox.getChildren().addAll(messageField, sendButton);

        // Self-destruct options
        HBox optionsBox = new HBox(15);
        optionsBox.setPadding(new Insets(5, 0, 0, 0));

        selfDestructCheck = new CheckBox("Enable Self-Destruct");
        selfDestructCheck.setStyle("-fx-font-weight: bold;");

        Label ttlLabel = new Label("After:");
        ttlLabel.setStyle("-fx-font-weight: bold;");

        ttlSpinner = new Spinner<>(1, 60, 5);
        ttlSpinner.setEditable(true);
        ttlSpinner.setPrefWidth(80);
        ttlSpinner.setStyle("-fx-background-color: white;");

        Label minuteLabel = new Label("minutes");
        minuteLabel.setStyle("-fx-font-weight: bold;");

        optionsBox.getChildren().addAll(selfDestructCheck, ttlLabel, ttlSpinner, minuteLabel);

        panel.getChildren().addAll(messageBox, optionsBox);

        // Event handlers
        sendButton.setOnAction(e -> sendSecureMessage());
        messageField.setOnAction(e -> sendSecureMessage());

        return panel;
    }

    private VBox createManagementPanel() {
        VBox panel = new VBox(20);
        panel.setPadding(new Insets(10));
        panel.setPrefWidth(300);
        panel.setStyle("-fx-border-color: #2c3e50; -fx-border-width: 0 0 0 2; -fx-background-color: #ecf0f1;");

        // ========== DELETE MESSAGE SECTION ==========
        VBox deleteBox = new VBox(10);
        deleteBox.setPadding(new Insets(15));
        deleteBox.setStyle("""
            -fx-border-color: #e74c3c;
            -fx-border-width: 2;
            -fx-border-radius: 5;
            -fx-background-color: #fadbd8;
            -fx-background-radius: 5;
        """);

        Label deleteTitle = new Label("🗑️ Delete Messages");
        deleteTitle.setStyle("-fx-font-weight: bold; -fx-font-size: 16px; -fx-text-fill: #c0392b;");

        deleteMessageIdField = new TextField();
        deleteMessageIdField.setPromptText("Enter Message ID to delete");
        deleteMessageIdField.setStyle("-fx-background-color: white;");

        deleteButton = new Button("Delete Message");
        deleteButton.setStyle("-fx-background-color: #e74c3c; -fx-text-fill: white; -fx-font-weight: bold;");
        deleteButton.setPrefWidth(200);

        Button viewMessagesBtn = new Button("View Message History");
        viewMessagesBtn.setStyle("-fx-background-color: #3498db; -fx-text-fill: white;");
        viewMessagesBtn.setPrefWidth(200);

        deleteBox.getChildren().addAll(deleteTitle, deleteMessageIdField, deleteButton, viewMessagesBtn);

        // ========== SECURITY INFO SECTION ==========
        VBox securityBox = new VBox(10);
        securityBox.setPadding(new Insets(15));
        securityBox.setStyle("""
            -fx-border-color: #27ae60;
            -fx-border-width: 2;
            -fx-border-radius: 5;
            -fx-background-color: #d5f4e6;
            -fx-background-radius: 5;
        """);

        Label securityTitle = new Label("🔒 Security Information");
        securityTitle.setStyle("-fx-font-weight: bold; -fx-font-size: 16px; -fx-text-fill: #27ae60;");

        VBox securityInfo = new VBox(5);
        securityInfo.getChildren().addAll(
                createInfoLabel("✓ All messages are encrypted"),
                createInfoLabel("✓ RSA + AES hybrid encryption"),
                createInfoLabel("✓ End-to-end encryption"),
                createInfoLabel("✓ Password-protected keys"),
                createInfoLabel("✓ Self-destruct messages")
        );

        // ========== STATISTICS SECTION ==========
        VBox statsBox = new VBox(10);
        statsBox.setPadding(new Insets(15));
        statsBox.setStyle("""
            -fx-border-color: #f39c12;
            -fx-border-width: 2;
            -fx-border-radius: 5;
            -fx-background-color: #fef5e7;
            -fx-background-radius: 5;
        """);

        Label statsTitle = new Label("📊 User Information");
        statsTitle.setStyle("-fx-font-weight: bold; -fx-font-size: 16px; -fx-text-fill: #f39c12;");

        Label userLabel = new Label("Logged in as: " + currentUser);
        userLabel.setStyle("-fx-font-weight: bold;");

        Button testEncryptionBtn = new Button("Test Encryption");
        testEncryptionBtn.setStyle("-fx-background-color: #8e44ad; -fx-text-fill: white;");
        testEncryptionBtn.setPrefWidth(200);

        statsBox.getChildren().addAll(statsTitle, userLabel, testEncryptionBtn);

        // Add all sections to panel
        panel.getChildren().addAll(deleteBox, securityBox, statsBox);

        // Event handlers
        deleteButton.setOnAction(e -> deleteMessage());
        viewMessagesBtn.setOnAction(e -> showMessageHistory());
        testEncryptionBtn.setOnAction(e -> testEncryption());

        return panel;
    }

    private Label createInfoLabel(String text) {
        Label label = new Label(text);
        label.setStyle("-fx-text-fill: #2c3e50;");
        return label;
    }

    private void toggleConnection() {
        if (udpClient == null || !udpClient.isRunning()) {
            startUDPClient();
        } else {
            stopUDPClient();
        }
    }

    private void startUDPClient() {
        try {
            int localPort = Integer.parseInt(portField.getText());
            String remoteHost = remoteHostField.getText();
            int remotePort = Integer.parseInt(remotePortField.getText());

            if (localPort < 1024 || localPort > 65535) {
                showAlert("Invalid Port", "Local port must be between 1024 and 65535");
                return;
            }

            if (remotePort < 1024 || remotePort > 65535) {
                showAlert("Invalid Port", "Remote port must be between 1024 and 65535");
                return;
            }

            System.out.println("\n=== Starting UDP Client ===");
            System.out.println("Local Port: " + localPort);
            System.out.println("Remote Host: " + remoteHost);
            System.out.println("Remote Port: " + remotePort);
            System.out.println("User: " + currentUser);

            // Create UDP client with password
            udpClient = new EnhancedUDPClient(localPort, remoteHost, remotePort,
                    this::appendToChat, currentUser, currentUserPassword);

            udpClient.start();

            // Update UI
            connectButton.setText("Disconnect");
            connectButton.setStyle("-fx-background-color: #e74c3c; -fx-text-fill: white; -fx-font-weight: bold;");
            statusLabel.setText("Status: Connected (Port " + localPort + ")");
            statusLabel.setStyle("-fx-text-fill: #27ae60; -fx-font-weight: bold;");

            appendToChat("=== System ===");
            appendToChat("✅ Secure UDP client started on port " + localPort);
            appendToChat("📡 Listening for encrypted messages...");
            appendToChat("🔒 All messages are end-to-end encrypted");

        } catch (NumberFormatException e) {
            showAlert("Invalid Input", "Port numbers must be integers");
        } catch (Exception e) {
            showAlert("Connection Error", "Failed to start UDP client:\n" + e.getMessage());
            e.printStackTrace();
        }
    }

    private void stopUDPClient() {
        if (udpClient != null) {
            udpClient.stopClient();

            connectButton.setText("Connect");
            connectButton.setStyle("-fx-background-color: #27ae60; -fx-text-fill: white; -fx-font-weight: bold;");
            statusLabel.setText("Status: Disconnected");
            statusLabel.setStyle("-fx-text-fill: #e74c3c; -fx-font-weight: bold;");

            appendToChat("=== System ===");
            appendToChat("🛑 UDP client stopped");

            udpClient = null;
        }
    }

    private void sendSecureMessage() {
        String receiver = receiverField.getText().trim();
        String message = messageField.getText().trim();

        if (receiver.isEmpty()) {
            showAlert("Error", "Please specify a receiver username");
            return;
        }

        if (message.isEmpty()) {
            showAlert("Error", "Message cannot be empty");
            return;
        }

        if (udpClient == null || !udpClient.isRunning()) {
            showAlert("Error", "Client not connected. Please click 'Connect' first.");
            return;
        }

        // Check if receiver exists in database
        DatabaseManager dbManager = DatabaseManager.getInstance();
        if (!dbManager.userExists(receiver)) {
            showAlert("User Not Found", "User '" + receiver + "' does not exist. They need to register first.");
            return;
        }

        boolean selfDestruct = selfDestructCheck.isSelected();
        int ttlMinutes = ttlSpinner.getValue();

        // Send the message
        udpClient.sendMessage(receiver, message, selfDestruct, ttlMinutes);

        // Clear message field
        messageField.clear();
        messageField.requestFocus();
    }

    private void deleteMessage() {
        String messageId = deleteMessageIdField.getText().trim();

        if (messageId.isEmpty()) {
            showAlert("Error", "Please enter a Message ID");
            return;
        }

        if (udpClient == null || !udpClient.isRunning()) {
            showAlert("Error", "Client not connected");
            return;
        }

        // Confirmation dialog
        Alert confirmAlert = new Alert(Alert.AlertType.CONFIRMATION);
        confirmAlert.setTitle("Confirm Delete");
        confirmAlert.setHeaderText("Delete Message");
        confirmAlert.setContentText("Are you sure you want to delete message:\n" + messageId + "\n\nThis action cannot be undone.");

        Optional<ButtonType> result = confirmAlert.showAndWait();
        if (result.isPresent() && result.get() == ButtonType.OK) {
            udpClient.deleteMessage(messageId);
            deleteMessageIdField.clear();
            appendToChat("System: Delete request sent for message " + messageId);
        }
    }

    private void showMessageHistory() {
        Alert infoAlert = new Alert(Alert.AlertType.INFORMATION);
        infoAlert.setTitle("Message History");
        infoAlert.setHeaderText("Message History");
        infoAlert.setContentText("Message history feature is currently stored in the database.\n\n"
                + "To view complete message history, check the MySQL database:\n"
                + "Database: secure_chat_db\n"
                + "Table: messages\n\n"
                + "Future versions will include an in-app message history viewer.");
        infoAlert.showAndWait();
    }

    private void testEncryption() {
        SecurityUtils.testEncryption();
        appendToChat("System: Encryption test completed. Check console for results.");
    }

    private void appendToChat(String text) {
        Platform.runLater(() -> {
            chatArea.appendText(text + "\n");
            // Auto-scroll to bottom
            chatArea.setScrollTop(Double.MAX_VALUE);
        });
    }

    private void showAlert(String title, String content) {
        Platform.runLater(() -> {
            Alert alert = new Alert(Alert.AlertType.ERROR);
            alert.setTitle(title);
            alert.setHeaderText(null);
            alert.setContentText(content);
            alert.showAndWait();
        });
    }
}