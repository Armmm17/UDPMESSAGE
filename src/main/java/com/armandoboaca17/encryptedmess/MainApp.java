package com.armandoboaca17.encryptedmess;

import javafx.application.Application;
import javafx.geometry.Insets;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.layout.*;
import javafx.stage.Stage;
import javafx.stage.Modality;

public class MainApp extends Application {
    private DatabaseManager dbManager;
    private Stage primaryStage;

    @Override
    public void start(Stage primaryStage) {
        this.primaryStage = primaryStage;
        this.dbManager = DatabaseManager.getInstance();

        // Test database connection
        dbManager.testConnection();
        dbManager.printAllUsers();

        showLoginScreen();
    }

    private void showLoginScreen() {
        primaryStage.setTitle("Secure UDP Chat - Login");

        // Create main layout
        BorderPane mainLayout = new BorderPane();
        mainLayout.setPadding(new Insets(20));
        mainLayout.setStyle("-fx-background-color: #2c3e50;");

        // Title
        Label titleLabel = new Label("🔐 Secure UDP Chat");
        titleLabel.setStyle("-fx-font-size: 28px; -fx-font-weight: bold; -fx-text-fill: #ecf0f1;");
        BorderPane.setAlignment(titleLabel, javafx.geometry.Pos.CENTER);
        mainLayout.setTop(titleLabel);

        // Login form
        GridPane loginGrid = new GridPane();
        loginGrid.setHgap(15);
        loginGrid.setVgap(15);
        loginGrid.setPadding(new Insets(30));
        loginGrid.setStyle("""
            -fx-background-color: #34495e;
            -fx-border-color: #3498db;
            -fx-border-width: 2;
            -fx-border-radius: 10;
            -fx-background-radius: 10;
        """);

        // Username
        Label userLabel = new Label("Username:");
        userLabel.setStyle("-fx-text-fill: #ecf0f1; -fx-font-size: 14px; -fx-font-weight: bold;");
        TextField userField = new TextField();
        userField.setPromptText("Enter your username");
        userField.setPrefWidth(250);
        userField.setStyle("-fx-background-color: white; -fx-border-color: #bdc3c7;");

        // Password
        Label passLabel = new Label("Password:");
        passLabel.setStyle("-fx-text-fill: #ecf0f1; -fx-font-size: 14px; -fx-font-weight: bold;");
        PasswordField passField = new PasswordField();
        passField.setPromptText("Enter your password");
        passField.setPrefWidth(250);
        passField.setStyle("-fx-background-color: white; -fx-border-color: #bdc3c7;");

        // Buttons
        Button loginButton = new Button("Login");
        loginButton.setStyle("-fx-background-color: #27ae60; -fx-text-fill: white; -fx-font-weight: bold; -fx-font-size: 14px;");
        loginButton.setPrefWidth(100);

        Button registerButton = new Button("Register");
        registerButton.setStyle("-fx-background-color: #3498db; -fx-text-fill: white; -fx-font-weight: bold; -fx-font-size: 14px;");
        registerButton.setPrefWidth(100);

        Button exitButton = new Button("Exit");
        exitButton.setStyle("-fx-background-color: #e74c3c; -fx-text-fill: white; -fx-font-weight: bold; -fx-font-size: 14px;");
        exitButton.setPrefWidth(100);

        HBox buttonBox = new HBox(15);
        buttonBox.getChildren().addAll(loginButton, registerButton, exitButton);

        // Status label
        Label statusLabel = new Label();
        statusLabel.setStyle("-fx-text-fill: #e74c3c; -fx-font-weight: bold;");

        // Add to grid
        loginGrid.add(userLabel, 0, 0);
        loginGrid.add(userField, 1, 0);
        loginGrid.add(passLabel, 0, 1);
        loginGrid.add(passField, 1, 1);
        loginGrid.add(buttonBox, 1, 2);
        loginGrid.add(statusLabel, 1, 3);

        // Center the grid
        BorderPane.setAlignment(loginGrid, javafx.geometry.Pos.CENTER);
        mainLayout.setCenter(loginGrid);

        // Footer
        Label footerLabel = new Label("Secure End-to-End Encrypted Messaging over UDP Protocol");
        footerLabel.setStyle("-fx-text-fill: #bdc3c7; -fx-font-size: 12px;");
        BorderPane.setAlignment(footerLabel, javafx.geometry.Pos.CENTER);
        mainLayout.setBottom(footerLabel);

        // Event handlers
        loginButton.setOnAction(e -> {
            String username = userField.getText().trim();
            String password = passField.getText();

            if (username.isEmpty() || password.isEmpty()) {
                statusLabel.setText("Please fill in all fields!");
                return;
            }

            if (dbManager.authenticateUser(username, password)) {
                statusLabel.setText("Login successful! Opening chat...");

                // Open chat window with username AND password
                openChatWindow(username, password);
                primaryStage.close();
            } else {
                statusLabel.setText("Invalid username or password!");
            }
        });

        registerButton.setOnAction(e -> {
            showRegistrationDialog();
        });

        exitButton.setOnAction(e -> {
            dbManager.close();
            System.exit(0);
        });

        // Set up scene
        Scene scene = new Scene(mainLayout, 600, 400);
        primaryStage.setScene(scene);
        primaryStage.show();
    }

    private void showRegistrationDialog() {
        Stage dialog = new Stage();
        dialog.setTitle("Register New User");
        dialog.initModality(Modality.WINDOW_MODAL);
        dialog.initOwner(primaryStage);

        GridPane grid = new GridPane();
        grid.setHgap(15);
        grid.setVgap(15);
        grid.setPadding(new Insets(25));
        grid.setStyle("-fx-background-color: #ecf0f1;");

        // Title
        Label titleLabel = new Label("Create New Account");
        titleLabel.setStyle("-fx-font-size: 18px; -fx-font-weight: bold; -fx-text-fill: #2c3e50;");
        grid.add(titleLabel, 0, 0, 2, 1);

        // Username
        Label userLabel = new Label("Username:");
        userLabel.setStyle("-fx-font-weight: bold;");
        TextField userField = new TextField();
        userField.setPromptText("Choose a username");
        userField.setPrefWidth(250);

        // Password
        Label passLabel = new Label("Password:");
        passLabel.setStyle("-fx-font-weight: bold;");
        PasswordField passField = new PasswordField();
        passField.setPromptText("Choose a password (min 6 chars)");

        // Confirm Password
        Label confirmLabel = new Label("Confirm:");
        confirmLabel.setStyle("-fx-font-weight: bold;");
        PasswordField confirmField = new PasswordField();
        confirmField.setPromptText("Confirm your password");

        // Buttons
        Button registerButton = new Button("Register");
        registerButton.setStyle("-fx-background-color: #27ae60; -fx-text-fill: white; -fx-font-weight: bold;");

        Button cancelButton = new Button("Cancel");
        cancelButton.setStyle("-fx-background-color: #95a5a6; -fx-text-fill: white;");

        HBox buttonBox = new HBox(15);
        buttonBox.getChildren().addAll(registerButton, cancelButton);

        // Status label
        Label statusLabel = new Label();
        statusLabel.setStyle("-fx-text-fill: #e74c3c; -fx-font-weight: bold;");

        // Add to grid
        grid.add(userLabel, 0, 1);
        grid.add(userField, 1, 1);
        grid.add(passLabel, 0, 2);
        grid.add(passField, 1, 2);
        grid.add(confirmLabel, 0, 3);
        grid.add(confirmField, 1, 3);
        grid.add(buttonBox, 1, 4);
        grid.add(statusLabel, 1, 5);

        // Event handlers
        registerButton.setOnAction(e -> {
            String username = userField.getText().trim();
            String password = passField.getText();
            String confirm = confirmField.getText();

            if (username.isEmpty() || password.isEmpty()) {
                statusLabel.setText("All fields are required!");
                return;
            }

            if (username.length() < 3) {
                statusLabel.setText("Username must be at least 3 characters!");
                return;
            }

            if (!password.equals(confirm)) {
                statusLabel.setText("Passwords don't match!");
                return;
            }

            if (password.length() < 6) {
                statusLabel.setText("Password must be at least 6 characters!");
                return;
            }

            if (dbManager.registerUser(username, password)) {
                statusLabel.setText("Registration successful! You can now login.");

                // Auto-fill login fields
                // Note: We can't directly access the main window fields from here
                // In a real app, you might want to pass this info back

                // Close dialog after a short delay
                new java.util.Timer().schedule(
                        new java.util.TimerTask() {
                            @Override
                            public void run() {
                                javafx.application.Platform.runLater(() -> dialog.close());
                            }
                        },
                        2000
                );
            } else {
                statusLabel.setText("Username already exists!");
            }
        });

        cancelButton.setOnAction(e -> dialog.close());

        Scene scene = new Scene(grid, 400, 300);
        dialog.setScene(scene);
        dialog.showAndWait();
    }

    private void openChatWindow(String username, String password) {
        try {
            Stage chatStage = new Stage();
            ChatWindow chatWindow = new ChatWindow(username, password);
            chatWindow.start(chatStage);
        } catch (Exception e) {
            System.err.println("Error opening chat window: " + e.getMessage());
            e.printStackTrace();
        }
    }

    public static void main(String[] args) {
        System.out.println("=== Secure UDP Chat Application ===");
        System.out.println("Starting application...");

        // Test encryption
        System.out.println("\nTesting encryption system...");
        SecurityUtils.testEncryption();

        launch(args);
    }
}