module com.armando.udpmessage {
    requires javafx.controls;
    requires javafx.fxml;
    requires java.sql;
    requires org.json;


    opens com.armando.udpmessage to javafx.fxml;
    exports com.armandoboaca17.encryptedmess;
}