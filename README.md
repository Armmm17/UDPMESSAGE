# 🔐 Secure UDP Chat

**Secure UDP Chat** è un'applicazione desktop di messaggistica peer-to-peer sviluppata in **Java 23** con interfaccia grafica **JavaFX**. Trasmette i messaggi tramite il protocollo **UDP**, li cifra con crittografia ibrida **RSA-2048 + AES-256** e ne gestisce la persistenza su un database **MySQL**.

---

## ✨ Funzionalità

- **Registrazione e login** — autenticazione con password hashata tramite PBKDF2WithHmacSHA256 (65.536 iterazioni, salt casuale a 32 byte)
- **Crittografia end-to-end** — cifratura ibrida: la chiave AES viene cifrata con RSA-2048 (OAEP/SHA-256) e il messaggio con AES-256-CBC; in assenza della chiave pubblica del destinatario si usa un fallback AES con segreto condiviso
- **Chiave privata protetta** — la chiave RSA privata viene cifrata con la password dell'utente prima di essere salvata nel database
- **Messaggi autodistruttivi** — i messaggi possono avere un TTL (da 1 a 60 minuti), dopo il quale vengono eliminati automaticamente sia in locale che sul peer remoto
- **Eliminazione remota** — un messaggio può essere cancellato per entrambi i partecipanti inviando un pacchetto di tipo `DELETE` via UDP
- **Persistenza** — messaggi e utenti vengono salvati su MySQL; la cronologia è separata per owner (mittente e destinatario hanno la propria copia)
- **Interfaccia grafica** — GUI dark-mode costruita interamente in JavaFX (senza FXML)

---

## 🏗️ Architettura

```
MainApp (login/registrazione)
    └── ChatWindow (finestra di chat)
            ├── EnhancedUDPClient (thread UDP send/receive)
            │       ├── SecurityUtils (AES, RSA, cifratura ibrida)
            │       └── DatabaseManager (MySQL, singleton)
            └── DatabaseManager
```

### Classi principali

| Classe | Responsabilità |
|---|---|
| `MainApp` | Entry point JavaFX; schermata di login e dialog di registrazione |
| `ChatWindow` | Interfaccia di chat: configurazione rete, area messaggi, self-destruct, eliminazione |
| `EnhancedUDPClient` | Thread UDP: invio/ricezione di datagrammi JSON cifrati, timer self-destruct |
| `DatabaseManager` | Singleton; gestione connessione MySQL, tabelle `users` e `messages` |
| `SecurityUtils` | PBKDF2, AES-256-CBC, RSA-2048-OAEP, crittografia ibrida, test di auto-verifica |

---

## 🛠️ Tecnologie

| Tecnologia | Versione | Scopo |
|---|---|---|
| Java | 23 | Linguaggio principale |
| JavaFX | 21.0.6 | Interfaccia grafica |
| MySQL Connector/J | 8.0.33 | Connessione al database |
| org.json | 20230227 | Serializzazione messaggi UDP in JSON |
| JUnit Jupiter | 5.12.1 | Testing |
| Maven | — | Build e gestione dipendenze |

> **Nota:** la dipendenza BouncyCastle è dichiarata nel `pom.xml` ma la crittografia è implementata con la JCE standard (`javax.crypto`).

---

## 📋 Prerequisiti

- **Java 23** o superiore
- **Maven** 3.8+
- **MySQL** 8.x in esecuzione su `localhost:3306`

---

## 🗄️ Schema del database

Il database `secure_chat_db` viene creato automaticamente all'avvio. Le tabelle principali sono:

**`users`**
- `username`, `password_hash`, `salt` — credenziali con hashing PBKDF2
- `public_key` — chiave RSA pubblica in chiaro (usata dai peer per cifrare)
- `private_key_encrypted` — chiave RSA privata cifrata con la password dell'utente

**`messages`**
- `message_id`, `message_owner` — ogni messaggio ha una copia per mittente e destinatario
- `encrypted_content`, `iv`, `encryption_type` — payload cifrato e metadati crittografici
- `is_self_destruct`, `delete_timestamp` — gestione autodistruzione

---

## 🚀 Installazione ed esecuzione

### 1. Clona la repository

```bash
git clone https://github.com/Armmm17/UDPMESSAGE.git
cd UDPMESSAGE
```

### 2. Configura la password MySQL

Apri `src/main/java/com/armandoboaca17/encryptedmess/DatabaseManager.java` e imposta la tua password MySQL:

```java
private String password = ""; // inserisci qui la tua password MySQL
```

### 3. Compila il progetto

```bash
mvn clean install
```

### 4. Avvia l'applicazione

```bash
mvn javafx:run
```

> Per simulare una chat tra due utenti sulla stessa macchina, avvia due istanze: la prima usa le porte locali/remote `12345`/`12346`, la seconda `12346`/`12345`.

---

## 📂 Struttura del progetto

```
UDPMESSAGE/
├── src/
│   └── main/
│       ├── java/
│       │   ├── module-info.java
│       │   └── com/armandoboaca17/encryptedmess/
│       │       ├── MainApp.java              # Entry point, login e registrazione
│       │       ├── ChatWindow.java           # Interfaccia di chat JavaFX
│       │       ├── EnhancedUDPClient.java    # Client UDP (invio/ricezione)
│       │       ├── DatabaseManager.java      # Gestione MySQL (singleton)
│       │       └── SecurityUtils.java        # Algoritmi crittografici
│       └── resources/
│           └── com/armando/udpmessage/
│               └── hello-view.fxml           # FXML legacy (non utilizzato)
├── .mvn/wrapper/
├── pom.xml
├── mvnw
└── mvnw.cmd
```

---

## 🔐 Dettagli crittografici

| Operazione | Algoritmo |
|---|---|
| Hashing password | PBKDF2WithHmacSHA256, 65.536 iter., sale 32 byte |
| Cifratura messaggi (default) | Ibrida: RSA-2048-OAEP/SHA-256 + AES-256-CBC |
| Cifratura messaggi (fallback) | AES-256-CBC con segreto condiviso |
| Protezione chiave privata | AES-256-CBC derivato dalla password utente |
| IV | 16 byte casuali per ogni messaggio |

---

## 🧪 Testing

```bash
mvn test
```

`SecurityUtils` include anche un metodo `testEncryption()` che verifica AES, RSA, cifratura ibrida e semplice all'avvio dell'applicazione (output su console).

---

## 👤 Autore

**Armando Boaca** — [@Armmm17](https://github.com/Armmm17)
