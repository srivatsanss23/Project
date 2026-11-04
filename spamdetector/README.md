# 🛡️ SpamGuard AI — Academic Capstone Threat & Spam Detection Platform

> **Final-Year Engineering Capstone Project**  
> An intelligent multi-model spam, phishing, and cybersecurity threat analysis engine featuring **Explainable AI (XAI)**, **Tri-Model Stacking**, **Adversarial Evasion Defense**, **MITRE ATT&CK Matrix Mapping**, **SOC IOC Defanging**, and **Quishing Forensics**.

---

## 👥 Contributors & Project Credits

- **Samjo** ([@sam-black007](https://github.com/sam-black007)) — Tri-Model Stacking Classifier, Information-Theoretic Stylometry (Shannon Entropy), Adversarial Attack & Defense Lab, MITRE ATT&CK Mapping, Safe IOC Defanging, STIX 2.1 Threat Export, Quishing SSRF Forensics, Interactive SVG ROC Curve, and VS Code developer tooling.
- **Srivatsan** ([@srivatsanss23](https://github.com/srivatsanss23)) — Original creator, core spam heuristic rules, baseline Naive Bayes model, and project architecture.

---

## 🌟 Key Technical Features

### 1. 🧠 Tri-Model Stacking Ensemble
Combines three distinct machine learning paradigms via soft voting and calibrated odds:
- **Multinomial Naive Bayes** with Laplace smoothing ($\alpha = 1$).
- **TF-IDF Vector Space Model** with cosine similarity centroids.
- **Supervised Logistic Regression** trained via Stochastic Gradient Descent (SGD) with $L_2$ regularization.

### 2. 🧮 Information-Theoretic Stylometry & Shannon Entropy
- Calculates bit-entropy per character:
  $$H(X) = -\sum_{i} P(x_i) \log_2 P(x_i)$$
- Computes **Type-Token Ratio (TTR)** for lexical diversity, character density metrics, and Flesch Reading Ease approximations.

### 3. 🛡️ Deep Adversarial Attack & Defense Lab
- Detects and mitigates:
  - **Cyrillic & Greek Homoglyphs** (Unicode NFKD normalization + mapping).
  - **Zero-Width Invisible Characters** (`\u200B`, `\uFEFF`, soft hyphens).
  - **Leet-Speak Camouflage** (`p@ssw0rd`, `fr33`, `b!tc0!n`).
  - **Good-Word / Shakespeare Ham Poisoning**.

### 4. 🔬 Cybersecurity SOC Forensics & Telemetry
- **MITRE ATT&CK Enterprise Matrix:** Automatically tags techniques (`T1566.002 Spearphishing Link`, `T1056.003 Credential Harvesting`, `T1036.007 Brand Typosquatting`, `T1027.013 Obfuscation`).
- **Safe IOC Extraction:** Extracts and **defangs** URLs (`hxxp://...`), target domains (`[.]`), emails (`[at]`), and computes an immutable **SHA-256 artifact hash**.
- **STIX 2.1 Threat Bundle Export:** Instant export of OASIS STIX 2.1 JSON for SIEM/SOAR platforms (Splunk, Sentinel, QRadar).
- **Automated SOC Playbook:** Real-time defensive standard operating procedures (SOPs).

### 5. 📷 Quishing (QR Phishing) Forensics
- Drag-and-drop QR image scanner with detection for **SSRF Intranet IP exploitation** (`RFC 1918` subnets, AWS metadata `169.254.169.254`) and multi-hop URL shorteners.

### 6. 📈 Academic Model Benchmark & ROC-AUC
- **5-Fold Stratified Cross-Validation** over open-source corpora.
- **2×2 Contingency Confusion Matrices** (TP, FP, TN, FN).
- **Interactive SVG ROC Space Visualizer** with Youden's $J$-statistic optimal decision cutoff ($\tau^*$).

---

## 💻 Prerequisites

Ensure you have the following installed on your machine:
- **Java JDK 17 or higher** ([Download Oracle JDK 17](https://www.oracle.com/java/technologies/downloads/#java17) or [Eclipse Temurin](https://adoptium.net/))
- **Git** ([Download Git](https://git-scm.com/))
- *(Optional)* **Maven 3.8+** (A self-contained `mvnw` wrapper is already included in this repository, so global Maven is not required).

---

## 🚀 Quick Start (Command Line)

### 1. Clone the Repository
```bash
git clone https://github.com/sam-black007/spamguard-ai.git
cd spamguard-ai
```
*(Or navigate to the `spamdetector` directory if working in a multi-directory repo)*

### 2. Run All Automated Tests
Verify all 15 automated JUnit 5 unit and integration tests:
- **Windows:**
  ```powershell
  .\mvnw.cmd clean test
  ```
- **macOS / Linux:**
  ```bash
  chmod +x mvnw
  ./mvnw clean test
  ```

### 3. Launch the Application
- **Windows:**
  ```powershell
  .\mvnw.cmd spring-boot:run
  ```
- **macOS / Linux:**
  ```bash
  ./mvnw spring-boot:run
  ```

### 4. Access the Web Dashboard
Open your browser and navigate to:
👉 **`http://localhost:8080`**

---

## 🛠️ How to Setup and Run in Visual Studio Code (VS Code)

### Step 1: Install Required VS Code Extensions
Open VS Code, press `Ctrl + Shift + X` (or `Cmd + Shift + X` on Mac), and install:
1. **Extension Pack for Java** (by Microsoft) — *includes Language Support, Debugger, Test Runner, and Maven for Java.*
2. **Spring Boot Extension Pack** (by VMware) — *provides Spring Boot Tools, Spring Initializr, and Dashboard support.*

### Step 2: Open the Project in VS Code
1. Open VS Code.
2. Click **File > Open Folder...** (`Ctrl + K, Ctrl + O`).
3. Select the `spamdetector` folder (where `pom.xml` is located).
4. Wait a few seconds for the Java Language Server to import and index the Maven project dependencies. You will see a thumbs-up icon or *"Java: Ready"* in the bottom status bar.

### Step 3: Run the Application in VS Code

#### Option A: 1-Click Launch (Recommended)
1. In the file explorer, navigate to:  
   `src/main/java/com/example/spamdetector/SpamdetectorApplication.java`
2. You will see a **Run | Debug** code-lens button directly above the `public static void main` method.
3. Click **Run**.
4. The integrated terminal will display the Spring Boot banner and `Tomcat started on port 8080`.

#### Option B: Using the Spring Boot Dashboard
1. In the VS Code left sidebar, click the **Spring** leaf icon (Spring Boot Dashboard).
2. Under **Apps**, look for `spamdetector`.
3. Click the green **Play (▶️)** button to start the server.

#### Option C: Running via the Built-In Terminal
Press `` Ctrl + ` `` to open the terminal in VS Code and execute:
```powershell
.\mvnw.cmd spring-boot:run
```

---

## 🧪 Running Unit Tests in VS Code

1. Click the **Testing (Flask icon)** on the left sidebar.
2. Expand `spamdetector > src/test/java > com.example.spamdetector`.
3. Click **Run Tests (▶️)** on `SpamServiceTest`.
4. All 15 tests (covering False Positive Avoidance, Adversarial Homoglyph Mitigation, Shannon Entropy, Tri-Model Stacking, and MITRE ATT&CK extraction) will execute with green checkmarks.

---

## 🌐 API Reference

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/api/classify` | Classifies raw text message via the full Tri-Model Ensemble & threat heuristics. |
| `POST` | `/api/scan-qr` | Decodes Base64 QR code and inspects for Quishing, SSRF & open redirects. |
| `GET` | `/api/benchmark` | Runs 5-Fold Stratified Cross-Validation benchmark & computes ROC-AUC curves. |
| `POST` | `/api/adversarial-attack` | Simulates Cyrillic, zero-width, leet-speak, or good-word evasion attacks. |
| `POST` | `/api/stix-bundle` | Generates a standardized OASIS STIX 2.1 Threat Report JSON. |
| `GET` | `/api/dataset/samples` | Streams raw labeled messages from the open-source corpus. |
| `GET` | `/api/dossier` | Generates the comprehensive technical markdown defense guide for viva. |
| `GET` | `/api/health` | Health check endpoint (`{"status": "UP"}`). |

---

## 📄 License & Academic Integrity

This project is submitted as an undergraduate engineering Capstone Project. It is built strictly for academic defense, educational research, and threat intelligence analysis.
