# EECS 994 Capstone Project: AI-Enhanced Autonomous IDS

This document summarizes the steps taken, challenges encountered, and solutions implemented to build the AI-Enhanced Autonomous IDS project.

## 1. Project Initialization & Setup
**Objective:** Build an AI-enhanced autonomous IDS using Snort 3, machine learning, and an LLM, fulfilling the requirements of the provided syllabus and project instructions.

**Initial Lab Setup:**
- Physical hardware:
  - Kali Linux (IDS Sensor): IP 192.168.1.44, running Snort 3.
  - Linux Mint (Attacker/AI Host): IP 192.168.1.6, used for generating attacks, running the Python AI pipeline, and hosting the Ollama LLM.
  - Network: Managed by an OPNsense router.
- **Project Phases:** Part A (Snort Setup), Part B (AI Classification), and Part C (Autonomous AI Rule Generation).

## 2. Part A: Snort IDS Deployment & Rule Validation
**Snort Configuration:**
- Edited `/etc/snort/snort.lua` on Kali to set `HOME_NET = '192.168.1.0/24'`.

**Custom Rule 1: Nmap FIN Scan:**
- Created rule (sid:1000001) in `/etc/snort/rules/local.rules`.
- Tested using `sudo nmap -sF 192.168.1.44` from Mint.

**Troubleshooting - Logging:**
- Initial issue: No log file created.
- Solution 1: Explicitly specified log directory using `-l /var/log/snort` in the Snort command.
- Solution 2: Configured `alert_fast = { file = true }` in `snort.lua`.

**Troubleshooting - Console Alerts:**
- Issue: Alerts logged to file but not console.
- Attempted solutions: Removing `-A` flag, explicit `stderr` output for `alert_console`, `2>&1` redirection.
- Final Workaround: Deemed console alerts non-essential for the project; used `tail -f /var/log/snort/alert_fast.txt` on Kali for live demonstration purposes.

**Custom Rule 2: SSH Brute-Force Attempt:**
- Installed `hydra` on Mint.
- Created rule (sid:1000002), initially using incorrect Snort 3 syntax (`threshold`, `nocase`).
- **Troubleshooting - Rule Syntax:** Corrected rule using modern Snort 3 syntax (`detection_filter`, `content:"..."`, `nocase`).
- Tested successfully using `hydra -l root -P ... ssh://192.168.1.44`.

**Custom Rule 3 (Attempt 1): Curl User-Agent:**
- Created rule (sid:1000003) to detect `User-Agent: curl` on port 80.
- Tested using `curl http://192.168.1.44` (connection refused, as expected).
- **Troubleshooting - Rule Logic:** Alert failed. Diagnosed that `flow: established` prevented matching since the connection failed. Removed `established`.
- **Troubleshooting - Network Filtering:** Alert still failed. Diagnosed potential firewall blocking. Flushed `iptables` on Kali (`sudo iptables -F`).
- **Troubleshooting - Persistent Failure:** Alert still failed despite direct connection confirmed via `traceroute`.
- **Decision:** Pivoted to a different rule type due to persistent environment-specific issues with the HTTP test.

**Custom Rule 3 (Replacement): ICMP Ping Sweep:**
- Created rule (sid:1000004) to detect ICMP Echo Requests (Type 8, Code 0) using `detection_filter`.
- Tested using `sudo nmap -sn -PE 192.168.1.44`.
- **Troubleshooting - Threshold:** Alert failed. Diagnosed that `nmap` against a single host was too efficient for the `count 10` threshold. Lowered to `count 2`.
- **Troubleshooting - Network Path:** Alert still failed. Confirmed OPNsense firewall was not blocking via live logs.
- **Alternative Test:** Used a `for` loop (`for i in {1..15}; do ping -c 1 192.168.1.44; done`) from Mint.
- **Success:** The loop-based ping test successfully triggered the ICMP rule.
- **Outcome:** Part A successfully completed with three validated custom rules. Saved successful attack commands for reference.

## 3. Part B: AI-Enhanced Detection - Data Pipeline & Model Training
**Automated Log Forwarding (Rsyslog):**
- Configured Snort (Kali) to log to `local5` syslog facility (`alert_syslog` in `snort.lua`).
- Configured Rsyslog (Kali) to forward `local5.*` logs to the Mint machine's IP (192.168.1.6) via UDP port 514 (`/etc/rsyslog.d/60-snort.conf`).
- Configured Rsyslog (Mint) to enable UDP reception on port 514 (`/etc/rsyslog.conf`).
- Configured Rsyslog (Mint) to filter incoming `local5` messages to a dedicated file `/var/log/snort_alerts.log` and prevent duplication in `/var/log/syslog` (`/etc/rsyslog.d/40-snort.conf`).

**Log Parsing (parse_logs.py):**
- Created script on Mint to parse logs into CSV.
- **Troubleshooting - Permissions:** Initial run failed. Required `sudo` to read `/var/log/snort_alerts.log`.
- **Troubleshooting - Log Format:** Script failed again. Diagnosed that the rsyslog format (timestamp, hostname, process) differed from `alert_fast.txt`. Updated the regular expression in the script to handle the new format.
- **Success:** Script successfully parsed logs and created `snort_alerts.csv`.

**Model Training Iteration 1 (Decision Tree):**
- Created `train_model.py` on Mint.
- Installed `pandas`, `scikit-learn`.
- Loaded CSV, labeled data based on custom rule messages ('Nmap', 'SSH', 'ICMP').
- Used `TfidfVectorizer` for the 'message' feature.
- Trained a `DecisionTreeClassifier`. Achieved perfect 1.00 scores (indicative of overfitting on simple data).
- Added `joblib.dump` to save the trained model and vectorizer.

**Model Training Iteration 2 (Random Forest + More Features):**
- **Goal:** Improve generalization.
- Upgraded model to `RandomForestClassifier`.
- Added `dest_port` as a numerical feature.
- Implemented `ColumnTransformer` and `Pipeline` in `train_model.py` to handle mixed data types (text + numeric) and scaling (`StandardScaler`).
- Saved the entire pipeline (`random_forest_pipeline.joblib`).

**Model Training Iteration 3 (Integration of CIC-IDS-2017):**
- **Goal:** Train on diverse, large-scale public data.
- Discussed using "Generated Labelled Flows" vs "Machine Learning CSV" files (selected the former).
- Updated `train_model.py` to:
  - Find and loop through all CSVs in a `cicids_data/` subfolder.
  - Transform CIC-IDS data by selecting `Destination Port` and `Label`, mapping labels to expected alert messages ('Nmap Scan Attempt', 'SSH Brute-Force Attempt', etc.).
- **Troubleshooting - Data Merging:** Initial merge failed (`dropna` removed all CIC-IDS data due to mismatched columns). Corrected script to ensure both local and CIC-IDS dataframes had only `message`, `dest_port`, `label` before concatenation.
- Trained Random Forest on the combined dataset (~3 million records). Achieved ~0.99 accuracy (more realistic).

**Model Training Iteration 4 (Advanced Feature Engineering):**
- **Goal:** Help model recognize suspicious patterns beyond specific words.
- Added new features engineered from the 'message' column to `train_model.py`:
  - `message_length`
  - `special_char_count` (counting `${`, `(`, `'`, `/`, etc.)
  - `keyword_count` (counting `select`, `union`, `script`, `jndi`, `ldap`, `payload`, etc.)
- Included these new numerical features in the `ColumnTransformer` and retrained the Random Forest pipeline.

## 4. Part C: Autonomous AI Rule Generation
**LLM Setup (Ollama):**
- Installed `ollama` Python library on Mint.
- Confirmed Ollama service running with the `llama3` model.

**Rule Suggestion Script Iteration 1 (suggest_rule.py):**
- Loaded the simple Decision Tree model.
- Simulated a novel Log4j threat (`GET /?payload=${jndi:ldap...}`).
- **Key Finding 1:** The simple, overfitted model classified the novel threat as "Benign".
- Implemented a manual override (`if True:`) to force the LLM trigger for demonstration.
- Constructed a detailed prompt with alert context.
- Successfully called Ollama API, received a suggested Snort rule (initially just IP blocking), and saved it to `suggested_rules.txt`.

**Rule Suggestion Script Iteration 2 (Using Advanced RF Model):**
- Updated `suggest_rule.py` to load the advanced Random Forest pipeline (`random_forest_pipeline.joblib`).
- Added feature engineering steps to the script to prepare the novel Log4j alert with the same features the model was trained on (`message_length`, etc.).
- Removed the manual override (`if True:`).
- **Key Finding 2:** Even the advanced Random Forest, trained on millions of records with engineered features, classified the novel Log4j threat as "Benign". Diagnosis: Vocabulary limitation – the model's text vectorizer had never encountered `jndi:ldap`.

**Hybrid Model Solution:**
- **Concept:** Combine the classifier (good for known patterns) with an anomaly detector (good for unknown deviations).
- Updated `train_model.py` to train and save two pipelines:
  - `random_forest_pipeline.joblib` (Classifier, trained on all data).
  - `isolation_forest_pipeline.joblib` (Anomaly Detector, trained only on benign data).
- **Updated `suggest_rule.py` (Final Version):**
  - Loads both pipelines.
  - Engineers features for the novel Log4j alert.
  - Gets predictions from both models.
  - Implements hybrid logic: Flag as Malicious IF (Classifier predicts Malicious) OR (Anomaly Detector predicts Anomaly [-1]).
- **Success:** The hybrid system correctly flagged the Log4j threat. The Random Forest predicted "Benign", but the Isolation Forest predicted "ANOMALY".
- Ollama generated a high-quality rule including a content match for the payload.

**Feedback Loop Implementation (approve_rules.py):**
- Created script on Mint to provide Human-in-the-Loop functionality.
- Requires SSH access (key-based recommended, `sshpass` optional).
- Reads rules from `suggested_rules.txt`.
- Prompts the user (analyst) to approve ('y') or reject ('n') each rule.
- If approved:
  - Uses `scp` to copy the rule to a temp file on Kali.
  - Uses `ssh` to append the rule from the temp file to `/etc/snort/rules/local.rules` on Kali.
  - Uses `ssh` to attempt reloading Snort rules via `sudo kill -HUP <PID>`.
- Optionally clears `suggested_rules.txt` after review.

## 5. Documentation
- **Quarterly Reports:** Writing reports in IEEE LaTeX format, covering Phase 1, Phase 2, and Phase 3 progress.
- **Literature Review:** Incorporated and formatted references into the reports.
- **README.md:** Created, updated, and refined the GitHub README file in Markdown, including:
  - Abstract, Key Features, Architecture Diagram, Tech Stack.
  - Detailed Setup Instructions (Prerequisites, Rsyslog config for both machines).
  - Step-by-step Demonstration Workflow.
  - Project Evolution section detailing the iterative ML model improvements and key findings.
  - Future Work, License, and Acknowledgments sections.
  - Corrected formatting issues for proper GitHub rendering.
  - Updated to reflect the use of physical hardware instead of VMs.

This summary covers the entire technical journey, including all development, testing, troubleshooting, and refinement steps, culminating in a fully functional prototype.

