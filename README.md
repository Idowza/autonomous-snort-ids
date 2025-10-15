# AI-Enhanced Autonomous IDSA Cybersecurity Capstone Project

This repository contains the code for an AI-enhanced Intrusion Detection System (IDS) for the University of North Dakota (EECS 994). The system uses Snort 3 to detect network threats with custom rules and a Python-based machine learning pipeline to classify the resulting alerts. The ultimate goal is to create an autonomous system that can suggest new detection rules in response to emerging threats.

## About The Project

This repository contains the code for an AI-enhanced Intrusion Detection System (IDS). The system uses Snort 3 to detect network threats with custom rules and a Python-based machine learning pipeline to classify the resulting alerts. The ultimate goal is to create an autonomous system that can suggest new detection rules in response to emerging threats.

## Technology Stack

*   **IDS Engine:** Snort 3
*   **Programming Language:** Python 3
*   **Core Libraries:** Pandas, Scikit-learn, Joblib
*   **LLM Integration:** Ollama with Llama 3
*   **Operating Systems:** Kali Linux (IDS) and Linux Mint (Attacker)

## Getting Started

### Prerequisites

*   Python 3 and pip
*   Ollama and the `llama3` model pulled (`ollama run llama3`)
*   Required Python libraries:
    ```bash
    pip3 install pandas scikit-learn joblib ollama
    ```

### Lab Environment

The lab consists of two bare metal machines on an isolated network:

*   **Kali Snort IDS Machine:** `192.168.1.44`
*   **Linux Mint (Attacker) Machine:** `192.168.1.6`

### Snort Configuration

Snort 3 is configured via `/etc/snort/snort.lua`. Ensure `HOME_NET` is set to your lab network and that your custom rules file (`/etc/snort/rules/local.rules`) is included in the `ips` section.

### How to Run

1.  **Start the IDS:** On the Snort machine, run Snort to begin monitoring traffic.
    ```bash
    # (Optional) Ensure log directory exists with correct permissions
    # sudo mkdir -p /var/log/snort && sudo chown snort:snort /var/log/snort

    sudo snort -c /etc/snort/snort.lua -R /etc/snort/rules/local.rules -i eth0 -k none -l /var/log/snort
    ```

2.  **Generate Test Traffic:** From the Attacker machine, trigger the existing rules.
    ```bash
    # Ping Sweep, Nmap, and SSH Brute Force tests
    for i in {1..15}; do ping -c 1 192.168.1.44; done
    sudo nmap -sF 192.168.1.44
    hydra -l root -P /usr/share/wordlists/rockyou.txt -t 5 ssh://192.168.1.44
    ```

3.  **Run the AI Pipeline:** On the Snort machine, execute the Python scripts in order.
    ```bash
    # 1. Parse Snort logs into a structured CSV file
    python3 parse_logs.py
    
    # 2. Train the model and save it to disk
    python3 train_model.py
    
    # 3. Simulate a new threat and generate a rule suggestion
    python3 suggest_rule.py
    ```
    This will parse logs, train a model, and then use the model to detect a simulated new threat, for which it will generate a new Snort rule using Llama 3.

## Project Status

- [x] **Phase 1: IDS Deployment & Rule Creation** - Completed
- [x] **Phase 2: AI-Enhanced Detection** - Data pipeline and baseline model complete.
- [x] **Phase 3: Autonomous Rule Suggestion** - Initial implementation complete.
    - [x] Installed Ollama and the `ollama` Python library.
    - [x] Pulled the `llama3` model.
    - [x] Updated `train_model.py` to save the trained model and vectorizer.
    - [x] Created `suggest_rule.py` to generate new rules for unseen threats using the LLM.
- [ ] **Next Steps:**
    - [ ] Refine the prompt engineering for more accurate and robust rule generation.
    - [ ] Integrate the suggested rules back into the Snort pipeline automatically for analyst review.
    - [ ] Expand the dataset with more diverse benign and malicious traffic to improve model accuracy.
    - [ ] Research and implement a fully automated pipeline, including forwarding Snort alerts to the AI machine and running the Python scripts to generate new rules for approval.

## Future Work

With the dataset now balanced and the model re-trained/evaluated, the focus shifts to building the autonomous rule generation system. The next major milestone is integrating a local Large Language Model (LLM) with Ollama to propose, validate, and iterate on new Snort rules based on observed alerts and model insights.

## License

This project is licensed under the MIT License - see the `LICENSE` file for details.

## Acknowledgments

*   Dr. Zhang - Capstone Advisor, University of North Dakota

