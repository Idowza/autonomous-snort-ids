# AI-Enhanced Autonomous IDSA Cybersecurity Capstone Project

This repository contains the code for an AI-enhanced Intrusion Detection System (IDS) for the University of North Dakota (EECS 994). The system uses Snort 3 to detect network threats with custom rules and a Python-based machine learning pipeline to classify the resulting alerts. The ultimate goal is to create an autonomous system that can suggest new detection rules in response to emerging threats.

## About The Project

This repository contains the code for an AI-enhanced Intrusion Detection System (IDS) developed for the EECS 994 Capstone Project. The system integrates Snort 3 with a sophisticated, hybrid AI pipeline to overcome the limitations of traditional rule-based engines. While effective against known signatures, static rules fail to detect novel or "zero-day" threats. This project bridges that gap by combining a Random Forest classifier for known threats with an Isolation Forest anomaly detector for unknown attacks. The ultimate goal is to create an autonomous system that can suggest new detection rules in response to emerging threats using a local Large Language Model (Ollama).

## Technology Stack

*   **IDS Engine:** Snort 3
*   **Log Management:** Rsyslog
*   **Programming Language:** Python 3
*   **Core Libraries:** Pandas, Scikit-learn (Random Forest, Isolation Forest), Joblib
*   **LLM Integration:** Ollama with Llama 3
*   **Operating Systems:** Kali Linux (IDS) and Linux Mint (Attacker/AI Host)

## Log Forwarding Architecture

The log transfer from the Kali machine (Snort IDS) to the Linux Mint machine (AI/Attacker) happens through the Syslog protocol over the network.

1.  **Generation:** Snort on Kali detects an attack and generates an alert.
2.  **Internal Handoff:** Because `alert_syslog` is configured in `snort.lua`, Snort hands this alert message to the local logging service on Kali (Rsyslog), tagging it with the "facility" `local5`.
3.  **Network Transmission:** The Rsyslog service on Kali reads its config file (`/etc/rsyslog.d/60-snort.conf`). It sees the rule `local5.* @192.168.1.6:514`. This tells it to wrap the message in a UDP packet and send it to IP `192.168.1.6` on port 514.
4.  **Reception:** The Rsyslog service on the Mint machine is listening on UDP port 514 and receives the packet.
5.  **Filtering & Writing:** Rsyslog on Mint reads its config (`/etc/rsyslog.d/40-snort.conf`). It sees the rule `if $syslogfacility-text == 'local5' then /var/log/snort_alerts.log`. It recognizes the `local5` tag and writes the message into that specific text file.

This effectively creates a dedicated, invisible pipeline sending text messages from one operating system's log manager to another's.

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

To enable log forwarding to Rsyslog, add the following configuration to `snort.lua`:

```lua
-- Configure syslog to send alerts using a specific 'facility'
alert_syslog = {
    facility = 'local5',
    level = 'alert',
}

-- Activate ONLY the syslog logger
loggers = {
    'alert_syslog',
}
```

### Custom Snort Rules

Three custom Snort 3 rules were developed and validated as part of Phase 1:

1.  **Nmap FIN Scan Detection:** Acts as a silent alarm for stealthy reconnaissance. It watches for TCP packets with only the 'FIN' flag set (no SYN or ACK), a classic signature of an Nmap 'FIN scan'.
2.  **SSH Brute-Force Attempt Detection:** Serves as a tripwire for sustained brute-force attacks. It triggers if five connection attempts to port 22 are observed from the same source IP within 60 seconds.
3.  **ICMP Ping Sweep Detection:** Identifies attackers performing initial network mapping. It generates an alert if two or more ping requests (ICMP Type 8) are received from the same source within a 10-second window.

### How to Run

1.  **Start the IDS:** On the Snort machine, run Snort to begin monitoring traffic.
    ```bash
    # (Optional) Ensure log directory exists with correct permissions
    # sudo mkdir -p /var/log/snort && sudo chown snort:snort /var/log/snort

    sudo snort -c /etc/snort/snort.lua -R /etc/snort/rules/local.rules -i eth0 -k none -l /var/log/snort
    ```

2.  **Monitor Live Logs:** On the Mint machine, view the live logs to confirm alerts are being received.
    ```bash
    sudo tail -f /var/log/snort_alerts.log
    ```

3.  **Generate Test Traffic:** From the Attacker machine, trigger the existing rules.
    ```bash
    # Ping Sweep, Nmap, and SSH Brute Force tests
    for i in {1..15}; do ping -c 1 192.168.1.44; done
    sudo nmap -sF 192.168.1.44
    hydra -l root -P /usr/share/wordlists/rockyou.txt -t 5 ssh://192.168.1.44
    ```

4.  **Run the AI Pipeline:** On the Snort machine, execute the Python scripts in order.
    ```bash
    # 1. Parse Snort logs into a structured CSV file
    python3 parse_logs.py
    
    # 2. Train the model and save it to disk
    python3 train_model.py
    
    # 3. Simulate a new threat and generate a rule suggestion
    python3 suggest_rule.py
    
    # 4. Review and deploy the suggested rules
    python3 approve_rules.py
    ```
    This will parse logs, train a hybrid model (Classifier + Anomaly Detector), detect threats, generate a new Snort rule using Llama 3, and allow for human-in-the-loop approval and deployment.

## Project Status

- [x] **Phase 1: IDS Deployment & Rule Creation** - Completed.
- [x] **Phase 2: AI-Enhanced Detection** - Data pipeline and baseline model complete.
- [x] **Phase 3: Autonomous Rule Suggestion** - Significant progress. Functional end-to-end prototype demonstrated.
    - [x] Implemented Hybrid Model (Random Forest + Isolation Forest).
    - [x] Successfully detected novel Log4j attack (missed by classifier, caught by anomaly detector).
    - [x] Integrated Ollama for autonomous rule generation.
    - [x] Created `approve_rules.py` for human-in-the-loop feedback and dynamic deployment.
    - [x] **Expand Model Knowledge:** Updated `train_model.py` to ingest UNSW-NB15, CICIoV2024, CICEV2023, and CSE-CIC-IDS2018 datasets.
    - [x] **Full "Lights-Out" Automation:** Created a master script (`run_pipeline.py`) to orchestrate the entire lifecycle.
- [ ] **Next Steps (Final Report):**
    1. **Automated Rule Validation:** Develop a script to re-launch attacks and verify that newly deployed rules successfully detect them.

## Future Work

With the hybrid model and autonomous loop functional, the final phase focuses on enhancing robustness and full automation. The system will be scaled to handle a wider variety of real-world attacks by training on comprehensive public datasets, and the "self-testing" capability will be added to ensure the reliability of AI-generated rules.

## License

This project is licensed under the MIT License - see the `LICENSE` file for details.

## Acknowledgments

I would like to thank my capstone advisor, Dr. Zhang, for his guidance and support throughout this project. I also wish to acknowledge the Canadian Institute for Cybersecurity (CIC) for providing the CIC-IDS-2017 dataset, and the open-source communities behind Snort, Ollama, and Scikit-learn, whose tools made this project possible.

