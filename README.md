# AI-Enhanced Autonomous IDSA Cybersecurity Capstone Project

This repository contains the code for an AI-enhanced Intrusion Detection System (IDS) for the University of North Dakota (EECS 994). The system uses Snort 3 to detect network threats with custom rules and a Python-based machine learning pipeline to classify the resulting alerts. The ultimate goal is to create an autonomous system that can suggest new detection rules in response to emerging threats.

## About The Project

This repository contains the code for an AI-enhanced Intrusion Detection System (IDS). The system uses Snort 3 to detect network threats with custom rules and a Python-based machine learning pipeline to classify the resulting alerts. The ultimate goal is to create an autonomous system that can suggest new detection rules in response to emerging threats.

## Technology Stack

*   **IDS Engine:** Snort 3
*   **Programming Language:** Python 3
*   **Core Libraries:** Pandas, Scikit-learn
*   **Virtualization:** KVM/QEMU with Virt-Manager
*   **Operating Systems:** Kali Linux (for both IDS and Attacker VMs)
*   **Future Integration:** Ollama with a local LLM (e.g., Llama 3)

## Getting Started

### Prerequisites

*   KVM/QEMU and Virt-Manager
*   Python 3 and pip
*   Required Python libraries:
    ```bash
    pip3 install pandas scikit-learn
    ```

### Lab Environment

The lab consists of two Kali Linux VMs on an isolated network (192.168.100.0/24):

*   **Snort IDS VM:** `192.168.100.184`
*   **Attacker VM:** `192.168.100.212`

### Snort Configuration

Snort 3 is configured via `/etc/snort/snort.lua`. Ensure `HOME_NET` is set to your lab network and that your custom rules file (`/etc/snort/rules/local.rules`) is included in the `ips` section.

### How to Run

1.  **Start the IDS:** On the Snort VM, run Snort to begin monitoring traffic.
    ```bash
    # (Optional) Ensure log directory exists with correct permissions
    # sudo mkdir -p /var/log/snort && sudo chown snort:snort /var/log/snort

    sudo snort -c /etc/snort/snort.lua -i <interface> -l /var/log/snort
    ```

2.  **Generate Test Traffic:** From the Attacker VM, trigger the rules.
    ```bash
    # Test ICMP Ping Rule
    ping -c 1 192.168.100.184

    # Test Nmap NULL Scan Rule
    sudo nmap -sN 192.168.100.184

    # Test Nmap Xmas Scan Rule
    sudo nmap -sX 192.168.100.184
    ```

3.  **Run the AI Pipeline:** On the Snort VM, execute the Python scripts in order.
    ```bash
    python3 log_parser.py
    python3 data_preprocessor.py
    python3 model_trainer.py
    ```
    This will parse the logs, preprocess the data, and train a Random Forest model, outputting a performance report.

## Project Status

- [x] **Phase 1: IDS Deployment & Rule Creation** - Completed
- [x] **Phase 2: AI-Enhanced Detection** - Data pipeline and baseline model complete.
- [ ] **Next Steps:**
    - Generate benign network traffic and label it (0) to create a balanced dataset.
    - Re-train and evaluate the model on the new balanced dataset.
    - Begin development on the autonomous rule suggestion component (Part C).

## Future Work

The immediate next step is to address the data imbalance in the training set by generating and labeling benign traffic. The final phase of the project will focus on building the autonomous rule generation system by integrating a local Large Language Model (LLM) with Ollama.

## License

This project is licensed under the MIT License - see the `LICENSE` file for details.

## Acknowledgments

*   Dr. Zhang - Capstone Advisor, University of North Dakota

