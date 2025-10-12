AI-Enhanced Autonomous Intrusion Detection System

A Capstone Project for the Master's in Cybersecurity Program (EECS 994) at the University of North Dakota.
Table of Contents

    About The Project

    Technology Stack

    Getting Started

        Prerequisites

        Lab Environment Setup

        IDS Configuration

    Usage and Workflow

    Project Status

    Future Work

    License

    Acknowledgments

    References

About The Project

This repository documents the development of an AI-enhanced, autonomous Network Intrusion Detection System (NIDS). The project's core objective is to integrate the powerful rule-based detection capabilities of Snort 3 with a custom-trained machine learning model. This hybrid approach aims to improve the classification of security alerts and lay the groundwork for an autonomous system that can dynamically suggest new detection rules in response to emerging threats.

The project is structured in three primary phases:

    Part A: IDS Deployment: Building and validating a functional Snort 3 sensor in a virtualized lab environment.

    Part B: AI-Enhanced Detection: Creating a data pipeline to process Snort alerts and training an ML model for classification.

    Part C: Advanced Autonomous AI: Developing a feedback loop for the AI to autonomously suggest new rules, inspired by cutting-edge research in the field.

Technology Stack

    IDS Engine: Snort 3

    Programming Language: Python 3

    Core Libraries:

        Pandas (Data Manipulation)

        Scikit-learn (Machine Learning)

    Virtualization: KVM/QEMU with Virt-Manager

    Operating Systems:

        Kali Linux (Attacker VM & Snort IDS VM)

    Future Integration:

        Ollama with a local LLM (e.g., Llama 3) for advanced rule generation.

Getting Started
Prerequisites

Ensure the following software is installed on your host machine:

    KVM/QEMU and Virt-Manager

    Python 3 and pip

    Git (for cloning the repository)

Lab Environment Setup

The lab environment consists of two virtual machines on an isolated network (192.168.100.0/24).

    Snort IDS VM:

        OS: Kali Linux

        IP Address: 192.168.100.184

        Monitored Interface: enp7s0

        Software: Snort 3, Python 3, required libraries.

    Attacker VM:

        OS: Kali Linux

        IP Address: 192.168.100.212

        Software: nmap, ping, etc.

IDS Configuration

Snort 3 is configured using /etc/snort/snort.lua. The following modifications are required:

    Set HOME_NET to the lab network range:

    HOME_NET = '192.168.100.0/24'

    Include Custom Rules: Add the following line within the ips configuration block to load the custom rules file:

    include = 'rules/local.rules'

    Custom Rules: All custom rules are located in /etc/snort/rules/local.rules.

Usage and Workflow

The project follows a sequential workflow from traffic generation to model training.

    Start the IDS: On the Snort IDS VM, start the Snort service in live logging mode.

    # Ensure log directory exists with correct permissions
    sudo mkdir -p /var/log/snort
    sudo chown snort:snort /var/log/snort

    # Start Snort (replace <interface> with your network interface)
    sudo snort -c /etc/snort/snort.lua -i <interface> -l /var/log/snort

    Generate Test Traffic: From the Attacker VM, run commands to trigger the custom rules.

    # Test ICMP Ping Rule
    ping -c 1 192.168.100.184

    # Test Nmap NULL Scan Rule
    sudo nmap -sN 192.168.100.184

    # Test Nmap Xmas Scan Rule
    sudo nmap -sX 192.168.100.184

    Parse Raw Logs: Run the log_parser.py script to convert the alert.fast file into snort_alerts.csv.

    python3 log_parser.py

    Preprocess Data: Run the data_preprocessor.py script to one-hot encode the data and prepare it for the ML model.

    python3 data_preprocessor.py

    This creates processed_alerts.csv.

    Train and Evaluate Model: Run model_trainer.py to train the Random Forest model and see its performance.

    python3 model_trainer.py

Project Status

    [x] Phase 1: IDS Deployment and Rule Creation - Completed

        [x] Virtual lab environment established on KVM.

        [x] Snort 3 installed and configured on a Kali Linux VM.

        [x] Three custom stateless rules (ICMP, Nmap NULL, Nmap Xmas) written and validated.

    [x] Phase 2: AI-Enhanced Detection - In Progress

        [x] Python data pipeline developed (log_parser.py, data_preprocessor.py).

        [x] Baseline Random Forest model trained and validated (model_trainer.py).

        [ ] Generate benign network traffic and label as 0.

        [ ] Create a balanced dataset of malicious (1) and benign (0) alerts.

        [ ] Re-train and evaluate the model on the new balanced dataset.

    [ ] Phase 3: Advanced Autonomous AI

        [ ] Design and implement the autonomous rule suggestion component.

        [ ] Integrate a local LLM via Ollama for advanced rule generation.

Future Work

The immediate next step is to address the data imbalance in the training set, a critical issue highlighted by Ahsan et al. [1]. This will involve generating and labeling benign network traffic to create a more realistic dataset.

For the final phase of the project, the autonomous rule generation system will be developed. This will be inspired by the framework proposed in the "RuleMaster+" paper [2], which details using an LLM to automatically generate Snort rules from alert data. This will be implemented using a local instance of Ollama to create a self-contained, autonomous feedback loop.
License

This project is licensed under the MIT License - see the LICENSE file for details.
Acknowledgments

    Dr. Zhang - Capstone Advisor, University of North Dakota

References

[1] R. Ahsan, W. Shi, and J.-P. Corriveau, "Network intrusion detection using machine learning approaches: Addressing data imbalance," IET Cyber-Physical Systems: Theory & Applications, 2021.

[2] W. Lian, C. Zhang, H. Zhang, B. Jia, and B. Liu, "RuleMaster+: LLM-Based Automated Rule Generation Framework for Intrusion Detection Systems," Chinese Journal of Electronics, vol. 34, no. 5, pp. 1-13, 2025.
