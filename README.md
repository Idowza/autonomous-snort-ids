AI-Enhanced Autonomous Intrusion Detection SystemEECS 994 Capstone Project - University of North DakotaAbout The ProjectThis repository contains the source code and documentation for the capstone project, "Building an AI-Enhanced Autonomous Intrusion Detection System with Snort3." The objective is to design, deploy, and evaluate a hybrid NIDS that leverages the rule-based detection of Snort 3 and enhances it with a machine learning model for advanced alert classification and autonomous response capabilities.The project is divided into three main phases:Part A: Snort 3 IDS Deployment: Set up a virtual lab, install and configure Snort 3, and write and validate custom detection rules.Part B: AI-Enhanced Detection: Develop a data pipeline to process Snort alerts and train a machine learning model to classify them.Part C: Advanced Autonomous AI: Create a feedback loop where the AI model can autonomously suggest new rules to enhance detection capabilities, with future plans to integrate a local LLM for rule generation.Technology StackThis project utilizes the following technologies and libraries:IDS Engine: Snort 3Programming Language: Python 3Data Manipulation: PandasMachine Learning: Scikit-learnVirtualization: KVM/QEMU with Virt-ManagerOperating Systems:Kali Linux (Attacker VM & Snort IDS VM)Future Integration:Ollama with Llama 3 for LLM-based rule generationSetup and Installation1. Virtual EnvironmentThe lab environment consists of two virtual machines running on an isolated network (192.168.100.0/24) using KVM.Snort IDS VM: A Kali Linux instance running Snort 3.IP Address: 192.168.100.184Monitored Interface: enp7s0Attacker VM: A Kali Linux instance for generating test traffic.IP Address: 192.168.100.2122. Snort ConfigurationSnort 3 is configured using /etc/snort/snort.lua. Key configurations include:Setting HOME_NET to the lab's network range:HOME_NET = '192.168.100.0/24'

Including the custom rules file within the ips configuration block:include = 'rules/local.rules'

The custom rules are located in /etc/snort/rules/local.rules.3. Python EnvironmentThe Python scripts rely on a few key libraries. It is recommended to set up a virtual environment.# Install required libraries
pip3 install pandas scikit-learn

Workflow and UsageThe project follows a sequential workflow from detection to model training.1. Start the IDSOn the Snort IDS VM, start Snort in live logging mode. This will log alerts to /var/log/snort/alert.fast and also print them to the console.# Ensure the log directory exists and has correct permissions
sudo mkdir -p /var/log/snort
sudo chown snort:snort /var/log/snort

# Start Snort (replace <interface> with your network interface)
sudo snort -c /etc/snort/snort.lua -i <interface> -l /var/log/snort

2. Generate Test TrafficFrom the Attacker VM, run commands to trigger the custom rules.# Test ICMP Ping Rule
ping -c 1 192.168.100.184

# Test Nmap NULL Scan Rule
sudo nmap -sN 192.168.100.184

# Test Nmap Xmas Scan Rule
sudo nmap -sX 192.168.100.184

3. Parse Raw LogsRun the log_parser.py script on the Snort IDS VM to convert the raw alert.fast file into a structured CSV file.python3 log_parser.py

This will produce snort_alerts.csv.4. Preprocess the DataRun the data_preprocessor.py script to perform one-hot encoding and prepare the data for machine learning.python3 data_preprocessor.py

This will produce processed_alerts.csv.5. Train and Evaluate the ModelRun the model_trainer.py script to train the Random Forest classifier and evaluate its performance.python3 model_trainer.py

The script will output a classification report and a confusion matrix.Project Statusx Phase 1: IDS Deployment and Rule Creation - Completedx Phase 2: AI-Enhanced Detection - Data pipeline and baseline model complete. Next Steps:Generate benign network traffic and label it appropriately to create a balanced dataset.Re-train and evaluate the model on the balanced dataset.Begin development on the autonomous rule suggestion component (Part C), integrating Ollama for LLM-based rule generation.LicenseThis project is licensed under the MIT License - see the LICENSE file for details.AcknowledgmentsDr. Zhang - Capstone Advisor, University of North Dakota
