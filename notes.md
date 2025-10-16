# Ping Sweep Test
```bash
for i in {1..15}; do ping -c 1 192.168.1.44; done
```

# Nmap test
```bash
sudo nmap -sF 192.168.1.44
```

# SSH Brute Force
```bash
hydra -l root -P /usr/share/wordlists/rockyou.txt -t 5 ssh://192.168.1.44
```

# Read live log in terminal
```bash
sudo tail -f /var/log/snort/alert_fast.txt
```

# Start snort
```bash
sudo snort -c /etc/snort/snort.lua -R /etc/snort/rules/local.rules -i eth0 -k none -l /var/log/snort
```

# Install scikit-learn
```bash
sudo apt-get install python3-sklearn python3-sklearn-lib python-sklearn-doc
```

# Run Llama 3 with Ollama
```bash
ollama run llama3
```

# View live log on Mint machine (from Kali)
```bash
sudo tail -f /var/log/snort_alerts.log
```
