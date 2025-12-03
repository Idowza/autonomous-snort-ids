graph TD
    subgraph "Physical Lab Network (192.168.1.0/24)"
        Router[OPNsense Router<br/>Gateway]
        
        subgraph "Sensor Node"
            Kali[Kali Linux<br/>IP: 192.168.1.44]
            Snort[Snort 3 IDS]
            Promisc[Promiscuous Mode NIC]
        end
        
        subgraph "AI & Attack Node"
            Mint[Linux Mint<br/>IP: 192.168.1.6]
            AI_Engine[Python AI Pipeline]
            Ollama[Ollama (Llama 3)]
            Attacker[Attack Tools<br/>Hydra, Nmap]
        end
        
        Router --- Kali
        Router --- Mint
    end

    %% Data Flows
    Attacker -- "Malicious Traffic" --> Kali
    Snort -- "Syslog (UDP 514)" --> AI_Engine
    Promisc -- "Raw Packets (Scapy)" --> AI_Engine
    AI_Engine -- "SSH/SCP (New Rules)" --> Kali