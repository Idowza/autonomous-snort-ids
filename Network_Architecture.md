Network Architecture Diagramgraph TD
    %% Main Network Cluster
    subgraph "Physical Lab Network (192.168.1.0/24)"
        
        Router("OPNsense Router<br/>(Gateway)")
        style Router fill:#ff9900,stroke:#333,stroke-width:2px

        %% Sensor Node Cluster
        subgraph "Sensor Node"
            Kali("Kali Linux<br/>IP: 192.168.1.44")
            Snort["Snort 3 IDS"]
            Promisc["Promiscuous Mode NIC"]
            style Kali fill:#e1f5fe
        end
        
        %% AI Node Cluster
        subgraph "AI & Attack Node"
            Mint("Linux Mint<br/>IP: 192.168.1.6")
            AI_Engine["Python AI Pipeline"]
            Ollama["Ollama (Llama 3)"]
            Attacker["Attack Tools<br/>(Hydra, Nmap)"]
            style Mint fill:#e8f5e9
        end
        
        %% Physical Connections
        Router --- Kali
        Router --- Mint
    end

    %% Logical Data Flows
    Attacker -.->|Malicious Traffic| Kali
    Snort -.->|Syslog UDP 514| AI_Engine
    Promisc -.->|Raw Packets (Scapy)| AI_Engine
    AI_Engine == "SSH/SCP (New Rules)" ==> Kali
