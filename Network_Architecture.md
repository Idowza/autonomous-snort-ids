graph TD
    %% Main Network Cluster
    subgraph cluster_01 [Physical Lab Network 192.168.1.0/24]
        style cluster_01 fill:#f9f9f9,stroke:#333,stroke-width:2px
        
        Router[OPNsense Router<br/>Gateway]
        style Router fill:#ff9900,stroke:#333,stroke-width:2px

        %% Sensor Node Cluster
        subgraph cluster_02 [Sensor Node]
            style cluster_02 fill:#e1f5fe,stroke:#333,stroke-width:1px
            Kali[Kali Linux<br/>IP: 192.168.1.44]
            Snort[Snort 3 IDS]
            Promisc[Promiscuous Mode NIC]
        end
        
        %% AI Node Cluster
        subgraph cluster_03 [AI & Attack Node]
            style cluster_03 fill:#e8f5e9,stroke:#333,stroke-width:1px
            Mint[Linux Mint<br/>IP: 192.168.1.6]
            AI_Engine[Python AI Pipeline]
            Ollama[Ollama Llama 3]
            Attacker[Attack Tools<br/>Hydra, Nmap]
        end
        
        %% Physical Connections
        Router --- Kali
        Router --- Mint
    end

    %% Logical Data Flows
    Attacker -.->|Malicious Traffic| Kali
    Snort -.->|Syslog UDP 514| AI_Engine
    Promisc -.->|Raw Packets Scapy| AI_Engine
    AI_Engine == SSH/SCP New Rules ==> Kali
