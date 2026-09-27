# ============================================================
# ZANGBETO ORCHESTRATOR - GOVERNMENT-GRADE SANDBOX
# Base: Kali Linux Rolling (The Industry Standard for Security)
# ============================================================

FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1

# ------------------------------------------------------------
# 1. UPDATE KALI AND INSTALL CORE UTILITIES + MASSIVE TOOLSET
# ------------------------------------------------------------
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Core Utilities
    bash \
    ca-certificates \
    curl \
    wget \
    git \
    vim \
    nano \
    less \
    file \
    unzip \
    zip \
    jq \
    tree \
    procps \
    psmisc \
    lsof \
    htop \
    sudo \
    net-tools \
    iproute2 \
    iputils-ping \
    traceroute \
    socat \
    netcat-openbsd \
    tcpdump \
    openssl \
    python3 \
    python3-pip \
    python3-venv \
    \
    # Build Dependencies for Python Packages (Added to fix the build error)
    build-essential \
    cmake \
    pkg-config \
    libssl-dev \
    libffi-dev \
    python3-dev \
    libyara-dev \
    \
    # Blue Team (Defense & Forensics)
    # NOTE: We use tshark (CLI) instead of wireshark (GUI) to avoid GUI dependencies.
    tshark \
    suricata \
    clamav \
    yara \
    chkrootkit \
    rkhunter \
    lynis \
    aide \
    auditd \
    ufw \
    fail2ban \
    sleuthkit \
    binwalk \
    foremost \
    exiftool \
    \
    # Red Team (Authorized Penetration Testing)
    nmap \
    masscan \
    arp-scan \
    netdiscover \
    nikto \
    sqlmap \
    dirb \
    gobuster \
    wfuzz \
    ffuf \
    hydra \
    john \
    aircrack-ng \
    reaver \
    snmp \
    smbclient \
    ldap-utils \
    krb5-user \
    hping3 \
    && rm -rf /var/lib/apt/lists/*

# ------------------------------------------------------------
# 2. INSTALL METASPLOIT FRAMEWORK SEPARATELY
# This is a massive package, so we isolate it. If it fails, the
# rest of the sandbox still builds successfully.
# ------------------------------------------------------------
RUN apt-get update && apt-get install -y --no-install-recommends \
    metasploit-framework \
    exploitdb \
    && rm -rf /var/lib/apt/lists/*

# ------------------------------------------------------------
# 3. INSTALL PYTHON SECURITY LIBRARIES
# ------------------------------------------------------------
RUN pip3 install --no-cache-dir --break-system-packages \
    requests \
    urllib3 \
    cryptography \
    dnspython \
    psutil \
    impacket \
    scapy \
    pwntools \
    volatility3

# ------------------------------------------------------------
# 4. WORKSPACE SETUP
# ------------------------------------------------------------
RUN mkdir -p \
    /opt/security \
    /opt/security/scripts \
    /opt/security/logs \
    /opt/security/reports \
    /opt/security/samples \
    /opt/security/pcaps \
    /opt/security/evidence \
    /opt/security/threat-intel \
    /opt/security/scans

WORKDIR /opt/security

# ------------------------------------------------------------
# 5. KEEP CONTAINER ALIVE
# ------------------------------------------------------------
CMD ["sleep", "infinity"]