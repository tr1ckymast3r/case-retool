FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV GHIDRA_VERSION=11.3.2
ENV JADX_VERSION=1.5.1
ENV FRIDA_VERSION=16.5.6

# System deps
RUN apt-get update && apt-get install -y \
    # Base tools
    wget curl git unzip xz-utils file \
    # Analysis tools
    strace ltrace tcpdump binutils \
    # Build tools for Ghidra
    openjdk-17-jdk-headless \
    # Python
    python3 python3-pip python3-venv \
    # Network tools
    net-tools iproute2 nmap \
    # Archive tools
    p7zip-full ar \
    # Wine for Windows binaries
    wine64 wine32 \
    # Libraries
    libssl-dev libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# --- Ghidra (headless decompiler) ---
RUN wget -q "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VERSION}_build/ghidra_${GHIDRA_VERSION}_PUBLIC_20250415.zip" \
        -O /tmp/ghidra.zip && \
    unzip -q /tmp/ghidra.zip -d /opt && \
    mv /opt/ghidra_* /opt/ghidra && \
    rm /tmp/ghidra.zip && \
    chmod +x /opt/ghidra/ghidraRun /opt/ghidra/support/analyzeHeadless

ENV PATH="/opt/ghidra/support:${PATH}"

# --- jadx (APK → Java decompiler) ---
RUN wget -q "https://github.com/skylot/jadx/releases/download/v${JADX_VERSION}/jadx-${JADX_VERSION}.zip" \
        -O /tmp/jadx.zip && \
    unzip -q /tmp/jadx.zip -d /opt/jadx && \
    chmod +x /opt/jadx/bin/jadx && \
    rm /tmp/jadx.zip

ENV PATH="/opt/jadx/bin:${PATH}"

# --- apktool (APK decode) ---
RUN wget -q "https://github.com/iBotPeaches/Apktool/releases/download/v2.10.0/apktool_2.10.0.jar" \
        -O /opt/apktool.jar && \
    echo '#!/bin/bash\njava -jar /opt/apktool.jar "$@"' > /usr/local/bin/apktool && \
    chmod +x /usr/local/bin/apktool

# --- radare2 ---
RUN git clone --depth 1 https://github.com/radareorg/radare2 /tmp/radare2 && \
    cd /tmp/radare2 && sys/install.sh && \
    rm -rf /tmp/radare2

# --- Python RE tools ---
RUN pip3 install --no-cache-dir \
    frida-tools \
    capstone \
    keystone-engine \
    unicorn \
    r2pipe \
    mitmproxy \
    pyopenssl \
    pefile \
    python-magic \
    yara-python \
    ssdeep \
    lief

# --- Frida server (for dynamic instrumentation) ---
RUN ARCH=$(dpkg --print-architecture) && \
    if [ "$ARCH" = "amd64" ]; then FRIDA_ARCH="x86_64"; else FRIDA_ARCH="arm64"; fi && \
    wget -q "https://github.com/frida/frida/releases/download/${FRIDA_VERSION}/frida-server-${FRIDA_VERSION}-linux-${FRIDA_ARCH}.xz" \
        -O /tmp/frida-server.xz && \
    xz -d /tmp/frida-server.xz && \
    mv /tmp/frida-server /opt/frida-server && \
    chmod +x /opt/frida-server

# --- binwalk ---
RUN pip3 install --no-cache-dir binwalk

# --- Create analysis user ---
RUN useradd -m -s /bin/bash analyst && \
    mkdir -p /data/input /data/output /data/scripts && \
    chown -R analyst:analyst /data

# --- Analysis scripts ---
COPY worker/scripts/ /opt/retool/scripts/
RUN chmod +x /opt/retool/scripts/*.sh /opt/retool/scripts/*.py 2>/dev/null || true

WORKDIR /data
CMD ["python3", "/opt/retool/scripts/worker.py"]
