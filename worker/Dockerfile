FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# System deps
RUN apt-get update && apt-get install -y \
    wget curl git unzip xz-utils file \
    strace ltrace tcpdump binutils \
    openjdk-17-jdk-headless \
    python3 python3-pip \
    net-tools iproute2 \
    p7zip-full ar \
    libssl-dev libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# --- Ghidra (headless decompiler) ---
RUN wget -q "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.3.2_build/ghidra_11.3.2_PUBLIC_20250415.zip" \
        -O /tmp/ghidra.zip && \
    unzip -q /tmp/ghidra.zip -d /opt && \
    mv /opt/ghidra_* /opt/ghidra && \
    rm /tmp/ghidra.zip && \
    chmod +x /opt/ghidra/ghidraRun /opt/ghidra/support/analyzeHeadless

ENV PATH="/opt/ghidra/support:${PATH}"
ENV JAVA_HOME="/usr/lib/jvm/java-17-openjdk-amd64"

# --- jadx (APK → Java decompiler) ---
RUN wget -q "https://github.com/skylot/jadx/releases/download/v1.5.1/jadx-1.5.1.zip" \
        -O /tmp/jadx.zip && \
    unzip -q /tmp/jadx.zip -d /opt/jadx && \
    chmod +x /opt/jadx/bin/jadx && \
    rm /tmp/jadx.zip

ENV PATH="/opt/jadx/bin:${PATH}"

# --- apktool ---
RUN wget -q "https://github.com/iBotPeaches/Apktool/releases/download/v2.10.0/apktool_2.10.0.jar" \
        -O /opt/apktool.jar && \
    printf '#!/bin/bash\njava -jar /opt/apktool.jar "$@"\n' > /usr/local/bin/apktool && \
    chmod +x /usr/local/bin/apktool

# --- radare2 ---
RUN git clone --depth 1 https://github.com/radareorg/radare2 /tmp/radare2 && \
    cd /tmp/radare2 && sys/install.sh && \
    rm -rf /tmp/radare2

# --- Python RE tools ---
RUN pip3 install --no-cache-dir \
    frida-tools \
    capstone \
    r2pipe \
    mitmproxy \
    pefile \
    python-magic \
    yara-python \
    lief

# --- Frida server ---
RUN ARCH=$(dpkg --print-architecture) && \
    if [ "$ARCH" = "amd64" ]; then FRIDA_ARCH="x86_64"; else FRIDA_ARCH="arm64"; fi && \
    wget -q "https://github.com/frida/frida/releases/download/16.5.6/frida-server-16.5.6-linux-${FRIDA_ARCH}.xz" \
        -O /tmp/frida-server.xz && \
    xz -d /tmp/frida-server.xz && \
    mv /tmp/frida-server /opt/frida-server && \
    chmod +x /opt/frida-server

# --- Create dirs ---
RUN mkdir -p /data/input /data/output /opt/retool/scripts

COPY scripts/ /opt/retool/scripts/
RUN chmod +x /opt/retool/scripts/*.py 2>/dev/null || true

WORKDIR /data
CMD ["python3", "/opt/retool/scripts/worker.py"]
