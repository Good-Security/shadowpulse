FROM alpine:3.19

# Install glibc compatibility (needed by katana which is built against glibc)
RUN apk add --no-cache gcompat

# Install Nmap, Nikto, testssl.sh, and runtime deps
RUN apk add --no-cache nmap nmap-scripts curl ca-certificates unzip bash perl nikto openssl coreutils bind-tools procps \
    perl-net-ssleay perl-io-socket-ssl

# Detect architecture for downloading correct binaries
ARG TARGETARCH=amd64

# Install Nuclei (pre-built binary)
RUN NUCLEI_VERSION=$(curl -s https://api.github.com/repos/projectdiscovery/nuclei/releases/latest | grep tag_name | cut -d '"' -f 4 | sed 's/^v//') && \
    ARCH=$(case ${TARGETARCH} in amd64) echo "amd64" ;; arm64) echo "arm64" ;; *) echo "amd64" ;; esac) && \
    curl -sL "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_${ARCH}.zip" -o /tmp/nuclei.zip && \
    unzip -o /tmp/nuclei.zip -d /usr/local/bin/ && \
    chmod +x /usr/local/bin/nuclei && \
    rm /tmp/nuclei.zip

# Install Subfinder (pre-built binary)
RUN SUBFINDER_VERSION=$(curl -s https://api.github.com/repos/projectdiscovery/subfinder/releases/latest | grep tag_name | cut -d '"' -f 4 | sed 's/^v//') && \
    ARCH=$(case ${TARGETARCH} in amd64) echo "amd64" ;; arm64) echo "arm64" ;; *) echo "amd64" ;; esac) && \
    curl -sL "https://github.com/projectdiscovery/subfinder/releases/download/v${SUBFINDER_VERSION}/subfinder_${SUBFINDER_VERSION}_linux_${ARCH}.zip" -o /tmp/subfinder.zip && \
    unzip -o /tmp/subfinder.zip -d /usr/local/bin/ && \
    chmod +x /usr/local/bin/subfinder && \
    rm /tmp/subfinder.zip

# Install httpx (pre-built binary)
RUN HTTPX_VERSION=$(curl -s https://api.github.com/repos/projectdiscovery/httpx/releases/latest | grep tag_name | cut -d '"' -f 4 | sed 's/^v//') && \
    ARCH=$(case ${TARGETARCH} in amd64) echo "amd64" ;; arm64) echo "arm64" ;; *) echo "amd64" ;; esac) && \
    curl -sL "https://github.com/projectdiscovery/httpx/releases/download/v${HTTPX_VERSION}/httpx_${HTTPX_VERSION}_linux_${ARCH}.zip" -o /tmp/httpx.zip && \
    unzip -o /tmp/httpx.zip -d /usr/local/bin/ && \
    chmod +x /usr/local/bin/httpx && \
    rm /tmp/httpx.zip

# Install katana (pre-built binary)
RUN KATANA_VERSION=$(curl -s https://api.github.com/repos/projectdiscovery/katana/releases/latest | grep tag_name | cut -d '"' -f 4 | sed 's/^v//') && \
    ARCH=$(case ${TARGETARCH} in amd64) echo "amd64" ;; arm64) echo "arm64" ;; *) echo "amd64" ;; esac) && \
    curl -sL "https://github.com/projectdiscovery/katana/releases/download/v${KATANA_VERSION}/katana_${KATANA_VERSION}_linux_${ARCH}.zip" -o /tmp/katana.zip && \
    unzip -o /tmp/katana.zip -d /usr/local/bin/ && \
    chmod +x /usr/local/bin/katana && \
    rm /tmp/katana.zip

# Install dnsx (pre-built binary)
RUN DNSX_VERSION=$(curl -s https://api.github.com/repos/projectdiscovery/dnsx/releases/latest | grep tag_name | cut -d '"' -f 4 | sed 's/^v//') && \
    ARCH=$(case ${TARGETARCH} in amd64) echo "amd64" ;; arm64) echo "arm64" ;; *) echo "amd64" ;; esac) && \
    curl -sL "https://github.com/projectdiscovery/dnsx/releases/download/v${DNSX_VERSION}/dnsx_${DNSX_VERSION}_linux_${ARCH}.zip" -o /tmp/dnsx.zip && \
    unzip -o /tmp/dnsx.zip -d /usr/local/bin/ && \
    chmod +x /usr/local/bin/dnsx && \
    rm /tmp/dnsx.zip

# Install ffuf (pre-built binary)
RUN FFUF_VERSION=$(curl -s https://api.github.com/repos/ffuf/ffuf/releases/latest | grep tag_name | cut -d '"' -f 4 | sed 's/^v//') && \
    ARCH=$(case ${TARGETARCH} in amd64) echo "amd64" ;; arm64) echo "arm64" ;; *) echo "amd64" ;; esac) && \
    curl -sL "https://github.com/ffuf/ffuf/releases/download/v${FFUF_VERSION}/ffuf_${FFUF_VERSION}_linux_${ARCH}.tar.gz" -o /tmp/ffuf.tar.gz && \
    tar -xzf /tmp/ffuf.tar.gz -C /usr/local/bin/ ffuf && \
    chmod +x /usr/local/bin/ffuf && \
    rm /tmp/ffuf.tar.gz

# Install testssl.sh
# Note: testssl.sh doesn't reliably publish GitHub "releases" tags. Use the default branch tarball.
RUN curl -fsSL "https://github.com/drwetter/testssl.sh/archive/refs/heads/master.tar.gz" -o /tmp/testssl.tar.gz && \
    mkdir -p /opt/testssl && \
    tar -xzf /tmp/testssl.tar.gz -C /opt/testssl --strip-components=1 && \
    ln -sf /opt/testssl/testssl.sh /usr/local/bin/testssl.sh && \
    chmod +x /opt/testssl/testssl.sh && \
    rm /tmp/testssl.tar.gz

# Download a common wordlist for ffuf
RUN mkdir -p /usr/share/wordlists && \
    curl -sL "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt" -o /usr/share/wordlists/common.txt && \
    curl -sL "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-small-directories.txt" -o /usr/share/wordlists/raft-small-directories.txt

# Create output directory
RUN mkdir -p /output

# Update Nuclei templates
RUN nuclei -update-templates 2>/dev/null || true

# Keep container running
CMD ["tail", "-f", "/dev/null"]
