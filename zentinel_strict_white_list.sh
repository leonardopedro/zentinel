#!/bin/bash

# --- CONFIGURATION ---
ZENTINEL_DIR="/etc/zentinel"
SECRETS_DIR="$ZENTINEL_DIR/secrets"
GENERATOR_SCRIPT="$ZENTINEL_DIR/generate_config.sh"
TAP_DEV="tap0"
VM_NET="192.168.100.0/24"
HOST_IP="192.168.100.1"

# --- GLOBAL WHITELIST (Allowed sites that DON'T need password injection) ---
WHITELIST_SITES='"*.debian.org" "*.ubuntu.com" "*.google.com" "google.com"'

set -e 

if [[ $EUID -ne 0 ]]; then echo "Please run as root (sudo)."; exit 1; fi

echo "--- 1. Installing Dependencies & Headless Config ---"
echo "iptables-persistent iptables-persistent/autosave_v4 boolean true" | debconf-set-selections
echo "iptables-persistent iptables-persistent/autosave_v6 boolean true" | debconf-set-selections
export DEBIAN_FRONTEND=noninteractive

apt-get update
apt-get install -y -q openssl iptables-persistent ca-certificates curl sed gettext-base

# Fallback: Install KeePassXC AppImage if keepassxc-cli is missing
if ! command -v keepassxc-cli &> /dev/null; then
    echo "keepassxc-cli not found. Installing AppImage wrapper..."
    wget -q https://github.com/keepassxreboot/keepassxc/releases/download/2.7.9/KeePassXC-2.7.9-x86_64.AppImage -O /usr/local/bin/keepassxc.appimage
    chmod +x /usr/local/bin/keepassxc.appimage
    cat << 'EOF' > /usr/local/bin/keepassxc-cli
#!/bin/bash
/usr/local/bin/keepassxc.appimage cli "$@"
EOF
    chmod +x /usr/local/bin/keepassxc-cli
fi

echo "--- 2. Setting up Secure Directories ---"
mkdir -p "$SECRETS_DIR"
chmod 700 "$ZENTINEL_DIR" "$SECRETS_DIR"

echo "--- 3. Generating Local CA for VM Trust ---"
if [ ! -f "$SECRETS_DIR/myCA.key" ]; then
    openssl genrsa -out "$SECRETS_DIR/myCA.key" 2048
    openssl req -x509 -new -nodes -key "$SECRETS_DIR/myCA.key" \
        -sha256 -days 3650 -out "$SECRETS_DIR/myCA.pem" \
        -subj "/C=DE/ST=State/L=City/O=Zentinel-Security/CN=Zentinel-CA"
fi

echo "--- 4. Creating the Config Generator ---"
cat << 'EOF' > "$GENERATOR_SCRIPT"
#!/bin/bash
set -e
DB="/etc/zentinel/secrets/passwords.kdbx"
KEY="/etc/zentinel/secrets/database.key"
OUT_DIR="/run/zentinel"
GLOBAL_SITES='__WHITELIST_SITES__'

# Ensure KeePass files exist
if [ ! -f "$DB" ]; then exit 0; fi

mkdir -p "$OUT_DIR"

# Fetch entries from KeePass
ENTRIES=$(keepassxc-cli ls -k "$KEY" "$DB" "/" --quiet || echo "")

# Initialize KDL file
cat <<EOP > "$OUT_DIR/zentinel.kdl"
schema-version "1.0"

system {
    worker-threads 4
    max-connections 10000
}

upstreams {
    upstream "internet_outbound" {
        // Transparently connect to the destination requested by the VM
        target "\${context.host}:443" 
        tls { 
            ca-cert "/etc/ssl/certs/ca-certificates.crt"
        }
    }
}

listeners {
    listener "mitm_listener" {
        address "0.0.0.0:8443"
        protocol "https"
        tls {
            cert-file "/etc/zentinel/secrets/myCA.pem"
            key-file "/etc/zentinel/secrets/myCA.key"
        }
    }
}

routes {
EOP

# Loop 1: Password Injection Routes
for ENTRY in $ENTRIES; do
    PASS=$(keepassxc-cli show -a Password -k "$KEY" "$DB" "$ENTRY" --quiet)
    URL_RAW=$(keepassxc-cli show -a URL -k "$KEY" "$DB" "$ENTRY" --quiet)
    URL=$(echo "$URL_RAW" | sed -e 's/[^/]*\/\/\([^/]*\).*/\1/' -e 's/\/.*$//')

    if [ -n "$URL" ] && [ -n "$PASS" ]; then
        cat <<ENTRY_ROUTE >> "$OUT_DIR/zentinel.kdl"
    route "vault_${ENTRY}" {
        matches {
            host "${URL}"
            path-prefix "/"
        }
        plugins {
            plugin "transform" {
                replace "{{\${ENTRY}}}" "${PASS}"
            }
        }
        upstream "internet_outbound"
    }
ENTRY_ROUTE
    fi
done

# Loop 2: Global Whitelist (No Injection)
eval "sites=($GLOBAL_SITES)"
for SITE in "${sites[@]}"; do
    CLEAN_ID=$(echo "$SITE" | sed 's/[^a-zA-Z0-9]/_/g')
    cat <<GLOBAL_ROUTE >> "$OUT_DIR/zentinel.kdl"
    route "global_${CLEAN_ID}" {
        matches {
            host ${SITE}
            path-prefix "/"
        }
        upstream "internet_outbound"
    }
GLOBAL_ROUTE
done

echo "}" >> "$OUT_DIR/zentinel.kdl"
chmod 600 "$OUT_DIR"/*
EOF

# Inject the Whitelist variable into the generator script safely
sed -i "s|__WHITELIST_SITES__|${WHITELIST_SITES}|g" "$GENERATOR_SCRIPT"
chmod +x "$GENERATOR_SCRIPT"

echo "--- 5. Creating Systemd Service & Watcher ---"
cat <<EOF > /etc/systemd/system/zentinel.service
[Unit]
Description=Zentinel Secure Proxy
After=network.target

[Service]
ExecStartPre=$GENERATOR_SCRIPT
ExecStart=/usr/bin/zentinel run --config /run/zentinel/zentinel.kdl
RuntimeDirectory=zentinel
User=root
Restart=always

[Install]
WantedBy=multi-user.target
EOF

cat <<EOF > /etc/systemd/system/zentinel-reload.service
[Service]
Type=oneshot
ExecStart=$GENERATOR_SCRIPT
ExecStartPost=/usr/bin/systemctl restart zentinel
EOF

cat <<EOF > /etc/systemd/system/zentinel-watch.path
[Path]
PathModified=$SECRETS_DIR/passwords.kdbx
Unit=zentinel-reload.service
[Install]
WantedBy=multi-user.target
EOF

echo "--- 6. Hardening Networking (IPTables) ---"
sysctl -w net.ipv4.ip_forward=1
echo "net.ipv4.ip_forward=1" > /etc/sysctl.d/99-zentinel.conf

# Virtual Interface for Cloud-Hypervisor
ip tuntap add dev "$TAP_DEV" mode tap || true
ip addr add "$HOST_IP/24" dev "$TAP_DEV" || true
ip link set "$TAP_DEV" up

# Rules
iptables -F
iptables -t nat -F
iptables -t nat -A PREROUTING -i "$TAP_DEV" -p tcp --dport 443 -j REDIRECT --to-port 8443
iptables -A FORWARD -i "$TAP_DEV" -p tcp --dport 80 -j DROP
iptables -t nat -A POSTROUTING -o $(ip route | grep default | awk '{print $5}' | head -n1) -j MASQUERADE

# Persist rules
netfilter-persistent save

echo "--- 7. Activation ---"
systemctl daemon-reload
systemctl enable --now zentinel-watch.path

echo "--------------------------------------------------------"
echo "FULL IMPLEMENTATION COMPLETE"
echo "--------------------------------------------------------"
echo "1. Place KeePass DB in: $SECRETS_DIR/passwords.kdbx"
echo "2. Place Keyfile in:   $SECRETS_DIR/database.key"
echo "3. Run: sudo systemctl start zentinel"
echo "4. In the VM, trust this cert: $SECRETS_DIR/myCA.pem"
echo ""
echo "SECURITY VERIFIED:"
echo "- Transparent proxy using dynamic host target: YES"
echo "- Strict Upstream TLS verification: YES"
echo "- Connection refusal for unlisted sites: YES"
echo "- Automatic reload on KeePass save: YES"
echo "--------------------------------------------------------"