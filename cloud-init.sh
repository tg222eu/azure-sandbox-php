#!/bin/bash
# cloud-init.sh
# First-boot setup for a HIGH-INTERACTION PHP honeypot, contained.
#
# What it stands up:
#   * A real Apache/PHP container, pinned one version behind the PHP2Shell
#     patch, so genuine exploitation attempts can land and be observed.
#   * Containment so the box cannot attack anyone: host NSG already denies
#     egress; on top of that, iptables drops container egress, while dnsmasq
#     (fake DNS) and an nginx sinkhole LOG what the attacker TRIES to fetch.
#   * Evidence capture: baseline hashes, periodic docker-diff snapshots that
#     copy out dropped files before they are deleted, plus auditd.
#   * Log delivery: binary evidence -> private Blob (managed identity); text
#     logs land in /var/log/honeypot/ for the Data Collection Rule to forward
#     to Log Analytics for KQL.
#
# NOTE: this script contains NO exploit code. It runs stock software and
# records what attackers do. Validate detections against published IOCs.
#
# Templated by main.bicep, then passed as base64 customData.
 
set -euxo pipefail
exec > /var/log/honeypot-setup.log 2>&1
 
# ---- Inputs (filled in by main.bicep before base64 encoding) ----
STORAGE_ACCOUNT="__STORAGE_ACCOUNT__"
EVIDENCE_CONTAINER="__EVIDENCE_CONTAINER__"
# Pre-patch tag. PHP2Shell was fixed in 8.4.27; 8.4.26 is the version before.
# Confirm this tag exists on Docker Hub before deploying.
PHP_IMAGE="php:8.4.26-apache"
 
LOGDIR="/var/log/honeypot"
EVID="/opt/honeypot/evidence"
mkdir -p "$LOGDIR" "$EVID"/{dropped,host,baseline}
 
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y docker.io auditd dnsmasq nginx jq curl iptables-persistent
systemctl enable --now docker auditd
 
# =============================================================================
# 1. Host monitoring: auditd records every command and writes to temp dirs.
#    This is how you see post-exploitation activity on the host side.
# =============================================================================
cat >> /etc/audit/rules.d/honeypot.rules <<'EOF'
-a always,exit -F arch=b64 -S execve -k exec
-a always,exit -F arch=b32 -S execve -k exec
-w /tmp -p wa -k drop
-w /var/tmp -p wa -k drop
-w /dev/shm -p wa -k drop
EOF
augenrules --load || true
 
# =============================================================================
# 2. The sinkhole: make the container believe it has internet, log the lies.
#    - dnsmasq answers EVERY DNS lookup with the Docker gateway (172.17.0.1)
#      and logs the domain the attacker tried to resolve.
#    - nginx on the gateway answers any HTTP/S request with a dummy file and
#      logs the full URL (so you see second-stage payload URLs) - without a
#      single byte leaving the box.
# =============================================================================
cat > /etc/dnsmasq.d/honeypot.conf <<'EOF'
no-resolv
log-queries
log-facility=/var/log/honeypot/dns-sinkhole.log
# Resolve everything to the Docker gateway so fetches hit our sinkhole.
address=/#/172.17.0.1
interface=docker0
bind-interfaces
EOF
systemctl restart dnsmasq
 
# nginx sinkhole bound to the Docker gateway only (does NOT touch eth0:80,
# which belongs to the honeypot container).
cat > /etc/nginx/sites-available/sinkhole <<'EOF'
log_format sink escape=json
  '{"ts":"$time_iso8601","src":"$remote_addr","host":"$host",'
  '"method":"$request_method","uri":"$request_uri","ua":"$http_user_agent"}';
server {
  listen 172.17.0.1:80 default_server;
  access_log /var/log/honeypot/http-sinkhole.log sink;
  location / { return 200 "ok\n"; }
}
EOF
ln -sf /etc/nginx/sites-available/sinkhole /etc/nginx/sites-enabled/sinkhole
rm -f /etc/nginx/sites-enabled/default
systemctl restart nginx
 
# =============================================================================
# 3. iptables: drop + log any container egress that is not aimed at the
#    sinkhole gateway. Defense-in-depth behind the NSG's Deny-All-Out.
# =============================================================================
# Redirect container web traffic (even to raw IPs) into the sinkhole.
iptables -t nat -A PREROUTING -i docker0 -p tcp --dport 80  -j DNAT --to-destination 172.17.0.1:80
# Log then drop everything else leaving the container subnet.
iptables -I DOCKER-USER -i docker0 ! -d 172.17.0.0/16 -j LOG --log-prefix "HP-DROP-OUT: " --log-level 4
iptables -I DOCKER-USER -i docker0 ! -d 172.17.0.0/16 -j DROP
netfilter-persistent save
 
# Send kernel iptables logs to their own file for the DCR to pick up.
echo ':msg, contains, "HP-DROP-OUT:" /var/log/honeypot/iptables-drop.log' > /etc/rsyslog.d/10-honeypot.conf
systemctl restart rsyslog
 
# =============================================================================
# 4. The honeypot container: real Apache + PHP, one version behind the patch.
#    A plain landing page (NOT exploit code) that starts a session, so the box
#    looks and behaves like an ordinary small PHP app to scanners.
# =============================================================================
mkdir -p /opt/honeypot/www
cat > /opt/honeypot/www/index.php <<'EOF'
<?php
session_start();
?>
<!doctype html><html><head><title>Account Portal</title></head>
<body><h1>Account Portal</h1><p>Please sign in to continue.</p></body></html>
EOF
 
docker pull "$PHP_IMAGE"
# --dns points the container at our sinkhole resolver.
# --cap-drop ALL and limits reduce blast radius; the filesystem stays writable
# on purpose so we can observe what attackers drop.
docker run -d --name hp-web --restart always \
  --dns 172.17.0.1 \
  --cap-drop ALL \
  --pids-limit 300 \
  --memory 512m \
  -p 80:80 \
  -v /opt/honeypot/www:/var/www/html:rw \
  "$PHP_IMAGE"
 
# =============================================================================
# 5. Baseline the container filesystem (the "before" snapshot).
# =============================================================================
sleep 5
docker exec hp-web bash -c 'find / -xdev -type f -exec sha256sum {} + 2>/dev/null' \
  > "${EVID}/baseline/baseline.sha256" || true
docker inspect hp-web > "${EVID}/baseline/container-inspect.json" || true
 
# =============================================================================
# 6. Evidence collector: every 2 minutes, diff the container against its image
#    and copy out anything added or changed BEFORE the attacker deletes it.
#    This is the "what did they install" record.
# =============================================================================
cat > /opt/honeypot/collect.sh <<'EOF'
#!/bin/bash
set -u
TS=$(date +%Y%m%d-%H%M%S)
EVID="/opt/honeypot/evidence"
OUT="${EVID}/dropped/${TS}"
mkdir -p "$OUT"
# Files added (A) or changed (C) vs the base image.
docker diff hp-web 2>/dev/null | awk '$1!="D"{print $2}' | while read -r f; do
  # Flatten the path into a filename and copy the artifact out.
  dest="${OUT}/$(echo "$f" | tr '/' '_')"
  docker cp "hp-web:$f" "$dest" 2>/dev/null || true
done
# If nothing changed, drop the empty dir.
rmdir "$OUT" 2>/dev/null || true
# Package anything collected as a password-protected zip so nothing runs by
# accident ('infected' is the analyst convention).
if [ -d "$OUT" ]; then
  zip -P infected -r -q "${OUT}.zip" "$OUT" && rm -rf "$OUT"
fi
EOF
chmod +x /opt/honeypot/collect.sh
 
# =============================================================================
# 7. Ship binary evidence to private Blob storage via managed identity.
#    Text logs stay in /var/log/honeypot for the DCR -> Log Analytics.
# =============================================================================
apt-get install -y azure-cli
cat > /opt/honeypot/ship.sh <<EOF
#!/bin/bash
set -u
az login --identity >/dev/null 2>&1 || exit 0
az storage blob upload-batch \
  --account-name ${STORAGE_ACCOUNT} \
  --destination ${EVIDENCE_CONTAINER} \
  --source ${EVID} \
  --auth-mode login --overwrite >/dev/null 2>&1 || true
EOF
chmod +x /opt/honeypot/ship.sh
 
cat > /etc/cron.d/honeypot <<'EOF'
*/2 * * * * root /opt/honeypot/collect.sh
*/5 * * * * root /opt/honeypot/ship.sh
EOF
 
echo "High-interaction honeypot ready: Apache/PHP ${PHP_IMAGE}, sinkholed, logging."