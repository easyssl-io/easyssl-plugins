#!/bin/sh
# capture.sh OUT: for every case master setup.sh started under /srv/cases,
# writes OUT/<case>/{config,vhosts} (httpd's DUMP_CONFIG with mod_info loaded,
# and DUMP_VHOSTS) and OUT/<case>/files, one line per certificate or key file
# the configuration names: "<path> <kind>". Paths keep /srv/cases as @ROOT@.
# OUT then replaces testdata/cases, and `go test -run TestDiscoverCases
# -update` rewrites discover.golden from it. Run as root, with the HTTPD and
# MODULES setup.sh was given.
set -u
OUT=$1
H=${HTTPD:-/opt/httpd/bin/httpd}
MODULES=${MODULES:-$(dirname "$(dirname "$H")")/modules}
MI=$MODULES/mod_info.so
rm -rf "$OUT"; mkdir -p "$OUT"
for conf in /srv/cases/*/httpd.conf; do
  c=$(basename "$(dirname "$conf")"); d=$OUT/$c; mkdir -p "$d"
  $H -f "$conf" -t -D DUMP_CONFIG -C "LoadModule info_module $MI" 2>/dev/null | sed 's#/srv/cases#@ROOT@#g' > "$d/config"
  $H -f "$conf" -t -D DUMP_VHOSTS 2>/dev/null | sed 's#/srv/cases#@ROOT@#g' > "$d/vhosts"
  grep -hoE 'SSLCertificate(Key|Chain)?File +"?[^" ]+' "$d/config" | awk '{print $2}' | tr -d '"' | sort -u | while read -r p; do
    f=$(echo "$p" | sed 's#@ROOT@#/srv/cases#')
    [ -e "$f" ] || { echo "$p missing" >> "$d/files"; continue; }
    k=""
    grep -q 'ENCRYPTED' "$f" && k="$k,encrypted"
    grep -q 'PRIVATE KEY' "$f" && k="$k,key"
    if grep -q 'BEGIN CERTIFICATE' "$f"; then
      a=$(openssl x509 -in "$f" -noout -text | grep -m1 'Public Key Algorithm' | grep -q rsa && echo rsa || echo ec)
      k="$k,cert-$a,$(openssl x509 -in "$f" -noout -pubkey | sha256sum | cut -c1-8)"
    elif ! echo "$k" | grep -q encrypted; then
      k="$k,$(openssl pkey -in "$f" -pubout 2>/dev/null | sha256sum | cut -c1-8)"
    fi
    echo "$p ${k#,}" >> "$d/files"
  done
done
