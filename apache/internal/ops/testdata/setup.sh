#!/bin/bash
# Builds and starts one throwaway Apache master per configuration that
# testdata/cases records, each under /srv/cases/<case>, all from one httpd
# binary. capture.sh then records what that httpd reports for each, and
# discover.golden is what discover answers for them.
#
# Usage (as root):  bash setup.sh          build and start every case
#                   bash setup.sh stop     stop every case and delete /srv/cases
#
# HTTPD is the binary (default /opt/httpd/bin/httpd, a build from source) and
# MODULES the directory of its shared modules (default the build's modules/);
# a distribution's httpd needs both, e.g. HTTPD=/usr/sbin/apache2
# MODULES=/usr/lib/apache2/modules on Debian and Ubuntu.
#
# Every case's httpd.conf starts with the same 19 lines whatever the build,
# because discover.golden cites lines of it: a module the binary has built in
# leaves a comment in its place, and the first such place loads the MPM when
# none is built in.
#
# Cases G, V3 and X1 listen on 192.168.5.15, the address of the host they
# were recorded on; elsewhere those masters do not start.
set -e
B=/srv/cases
H=${HTTPD:-/opt/httpd/bin/httpd}
MODULES=${MODULES:-$(dirname "$(dirname "$H")")/modules}

stop_all() {
  for p in $B/*/httpd.pid; do [ -f "$p" ] && kill -TERM "$(cat "$p")" 2>/dev/null || true; done
  sleep 2; rm -rf $B
}
[ "${1:-}" = stop ] && { stop_all; exit 0; }
[ -x "$H" ] && [ -f "$MODULES/mod_ssl.so" ] || { echo "no httpd at $H with mod_ssl.so in $MODULES; set HTTPD and MODULES" >&2; exit 1; }

# The five module lines of every case's head.
builtin=$("$H" -l)
mpm=""
echo "$builtin" | grep -qE '^ *(event|worker|prefork)\.c$' || mpm="LoadModule mpm_event_module $MODULES/mod_mpm_event.so"
MODS=()
for m in authz_core unixd socache_shmcb ssl remoteip; do
  if echo "$builtin" | grep -q "^ *mod_$m\.c$"; then
    if [ -n "$mpm" ]; then line=$mpm; mpm=""; else line="# mod_$m is built in"; fi
  else
    line="LoadModule ${m}_module $MODULES/mod_$m.so"
  fi
  MODS+=("$line")
done
[ -z "$mpm" ] || { echo "this httpd has no MPM and no built-in module whose line could load one" >&2; exit 1; }

stop_all; mkdir -p $B

# cert DIR NAME [rsa|ec]: DIR/NAME.crt and DIR/NAME.key for NAME.test
cert() {
  local alg=(-newkey ec -pkeyopt ec_paramgen_curve:P-256); [ "${3:-ec}" = rsa ] && alg=(-newkey rsa:2048)
  openssl req -x509 "${alg[@]}" -nodes -days 30 -subj "/CN=$2.test" -addext "subjectAltName=DNS:$2.test" \
    -keyout "$1/$2.key" -out "$1/$2.crt" 2>/dev/null
  chmod 600 "$1/$2.key"
}
# conf CASE: writes the common head of CASE's httpd.conf, then stdin
conf() {
  local D=$B/$1; mkdir -p $D
  { cat <<EOF
ServerRoot "$(dirname "$MODULES")"
$(printf '%s\n' "${MODS[@]}")
User daemon
Group daemon
ServerName localhost
StartServers 1
ServerLimit 1
ThreadsPerChild 4
MinSpareThreads 1
MaxSpareThreads 4
MaxRequestWorkers 4
PidFile $D/httpd.pid
ErrorLog $D/error_log
DefaultRuntimeDir $D
DocumentRoot $D
EOF
    cat; } > $D/httpd.conf
}
vh() { # vh ADDR NAME CERTDIR CERT [extra lines...]: a TLS vhost
  local addr=$1 name=$2 d=$3 c=$4; shift 4
  echo "<VirtualHost $addr>"
  [ -n "$name" ] && echo "  ServerName $name"
  echo "  SSLEngine on"
  echo "  SSLCertificateFile $d/$c.crt"
  echo "  SSLCertificateKeyFile $d/$c.key"
  for l in "$@"; do echo "  $l"; done
  echo "</VirtualHost>"
}

# A. a plain, sound vhost: the control case
D=$B/A; mkdir -p $D; cert $D a
conf A <<EOF
Listen 9441
$(vh '*:9441' a.test $D a)
EOF

# B. two vhosts with the same ServerName: the second is never selected
D=$B/B; mkdir -p $D; cert $D b1; cert $D b2
conf B <<EOF
Listen 9442
$(vh '*:9442' dup.test $D b1)
$(vh '*:9442' dup.test $D b2)
EOF

# C. a ServerName already claimed by an earlier vhost's ServerAlias (c2), and a
#    shadowed ServerName still reachable through its own unique alias (c3)
D=$B/C; mkdir -p $D; cert $D c1; cert $D c2; cert $D c3
conf C <<EOF
Listen 9443
$(vh '*:9443' c1.test $D c1 'ServerAlias c2.test')
$(vh '*:9443' c2.test $D c2)
$(vh '*:9443' c1.test $D c3 'ServerAlias c3.test')
EOF

# D. a ServerName that is an IP address, on a vhost that is not the default
D=$B/D; mkdir -p $D; cert $D d1; cert $D d2
conf D <<EOF
Listen 9444
$(vh '*:9444' d1.test $D d1)
$(vh '*:9444' 127.0.0.1 $D d2)
EOF

# E. two vhosts without ServerName on one port
D=$B/E; mkdir -p $D; cert $D e1; cert $D e2
conf E <<EOF
Listen 9445
$(vh '*:9445' '' $D e1)
$(vh '*:9445' '' $D e2)
EOF

# F. two _default_ vhosts on one port
D=$B/F; mkdir -p $D; cert $D f1; cert $D f2
conf F <<EOF
Listen 9446
$(vh '_default_:9446' '' $D f1)
$(vh '_default_:9446' '' $D f2)
EOF

# G. an exact-address vhost and a * vhost on one port: each is reachable, at a different address
D=$B/G; mkdir -p $D; cert $D g1; cert $D g2
conf G <<EOF
Listen 9447
$(vh '127.0.0.1:9447' g1.test $D g1)
$(vh '*:9447' g2.test $D g2)
EOF

# H. a vhost on a port nothing listens on
D=$B/H; mkdir -p $D; cert $D h; cert $D hx
conf H <<EOF
Listen 9461
$(vh '*:9461' hx.test $D hx)
$(vh '*:9448' h.test $D h)
EOF

# I. a certificate in a vhost with SSLEngine off
D=$B/I; mkdir -p $D; cert $D i
conf I <<EOF
Listen 9449
<VirtualHost *:9449>
  ServerName i.test
  SSLEngine off
  SSLCertificateFile $D/i.crt
  SSLCertificateKeyFile $D/i.key
</VirtualHost>
EOF

# J. a TLS vhost on a port whose default vhost is plain HTTP
D=$B/J; mkdir -p $D; cert $D j2
conf J <<EOF
Listen 9450
<VirtualHost *:9450>
  ServerName j1.test
</VirtualHost>
$(vh '*:9450' j2.test $D j2)
EOF

# K. two RSA certificates in one vhost
D=$B/K; mkdir -p $D; cert $D k1 rsa; cert $D k2 rsa
conf K <<EOF
Listen 9451
<VirtualHost *:9451>
  ServerName k.test
  SSLEngine on
  SSLCertificateFile $D/k1.crt
  SSLCertificateKeyFile $D/k1.key
  SSLCertificateFile $D/k2.crt
  SSLCertificateKeyFile $D/k2.key
</VirtualHost>
EOF

# L. one certificate file paired with two different key files
D=$B/L; mkdir -p $D; cert $D l; cp -p $D/l.key $D/l-copy.key
conf L <<EOF
Listen 9452
<VirtualHost *:9452>
  ServerName l1.test
  SSLEngine on
  SSLCertificateFile $D/l.crt
  SSLCertificateKeyFile $D/l.key
</VirtualHost>
<VirtualHost *:9452>
  ServerName l2.test
  SSLEngine on
  SSLCertificateFile $D/l.crt
  SSLCertificateKeyFile $D/l-copy.key
</VirtualHost>
EOF

# M. a vhost still using SSLCertificateChainFile
D=$B/M; mkdir -p $D; cert $D m; cert $D mca
conf M <<EOF
Listen 9453
$(vh '*:9453' m.test $D m "SSLCertificateChainFile $D/mca.crt")
EOF

# N. a passphrase-protected key, supplied by an exec: program
D=$B/N; mkdir -p $D; cert $D n
openssl pkey -in $D/n.key -aes256 -passout pass:secret -out $D/n.enc && mv $D/n.enc $D/n.key && chmod 600 $D/n.key
printf '#!/bin/sh\necho secret\n' > $D/pass.sh; chmod 700 $D/pass.sh
conf N <<EOF
SSLPassPhraseDialog exec:$D/pass.sh
Listen 9454
$(vh '*:9454' n.test $D n)
EOF

# O. a vhost behind the PROXY protocol
D=$B/O; mkdir -p $D; cert $D o
conf O <<EOF
Listen 9455
$(vh '*:9455' o.test $D o 'RemoteIPProxyProtocol On')
EOF

# P. a configuration edited after the master started (the edit is made below)
D=$B/P; mkdir -p $D; cert $D p
conf P <<EOF
Listen 9456
$(vh '*:9456' p.test $D p)
EOF

# R. one certificate file loaded by two separate masters
D=$B/R; mkdir -p $D; cert $D r
conf R1 <<EOF
Listen 9457
$(vh '*:9457' r.test $D r)
EOF
conf R2 <<EOF
Listen 9458
$(vh '*:9458' r.test $D r)
EOF

# S. a server-level certificate inherited by a vhost with none of its own
D=$B/S; mkdir -p $D; cert $D s
conf S <<EOF
Listen 9459
SSLCertificateFile $D/s.crt
SSLCertificateKeyFile $D/s.key
<VirtualHost *:9459>
  ServerName s.test
  SSLEngine on
</VirtualHost>
EOF

# T. the private key inside the certificate file, with no SSLCertificateKeyFile
D=$B/T; mkdir -p $D; cert $D t; cat $D/t.key >> $D/t.crt; rm $D/t.key; chmod 600 $D/t.crt
conf T <<EOF
Listen 9460
<VirtualHost *:9460>
  ServerName t.test
  SSLEngine on
  SSLCertificateFile $D/t.crt
</VirtualHost>
EOF

# U. an RSA and an ECDSA certificate in one vhost: each is served to a client asking for its type
D=$B/U; mkdir -p $D; cert $D ursa rsa; cert $D uec ec
conf U <<EOF
Listen 9470
<VirtualHost *:9470>
  ServerName u.test
  SSLEngine on
  SSLCertificateFile $D/ursa.crt
  SSLCertificateKeyFile $D/ursa.key
  SSLCertificateFile $D/uec.crt
  SSLCertificateKeyFile $D/uec.key
</VirtualHost>
EOF

# V1. an IPv6 vhost; V2. a * vhost that only an IPv6 Listen opens; V3. a * vhost behind Listen [::]
D=$B/V; mkdir -p $D; cert $D v1; cert $D v2; cert $D v3
conf V1 <<EOF
Listen [::1]:9471
$(vh '[::1]:9471' v1.test $D v1)
EOF
conf V2 <<EOF
Listen [::1]:9472
$(vh '*:9472' v2.test $D v2)
EOF
conf V3 <<EOF
Listen [::]:9473
$(vh '*:9473' v3.test $D v3)
EOF

# W. a vhost with a wildcard port, behind two Listen ports
D=$B/W; mkdir -p $D; cert $D w
conf W <<EOF
Listen 9474
Listen 9484
$(vh '*:*' w.test $D w)
EOF

# X1. a vhost on two addresses, both open; X2. a vhost on two addresses, one never opened
D=$B/X; mkdir -p $D; cert $D x1; cert $D x2
conf X1 <<EOF
Listen 127.0.0.1:9475
Listen 192.168.5.15:9476
$(vh '127.0.0.1:9475 192.168.5.15:9476' x1.test $D x1)
EOF
conf X2 <<EOF
Listen 9477
$(vh '*:9477 *:9478' x2.test $D x2)
EOF

# Y. wildcard ServerAlias: y2 is taken by y1's *.y.test; y3 is reachable only through *.y3.test
D=$B/Y; mkdir -p $D; cert $D y1; cert $D y2; cert $D y3
conf Y <<EOF
Listen 9479
$(vh '*:9479' y1.test $D y1 'ServerAlias *.y.test')
$(vh '*:9479' www.y.test $D y2)
$(vh '*:9479' y1.test $D y3 'ServerAlias *.y3.test')
EOF

# Z. SSLEngine optional (an RFC 2817 upgrade, not TLS from the first byte)
D=$B/Z; mkdir -p $D; cert $D z
conf Z <<EOF
Listen 9480
<VirtualHost *:9480>
  ServerName z.test
  SSLEngine optional
  SSLCertificateFile $D/z.crt
  SSLCertificateKeyFile $D/z.key
</VirtualHost>
EOF

# AA. TLS on the main server, with no vhost at all
D=$B/AA; mkdir -p $D; cert $D aa
conf AA <<EOF
Listen 9481
SSLEngine on
SSLCertificateFile $D/aa.crt
SSLCertificateKeyFile $D/aa.key
EOF

# AB. a server-level certificate nothing serves: the only vhost has its own, and the main server no TLS
D=$B/AB; mkdir -p $D; cert $D ab; cert $D abv
conf AB <<EOF
Listen 9482
SSLCertificateFile $D/ab.crt
SSLCertificateKeyFile $D/ab.key
$(vh '*:9482' abv.test $D abv)
EOF

ALL="A B C D E F G H I J K L M N O P R1 R2 S T U V1 V2 V3 W X1 X2 Y Z AA AB"
for c in $ALL; do
  if ! out=$($H -f $B/$c/httpd.conf -k start 2>&1); then echo "$c: did not start: $out"; fi
done
# Past the slack discovery allows between a master writing its PidFile and an
# edit it counts as part of that load.
sleep 4
echo "# edited after start" >> $B/P/httpd.conf
for c in $ALL; do
  p=$(cat $B/$c/httpd.pid 2>/dev/null); kill -0 "$p" 2>/dev/null && echo "$c: master $p" || echo "$c: NOT RUNNING"
done
