#!/bin/sh
# Provision a throwaway domain KYG.TEST on dc1 and serve LDAPS on 636 with the test's own
# CA and server certificate from /tls (Samba's generated one has no SAN). Test-only
# credentials. Samba, unlike AD for LDAP simple binds, accepts the previous password for an
# hour by default; the tests turn that off so "the old password no longer authenticates".
set -eu
rm -f /etc/samba/smb.conf
install -d -m 0700 /var/lib/samba/private/tls
install -m 0600 /tls/key.pem /var/lib/samba/private/tls/key.pem
install -m 0644 /tls/cert.pem /tls/ca.pem /var/lib/samba/private/tls/
samba-tool domain provision --realm=KYG.TEST --domain=KYG --server-role=dc \
  --dns-backend=SAMBA_INTERNAL --adminpass='Admin-Passw0rd!' \
  --option='tls enabled = yes' \
  --option='tls keyfile = /var/lib/samba/private/tls/key.pem' \
  --option='tls certfile = /var/lib/samba/private/tls/cert.pem' \
  --option='tls cafile = /var/lib/samba/private/tls/ca.pem' >/dev/null
sed -i 's/^\[global\]$/[global]\n\told password allowed period = 0/' /etc/samba/smb.conf
# Count bad passwords (tests check one wrong bind is one attempt); never lock anyone out here.
samba-tool domain passwordsettings set --account-lockout-threshold=100 >/dev/null
echo ready > /tmp/provisioned
exec samba --foreground --no-process-group
