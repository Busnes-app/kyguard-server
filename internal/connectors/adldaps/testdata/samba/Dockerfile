# Test-only Samba AD DC for the ad_ldaps connector tests (spec §13 Phase 1A).
FROM alpine:3.22
RUN apk add --no-cache samba-dc py3-cryptography openssl
COPY entrypoint.sh /entrypoint.sh
EXPOSE 636
ENTRYPOINT ["/bin/sh", "/entrypoint.sh"]
