# Test-only OpenSSH target with linux-pam passwd for the ssh_passwd connector (spec §13 1A).
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends openssh-server passwd \
    && rm -rf /var/lib/apt/lists/* && mkdir -p /run/sshd \
    && rm -f /etc/ssh/ssh_host_*_key* && ssh-keygen -q -t ed25519 -N '' -f /etc/ssh/ssh_host_ed25519_key
COPY sshd_config /etc/ssh/sshd_config
# A login shell that answers every command with a prompt passwd never shows.
COPY oddshell recordshell /usr/local/bin/
RUN chmod 0755 /usr/local/bin/oddshell /usr/local/bin/recordshell \
    && printf '/usr/local/bin/oddshell\n/usr/local/bin/recordshell\n' >> /etc/shells
EXPOSE 22
CMD ["/usr/sbin/sshd", "-D", "-e"]
