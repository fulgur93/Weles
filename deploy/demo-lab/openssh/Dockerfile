# OpenSSH 7.9p1 (Alpine 3.9, 2019). Serwer przyjmuje tylko klucze, a żadnego klucza nie ma –
# do pokazu wystarczy baner wersji, logowanie jest niemożliwe.
FROM alpine:3.9
RUN apk add --no-cache openssh-server=7.9_p1-r6 \
 && ssh-keygen -A \
 && sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/; s/^#\?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
EXPOSE 22
CMD ["/usr/sbin/sshd", "-D", "-e"]
