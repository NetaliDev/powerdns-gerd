FROM alpine:edge

RUN apk --update --no-cache add pdns pdns-backend-sqlite3 && \
    rm -rf /var/cache/apk/*

RUN mkdir /pdns && \
    chmod 755 -R /pdns && \
    chown -R pdns:pdns /pdns

ADD ./schema.sql /
ADD ./entrypoint.sh /
ADD ./pdns.conf /etc/pdns/

RUN mkdir -p /var/empty/var/run/ && \
    chmod +x /entrypoint.sh

EXPOSE 53/udp 53/tcp 8081/tcp

CMD ["/entrypoint.sh"]
