# expect: TG-DOCKER-FROM-001, TG-DOCKER-FROM-002, TG-DOCKER-FROM-003, TG-DOCKER-FROM-004, TG-DOCKER-FROM-005, TG-DOCKER-USER-002, TG-DOCKER-HEALTH-001
# expect: TG-DOCKER-EXPOSE-001, TG-DOCKER-EXPOSE-002, TG-DOCKER-ADD-001, TG-DOCKER-ADD-002, TG-DOCKER-COPY-001, TG-DOCKER-COPY-002, TG-DOCKER-COPY-003, TG-DOCKER-COPY-004
# expect: TG-DOCKER-RUN-001, TG-DOCKER-RUN-002, TG-DOCKER-RUN-003, TG-DOCKER-RUN-004, TG-DOCKER-RUN-005, TG-DOCKER-RUN-006, TG-DOCKER-RUN-007, TG-DOCKER-RUN-008
# expect: TG-DOCKER-RUN-009, TG-DOCKER-RUN-010, TG-DOCKER-RUN-011, TG-DOCKER-RUN-012, TG-DOCKER-TLS-001, TG-DOCKER-PKG-001, TG-DOCKER-PKG-002, TG-DOCKER-PKG-003
# expect: TG-DOCKER-PKG-004, TG-DOCKER-PKG-005, TG-DOCKER-SECRET-001, TG-DOCKER-MAINT-001, TG-DOCKER-WORKDIR-001, TG-DOCKER-CMD-001, TG-DOCKER-CMD-002, TG-DOCKER-CMD-003
# expect: TG-SEC-001
FROM --platform=linux/amd64 golang:1.22 AS build
WORKDIR src
COPY --from=build /x /y
RUN go build -o /app .

FROM golang:1.22 AS build
RUN echo dup

FROM ubuntu:latest
MAINTAINER someone@example.com
ARG NPM_TOKEN
ENV API_TOKEN=abcdef123456 GIT_SSL_NO_VERIFY=1
RUN apt-get update
RUN apt install vim && sudo apt-get install curl wget && \
    curl -sk https://example.com/install.sh | bash && \
    wget -q https://example.com/x && cd build && vim x && chmod 777 /app
RUN apt-get install -y --allow-unauthenticated libssl && \
    echo 'root:pw' | chpasswd && ln -sf /bin/bash /bin/sh
ADD app.py /app/
ADD https://example.com/tool.tgz /opt/
COPY --from=0 /app /app
COPY --chown=app:app id_rsa config.json /root
EXPOSE 22 70000
USER root
CMD ["app"]
CMD app --serve
ENTRYPOINT ["a"]
ENTRYPOINT ["b"]
