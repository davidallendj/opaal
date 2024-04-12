FROM cgr.dev/chainguard/wolfi-base

RUN apk add --no-cache tini bash curl

RUN mkdir -p /opaal/pages/static/stylesheets
RUN chown 65534:65534 /opaal
WORKDIR /opaal

# nobody 65534:65534
USER 65534:65534

COPY opaal /opaal/opaal
COPY pages/* /opaal/pages/


CMD [ "/opaal/opaal" ]

ENTRYPOINT [ "/sbin/tini", "--" ]
