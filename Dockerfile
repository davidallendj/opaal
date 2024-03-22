FROM cgr.dev/chainguard/wolfi-base

RUN apk add --no-cache tini bash curl

# nobody 65534:65534
USER 65534:65534


COPY  opaal  /opaal

CMD [ "/opaal" ]

ENTRYPOINT [ "/sbin/tini", "--" ]
