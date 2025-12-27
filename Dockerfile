FROM gcr.io/distroless/static

ARG TARGETPLATFORM

COPY $TARGETPLATFORM/dns /usr/bin/dns
COPY default.toml /usr/bin/default.toml
COPY LICENSE.md /usr/bin/LICENSE.md
COPY README.md /usr/bin/README.md
COPY licenses /usr/bin/licenses

# Default behaviour with no arguments is to just run the dns server on port 53.
ENTRYPOINT ["/usr/bin/dns"]
CMD ["serve", "/usr/bin/default.toml"]
EXPOSE 53
