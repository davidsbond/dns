FROM gcr.io/distroless/static

ARG TARGETPLATFORM

COPY $TARGETPLATFORM/dns /usr/bin/dns

# Default behaviour with no arguments is to just run the dns server on port 53.
ENTRYPOINT ["/usr/bin/dns"]
CMD ["serve", "--addr", ":53"]
EXPOSE 53
