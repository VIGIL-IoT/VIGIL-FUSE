ARG BASE_IMAGE=ubuntu@sha256:66460d557b25769b102175144d538d88219c077c678a49af4afca6fbfc1b5252
FROM ${BASE_IMAGE}
COPY syft /usr/local/bin/syft
RUN chmod 0555 /usr/local/bin/syft
ENTRYPOINT ["syft"]
