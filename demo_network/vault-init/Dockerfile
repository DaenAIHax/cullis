FROM hashicorp/vault:1.17

# Vault's `vault` CLI is already in PATH; we just need a shell + jq.
RUN apk add --no-cache bash jq curl

COPY init.sh /usr/local/bin/init.sh
RUN chmod +x /usr/local/bin/init.sh

ENTRYPOINT ["/usr/local/bin/init.sh"]
