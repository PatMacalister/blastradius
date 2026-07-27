# BlastRadius — container image.
#
# Two distinct uses, and it is worth being clear which is which, because this project is a
# CLI rather than a web service and "deploy it" means something different here than it does
# for a landing page:
#
#   1. Running a scan without installing Node — in CI, or against a mounted directory.
#   2. Hosting the *drift machinery* (changelog watcher, contract tests) on a VPS, which is
#      the Phase 2 maintenance strategy from DRIFT-AND-OSS-PLAN.md.
#
# What this image deliberately is NOT: a service that accepts other people's credentials
# over a network. That shape is ruled out in 03-execution-plan.md under non-goals, and it
# would make the tool the exact thing it warns about. Everything here either scans a locally
# mounted path or talks outward to provider APIs.
#
# BlastRadius has no runtime dependencies, so there is nothing to install and no build stage.

FROM node:22-alpine

# Tini gives us correct signal handling, so `docker compose stop` does not leave a scan
# half-finished holding a credential in memory.
RUN apk add --no-cache tini

WORKDIR /app

COPY package.json ./
COPY src ./src
COPY tools ./tools
COPY test ./test

# The changelog watcher keeps "what have I already reported" state here. Owned by the node
# user so the container can write it when a volume is mounted over the top.
RUN mkdir -p /app/tools/.changelog-state && chown -R node:node /app

# Never run a credential scanner as root. It reads whatever it is pointed at, and root plus
# a bind mount means it can read rather more than intended.
USER node

ENTRYPOINT ["/sbin/tini", "--"]
CMD ["node", "src/cli.mjs", "--help"]
