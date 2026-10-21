# Brod's preview service: headless Chromium (Playwright) that screenshots and records marketplace releases.
# Build from the repository root:
#   docker build -f deploy/preview/Dockerfile -t brod-preview .
# The image already holds the browsers for this Playwright version; keep the two in step with package-lock.json.
FROM mcr.microsoft.com/playwright:v1.64.1-noble@sha256:7852dc5a7d72f5fe458a597d690f6c42fbc8e9e26ddfa95f8e6ef552558d9bbf
WORKDIR /srv
RUN npm init -y >/dev/null && npm install --no-audit --no-fund playwright@1.56.1
COPY deploy/preview/server.mjs deploy/preview/guard.mjs /srv/
EXPOSE 8790
USER pwuser
# BROD_PREVIEW_SECRET must be set; Brod's internal listener is expected at http://brod:8080 (BROD_INTERNAL_URL).
CMD ["node", "/srv/server.mjs"]
