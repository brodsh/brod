# Brod's preview service: headless Chromium (Playwright) that screenshots and records marketplace releases.
# Build from the repository root:
#   docker build -f deploy/preview/Dockerfile -t brod-preview .
# The image already holds the browsers for this Playwright version; keep the two in step with package-lock.json.
FROM mcr.microsoft.com/playwright:v1.64.0-noble@sha256:06a9939e57531807f8d5fd76ce44b53165ffb7d7501d87ab10e285c20b1e971f
WORKDIR /srv
RUN npm init -y >/dev/null && npm install --no-audit --no-fund playwright@1.56.1
COPY deploy/preview/server.mjs deploy/preview/guard.mjs /srv/
EXPOSE 8790
USER pwuser
# BROD_PREVIEW_SECRET must be set; Brod's internal listener is expected at http://brod:8080 (BROD_INTERNAL_URL).
CMD ["node", "/srv/server.mjs"]
