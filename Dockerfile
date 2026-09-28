FROM python:3.14-slim AS backend

WORKDIR /app
COPY backend/requirements.txt backend/requirements.lock.txt ./
# Install from the lock file so the image matches the environment the test suite passed in.
RUN pip install --no-cache-dir -r requirements.lock.txt

COPY backend/app/ ./app/

# All of these are supplied at run time. Copied from backend/requirements.txt
# provenance: see backend/app/crypto/cert_analyzer.py for the certifi fallback
# that keeps certificate chain validation working in this slim image.
ENV AEGIS_API_KEY=""
ENV GEMINI_API_KEY=""
# The frontend talks to the API through the nginx reverse proxy (same origin), so
# cross-origin access is not required in the default deployment. A wildcard is
# accepted but disables credentialed CORS; set an explicit allowlist to enable it.
ENV CORS_ORIGINS="*"

EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "4", "--log-level", "info"]


FROM node:22-slim AS frontend-build

WORKDIR /app
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci

COPY frontend/ ./
# Empty (the default) means the bundle calls the API at its own origin and relies
# on the nginx reverse proxy below. Set this only when the API is served from a
# different host.
ARG VITE_API_BASE_URL=""
RUN npm run build


FROM nginx:alpine AS frontend

COPY --from=frontend-build /app/dist /usr/share/nginx/html
# The nginx entrypoint expands /etc/nginx/templates/*.template into
# /etc/nginx/conf.d/, which is how ${AEGIS_API_UPSTREAM} reaches the config.
COPY frontend/nginx.conf /etc/nginx/templates/default.conf.template
ENV AEGIS_API_UPSTREAM="aegiscrypta-api:8000"

EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
