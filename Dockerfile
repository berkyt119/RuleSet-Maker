FROM node:22-alpine AS frontend-build
WORKDIR /app/frontend
COPY frontend/package*.json ./
RUN npm install
COPY frontend/ ./
ENV VITE_API_BASE=/api
RUN npm run build

FROM python:3.12-slim
WORKDIR /app
ENV PYTHONUNBUFFERED=1 \
    PORT=8090 \
    DATABASE_URL=sqlite:////app/data/dogma_vpn.db \
    ENABLE_BROWSER_DISCOVERY=false \
    DOMAIN_JSON_EXPORT_PATH=/app/exports/domains-export.json \
    RULESET_OUTPUT_PATH=/var/www/files/data.json \
    RULESET_ARCHIVE_DIR=/var/www/files

COPY backend/requirements.txt /app/backend/requirements.txt
RUN pip install --no-cache-dir -r /app/backend/requirements.txt
COPY backend/app /app/backend/app
COPY --from=frontend-build /app/frontend/dist /app/frontend/dist
RUN mkdir -p /app/data /app/exports /var/www/files
WORKDIR /app/backend
EXPOSE 8090
CMD ["sh", "-c", "python -m uvicorn app.main:app --host 0.0.0.0 --port ${PORT}"]
