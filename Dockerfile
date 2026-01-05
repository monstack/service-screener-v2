# AWS Service Screener Web GUI - Dockerfile
# Multi-stage build for frontend + backend

# Stage 1: Build frontend
FROM node:20-alpine AS frontend-builder

WORKDIR /app/frontend
COPY webapp/frontend/package.json ./
RUN npm install

COPY webapp/frontend/ ./
RUN npm run build

# Stage 2: Production image
FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy the entire service-screener
COPY . /app/

# Install Python dependencies (original + webapp)
RUN pip install --no-cache-dir -r requirements.txt
RUN pip install --no-cache-dir -r webapp/requirements.txt

# Unzip lambda runtime as per original setup
RUN python3 unzip_botocore_lambda_runtime.py

# Copy built frontend from previous stage
COPY --from=frontend-builder /app/frontend/dist /app/webapp/static

# Create directory for reports
RUN mkdir -p /app/adminlte/aws

# Expose port
EXPOSE 8000

# Environment variables
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app

# Start the FastAPI server
CMD ["python", "-m", "uvicorn", "webapp.app:app", "--host", "0.0.0.0", "--port", "8000"]
