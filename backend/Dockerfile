FROM python:3.11-slim

WORKDIR /app

# System deps: curl for healthcheck, build tools for some pip packages
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Install Python deps first (layer cache)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy backend source
COPY . .

# Ensure backend/ is on PYTHONPATH (bare imports like "from config import ...")
ENV PYTHONPATH=/app

EXPOSE 7860

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "7860", "--workers", "1"]
