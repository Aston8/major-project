FROM python:3.10-slim

# Install system dependencies (e.g. magic libraries for MIME type validation, etc.)
RUN apt-get update && apt-get install -y \
    build-essential \
    libmagic1 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy dependency configs
COPY requirements.txt .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy backend files
COPY app/ app/
COPY run.py .

EXPOSE 8000

CMD ["python", "run.py"]
