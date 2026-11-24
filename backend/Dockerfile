FROM python:3.11-slim

WORKDIR /app

# Install FFmpeg/FFprobe and runtime libs for OpenCV/PDF
RUN apt-get update && apt-get install -y --no-install-recommends \
    ffmpeg \
    libgl1 \
    libglib2.0-0 \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Run as non-root user for upload & processing defense-in-depth
RUN useradd -m forensic && chown -R forensic:forensic /app
USER forensic

EXPOSE 8000
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
