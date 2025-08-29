# Dockerfile for testing Python SOAP Toolkit on Debian Stretch
FROM debian:stretch

# Fix Debian Stretch sources.list (repositories moved to archive)
COPY debian-stretch/sources.list /etc/apt/sources.list

# Install system dependencies
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    python3-dev \
    python3-lxml \
    python3-openssl \
    libssl-dev \
    libffi-dev \
    openssl \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt

# Copy toolkit files
COPY cybersource/ ./cybersource/
COPY sample.py ./
COPY sample2.py ./

# Set environment variables (you'll override these at runtime)
ENV CYBERSOURCE_KEY_ALIAS=your_key_alias
ENV CYBERSOURCE_KEY_FILE=certificate.p12
ENV CYBERSOURCE_KEY_PASS=your_password
ENV CYBERSOURCE_KEY_DIRECTORY=/app/certificates

# Create certificates directory
RUN mkdir -p /app/certificates

# Run sample by default
CMD ["python3", "sample2.py"]
