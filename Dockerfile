FROM python:3.9-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Download MaxMind DB (optional)
RUN apt-get update && apt-get install -y wget && \
    wget https://geolite.maxmind.com/download/geoip/database/GeoLite2-City.tar.gz && \
    tar -xzf GeoLite2-City.tar.gz && \
    mv GeoLite2-City_*/GeoLite2-City.mmdb . && \
    rm -rf GeoLite2-City_* GeoLite2-City.tar.gz

CMD ["python", "netrecon.py", "--help"]
