FROM python:3.14.2-slim
LABEL authors="rudig"

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
RUN apt-get update && apt-get install -y --no-install-recommends iproute2 libpcap-dev && apt-get clean && rm -rf /var/lib/apt/lists/*

COPY . .
