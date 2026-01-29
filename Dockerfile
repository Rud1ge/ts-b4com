FROM python:3.14.2-alpine
LABEL authors="rudig"

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
RUN apk add --no-cache tcpdump

COPY . .

CMD ["python", "./your-daemon-or-script.py"]
