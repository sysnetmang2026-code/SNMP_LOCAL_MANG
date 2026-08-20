FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends nmap iputils-ping \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src ./src
COPY view ./view
COPY data/oui.json ./data/oui.json

EXPOSE 8765

CMD ["python", "src/main_web.py", "--host", "0.0.0.0", "--port", "8765"]
