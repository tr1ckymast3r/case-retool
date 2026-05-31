FROM python:3.11-slim

RUN apt-get update && apt-get install -y libmagic1 file && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . ./app/
RUN mkdir -p /app/data /app/uploads /app/reports

EXPOSE 3010
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "3010"]
