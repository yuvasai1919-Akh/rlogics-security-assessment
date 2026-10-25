# INTENTIONALLY WEAK image for the lab (root user, old base, no healthcheck, COPY . .)
FROM python:3.9-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
# "COPY . ." also copies the runtime-planted synthetic secret file into the image,
# so image secret scanning has something to find.
COPY . .
EXPOSE 8000
CMD ["python", "app.py"]
