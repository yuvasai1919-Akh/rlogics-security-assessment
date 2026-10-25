FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
# Copy only what is needed (no planted/secret files can sneak in via "COPY . .")
COPY app.py .
# Non-root user (fixes Trivy misconfig: image should not run as root)
RUN useradd --system --uid 10001 --no-create-home appuser
USER 10001
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s CMD python -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8000/health')" || exit 1
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers", "2", "app:app"]
