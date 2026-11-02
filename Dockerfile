FROM python:3.12-slim
ARG SERVICE
ARG PORT
ENV PYTHONUNBUFFERED=1 PYTHONPATH=/app PORT=${PORT}
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && useradd -r -u 10001 app
COPY common/ /app/common/
COPY services/${SERVICE}/ /app/service/
USER app
# 2 workers x 2 threads keeps memory small enough for a 1 GB t3.micro
CMD gunicorn -b 0.0.0.0:${PORT} -w 2 --threads 2 --access-logfile - ${GUNICORN_EXTRA} service.app:app
