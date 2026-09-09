FROM python:3.12-slim

WORKDIR /app

COPY services/api/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY services/normalizers /app/services/normalizers
COPY services/api /app/services/api
COPY rules /app/rules
COPY samples /app/samples

ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1

EXPOSE 8000 5140/udp

CMD ["uvicorn", "services.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
