FROM python:3.12-slim
WORKDIR /app
COPY services/log-generator/generator.py /app/generator.py
ENV PYTHONUNBUFFERED=1
CMD ["python", "/app/generator.py"]
