FROM python:3.12-slim

WORKDIR /app
COPY . .
RUN pip install --no-cache-dir .

ENTRYPOINT ["logagent"]
CMD ["analyze", "--input", "/logs", "--config", "/app/config.yaml", "--out", "/reports/report.html"]