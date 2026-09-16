FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 SENTINEL_DATA_DIR=/data
WORKDIR /app
COPY sentinel.py README.md ./
COPY sentinel ./sentinel
RUN useradd --create-home --uid 10001 sentinel && mkdir /data && chown sentinel:sentinel /data
USER 10001:10001
VOLUME ["/data"]
ENTRYPOINT ["python", "sentinel.py"]
CMD ["--help"]
