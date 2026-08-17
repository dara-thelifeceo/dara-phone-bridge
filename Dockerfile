FROM python:3.12-slim

ENV HOST=0.0.0.0 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app
COPY --chown=65532:65532 dara_phone_bridge.py /app/dara_phone_bridge.py

USER 65532:65532
EXPOSE 8080

CMD ["python3", "dara_phone_bridge.py"]
