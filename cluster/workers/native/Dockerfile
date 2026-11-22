FROM python:3.14-slim@sha256:9aaa474097d094040649f2162a627c0049b408f52138d980916788d80f04802f
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY src/vigil_fuse/__init__.py src/vigil_fuse/execution_contract.py src/vigil_fuse/execution_worker.py /app/vigil_fuse/
USER 65532:65532
ENTRYPOINT ["python", "-m", "vigil_fuse.execution_worker"]
