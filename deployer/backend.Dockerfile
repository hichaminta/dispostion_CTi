FROM python:3.10-slim

WORKDIR /app

# System dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# Install python dependencies first (layer cache)
COPY app/backend/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# Copy full project code
COPY . /app

# Create runtime directories (data volumes will overlay these at runtime)
RUN mkdir -p \
    /app/store \
    /app/__TEMP__/global_output/output_cve_ioc \
    /app/__TEMP__/global_output/output_enrichment \
    /app/__TEMP__/global_output/output_correlation \
    /app/reports/cti_bulletins \
    /app/leak_data_integration/results \
    /app/misp_integration/tracking \
    /app/data \
    /app/bultein_de_security

EXPOSE 8000

WORKDIR /app/app/backend
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
