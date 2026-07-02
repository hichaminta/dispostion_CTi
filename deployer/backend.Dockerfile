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
RUN python -m spacy download en_core_web_sm

# Copy full project code
COPY . /app

# Create runtime directories (data volumes will overlay these at runtime)
RUN mkdir -p \
    /app/store \
    /app/tracking/tracking_enrichment \
    /app/Pipeline_cti/global_output/sources \
    /app/Pipeline_cti/global_output/output_cve_ioc \
    /app/Pipeline_cti/global_output/output_enrichment \
    /app/Pipeline_cti/global_output/output_correlation \
    /app/Pipeline_cti/global_output/reports/cti_bulletins \
    /app/leak_data_integration/output/data/leaks \
    /app/leak_data_integration/output/reports \
    /app/bultein_de_security

EXPOSE 8000

WORKDIR /app/app/backend
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
