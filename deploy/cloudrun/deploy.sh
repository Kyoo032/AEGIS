#!/usr/bin/env bash
# Deploy AEGIS dashboard to GCP Cloud Run.
#
# Prerequisites:
#   - gcloud CLI authenticated
#   - GCP_PROJECT_ID set
#   - Reports baked into the Docker image (COPY reports/ /app/reports/)
#
# Usage:
#   GCP_PROJECT_ID=my-project ./deploy/cloudrun/deploy.sh
set -euo pipefail

PROJECT_ID="${GCP_PROJECT_ID:?Set GCP_PROJECT_ID}"
REGION="${GCP_REGION:-us-central1}"
SERVICE_NAME="aegis-dashboard"
IMAGE="gcr.io/${PROJECT_ID}/${SERVICE_NAME}"

echo "Building and submitting image: ${IMAGE}"
gcloud builds submit \
    --tag "${IMAGE}" \
    --timeout=600 \
    --project="${PROJECT_ID}"

echo "Deploying to Cloud Run: ${SERVICE_NAME} in ${REGION}"
gcloud run deploy "${SERVICE_NAME}" \
    --image "${IMAGE}" \
    --platform managed \
    --region "${REGION}" \
    --port 8501 \
    --memory 512Mi \
    --min-instances 0 \
    --max-instances 2 \
    --allow-unauthenticated \
    --project="${PROJECT_ID}"

echo "Deployment complete."
gcloud run services describe "${SERVICE_NAME}" \
    --region "${REGION}" \
    --project="${PROJECT_ID}" \
    --format="value(status.url)"
