# Google Cloud Checklist

Use a dedicated personal competition project.

## Project Setup

- Create new project.
- Enable billing with budget alerts.
- Set default region deliberately. Melbourne `australia-southeast2` is attractive for data-sovereignty story, but confirm all selected Agent Platform features are supported.
- Enable required APIs only as needed.

## Likely APIs

- Vertex AI API or Gemini API path.
- Cloud Run Admin API.
- Firestore API.
- Pub/Sub API.
- Cloud Logging API.
- Cloud Trace API.
- Secret Manager API.
- Model Armor API if used.
- Agent Platform APIs if used.

## Cost Controls

- Cloud Run min instances: 0.
- Low max instances during build.
- Firestore small data footprint.
- Use Gemini Flash first.
- Avoid always-on databases.
- Record cloud proof in demo before turning services down.

