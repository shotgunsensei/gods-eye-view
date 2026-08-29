# Replit setup

## Run

- Use the **Start application** workflow.
- The workflow runs `PORT=5000 npm start`.
- Replit uses its Node 24 module (currently Node 24.13), which is covered by the project engine requirement and validated by the full test suite.
- The preview first shows the private sign-in screen. Sign in with the values stored in the `GEV_AUTH_USERNAME` and `GEV_AUTH_PASSWORD` Replit Secrets.

## Required Secrets

- `GEV_AUTH_USERNAME`
- `GEV_AUTH_PASSWORD` (at least 12 characters)
- `GOOGLE_MAPS_API_KEY` (Google Map Tiles API enabled; restrict the browser key to the app's Replit origin)

Optional provider keys are documented in `.env.example`.