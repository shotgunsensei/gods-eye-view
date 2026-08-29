# Private Replit website and Android app

This fork includes a server-side password wall and an installable Progressive Web App (PWA). It is designed for one owner's personal use.

## What protects the website

- Replit supplies the account name and password as server-only environment variables.
- The browser receives only a signed, `HttpOnly`, `SameSite=Strict` session cookie. The password is not added to the JavaScript bundle, browser storage, URL, or repository.
- Published Replit runs fail closed if either credential is missing or if the password is shorter than 12 characters.
- Five failed attempts from one address trigger a 15-minute sign-in cooldown.
- Sessions expire after 12 hours. Changing either credential invalidates every existing session.
- The password wall is registered before the map UI and all `/api/*` proxies, so direct API requests are protected too.

This is personal single-account protection, not a multi-user identity system. Do not share the Replit workspace with people who should not be able to read its Secrets.

## Import the fork into Replit

1. In Replit, choose **Create App** and **Import from GitHub**.
2. Select `shotgunsensei/gods-eye-view`.
3. Wait for the import to finish, then open **All tools** → **Secrets**.
4. Add each Key and Value below. Do not type the values into a code file.

| Secret key | What to enter | Required |
| --- | --- | --- |
| `GEV_AUTH_USERNAME` | The private account name you want to type at sign-in | Yes |
| `GEV_AUTH_PASSWORD` | A unique password containing at least 12 characters | Yes |
| `GOOGLE_MAPS_API_KEY` | Your restricted Google Map Tiles browser key | Yes |
| `OPENSKY_AUTH_MODE` | `anon` unless you later add an OpenSky account | Recommended |
| `GEV_RATELIMIT_GOOGLE_PER_MIN` | `10` | Recommended |
| `GEV_RATELIMIT_OPENAI_PER_MIN` | `10` | Recommended |
| `FIRMS_MAP_KEY` | Optional free NASA FIRMS map key | Optional |
| `AISSTREAM_API_KEY` | Optional free AISStream key | Optional |
| `CESIUM_ION_TOKEN` | Optional personal-use Cesium ion token | Optional |
| `TOMTOM_API_KEY` | Optional TomTom key, after checking its current allowance | Optional |

Replit exposes Secrets to this Node server as environment variables. Do not add `HOST` or a fixed Replit `PORT`: `npm start` already binds to `0.0.0.0`, and the existing Vite configuration accepts Replit's automatically assigned `PORT`.

## Test before publishing

1. Select **Run**. The included `.replit` file runs `npm start`.
2. Open the development preview. It must show the **God's Eye View sign-in** screen.
3. Try one incorrect password and confirm it is rejected.
4. Sign in with the two Secrets and confirm the globe loads.
5. Select the sign-out icon in the top-center controls and confirm the login screen returns.

If Replit shows **Private sign-in needs setup**, one of the two authentication Secrets is absent or the password is too short.

## Publish without accidentally exposing or overspending

This app cannot use Static Deployment because the sign-in gate, API-key proxies, and live feeds run on the Node server.

1. Select **Publish**.
2. Choose **Autoscale** and keep the maximum machine count at `1` for personal use.
3. The included `.replit` file supplies `npm ci && npm run build` as the build command and skips the unnecessary Puppeteer browser download.
4. It supplies `npm start` as the run command.
5. Confirm all Secrets are present in the Publishing pane.
6. Review Replit's price estimate. **Stop before the final Publish button if Replit shows any charge you have not approved.**
7. After Replit gives you the final `https://...replit.app` URL, add that exact origin to the Google Maps key's website restrictions, for example `https://your-exact-name.replit.app/*`.

The Google Maps browser key is intentionally present in the signed-in browser because Google's 3D Tiles client needs it. Password protection reduces access, but Google API restrictions and quotas remain the actual key-spend backstop.

## Install it on Android

The PWA is the best fit for this project: it needs no Play Store account, APK signing, or manual update process, and it always opens the current Replit-hosted version.

1. On the Android phone, open the published `https://...replit.app` address in **Chrome**.
2. Sign in.
3. Tap the phone-install icon in the top-center row when it appears. If it does not appear, open Chrome's **⋮** menu and choose **Install app** or **Add to Home screen**.
4. Confirm **Install**. God's Eye View then appears on the home screen and in the app drawer.

The installed app intentionally requires an internet connection. Its service worker does not cache the authenticated globe, API responses, or credentials for offline use.

## Local Windows use

Authentication is optional only when the server is bound to `localhost`. A LAN-visible server (`HOST=0.0.0.0`) fails closed without credentials, just like Replit. Put these entries in the ignored `.env` file and restart the server:

```dotenv
GEV_AUTH_USERNAME=your-account-name
GEV_AUTH_PASSWORD=your-unique-password-of-12-or-more-characters
```

Never commit `.env`.
