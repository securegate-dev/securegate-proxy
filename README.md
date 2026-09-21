# SecureGate v3

Passwortgeschützter Web-Proxy auf Basis von [Scramjet](https://github.com/MercuryWorkshop/scramjet) + Wisp.
Oberfläche und Proxy laufen zusammen auf einem Server (Render).

## Deployment auf Render

1. Diesen Ordner in ein GitHub-Repo pushen (ersetzt den alten Proxy-Code).
2. Render → Web Service → Repo verbinden.
   - **Build Command:** `npm install`
   - **Start Command:** `npm start`
3. Render → Environment → Variable `SG_PASSWORD` = dein Passwort.
4. Deploy. Seite aufrufen: `https://<dein-service>.onrender.com`

## Lokal testen

```
npm install
SG_PASSWORD=test node server.js
```
→ http://localhost:8080
