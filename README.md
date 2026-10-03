# PhishGuard AI – Explainable Phishing Detection Chatbot

An educational project demonstrating URL/webpage feature extraction, supervised phishing classification, SHAP explanations, and cautious next-step advice. Its focus is **detection + explanation + actionable security guidance**, not a claim that an AI can prove a website safe or malicious. The model currently trains on 15 lexical URL features; DNS/TLS/domain/page signals are also extracted for the scorecard and recommendation, but are not inputs to this model.

## Current model status

The source repository does not guarantee that a trained model artifact is present. The UI and API report a placeholder model state until you train a model from a real, labeled dataset. While it is untrained, `/scan` returns HTTP 503 with an explicit `model_not_trained` response instead of producing a made-up score. No fabricated sample dataset or model artifact is included.

## Project structure

```text
backend/
  main.py
  src/
    feature_extractor.py
    history_store.py
    predict.py
    decision_engine.py
    train.py
  models/                 # generated model artifact (keep dataset out of Git)
  data/                   # local SQLite scan history (git-ignored)
data/                     # place a labeled CSV here (git-ignored)
notebooks/
  model_training.ipynb    # notebook wrapper around the shared training pipeline
frontend/                 # React + TypeScript + Vite
tests/
.github/workflows/        # test and build on GitHub push/pull request
render.yaml               # Render API and frontend services
requirements.txt
```

## Requirements

- Python 3.8 or newer (the pinned backend dependencies support Python 3.8).
- Node.js 18 or newer and npm.
- A labeled phishing URL dataset that you are permitted to use.

## 1. Set up the backend

From the project root in PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
```

If PowerShell blocks virtual-environment activation, run the venv's interpreter directly, for example `.\.venv\Scripts\python.exe -m pip install -r requirements.txt`.

## 2. Train and evaluate

The trainer accepts either `url,label` columns with `0`=legitimate and `1`=phishing, or the Kaggle-style `URL,Label` columns with `good`/`bad` labels. For example, put the Kaggle file at `data\phishing_site_urls.csv`, then run:

```powershell
.\.venv\Scripts\python.exe -m backend.src.train --data data\phishing_site_urls.csv --model xgboost
```

By default, training takes a reproducible, label-stratified sample of up to 50,000 unique URLs, extracts URL-only lexical features without contacting websites, and holds out entire registered domains using a stratified group split. The live scanner uses the same URL feature function as training, avoiding differences caused by site availability or changing DNS/page content. It still extracts network and page signals for the scorecard and recommendation. SHAP explanations describe the URL features used by the model; the recommendation may additionally refer to live scan signals. You can change the sample limit with `--max-rows`; `--max-rows 0` uses all unique rows and may take longer.

The held-out split measures performance on domains not used for fitting. It is more informative than a random row split, but it is still drawn from the same dataset and does not establish current real-world accuracy. Predicted probabilities reflect the training data and should not be treated as perfectly calibrated for live traffic.

```powershell
.\.venv\Scripts\python.exe -m backend.src.train --data data\phishing_urls.csv --model xgboost
```

Supported models are `xgboost` (default), `random_forest`, and `logistic_regression`. All installed candidates are evaluated; metrics and domain-split counts are printed and saved. The selected model artifact is saved to `backend\models\phishing_model.pkl`. These metrics are results for that run, not a guarantee of performance on current real-world attacks.

The optional [model training notebook](./notebooks/model_training.ipynb) invokes the same training function.

## 3. Run the API

Start this after training (restart it after replacing the model artifact):

```powershell
python -m uvicorn backend.main:app --reload
```

- API docs: <http://127.0.0.1:8000/docs>
- Health/model status: <http://127.0.0.1:8000/health>
- Scan: `POST /scan` with `{"url":"https://example.com"}`
- Chat: `POST /chat` with `{"message":"Why?","scan_result":{...}}`

The API starts a local SQLite history database automatically. After a successful prediction, it saves the hostname, timestamp, risk category, probability, model type, and the top explanation labels. It does **not** save the URL path or query string. If `DATABASE_URL` is set, PostgreSQL is used instead. There is no public endpoint for listing stored scans.

Risk boundaries can be configured before launch:

```powershell
$env:PHISHGUARD_LOW_THRESHOLD = "0.40"
$env:PHISHGUARD_HIGH_THRESHOLD = "0.70"
python -m uvicorn backend.main:app --reload
```

The defaults classify probability `< 0.40` as low, `0.40–0.70` as suspicious, and `> 0.70` as high. Categories are predictions, not certainty.

## 4. Run the React chatbot

In a second PowerShell window:

```powershell
Set-Location frontend
npm.cmd install
npm.cmd run dev
```

Open <http://localhost:5173>. Enter a URL to scan, then ask “Why?” or “What should I do?” The current scan stays in the chat context. The result view includes the predicted category/probability, a signal scorecard, the three strongest SHAP contributions in plain language, and a feature-aware recommendation.

## GitHub and hosted deployment (Render + PostgreSQL)

1. Create an empty GitHub repository, then from this project root run the following (replace the URL with your repository URL). Keep `data\phishing_urls.csv`, `.env` files, and credentials out of GitHub. GitHub Actions runs the backend tests and frontend production build on pushes and pull requests.

   ```powershell
   git init
   git add .
   git commit -m "Initial PhishGuard AI project"
   git branch -M main
   git remote add origin https://github.com/<your-username>/<repository>.git
   git push -u origin main
   ```
2. Train and evaluate a model locally using the command above. The generated `backend\models\phishing_model.pkl` is allowed by `.gitignore` so you can deploy that model with the source. Only add it after checking the dataset license and confirming it is small enough for your repository. **Do not add the training CSV.** Without the trained artifact, the hosted app intentionally stays in placeholder mode and scans return HTTP 503.
3. Create a PostgreSQL database with a managed provider such as Neon. Copy its connection string (keep it private).
4. In Render, choose **New → Blueprint**, connect the GitHub repository, and select `render.yaml`. Enter the PostgreSQL connection string as the secret value for `DATABASE_URL`. The blueprint requests Render's `free` API service and a free static frontend; use a free PostgreSQL tier such as Neon if available for your account and region. Check each selected plan and any add-ons before confirming—provider free-tier limits and terms can change.
5. After deployment, check the actual service hostnames. If Render assigned different hostnames, set the frontend's `VITE_API_BASE_URL` to the API base URL and the API's `PHISHGUARD_CORS_ORIGINS` to the frontend origin, then redeploy. Open the frontend URL and confirm `/health` reports `"model_status":"trained"`.

On Render's free web-service tier, the API can spin down after inactivity and take time to wake on the next request; it is not continuously warm. The API loads the model when it starts and serves predictions while running. It does **not** retrain itself. Retraining should happen deliberately with a newly labeled, reviewed dataset; do not automatically treat user scans as training labels.

PostgreSQL scan history stores only hostname and a small result summary, not full paths or query strings. There is no scan-history listing API or user-account system in this college-project version. Anyone with database credentials can access the stored records, so keep the connection string private.

Scans contact the submitted website, Google Public DNS-over-HTTPS, and the public RDAP service. DNS lookups and network connections have timeouts, page downloads are limited to 1 MB, redirects are checked, and page fetches pin connections to resolved public IP addresses. Non-standard ports and private/local addresses are rejected. Do not scan websites without authorization. This is still an educational demo: add abuse controls and review the deployment security before advertising it as a public service.

## Network, privacy, and local data

Scans are on-demand. Local scan history is stored in `backend\data\scan_history.sqlite3`; hosted history is stored in PostgreSQL. The database stores the hostname, scan time, risk category, probability, model type, and top explanation labels only. It does not retain URL paths, query strings, page HTML, or chat messages. The scan is not a substitute for browser protections or independent verification.

The frontend development server proxies `/api` to `http://127.0.0.1:8000`. For another frontend origin, set `PHISHGUARD_CORS_ORIGINS` to a comma-separated allowlist.

## Tests

```powershell
pytest
```

Tests cover feature-schema consistency, URL validation, threshold boundaries, and recommendation wording. A real end-to-end model evaluation requires a genuine labeled dataset and network access.
