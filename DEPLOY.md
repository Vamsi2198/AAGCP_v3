# Deploy — AAGCP-Vector PRO

This version fixes the two things that broke the previous deploy:
1. **No bundled environments.** `.gitignore` excludes `.conda/`, `myenv/`,
   `__pycache__/`. Only ~code ships, not 200 MB of local venvs.
2. **No torch.** The app uses the built-in embedder by default and OpenAI's
   API (if you set a key) — never local torch — so it fits free-tier RAM.

Dependency footprint: `numpy`, `pyyaml`, `reportlab` (+ `openai` only if a key
is set). That's it.

## Render (recommended, works on free tier)
1. Push this folder to GitHub (the `.gitignore` keeps envs out).
2. Render → New → Web Service → connect the repo.
3. Build: `pip install -r requirements.txt`   Start: `python server.py`
   (Or just use the included `render.yaml` blueprint.)
4. Render sets `$PORT`; the server binds it automatically.
5. (Optional) Set `OPENAI_API_KEY` in the dashboard to switch to API
   embeddings — otherwise it runs on the built-in embedder.

## Streamlit Community Cloud
This app is a plain HTTP server, not a Streamlit app, so prefer Render/Fly/
HF Spaces. If you specifically want Streamlit, the earlier greenfield console
is the Streamlit-shaped one; this PRO server is framework-free on purpose.

## Hugging Face Spaces (best if you want the REAL local embedder)
Spaces gives 16 GB RAM free. Use a Docker Space:
    FROM python:3.11-slim
    WORKDIR /app
    COPY . .
    RUN pip install -r requirements.txt sentence-transformers
    CMD ["python","server.py"]
Then swap `auto_embedder` for `SentenceTransformerEmbedder` if you want local
MiniLM instead of the API.

## Fly.io / Google Cloud Run
Both work with the same `python server.py` start command and a trivial
Dockerfile (as above, minus sentence-transformers unless you want it).
Cloud Run scales to zero — cheapest for an intermittent demo.

## Local
    pip install -r requirements.txt
    python server.py            # http://localhost:8000

## Endpoints
    GET  /            console UI
    GET  /health      embedder + detector coverage
    GET  /report.pdf  branded PII audit PDF (current scan)
    POST /connect     {size}     seed/connect a production index
    POST /scan                    uncapped PII inventory
    POST /clean                   re-embed poisoned subset in place
    POST /query       {role}      role-gated retrieval
    POST /erase       {subject}   reference-counted crypto-shred

## Going to a REAL vector DB
Swap `InMemoryConnector` in `server.py` for `PineconeConnector` /
`QdrantConnector` / `PgVectorConnector` from `aagcp/store/connectors.py`.
The endpoints don't change. See `SMOKE_TEST.md` for the one-line setup per
backend, and install the matching client + (optionally) Presidio for full
global name/address detection.
```
```
