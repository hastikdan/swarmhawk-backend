# SwarmHawk Backend — Setup Guide
# ══════════════════════════════════════════════════════════════════

## OVERVIEW
You are building:
  - FastAPI backend (Python)
  - Supabase database (PostgreSQL, free)
  - Stripe webhooks (auto-mark paid)
  - Railway hosting (free tier, deploys from GitHub)
  - 18 European countries, ~1,800 domains

Total cost to start: $0/month (all free tiers)

---

## STEP 1 — Create Supabase project (5 min)

1. Go to supabase.com → Sign up free
2. Click "New Project"
   - Name: swarmhawk
   - Password: generate strong one, save it
   - Region: Central EU (Frankfurt)
3. Wait ~2 minutes for project to start
4. Go to Project Settings → API
5. Copy these three values:
   - Project URL  (https://xxxx.supabase.co)
   - anon/public key  (eyJ...)
   - JWT Secret  (Settings → API → JWT Secret)

---

## STEP 2 — Create database tables (2 min)

1. In Supabase → SQL Editor → New Query
2. Paste the contents of schema.sql
3. Click Run
4. You should see: "Success. No rows returned"

---

## STEP 3 — Create Railway project (5 min)

1. Go to railway.app → Login with GitHub
2. Click "New Project" → "Deploy from GitHub repo"
3. Select: hastikdan/cee-scanner
4. Railway auto-detects Python and deploys

OR create a separate backend repo:
  cd ~/
  mkdir swarmhawk-backend
  cd swarmhawk-backend
  git init
  git remote add origin https://github.com/hastikdan/swarmhawk-backend.git
  cp ~/cee_scanner/swarmhawk_backend/* .
  git add . && git commit -m "initial backend" && git push

---

## STEP 4 — Set environment variables on Railway (3 min)

In Railway → your project → Variables → Add all from .env.example:

  SUPABASE_URL        = https://xxxx.supabase.co
  SUPABASE_KEY        = eyJ... (anon key)
  SUPABASE_JWT_SECRET = your-jwt-secret
  STRIPE_SECRET_KEY   = sk_test_...
  STRIPE_WEBHOOK_SECRET = whsec_... (get this in next step)
  GOOGLE_CLIENT_ID    = 396286675021-tqhadhbp3jqc1jrqo5krk3j5njdss0cg.apps.googleusercontent.com
  FRONTEND_URL        = https://hastikdan.github.io/cee-scanner

Railway gives you a URL like: https://swarmhawk-backend.up.railway.app

---

## STEP 5 — Set up Stripe webhook (3 min)

1. Go to dashboard.stripe.com → Developers → Webhooks
2. Click "Add endpoint"
3. Endpoint URL: https://swarmhawk-backend.up.railway.app/webhook
4. Select events:
   - checkout.session.completed
5. Click "Add endpoint"
6. Copy "Signing secret" (whsec_...)
7. Add to Railway env vars as STRIPE_WEBHOOK_SECRET

---

## STEP 6 — Update frontend to use backend API (2 min)

In cee_scanner_saas.html, add at top of script:

  const API = "https://swarmhawk-backend.up.railway.app";

Then update auth flow:
  - After Google login: POST to API + "/auth/google" with credential
  - Store returned session_token in memory
  - Send as "Authorization: Bearer {token}" on all requests
  - GET API + "/domains" to load My Domains
  - POST API + "/domains" to add domain
  - POST API + "/checkout" to start payment

---

## STEP 7 — Copy new targets to scanner

  cp targets_europe.py ~/cee_scanner/cee_scanner/targets.py

Then run a test scan of one country:
  cd ~/cee_scanner
  python3 -c "
  from cee_scanner.scanner import Scanner
  from cee_scanner.targets import TARGETS
  s = Scanner()
  s.run_all(countries=['Estonia'])
  "

---

## ARCHITECTURE DIAGRAM

  [Browser]
      |
      | Google JWT
      v
  [FastAPI /auth/google]
      |
      | Saves user
      v
  [Supabase DB]
      |
      | Session token back to browser
      v
  [Browser adds domain]
      |
      | POST /domains
      v
  [FastAPI] --> [Scanner runs in background] --> [Saves scan to DB]
      |
      | User clicks $10
      v
  [FastAPI /checkout] --> [Stripe Checkout Page]
      |
      | Payment complete
      v
  [Stripe webhook → POST /webhook]
      |
      | Marks purchase in DB
      v
  [Browser GET /domains/{id}/report]
      |
      | Full report returned
      v
  [User sees unlocked report]

---

## TESTING LOCALLY

  cd ~/cee_scanner
  pip3 install fastapi uvicorn supabase stripe python-jose httpx --user

  # Copy .env.example to .env and fill in values
  cp swarmhawk_backend/.env.example .env
  nano .env

  # Run backend
  uvicorn swarmhawk_backend.main:app --reload --port 8000

  # Test health check
  curl http://localhost:8000/health
  # Should return: {"status":"ok","version":"2.0.0"}

---

## FILE STRUCTURE

  swarmhawk-backend/
  ├── main.py              ← FastAPI app (all routes)
  ├── requirements.txt     ← Python dependencies
  ├── schema.sql           ← Supabase database tables
  ├── targets_europe.py    ← 1,800+ domains across 18 countries
  ├── .env.example         ← Environment variables template
  └── .env                 ← Your actual keys (never commit this!)

---

## WHAT YOU GET WHEN DONE

  ✅ Real Google login — users saved to database
  ✅ Stripe payments — webhooks auto-mark domains paid
  ✅ Free scan — anyone can add a domain
  ✅ $10 full report — unlocked automatically after payment
  ✅ 18 European countries, ~1,800 domains monitored
  ✅ Weekly automated re-scans
  ✅ Admin stats endpoint (/admin/stats)
