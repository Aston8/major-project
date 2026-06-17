# SmartShield AI

**Multi-Modal Scam Detection, Threat Intelligence & Secure URL Sandbox Platform**

SmartShield AI is a comprehensive production-ready platform designed to inspect and protect against digital scam threats across text, screenshots, voice calls, emails, and URLs. The system aggregates local Machine Learning inference, Google Gemini and Grok generative AI pipelines, threat intelligence feeds, and containerized browser sandboxes to deliver explainable cybersecurity verdicts.

---

## Technical Architecture Overview

SmartShield AI is designed around a multi-layered verification strategy:

```
                  +----------------------------------+
                  |            User Input            |
                  +----------------------------------+
                                   |
            +----------------------+----------------------+
            |                                             |
            v                                             v
  +------------------+                          +-------------------+
  | Text/Media Input |                          |    URL Targets    |
  +------------------+                          +-------------------+
            |                                             |
            |                                             v
            |                                   +-------------------+
            |                                   |  Whois & SSL Check|
            |                                   +-------------------+
            |                                             |
            |                                             v
            |                                   +-------------------+
            |                                   | Threat Intel Feeds|
            |                                   +-------------------+
            |                                             |
            |                                             v
            |                                   +-------------------+
            |                                   |  Docker Sandbox   |
            |                                   | (Playwright Scans)|
            |                                   +-------------------+
            |                                             |
            v                                             v
+-----------------------+                      +-----------------------+
|  Local ML Models      |                      |  Screenshot Analysis  |
|  - DistilBERT         |                      |  - Gemini Vision      |
|  - EasyOCR            |                      |  - Grok Vision        |
|  - OpenAI Whisper     |                      |                       |
+-----------------------+                      +-----------------------+
            |                                             |
            +----------------------+----------------------+
                                   |
                                   v
                      +-------------------------+
                      |   Risk Fusion Engine    |
                      |  - Weighted Scores      |
                      |  - AI API Failovers     |
                      +-------------------------+
                                   |
                                   v
                      +-------------------------+
                      |     Final Decision      |
                      | (Safe/Suspicious/Danger)|
                      +-------------------------+
```

---

## Core Features & Modalities

1. **Text Scam Detector**: Scans SMS, WhatsApp, Telegram, or social posts for job traps, banking alerts, OTP extraction, and lottery fraud using a fine-tuned DistilBERT transformer combined with heuristic keyword profiles.
2. **Secure URL Sandbox (Core Feature)**: Dynamically spins up a headless containerized Playwright browser instance, visits the target website, records redirections, console notifications, download flags, extracts form fields for credential harvesting signatures, captures screenshots, and destroys the container.
3. **Screenshot OCR & QR Parser**: Extracts typography from image uploads using EasyOCR, reads QR codes to resolve URLs, and triggers the sandboxing pipeline on extracted links.
4. **Voice Scam Whisper ASR**: Decodes MP3, WAV, or M4A call recordings using OpenAI Whisper model to screen dialogue transcripts for voice phishing.
5. **Email Integrity Auditor**: Evaluates SPF registration keys, parses headers for DKIM signatures, flags domain mismatched return paths, and analyzes email contents.
6. **Risk Fusion Engine**: Aggregates multi-source scores:
   * **Text Scans**: 40% Local ML, 30% Gemini AI, 30% Grok AI
   * **URL Scans**: 35% Browser Sandbox logs, 25% Threat Intel feeds (VirusTotal, OpenPhish, PhishTank), 20% WHOIS/SSL Reputation, 20% Combined AI
7. **Interactive Dashboard**: Full reporting stats using Chart.js, administrative blacklist management portals, and security audit logs.
8. **PDF Report Compilation**: ReportLab integration building structured multi-page PDF records including screenshots.

---

## Installation & Deployment Guide

### Option 1: Quick Start via Docker Compose (Recommended)

1. Ensure **Docker Desktop** is running on your host machine.
2. Open a terminal in the project root folder.
3. Run the following command to build and launch all containers:
   ```bash
   docker-compose up --build
   ```
4. Access the web application portals:
   * **React Frontend**: [http://localhost:80](http://localhost:80)
   * **FastAPI Backend Swagger**: [http://localhost:8000/docs](http://localhost:8000/docs)
   * **MongoDB Gateway**: `mongodb://localhost:27017`
   * **Redis Cache**: `redis://localhost:6379`

---

### Option 2: Bare-Metal Setup (Development Mode)

If you prefer executing services natively on your host machine:

#### Prerequisites
* Python 3.10+
* Node.js 18+
* MongoDB Community Server active on `localhost:27017`
* Redis Server (Optional, program falls back to in-memory dictionary caching if missing)

#### 1. Setup Backend
1. Open a terminal window and navigate to the backend folder:
   ```bash
   cd backend
   ```
2. Create a virtual environment and activate it:
   ```bash
   python -m venv venv
   # On Windows:
   venv\Scripts\activate
   # On macOS/Linux:
   source venv/bin/activate
   ```
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
4. Copy the environment config and add your keys (Gemini / Grok / VirusTotal):
   ```bash
   copy .env.example .env
   ```
5. Install Playwright binaries for local sandbox fallbacks:
   ```bash
   playwright install chromium
   ```
6. Launch the backend gateway:
   ```bash
   python run.py
   ```

#### 2. Setup Frontend
1. Open a new terminal window and navigate to the frontend folder:
   ```bash
   cd frontend
   ```
2. Install Node packages:
   ```bash
   npm install
   ```
3. Launch the React Vite server:
   ```bash
   npm run dev
   ```
4. Open your browser to the local development portal: [http://localhost:5173](http://localhost:5173)

---

## Environment Variables (.env)

Customize parameters inside `backend/.env`:

* `GEMINI_API_KEY`: Google Gemini API credentials.
* `GROK_API_KEY`: Grok xAI API credentials.
* `VIRUSTOTAL_API_KEY`: VirusTotal API credentials.
* `USE_LOCAL_PLAYWRIGHT_FALLBACK`: Set to `true` to allow scanning without active local Docker daemons.
* `ACCESS_TOKEN_EXPIRE_MINUTES`: Expiry duration for authentication sessions (default 24h).

---

## Verification & Academic Evaluation

1. **Authentication**: Navigate to register, fill in an email, and create a user. The system automatically elevates the first created user to **ADMIN** status.
2. **Multi-Model Verification**: Submit a text scam (e.g. *"Congratulations! You won a lottery of 5 Lakhs. Share OTP to claim"*). Navigate to the audit panel to see how Local ML, Gemini, and Grok evaluated this text and how scores fused.
3. **URL Sandbox**: Input a suspicious URL (e.g. `http://verify-bank-rewards.info/claim`). The system will execute the browser script. View the rendered dashboard to see live forms found, logs, and screenshots.
4. **PDF Reports**: Go to history page, select a scan row, and click **Compile PDF** to download the ReportLab document showing evidence files.
