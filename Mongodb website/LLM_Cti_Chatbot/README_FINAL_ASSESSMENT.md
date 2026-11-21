# Final Assessment: LLM-Backed Threat Intelligence & Autonomous Remediation Chatbot on MongoDB

Synthesizes **Exercises 1 through 18** into a deployable AI Threat Intelligence assistant powered by **Hosted Google Gemini API** (`GEMINI_API_KEY` — **not Ollama**) and **MongoDB** (operational threat store, vector RAG index, and persistent conversation memory).

## Key Capabilities
1. **Multi-Platform & Lifecycle Threat Intelligence**: Covers **Anticipated**, **Active**, **Evolving**, and **Resolved** threats across **Linux**, **Windows**, **macOS**, **Android**, and **iOS** with exact CVEs, Indicators of Compromise (IoCs), and remediation procedures.
2. **Hosted LLM API Backend (`main.py`)**: FastAPI `/chat` endpoint using hosted Google Gemini REST API (`gemini-2.5-flash`) with `.env` secret management (Exercise 12), sliding-window rate limiting (Exercise 15), `/health` & `/metrics` telemetry (Exercise 14), and MongoDB `sessions` memory.
3. **Background Vulnerability Scanner & Conversational Confirmation (`background_scanner.py`)**: Scans target platforms (`system-wide` or `project-directory`), records findings in MongoDB `vulnerabilities`, and executes remediation only after explicit user confirmation (`CONFIRM FIX <VULN-ID>`), logging every action to `remediation_audit`.
4. **Full-Stack Containerization (`Dockerfile` & `docker-compose.yml`)**: Runs MongoDB 7, FastAPI backend (`:8000`), and Streamlit UI (`:8501`) seamlessly (Exercise 13).

## Quick Start
```bash
cd final_assessment_llm_cti_chatbot
cp .env.example .env
# Verify GEMINI_API_KEY is set in .env
docker compose up --build -d
```
