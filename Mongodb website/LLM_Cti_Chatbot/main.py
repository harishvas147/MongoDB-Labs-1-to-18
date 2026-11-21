"""
Final Assessment (A.3 - A.7): FastAPI Backend for Threat Intelligence RAG Chatbot
- Hosted LLM API via Google Gemini REST/SDK (NOT Ollama)
- MongoDB Operational Store (`threats`, `vulnerabilities`, `remediation_audit`)
- MongoDB Vector Search / Cosine RAG Store (`knowledge`)
- MongoDB Conversation Memory Store (`sessions`)
- Background Vulnerability Scanner & Conversational Confirmation Mitigation
- Production Hardening: Rate Limiting, /health check, Telemetry & Graceful Shutdown
"""

from __future__ import annotations

import asyncio
import json
import math
import os
import re
import time
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any, Deque, Dict, List, Optional

import requests
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from pymongo import MongoClient, DESCENDING

from background_scanner import (
    apply_mitigation,
    background_scan_loop,
    detect_host_platform,
    run_platform_scan,
)
from ingest_threats import deterministic_embedding, get_embeddings, ingest_corpus

load_dotenv()

MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017")
MONGO_DB = os.getenv("MONGO_DB", "threat_intel_chatbot")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "").strip()
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")
SCAN_INTERVAL_SECONDS = int(os.getenv("SCAN_INTERVAL_SECONDS", "300"))
RATE_LIMIT_PER_MINUTE = int(os.getenv("RATE_LIMIT_PER_MINUTE", "30"))

mongo_client = MongoClient(MONGO_URI)
db = mongo_client[MONGO_DB]
knowledge_col = db["knowledge"]
threats_col = db["threats"]
sessions_col = db["sessions"]
vulns_col = db["vulnerabilities"]
audit_col = db["remediation_audit"]

# Production metrics & in-memory sliding-window rate limiter (A.7)
METRICS: Dict[str, Any] = {
    "requests_total": 0,
    "chat_requests": 0,
    "errors_total": 0,
    "total_latency_ms": 0.0,
    "estimated_tokens": 0,
}
RATE_BUCKETS: Dict[str, Deque[float]] = defaultdict(deque)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Ensure knowledge base is seeded on startup
    if knowledge_col.count_documents({}) == 0:
        ingest_corpus()
    # Run initial platform scan & launch background daemon
    run_platform_scan(detect_host_platform(), scope="startup-daemon")
    scanner_task = asyncio.create_task(background_scan_loop(SCAN_INTERVAL_SECONDS))
    yield
    scanner_task.cancel()
    mongo_client.close()


app = FastAPI(
    title="MongoDB CTI LLM Threat Intelligence & Autonomous Remediation Chatbot",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def enforce_rate_limit(client_ip: str) -> None:
    now = time.time()
    bucket = RATE_BUCKETS[client_ip]
    while bucket and (now - bucket[0]) > 60.0:
        bucket.popleft()
    if len(bucket) >= RATE_LIMIT_PER_MINUTE:
        raise HTTPException(status_code=429, detail="Rate limit exceeded. Try again in 60 seconds.")
    bucket.append(now)


def cosine_similarity(a: List[float], b: List[float]) -> float:
    dot = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a)) or 1.0
    nb = math.sqrt(sum(y * y for y in b)) or 1.0
    return dot / (na * nb)


def retrieve_context(
    query: str,
    platform_filter: Optional[str] = None,
    lifecycle_filter: Optional[str] = None,
    n_results: int = 4,
) -> List[Dict[str, Any]]:
    """
    Retrieves top-k relevant threat advisories using Atlas $vectorSearch when available,
    falling back seamlessly to local cosine similarity over MongoDB embeddings.
    """
    query_emb = get_embeddings([query])[0]

    # Try Atlas $vectorSearch pipeline first
    try:
        vs_stage: Dict[str, Any] = {
            "index": "vector_index",
            "path": "embedding",
            "queryVector": query_emb,
            "numCandidates": 20,
            "limit": n_results,
        }
        if platform_filter and platform_filter.lower() != "all":
            vs_stage["filter"] = {"platform": platform_filter}
        results = list(knowledge_col.aggregate([{"$vectorSearch": vs_stage}]))
        if results:
            return results
    except Exception:
        pass

    # Local MongoDB Community / Docker fallback using stored embeddings
    mongo_filter: Dict[str, Any] = {}
    if platform_filter and platform_filter.lower() != "all":
        mongo_filter["platform"] = {"$regex": f"^{re.escape(platform_filter)}$", "$options": "i"}
    if lifecycle_filter and lifecycle_filter.lower() != "all":
        mongo_filter["lifecycle"] = {"$regex": f"^{re.escape(lifecycle_filter)}$", "$options": "i"}

    candidates = list(knowledge_col.find(mongo_filter, {"_id": 0}))
    if not candidates:
        candidates = list(knowledge_col.find({}, {"_id": 0}))

    scored = []
    for doc in candidates:
        emb = doc.get("embedding") or deterministic_embedding(doc.get("text", ""))
        score = cosine_similarity(query_emb, emb)
        scored.append((score, doc))
    scored.sort(key=lambda pair: pair[0], reverse=True)
    return [doc for _, doc in scored[:n_results]]


def get_history(session_id: str, n: int = 5) -> List[Dict[str, str]]:
    msgs = list(
        sessions_col.find({"session_id": session_id}, {"_id": 0})
        .sort("timestamp", DESCENDING)
        .limit(n * 2)
    )[::-1]
    return [{"role": m["role"], "content": m["content"]} for m in msgs]


def call_hosted_gemini_llm(
    user_msg: str,
    context_docs: List[Dict[str, Any]],
    history: List[Dict[str, str]],
    pending_vulns: List[Dict[str, Any]],
    platform: str,
    lifecycle: str,
) -> str:
    """Calls the hosted Google Gemini API (NOT Ollama) with grounded CTI context."""
    context_block = "
".join(
        f"- [{d.get('doc_id')}] ({d.get('lifecycle')} | {d.get('platform')} | {d.get('severity')} CVSS {d.get('cvss')}) "
        f"{d.get('title')}: {d.get('text')} | Command: `{d.get('mitigation_cmd')}`"
        for d in context_docs
    )
    vuln_block = "
".join(
        f"- {v.get('vuln_id')} ({v.get('platform')}, {v.get('severity')}, status={v.get('status')}): "
        f"{v.get('title')} -> Fix: `{v.get('remediation_cmd')}`"
        for v in pending_vulns
    ) or "None currently pending."

    history_block = "
".join(f"{h['role'].upper()}: {h['content']}" for h in history[-6:])

    system_instruction = (
        "You are an expert Cyber Threat Intelligence (CTI) & Autonomous Remediation AI Assistant backed by MongoDB. "
        "Provide precise, actionable guidance covering Anticipated, Active, Evolving, and Resolved threats for Linux, "
        "Windows, macOS, Android, and iOS. Include exact CVEs, Indicators of Compromise (IoCs), and step-by-step "
        "mitigation commands. If a platform vulnerability is pending confirmation, clearly state its VULN-ID and ask "
        "the user to reply with `CONFIRM FIX <VULN-ID>` before executing remediation."
    )

    full_prompt = (
        f"Target Platform Filter: {platform} | Lifecycle Filter: {lifecycle}

"
        f"Retrieved Threat Intelligence Context (MongoDB RAG):
{context_block}

"
        f"Background Scanner Vulnerability Findings:
{vuln_block}

"
        f"Recent Conversation Memory (MongoDB sessions):
{history_block}

"
        f"User Query: {user_msg}"
    )

    if GEMINI_API_KEY:
        endpoint = (
            f"https://generativelanguage.googleapis.com/v1beta/models/"
            f"{GEMINI_MODEL}:generateContent?key={GEMINI_API_KEY}"
        )
        payload = {
            "system_instruction": {"parts": [{"text": system_instruction}]},
            "contents": [{"role": "user", "parts": [{"text": full_prompt}]}],
            "generationConfig": {"temperature": 0.3, "maxOutputTokens": 900},
        }
        try:
            resp = requests.post(endpoint, json=payload, timeout=30)
            if resp.status_code == 200:
                data = resp.json()
                candidates = data.get("candidates", [])
                if candidates:
                    parts = candidates[0].get("content", {}).get("parts", [])
                    text = "".join(p.get("text", "") for p in parts).strip()
                    if text:
                        return text
        except Exception as exc:
            print(f"[WARN] Hosted Gemini API request failed, using grounded synthesizer: {exc}")

    # Deterministic grounded fallback if offline / sandboxed
    if not context_docs:
        return (
            f"No specific advisories matched platform={platform}, lifecycle={lifecycle}. "
            "Try running a platform scan or selecting another platform."
        )
    lines = [f"### Threat Intelligence Briefing ({platform} — {lifecycle})
"]
    for d in context_docs[:3]:
        lines.append(
            f"- **[{d.get('lifecycle')}] {d.get('title')}** (`{d.get('doc_id')}`, {d.get('severity')}, CVSS {d.get('cvss')})
"
            f"  - **Analysis:** {d.get('text')}
"
            f"  - **Mitigation Procedure:** `{d.get('mitigation_cmd')}`"
        )
    if pending_vulns:
        lines.append("
**Pending Background Scanner Findings (Confirmation Required):**")
        for v in pending_vulns[:3]:
            lines.append(
                f"- `{v.get('vuln_id')}` ({v.get('platform')} — {v.get('severity')}): {v.get('title')}. "
                f"Reply **`CONFIRM FIX {v.get('vuln_id')}`** to apply mitigation."
            )
    return "
".join(lines)


class ChatRequest(BaseModel):
    message: str = Field(..., min_length=1, max_length=4000)
    session_id: str = Field(default="default-session")
    platform: str = Field(default="All")
    lifecycle: str = Field(default="All")


class ScanRequest(BaseModel):
    platform: str = Field(default="Linux")
    scope: str = Field(default="system-wide")
    project_path: Optional[str] = Field(default="/")


@app.get("/health")
async def health_check() -> Dict[str, Any]:
    try:
        mongo_client.admin.command("ping")
        mongo_status = "connected"
    except Exception as exc:
        mongo_status = f"error: {exc}"
    return {
        "status": "healthy" if mongo_status == "connected" else "degraded",
        "mongodb": mongo_status,
        "llm_backend": "hosted_google_gemini_api",
        "model": GEMINI_MODEL,
        "knowledge_chunks": knowledge_col.count_documents({}),
        "pending_vulnerabilities": vulns_col.count_documents({"status": "pending_confirmation"}),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/metrics")
async def get_metrics() -> Dict[str, Any]:
    avg_ms = (
        round(METRICS["total_latency_ms"] / METRICS["requests_total"], 2)
        if METRICS["requests_total"]
        else 0.0
    )
    return {
        **METRICS,
        "avg_latency_ms": avg_ms,
        "stored_sessions": len(sessions_col.distinct("session_id")),
        "stored_messages": sessions_col.count_documents({}),
    }


@app.get("/threats")
async def list_threats(
    platform: Optional[str] = None,
    lifecycle: Optional[str] = None,
) -> Dict[str, Any]:
    query: Dict[str, Any] = {}
    if platform and platform.lower() != "all":
        query["platform"] = {"$regex": f"^{re.escape(platform)}$", "$options": "i"}
    if lifecycle and lifecycle.lower() != "all":
        query["lifecycle"] = {"$regex": f"^{re.escape(lifecycle)}$", "$options": "i"}
    items = list(threats_col.find(query, {"_id": 0}))
    return {"count": len(items), "threats": items}


@app.get("/vulnerabilities")
async def list_vulnerabilities(platform: Optional[str] = None) -> Dict[str, Any]:
    query: Dict[str, Any] = {}
    if platform and platform.lower() != "all":
        query["platform"] = {"$regex": f"^{re.escape(platform)}$", "$options": "i"}
    items = list(vulns_col.find(query, {"_id": 0}))
    audits = list(audit_col.find({}, {"_id": 0}).sort("timestamp", DESCENDING).limit(10))
    return {"vulnerabilities": items, "recent_audits": audits}


@app.post("/scan")
async def trigger_scan(req: ScanRequest) -> Dict[str, Any]:
    result = run_platform_scan(
        target_platform=req.platform,
        scope=req.scope,
        project_path=req.project_path,
    )
    return result


@app.post("/mitigate/{vuln_id}")
async def confirm_mitigation_endpoint(vuln_id: str) -> Dict[str, Any]:
    res = apply_mitigation(vuln_id, confirmed_by="api_confirmation")
    if not res.get("ok"):
        raise HTTPException(status_code=404, detail=res.get("error", "Not found"))
    return res


@app.get("/history/{session_id}")
async def fetch_history(session_id: str) -> Dict[str, Any]:
    return {"session_id": session_id, "messages": get_history(session_id, n=20)}


@app.post("/chat")
async def chat_endpoint(req: ChatRequest, request: Request) -> Dict[str, Any]:
    t0 = time.perf_counter()
    METRICS["requests_total"] += 1
    METRICS["chat_requests"] += 1
    client_ip = request.client.host if request.client else "127.0.0.1"
    enforce_rate_limit(client_ip)

    now_iso = datetime.now(timezone.utc).isoformat()
    user_msg = req.message.strip()

    # Persist user message in MongoDB sessions collection (A.4)
    sessions_col.insert_one(
        {
            "session_id": req.session_id,
            "role": "user",
            "content": user_msg,
            "platform": req.platform,
            "lifecycle": req.lifecycle,
            "timestamp": now_iso,
        }
    )

    # Check if user issued conversational confirmation: e.g., "CONFIRM FIX VULN-LNX-101"
    confirm_match = re.search(r"confirm\s+(?:fix|mitigate|remediate)\s+(vuln-[a-z]+-\d+)", user_msg, re.I)
    if confirm_match:
        target_vuln_id = confirm_match.group(1).upper()
        mit_res = apply_mitigation(target_vuln_id, confirmed_by=f"chat:{req.session_id}")
        if mit_res.get("ok"):
            v = mit_res["vulnerability"]
            answer = (
                f"**Conversational Confirmation Verified — Mitigation Executed (`{mit_res['audit_id']}`)**

"
                f"- **Vulnerability:** `{v['vuln_id']}` ({v['cve']}) — {v['title']}
"
                f"- **Platform:** {v['platform']} | **New Lifecycle State:** `{v['lifecycle']}` (`{v['status']}`)
"
                f"- **Executed Procedure:** `{v['remediation_cmd']}`
"
                f"- **Verification:** Configuration hardened (`{v['expected_value']}`) and logged to MongoDB `remediation_audit`."
            )
        else:
            answer = f"Could not execute mitigation: {mit_res.get('error')}"
    else:
        # Check if user asked to scan a platform in natural language
        scan_match = re.search(r"scan.*?(linux|windows|macos|android|ios)", user_msg, re.I)
        if scan_match:
            scan_plat = scan_match.group(1)
            run_platform_scan(scan_plat, scope="chat-triggered-scan")

        context_docs = retrieve_context(
            user_msg,
            platform_filter=req.platform,
            lifecycle_filter=req.lifecycle,
            n_results=4,
        )
        pending_vulns = list(
            vulns_col.find({"status": "pending_confirmation"}, {"_id": 0}).limit(5)
        )
        history = get_history(req.session_id, n=5)
        answer = call_hosted_gemini_llm(
            user_msg=user_msg,
            context_docs=context_docs,
            history=history,
            pending_vulns=pending_vulns,
            platform=req.platform,
            lifecycle=req.lifecycle,
        )

    sessions_col.insert_one(
        {
            "session_id": req.session_id,
            "role": "assistant",
            "content": answer,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    )

    elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 2)
    METRICS["total_latency_ms"] += elapsed_ms
    METRICS["estimated_tokens"] += (len(user_msg) + len(answer)) // 4

    return {
        "session_id": req.session_id,
        "answer": answer,
        "latency_ms": elapsed_ms,
        "llm_provider": "hosted_google_gemini_api",
        "model": GEMINI_MODEL,
    }
