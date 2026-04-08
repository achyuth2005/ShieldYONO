# ShieldYONO Architecture

## System Overview

ShieldYONO is a real-time URL phishing detection system with the following components:

### 1. Frontend (React + Tailwind CSS)
- Single-page dashboard for URL scanning
- Glassmorphism dark theme design
- Hindi + English bilingual support
- Real-time analytics panel

### 2. Backend (FastAPI)
- RESTful API with structured JSON responses
- Request validation and error handling
- CORS support for frontend proxy
- Swagger/OpenAPI documentation

### 3. URL Preprocessing Pipeline
```
Raw URL → Decode → Validate → SSRF Check → Resolve Redirects → Final URL
```

### 4. Feature Extraction Engine (34 features)
```
URL Structure (18) + Domain Intelligence (8) + Brand Impersonation (8) = 34 features
```

### 5. ML Classification
```
Feature Vector → XGBoost (primary) → Probability
                  ↓ fallback
                 LogReg → Probability
                  ↓ fallback
                 Heuristic Rules → Probability
```

### 6. Risk Scoring
```
ML Probability × 100 + Rule Boosters - Rule Reducers = Final Score (0-100)
                         ↓
                  0-34: SAFE
                  35-69: SUSPICIOUS
                  70-100: PHISHING
```

### 7. Caching (Redis)
- SAFE results: cached 1 hour
- SUSPICIOUS results: cached 10 minutes
- PHISHING results: cached 5 minutes
- Graceful fallback when Redis is unavailable

### 8. Storage (SQLite)
- All scans logged for analytics
- Queryable recent scan history
- Aggregate statistics (total, by tier, avg score)

## Data Flow

```
User Input
    ↓
FastAPI /api/check-url?url=...
    ↓
Redis Cache Check → HIT → Return cached result
    ↓ MISS
URL Preprocessing
    ↓
Feature Extraction (34 features)
    ↓
ML Prediction (XGBoost/LogReg/Heuristic)
    ↓
Risk Scoring (rules + probability)
    ↓
Build Response (score, tier, reasons, verdict)
    ↓
Cache Result in Redis
    ↓
Store in SQLite
    ↓
Return JSON to Frontend
```

## Security Design

1. **SSRF Prevention**: Private IPs blocked before any outbound request
2. **Redirect Limit**: Maximum 5 hops to prevent loops
3. **Timeout Enforcement**: All network calls (WHOIS, DNS, SSL) have configurable timeouts
4. **Input Sanitization**: URL scheme validation, length limits
5. **Graceful Degradation**: Network failures don't crash the request
