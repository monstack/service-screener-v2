# AWS Service Screener - Web GUI

A modern web interface for AWS Service Screener, providing an easy-to-use GUI for running AWS infrastructure scans against Well-Architected best practices.

## Quick Start with Docker

```bash
# Build and run
docker-compose up --build

# Access at http://localhost:8000
```

## Features

- 🌍 **Region Selection** - Choose multiple AWS regions to scan
- ⚙️ **Service Selection** - Pick specific AWS services (EC2, S3, RDS, IAM, etc.)
- 📋 **Compliance Frameworks** - Map findings to CIS, NIST, SOC2, Well-Architected
- 📊 **Real-time Progress** - Watch scan progress with live updates
- 📈 **Interactive Reports** - View and navigate generated HTML reports

## Architecture

```
webapp/
├── app.py              # FastAPI backend (wraps existing CLI)
├── requirements.txt    # Python dependencies
└── frontend/           # React + Vite frontend
    ├── src/
    │   ├── App.jsx     # Main React component
    │   ├── index.css   # Modern dark theme styles
    │   └── main.jsx    # React entry point
    └── package.json
```

## Manual Setup (Development)

### Backend
```bash
cd webapp
pip install -r requirements.txt
uvicorn app:app --reload --port 8000
```

### Frontend
```bash
cd webapp/frontend
npm install
npm run dev  # Runs on port 5173
```

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/health` | GET | Health check |
| `/api/services` | GET | List available AWS services |
| `/api/regions` | GET | List AWS regions |
| `/api/frameworks` | GET | List compliance frameworks |
| `/api/scan` | POST | Start a new scan |
| `/api/scan/{job_id}` | GET | Get scan status |
| `/api/reports` | GET | List generated reports |

## Requirements

- Docker & Docker Compose (recommended)
- OR Python 3.10+ and Node.js 18+
- AWS credentials configured (`~/.aws/credentials`)

## Notes

- The web GUI does **NOT** modify any original Service Screener code
- It calls the existing `main.py` CLI as a subprocess
- Reports are stored in `adminlte/aws/` directory
