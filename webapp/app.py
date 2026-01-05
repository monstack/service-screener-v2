"""
AWS Service Screener Web GUI - FastAPI Backend
This is a wrapper that calls the existing Service Screener functions
without modifying the original code.
"""
import os
import sys
import json
import uuid
import asyncio
from datetime import datetime
from typing import Optional, List, Dict, Any
from pathlib import Path

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel

# Add parent directory to path to import existing modules
SCREENER_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(SCREENER_ROOT))

# Import existing Service Screener modules
from utils.Config import Config
import constants as _C

app = FastAPI(
    title="AWS Service Screener Web GUI",
    description="Web interface for AWS Service Screener",
    version="1.0.0"
)

# Serve static frontend files (built React app)
STATIC_DIR = Path(__file__).parent / "static"
if STATIC_DIR.exists():
    app.mount("/assets", StaticFiles(directory=STATIC_DIR / "assets"), name="assets")

# CORS for frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:3000", "http://localhost:8080"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Store for running scan jobs
scan_jobs: Dict[str, Dict[str, Any]] = {}

# WebSocket connections for real-time updates
websocket_connections: Dict[str, List[WebSocket]] = {}

# Available services (from existing screener)
AVAILABLE_SERVICES = [
    {"id": "apigateway", "name": "API Gateway", "category": "Networking"},
    {"id": "cloudfront", "name": "CloudFront", "category": "Networking"},
    {"id": "cloudtrail", "name": "CloudTrail", "category": "Security"},
    {"id": "cloudwatch", "name": "CloudWatch", "category": "Management"},
    {"id": "dynamodb", "name": "DynamoDB", "category": "Database"},
    {"id": "ec2", "name": "EC2 (Compute)", "category": "Compute"},
    {"id": "efs", "name": "EFS", "category": "Storage"},
    {"id": "eks", "name": "EKS", "category": "Containers"},
    {"id": "elasticache", "name": "ElastiCache", "category": "Database"},
    {"id": "guardduty", "name": "GuardDuty", "category": "Security"},
    {"id": "iam", "name": "IAM", "category": "Security"},
    {"id": "kms", "name": "KMS", "category": "Security"},
    {"id": "lambda", "name": "Lambda", "category": "Compute"},
    {"id": "opensearch", "name": "OpenSearch", "category": "Analytics"},
    {"id": "rds", "name": "RDS", "category": "Database"},
    {"id": "redshift", "name": "Redshift", "category": "Analytics"},
    {"id": "s3", "name": "S3", "category": "Storage"},
    {"id": "sqs", "name": "SQS", "category": "Application Integration"},
]

# AWS Regions
AWS_REGIONS = [
    {"id": "us-east-1", "name": "US East (N. Virginia)"},
    {"id": "us-east-2", "name": "US East (Ohio)"},
    {"id": "us-west-1", "name": "US West (N. California)"},
    {"id": "us-west-2", "name": "US West (Oregon)"},
    {"id": "ap-southeast-1", "name": "Asia Pacific (Singapore)"},
    {"id": "ap-southeast-2", "name": "Asia Pacific (Sydney)"},
    {"id": "ap-northeast-1", "name": "Asia Pacific (Tokyo)"},
    {"id": "ap-northeast-2", "name": "Asia Pacific (Seoul)"},
    {"id": "ap-northeast-3", "name": "Asia Pacific (Osaka)"},
    {"id": "ap-south-1", "name": "Asia Pacific (Mumbai)"},
    {"id": "eu-west-1", "name": "Europe (Ireland)"},
    {"id": "eu-west-2", "name": "Europe (London)"},
    {"id": "eu-west-3", "name": "Europe (Paris)"},
    {"id": "eu-central-1", "name": "Europe (Frankfurt)"},
    {"id": "eu-north-1", "name": "Europe (Stockholm)"},
    {"id": "sa-east-1", "name": "South America (São Paulo)"},
    {"id": "ca-central-1", "name": "Canada (Central)"},
]

# Compliance Frameworks
FRAMEWORKS = [
    {"id": "WAFS", "name": "AWS Well-Architected Framework - Security Pillar"},
    {"id": "CIS", "name": "CIS AWS Foundations Benchmark"},
    {"id": "FTR", "name": "AWS Foundational Technical Review"},
    {"id": "NIST", "name": "NIST Cybersecurity Framework"},
    {"id": "SOC2", "name": "SOC 2 Compliance"},
    {"id": "SSB", "name": "AWS Startup Security Baseline"},
]


# Pydantic models
class ScanRequest(BaseModel):
    regions: List[str]
    services: List[str]
    frameworks: Optional[List[str]] = []
    aws_profile: Optional[str] = None
    # SSO credentials (optional - used when logged in via SSO)
    sso_account_id: Optional[str] = None
    sso_role_name: Optional[str] = None
    use_sso: Optional[bool] = False


class ScanJob(BaseModel):
    job_id: str
    status: str  # pending, running, completed, failed
    progress: int
    current_task: str
    created_at: str
    completed_at: Optional[str] = None
    report_path: Optional[str] = None
    error: Optional[str] = None


class SSOStartRequest(BaseModel):
    start_url: str  # e.g., https://my-company.awsapps.com/start
    region: Optional[str] = "us-east-1"


class SSORoleCredentialsRequest(BaseModel):
    account_id: str
    role_name: str
    region: Optional[str] = "us-east-1"


# Import SSO handler
from webapp.sso_auth import sso_handler


# API Endpoints
@app.get("/api/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "version": "1.0.0"}


@app.get("/api/services")
async def get_services():
    """Get list of available AWS services to scan"""
    return {"services": AVAILABLE_SERVICES}


@app.get("/api/regions")
async def get_regions():
    """Get list of AWS regions"""
    return {"regions": AWS_REGIONS}


@app.get("/api/frameworks")
async def get_frameworks():
    """Get list of compliance frameworks"""
    return {"frameworks": FRAMEWORKS}


@app.get("/api/aws-profiles")
async def get_aws_profiles():
    """Get available AWS profiles from ~/.aws/credentials"""
    profiles = ["default"]
    credentials_file = Path.home() / ".aws" / "credentials"
    
    if credentials_file.exists():
        try:
            content = credentials_file.read_text()
            import re
            profile_matches = re.findall(r'\[([^\]]+)\]', content)
            profiles = list(set(profiles + profile_matches))
        except Exception:
            pass
    
    return {"profiles": profiles}


# ============ SSO Authentication Endpoints ============

@app.get("/api/sso/status")
async def sso_status():
    """Check SSO authentication status"""
    return {
        "authenticated": sso_handler.is_authenticated(),
        "expires_at": sso_handler.token_expiry.isoformat() if sso_handler.token_expiry else None
    }


@app.post("/api/sso/start")
async def sso_start(request: SSOStartRequest):
    """
    Start SSO device authorization flow.
    Returns a URL that user needs to visit to complete login.
    """
    try:
        auth_info = sso_handler.start_device_authorization(
            start_url=request.start_url,
            region=request.region
        )
        return {
            "status": "started",
            "user_code": auth_info["user_code"],
            "verification_uri": auth_info["verification_uri"],
            "verification_uri_complete": auth_info["verification_uri_complete"],
            "expires_in": auth_info["expires_in"],
            "region": auth_info.get("region", request.region),
            "message": f"Please visit {auth_info['verification_uri_complete']} to complete login"
        }
    except Exception as e:
        import traceback
        traceback.print_exc()
        return {"status": "error", "message": str(e)}


@app.post("/api/sso/poll")
async def sso_poll():
    """Poll to check if user completed SSO login"""
    # Use the region that was set during start_device_authorization
    if not sso_handler.current_region:
        return {"status": "error", "message": "No SSO login in progress. Please start SSO login first."}
    if not sso_handler.client_id:
        return {"status": "error", "message": "SSO client not registered. Please restart SSO login."}
    result = sso_handler.poll_for_token(sso_handler.current_region)
    return result


@app.get("/api/sso/accounts")
async def sso_list_accounts():
    """List AWS accounts available after SSO login"""
    if not sso_handler.is_authenticated():
        return {"error": "Not authenticated", "accounts": []}
    
    region = sso_handler.current_region or "us-east-1"
    accounts = sso_handler.list_accounts(region)
    return {"accounts": accounts}


@app.get("/api/sso/accounts/{account_id}/roles")
async def sso_list_roles(account_id: str):
    """List roles available for a specific account"""
    if not sso_handler.is_authenticated():
        return {"error": "Not authenticated", "roles": []}
    
    region = sso_handler.current_region or "us-east-1"
    roles = sso_handler.list_account_roles(account_id, region)
    return {"roles": roles}


@app.post("/api/sso/credentials")
async def sso_get_credentials(request: SSORoleCredentialsRequest):
    """Get temporary credentials for a role (used for scanning)"""
    if not sso_handler.is_authenticated():
        return {"error": "Not authenticated"}
    
    creds = sso_handler.get_role_credentials(
        account_id=request.account_id,
        role_name=request.role_name,
        region=request.region
    )
    return creds


# Store SSO credentials for scanning
sso_credentials: Dict[str, Any] = {}


@app.post("/api/scan", response_model=ScanJob)
async def start_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    """Start a new scan job"""
    job_id = str(uuid.uuid4())[:8]
    
    scan_jobs[job_id] = {
        "job_id": job_id,
        "status": "pending",
        "progress": 0,
        "current_task": "Initializing...",
        "created_at": datetime.now().isoformat(),
        "completed_at": None,
        "report_path": None,
        "error": None,
        "request": request.dict()
    }
    
    # Start scan in background
    background_tasks.add_task(run_scan, job_id, request)
    
    return ScanJob(**scan_jobs[job_id])


@app.get("/api/scan/{job_id}", response_model=ScanJob)
async def get_scan_status(job_id: str):
    """Get status of a scan job"""
    if job_id not in scan_jobs:
        raise HTTPException(status_code=404, detail="Scan job not found")
    
    return ScanJob(**scan_jobs[job_id])


@app.get("/api/scans")
async def list_scans():
    """List all scan jobs"""
    return {"scans": list(scan_jobs.values())}


@app.get("/api/reports")
async def list_reports():
    """List available reports"""
    reports = []
    reports_dir = SCREENER_ROOT / "adminlte" / "aws"
    
    if reports_dir.exists():
        for account_dir in reports_dir.iterdir():
            if account_dir.is_dir() and account_dir.name.isdigit():
                index_file = account_dir / "index.html"
                if index_file.exists():
                    reports.append({
                        "account_id": account_dir.name,
                        "path": f"/reports/{account_dir.name}/index.html",
                        "created_at": datetime.fromtimestamp(index_file.stat().st_mtime).isoformat()
                    })
    
    return {"reports": sorted(reports, key=lambda x: x["created_at"], reverse=True)}


# WebSocket for real-time scan progress
@app.websocket("/ws/scan/{job_id}")
async def websocket_scan_progress(websocket: WebSocket, job_id: str):
    await websocket.accept()
    
    if job_id not in websocket_connections:
        websocket_connections[job_id] = []
    websocket_connections[job_id].append(websocket)
    
    try:
        while True:
            if job_id in scan_jobs:
                job = scan_jobs[job_id]
                await websocket.send_json(job)
                
                if job["status"] in ["completed", "failed"]:
                    break
            
            await asyncio.sleep(1)
    except WebSocketDisconnect:
        websocket_connections[job_id].remove(websocket)


async def broadcast_progress(job_id: str, data: dict):
    """Broadcast progress to all connected WebSocket clients"""
    if job_id in websocket_connections:
        for ws in websocket_connections[job_id]:
            try:
                await ws.send_json(data)
            except:
                pass


async def run_scan(job_id: str, request: ScanRequest):
    """Run the actual scan using existing Service Screener"""
    import subprocess
    
    try:
        scan_jobs[job_id]["status"] = "running"
        scan_jobs[job_id]["current_task"] = "Preparing scan..."
        scan_jobs[job_id]["progress"] = 5
        
        # Build command to run existing CLI
        cmd = [
            sys.executable, 
            str(SCREENER_ROOT / "main.py"),
            "--regions", ",".join(request.regions),
            "--services", ",".join(request.services),
        ]
        
        if request.frameworks:
            cmd.extend(["--frameworks", ",".join(request.frameworks)])
        
        # Set up environment
        env = os.environ.copy()
        
        # Check if using SSO credentials
        if request.use_sso and sso_handler.is_authenticated():
            scan_jobs[job_id]["current_task"] = "Getting SSO credentials..."
            
            if request.sso_account_id and request.sso_role_name:
                # Get temporary credentials from SSO
                region = sso_handler.current_region or "us-east-1"
                creds = sso_handler.get_role_credentials(
                    account_id=request.sso_account_id,
                    role_name=request.sso_role_name,
                    region=region
                )
                
                if "error" in creds:
                    scan_jobs[job_id]["status"] = "failed"
                    scan_jobs[job_id]["error"] = f"Failed to get SSO credentials: {creds['error']}"
                    return
                
                # Set AWS credentials as environment variables
                env["AWS_ACCESS_KEY_ID"] = creds["access_key_id"]
                env["AWS_SECRET_ACCESS_KEY"] = creds["secret_access_key"]
                env["AWS_SESSION_TOKEN"] = creds["session_token"]
                # Remove any conflicting profile setting
                env.pop("AWS_PROFILE", None)
                
                scan_jobs[job_id]["current_task"] = f"SSO credentials obtained for account {request.sso_account_id}"
            else:
                scan_jobs[job_id]["status"] = "failed"
                scan_jobs[job_id]["error"] = "SSO login detected but no account/role selected. Please select an account and role."
                return
        elif request.aws_profile:
            # Use AWS profile
            env["AWS_PROFILE"] = request.aws_profile
        
        scan_jobs[job_id]["current_task"] = f"Scanning {len(request.services)} services in {len(request.regions)} regions..."
        scan_jobs[job_id]["progress"] = 10
        
        # Run the scan
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            cwd=str(SCREENER_ROOT),
            env=env,
            text=True
        )
        
        # Read output and update progress
        total_services = len(request.services)
        services_scanned = 0
        output_lines = []
        
        for line in iter(process.stdout.readline, ''):
            if not line:
                break
            
            # Store output for debugging
            output_lines.append(line.strip())
            print(f"[SCAN {job_id}] {line.strip()}")  # Log to console
            
            # Update progress based on output
            if "Processing" in line or "Scanning" in line:
                services_scanned += 1
                progress = min(10 + int((services_scanned / total_services) * 80), 90)
                scan_jobs[job_id]["progress"] = progress
                scan_jobs[job_id]["current_task"] = line.strip()[:100]
        
        process.wait()
        
        if process.returncode == 0:
            scan_jobs[job_id]["status"] = "completed"
            scan_jobs[job_id]["progress"] = 100
            scan_jobs[job_id]["current_task"] = "Scan completed successfully"
            scan_jobs[job_id]["completed_at"] = datetime.now().isoformat()
            
            # Find the generated report
            reports_dir = SCREENER_ROOT / "adminlte" / "aws"
            if reports_dir.exists():
                for account_dir in reports_dir.iterdir():
                    if account_dir.is_dir() and account_dir.name.isdigit():
                        scan_jobs[job_id]["report_path"] = f"/reports/{account_dir.name}/index.html"
                        break
        else:
            scan_jobs[job_id]["status"] = "failed"
            # Get last few lines of output for error message
            error_output = "\n".join(output_lines[-10:]) if output_lines else "No output"
            scan_jobs[job_id]["error"] = f"Scan failed (exit code {process.returncode}). Last output:\n{error_output}"
            
    except Exception as e:
        import traceback
        traceback.print_exc()
        scan_jobs[job_id]["status"] = "failed"
        scan_jobs[job_id]["error"] = str(e)


# Serve static report files
@app.get("/reports/{account_id}/{file_path:path}")
async def serve_report(account_id: str, file_path: str):
    """Serve generated HTML reports"""
    report_file = SCREENER_ROOT / "adminlte" / "aws" / account_id / file_path
    
    if not report_file.exists():
        raise HTTPException(status_code=404, detail="Report not found")
    
    return FileResponse(report_file)


# Serve frontend index.html for root and SPA routes
@app.get("/")
async def serve_frontend():
    """Serve the frontend React app"""
    index_file = STATIC_DIR / "index.html"
    if index_file.exists():
        return FileResponse(index_file)
    # Fallback message if frontend not built
    return JSONResponse({
        "message": "AWS Service Screener API is running",
        "docs": "/docs",
        "frontend": "Build frontend with: cd webapp/frontend && npm install && npm run build"
    })


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
