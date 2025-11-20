# main.py - REST API cho SSH Brute Force Detector
# main.py = Người trung gian

# Nhận request từ Frontend
# Gọi các file Python khác để xử lý
# Trả response về Frontend
# Frontend chỉ nói chuyện với main.py, không gọi trực tiếp các file khác! 🎯
from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional

# Import các modules đã tạo
from generator import generate_ssh_bruteforce_log
from analyze import analyze_ssh_log
from time_filter import aggregate_incidents
from ai_service import analyze_with_ai

# ============================================
# SETUP FASTAPI
# ============================================

app = FastAPI(
    title="SSH Brute Force Detector API",
    description="API để phát hiện và phân tích SSH brute force attacks",
    version="1.0.0"
)

# CORS - Cho phép Frontend gọi API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ============================================
# REQUEST/RESPONSE MODELS
# ============================================

class SimulateRequest(BaseModel):
    """Request model cho /api/simulate"""
    attempts: int = 100
    duration: int = 5

class AnalyzeRequest(BaseModel):
    """Request model cho /api/analyze"""
    log_content: str

class AIAnalyzeRequest(BaseModel):
    """Request model cho /api/ai/single"""
    incident: dict

class AggregatedAnalyzeRequest(BaseModel):
    """Request model cho /api/ai/aggregated"""
    incidents: list
    time_range: str = "Custom period"

# ============================================
# ENDPOINTS
# ============================================

@app.get("/")
def root():
    """
    Root endpoint - Health check
    
    Chức năng: Kiểm tra API có hoạt động không
    """
    return {
        "message": "SSH Brute Force Detector API",
        "status": "running",
        "version": "1.0.0",
        "endpoints": {
            "simulate": "POST /api/simulate",
            "upload": "POST /api/upload",
            "analyze": "POST /api/analyze",
            "ai_single": "POST /api/ai/single",
            "ai_aggregated": "POST /api/ai/aggregated"
        }
    }


@app.post("/api/simulate")
def simulate_attack(request: SimulateRequest):
    """
    Endpoint 1: Generate fake SSH logs
    
    Chức năng: Tạo log giả để test
    
    Input:
        - attempts: Số lần thử (10-500)
        - duration: Thời gian tấn công (phút)
    
    Output:
        - log_content: Nội dung log
        - metadata: Thông tin về log
    """
    try:
        # Validate input
        if request.attempts < 10 or request.attempts > 500:
            raise HTTPException(
                status_code=400, 
                detail="Attempts phải từ 10-500"
            )
        
        if request.duration < 1 or request.duration > 60:
            raise HTTPException(
                status_code=400,
                detail="Duration phải từ 1-60 phút"
            )
        
        # Generate log
        log_content = generate_ssh_bruteforce_log(
            attempts=request.attempts,
            duration_minutes=request.duration
        )
        
        # Return response
        return {
            "status": "success",
            "log_content": log_content,
            "metadata": {
                "attempts": request.attempts,
                "duration": request.duration,
                "lines": len(log_content.split('\n'))
            }
        }
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error: {str(e)}")


@app.post("/api/upload")
async def upload_log(file: UploadFile = File(...)):
    """
    Endpoint 2: Upload SSH log file
    
    Chức năng: Upload log file thật từ server
    
    Input:
        - file: Log file (.log, .txt)
    
    Output:
        - log_content: Nội dung file
        - filename: Tên file
        - size: Kích thước
    """
    try:
        # Validate file type
        if not file.filename.endswith(('.log', '.txt')):
            raise HTTPException(
                status_code=400,
                detail="Chỉ chấp nhận file .log hoặc .txt"
            )
        
        # Read file content
        content = await file.read()
        log_content = content.decode('utf-8')
        
        # Validate content
        if len(log_content.strip()) == 0:
            raise HTTPException(
                status_code=400,
                detail="File rỗng"
            )
        
        # Return response
        return {
            "status": "success",
            "log_content": log_content,
            "filename": file.filename,
            "size": len(log_content),
            "lines": len(log_content.split('\n'))
        }
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error: {str(e)}")


@app.post("/api/analyze")
def analyze_log(request: AnalyzeRequest):
    """
    Endpoint 3: Analyze SSH log
    
    Chức năng: Phân tích log để phát hiện attacks
    
    Input:
        - log_content: Nội dung log
    
    Output:
        - incidents: List các incidents
        - summary: Tổng hợp thông tin
    """
    try:
        # Validate input
        if not request.log_content or len(request.log_content.strip()) == 0:
            raise HTTPException(
                status_code=400,
                detail="Log content không được rỗng"
            )
        
        # Analyze log
        incidents = analyze_ssh_log(request.log_content)
        
        # Tạo summary
        summary = {
            "total_incidents": len(incidents),
            "high_severity": len([i for i in incidents if i['severity'] == 'high']),
            "medium_severity": len([i for i in incidents if i['severity'] == 'medium']),
            "low_severity": len([i for i in incidents if i['severity'] == 'low']),
            "total_attempts": sum(i['attempts'] for i in incidents)
        }
        
        # Return response
        return {
            "status": "success",
            "incidents": incidents,
            "summary": summary
        }
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error: {str(e)}")


@app.post("/api/ai/single")
def ai_analyze_single(request: AIAnalyzeRequest):
    """
    Endpoint 4: AI analyze single incident
    
    Chức năng: AI phân tích CHI TIẾT 1 incident
    
    Input:
        - incident: Dict chứa thông tin incident
    
    Output:
        - ai_analysis: Phân tích từ AI
        - tokens_used: Số tokens đã dùng
    """
    try:
        # Validate input
        if not request.incident:
            raise HTTPException(
                status_code=400,
                detail="Incident không được rỗng"
            )
        
        # Call AI service
        result = analyze_with_ai(
            incident=request.incident,
            mode="single"
        )
        
        # Check for errors
        if "error" in result:
            raise HTTPException(
                status_code=500,
                detail=f"AI Error: {result['error']}"
            )
        
        # Return response
        return {
            "status": "success",
            "ai_analysis": result['analysis'],
            "tokens_used": result['tokens_used'],
            "model": result['model']
        }
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error: {str(e)}")


@app.post("/api/ai/aggregated")
def ai_analyze_aggregated(request: AggregatedAnalyzeRequest):
    """
    Endpoint 5: AI analyze aggregated incidents
    
    Chức năng: AI phân tích TỔNG QUAN nhiều incidents
    
    Input:
        - incidents: List các incidents
        - time_range: Khoảng thời gian
    
    Output:
        - aggregated_data: Data đã tổng hợp
        - ai_analysis: Phân tích từ AI
        - tokens_used: Số tokens đã dùng
    """
    try:
        # Validate input
        if not request.incidents or len(request.incidents) == 0:
            raise HTTPException(
                status_code=400,
                detail="Incidents không được rỗng"
            )
        
        # Aggregate incidents
        aggregated = aggregate_incidents(request.incidents)
        
        # Call AI service
        result = analyze_with_ai(
            aggregated=aggregated,
            mode="aggregated",
            time_range=request.time_range
        )
        
        # Check for errors
        if "error" in result:
            raise HTTPException(
                status_code=500,
                detail=f"AI Error: {result['error']}"
            )
        
        # Return response
        return {
            "status": "success",
            "aggregated_data": aggregated,
            "ai_analysis": result['analysis'],
            "tokens_used": result['tokens_used'],
            "model": result['model']
        }
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error: {str(e)}")


# ============================================
# RUN SERVER
# ============================================

if __name__ == "__main__":
    import uvicorn
    print("🚀 Starting SSH Brute Force Detector API...")
    print("📖 API Docs: http://localhost:8080/docs")
    print("🔍 Health Check: http://localhost:8080/")
    uvicorn.run(app, host="0.0.0.0", port=8080)
