# ai_service.py
# AI Service với 2 modes: Single Incident & Aggregated

import os
from groq import Groq
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Initialize Groq client
client = Groq(api_key=os.getenv("GROQ_API_KEY"))


def analyze_with_ai(incident=None, aggregated=None, mode="single", time_range=""):
    """
    Get AI analysis for incident(s) - Tối ưu token!
    
    Args:
        incident: Dict - single incident (for mode="single")
        aggregated: Dict - aggregated data (for mode="aggregated")
        mode: "single" hoặc "aggregated"
        time_range: Mô tả time range (optional)
    
    Returns:
        String: AI analysis
    """
    
    # Import functions
    from analyze import format_incident_for_ai
    from time_filter import format_aggregated_for_ai
    
    # Tạo prompt dựa trên mode
    if mode == "single" and incident:
        # Format single incident (đã tối ưu token)
        prompt_data = format_incident_for_ai(incident)
        
        prompt = f"""Bạn là chuyên gia SOC (Security Operations Center). 
Phân tích cuộc tấn công SSH brute force sau và đưa ra:

1. 🎯 Đánh giá mức độ nguy hiểm
2. 🛡️ Khuyến nghị hành động ngay
3. 🔍 Phân tích hành vi attacker

{prompt_data}

Trả lời bằng tiếng Việt, ngắn gọn, chuyên nghiệp. Sử dụng emoji để dễ đọc."""
    
    elif mode == "aggregated" and aggregated:
        # Format aggregated data (siêu tối ưu token!)
        prompt_data = format_aggregated_for_ai(aggregated, time_range or "Custom period")
        
        prompt = f"""Bạn là chuyên gia SOC. 
Phân tích tổng hợp các cuộc tấn công SSH brute force sau:

{prompt_data}

Đưa ra:
1. 📈 Xu hướng tấn công
2. 🚨 Top threats cần ưu tiên xử lý
3. 🛡️ Khuyến nghị bảo mật tổng thể

Trả lời bằng tiếng Việt, ngắn gọn, tập trung vào actionable insights."""
    
    else:
        return {
            "error": "Invalid mode or missing data",
            "message": "Please provide either 'incident' (single mode) or 'aggregated' (aggregated mode)"
        }
    
    # Call Groq API
    try:
        response = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[
                {
                    "role": "system",
                    "content": "Bạn là chuyên gia bảo mật SOC với 10+ năm kinh nghiệm phân tích SSH brute force attacks."
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            temperature=0.7,
            max_tokens=1000
        )
        
        # Parse response
        ai_analysis = response.choices[0].message.content
        
        # Return với metadata
        return {
            "analysis": ai_analysis,
            "mode": mode,
            "tokens_used": response.usage.total_tokens if hasattr(response, 'usage') else 'N/A',
            "model": "llama-3.3-70b-versatile"
        }
    
    except Exception as e:
        return {
            "error": str(e),
            "message": "Failed to call Groq API. Check your API key and internet connection."
        }


# Test code
if __name__ == "__main__":
    from generator import generate_ssh_bruteforce_log
    from analyze import analyze_ssh_log
    from time_filter import aggregate_incidents
    import random
    
    print("🧪 Testing AI Service with Groq\n")
    print("="*70)
    
    # Test Mode 1: Single Incident
    print("\n1️⃣ MODE 1: Single Incident Analysis")
    print("-"*70)
    
    # Random attempts mỗi lần chạy
    attempts = random.randint(50, 200)
    duration = random.randint(2, 5)
    
    print(f"   Generating log with {attempts} attempts over {duration} minutes...")
    log = generate_ssh_bruteforce_log(attempts=attempts, duration_minutes=duration)
    
    print("   Analyzing log...")
    incidents = analyze_ssh_log(log)
    
    if incidents:
        print(f"   Found {len(incidents)} incident(s)")
        print("   Calling Groq AI (Single Mode)...\n")
        
        result = analyze_with_ai(incident=incidents[0], mode="single")
        
        if "error" in result:
            print(f"   ❌ Error: {result['error']}")
            print(f"   Message: {result['message']}")
        else:
            print("\n" + "="*70)
            print("📊 AI ANALYSIS (Single Incident)")
            print("="*70)
            print(result['analysis'])
            print("-"*70)
            print(f"💰 Tokens: {result['tokens_used']}")
            print("="*70)
    
    # Test Mode 2: Aggregated
    print("\n\n2️⃣ MODE 2: Aggregated Analysis")
    print("-"*70)
    
    # 2 groups với attempts random
    NUM_GROUPS = 2
    print(f"   Generating {NUM_GROUPS} separate attack logs...")
    
    logs = []
    log_info = []
    for i in range(NUM_GROUPS):
        attempts = random.randint(50, 200)
        duration = random.randint(2, 5)
        log = generate_ssh_bruteforce_log(attempts=attempts, duration_minutes=duration)
        logs.append(log)
        log_info.append({'attempts': attempts, 'duration': duration})
        print(f"      Log {i+1}: {attempts} attempts over {duration} minutes")
    
    print("   Analyzing all logs...")
    all_incidents = []
    for i, log in enumerate(logs, 1):
        incidents = analyze_ssh_log(log)
        all_incidents.extend(incidents)
        if incidents:
            inc = incidents[0]
            print(f"      Log {i}: {len(incidents)} incident(s) - IP: {inc['source_ip']}, Severity: {inc['severity'].upper()}")
    
    print(f"   Total incidents: {len(all_incidents)}")
    print("   Aggregating incidents...")
    aggregated = aggregate_incidents(all_incidents)
    
    print(f"   Aggregated: {aggregated['total_attackers']} attackers, {aggregated['total_attempts']} attempts")
    print("   Calling Groq AI (Aggregated Mode)...\n")
    
    result = analyze_with_ai(aggregated=aggregated, mode="aggregated", time_range="Last 24 hours")
    
    if "error" in result:
        print(f"   ❌ Error: {result['error']}")
        print(f"   Message: {result['message']}")
    else:
        print("\n" + "="*70)
        print("📊 AI ANALYSIS (Aggregated)")
        print("="*70)
        print(result['analysis'])
        print("-"*70)
        print(f"💰 Tokens: {result['tokens_used']}")
        print("="*70)
    
    print("\n" + "="*70)
    print("💡 SUMMARY")
    print("="*70)
    print("✅ Single Mode: 1 incident → Chi tiết → Xử lý ngay")
    print("✅ Aggregated Mode: Nhiều incidents → Tổng quan → Báo cáo")
    print("="*70)
