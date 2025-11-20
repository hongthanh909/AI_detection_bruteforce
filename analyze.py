# analyze.py

import re
from collections import defaultdict
from datetime import datetime

def analyze_ssh_log(log_content):
    """Phân tích SSH log để phát hiện brute force attacks và tổng hợp data cho AI"""
    
    # Tạo dict để lưu thông tin chi tiết của mỗi IP
    ip_data = defaultdict(lambda: {
        'attempts': 0,
        'usernames': set(),
        'timestamps': [],
        'log_samples': []
    })
    
    # Tách log thành từng dòng
    lines = [line for line in log_content.split('\n') if line.strip()]
    
    # Đọc từng dòng log
    for line in lines:
        # Extract IP từ log (pattern: "from 1.2.3.4")
        ip_match = re.search(r'from (\d+\.\d+\.\d+\.\d+)', line)
        if ip_match:
            ip = ip_match.group(1)
            ip_data[ip]['attempts'] += 1
            
            # Extract username (pattern: "for root from")
            user_match = re.search(r'for (\w+) from', line)
            if user_match:
                username = user_match.group(1)
                ip_data[ip]['usernames'].add(username)
            
            # Extract timestamp (pattern: "Nov 19 10:00:00")
            time_match = re.search(r'^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})', line)
            if time_match:
                ip_data[ip]['timestamps'].append(time_match.group(1))
            
            # Lưu sample logs (chỉ lưu 10 dòng đầu)
            if len(ip_data[ip]['log_samples']) < 10:
                ip_data[ip]['log_samples'].append(line)
    
    # Phát hiện attacks (threshold: > 10 attempts)
    incidents = []
    
    for ip, data in ip_data.items():
        if data['attempts'] > 10:
            
            # Tính severity dựa trên số attempts
            if data['attempts'] > 100:
                severity = 'high'
            elif data['attempts'] > 50:
                severity = 'medium'
            else:
                severity = 'low'
            
            # Tính duration và rate
            duration_info = calculate_attack_metrics(data['timestamps'])
            
            # Tạo incident dict với data đã tổng hợp
            incident = {
                'type': 'ssh_brute_force',
                'source_ip': ip,
                'attempts': data['attempts'],
                'severity': severity,
                'usernames': list(data['usernames']),
                'timestamp': datetime.now().isoformat(),
                
                # Thông tin tổng hợp cho AI (tiết kiệm token)
                'summary': {
                    'total_attempts': data['attempts'],
                    'unique_usernames': len(data['usernames']),
                    'username_list': ', '.join(list(data['usernames'])[:10]),  # Max 10 usernames
                    'duration': duration_info['duration'],
                    'attack_rate': duration_info['rate'],
                    'first_seen': data['timestamps'][0] if data['timestamps'] else 'N/A',
                    'last_seen': data['timestamps'][-1] if data['timestamps'] else 'N/A'
                },
                
                # Sample logs (chỉ 10 dòng đầu)
                'log_samples': data['log_samples']
            }
            
            incidents.append(incident)
    
    return incidents


def calculate_attack_metrics(timestamps):
    """Tính toán metrics của attack (duration, rate)"""
    if len(timestamps) < 2:
        return {'duration': 'N/A', 'rate': 'N/A'}
    
    try:
        # Parse timestamps
        first_time = datetime.strptime(timestamps[0], '%b %d %H:%M:%S')
        last_time = datetime.strptime(timestamps[-1], '%b %d %H:%M:%S')
        
        # Tính duration (seconds)
        duration_seconds = (last_time - first_time).total_seconds()
        
        # Format duration
        if duration_seconds < 60:
            duration_str = f"{int(duration_seconds)} seconds"
        else:
            duration_str = f"{int(duration_seconds / 60)} minutes"
        
        # Tính rate (attempts/second)
        rate = len(timestamps) / duration_seconds if duration_seconds > 0 else 0
        rate_str = f"{rate:.2f} attempts/sec"
        
        return {
            'duration': duration_str,
            'rate': rate_str
        }
    except:
        return {'duration': 'N/A', 'rate': 'N/A'}


def format_incident_for_ai(incident):
    """Format incident thành text gọn gàng cho AI (tiết kiệm token)"""
    summary = incident['summary']
    
    # Tạo text summary ngắn gọn
    ai_text = f"""🚨 SSH Brute Force Attack Detected

Attacker IP: {incident['source_ip']}
Total Attempts: {summary['total_attempts']}
Duration: {summary['duration']}
Attack Rate: {summary['attack_rate']}
Severity: {incident['severity'].upper()}

Targeted Usernames: {summary['username_list']}
First Seen: {summary['first_seen']}
Last Seen: {summary['last_seen']}

Sample Logs (first 10 lines):
"""
    
    # Thêm sample logs
    for i, log in enumerate(incident['log_samples'], 1):
        ai_text += f"{i}. {log}\n"
    
    return ai_text


# Test code
if __name__ == "__main__":
    from generator import generate_ssh_bruteforce_log
    import random
    
    # Random attempts (50-200)
    attempts = random.randint(50, 200)
    
    print(f"Generating log with {attempts} attempts...")
    log = generate_ssh_bruteforce_log(attempts=attempts, duration_minutes=5)
    
    # Analyze log
    print("Analyzing log...")
    incidents = analyze_ssh_log(log)
    
    # Print kết quả tổng hợp
    print(f"\n🔍 Found {len(incidents)} incident(s):\n")
    
    for inc in incidents:
        print(f"{'='*60}")
        print(f"Type: {inc['type']}")
        print(f"Source IP: {inc['source_ip']}")
        print(f"Severity: {inc['severity'].upper()}")
        print(f"\n📊 Summary:")
        print(f"  - Total Attempts: {inc['summary']['total_attempts']}")
        print(f"  - Duration: {inc['summary']['duration']}")
        print(f"  - Attack Rate: {inc['summary']['attack_rate']}")
        print(f"  - Unique Usernames: {inc['summary']['unique_usernames']}")
        print(f"  - Usernames: {inc['summary']['username_list']}")
        print(f"  - First Seen: {inc['summary']['first_seen']}")
        print(f"  - Last Seen: {inc['summary']['last_seen']}")
        print(f"\n📝 Sample Logs ({len(inc['log_samples'])} lines):")
        for i, log_line in enumerate(inc['log_samples'][:3], 1):
            print(f"  {i}. {log_line}")
        print(f"  ... (showing 3/{len(inc['log_samples'])} samples)")
        print()
    
    # Demo: Format cho AI
    if incidents:
        print(f"\n{'='*60}")
        print("📤 DATA GỬI CHO GROQ AI (Tối ưu token):")
        print(f"{'='*60}\n")
        ai_text = format_incident_for_ai(incidents[0])
        print(ai_text)
        print(f"\n💡 Token estimate: ~{len(ai_text.split())} words (~{len(ai_text.split()) * 1.3:.0f} tokens)")
        print(f"   So với gửi toàn bộ {attempts} dòng log: ~{attempts * 20} tokens")
        print(f"   ✅ Tiết kiệm: ~{((attempts * 20 - len(ai_text.split()) * 1.3) / (attempts * 20) * 100):.1f}%")
