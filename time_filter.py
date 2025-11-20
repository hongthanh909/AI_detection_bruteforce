# time_filter.py
# Module để filter log theo time range và aggregate incidents

import re
from datetime import datetime, timedelta
from collections import defaultdict

def parse_log_timestamp(log_line):
    """Extract timestamp từ log line"""
    time_match = re.search(r'^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})', log_line)
    if time_match:
        try:
            # Parse timestamp (thêm năm hiện tại để tránh warning)
            time_str = time_match.group(1)
            current_year = datetime.now().year
            timestamp = datetime.strptime(f"{time_str} {current_year}", '%b %d %H:%M:%S %Y')
            return timestamp
        except:
            return None
    return None


def filter_log_by_timerange(log_content, hours_ago=None, start_time=None, end_time=None):
    """
    Filter log theo time range
    
    Args:
        log_content: String log content
        hours_ago: Lọc log trong X giờ gần nhất (ví dụ: 1, 24, 168)
        start_time: Custom start time (datetime object)
        end_time: Custom end time (datetime object)
    
    Returns:
        Filtered log content
    """
    lines = log_content.split('\n')
    filtered_lines = []
    
    # Tính time range
    if hours_ago:
        end_time = datetime.now()
        start_time = end_time - timedelta(hours=hours_ago)
    
    for line in lines:
        if not line.strip():
            continue
        
        timestamp = parse_log_timestamp(line)
        
        # Nếu không parse được timestamp, giữ lại dòng
        if not timestamp:
            filtered_lines.append(line)
            continue
        
        # Check nếu trong time range
        if start_time and end_time:
            if start_time <= timestamp <= end_time:
                filtered_lines.append(line)
        else:
            filtered_lines.append(line)
    
    return '\n'.join(filtered_lines)


def aggregate_incidents(incidents_list):
    """
    Aggregate nhiều incidents thành 1 summary
    
    Args:
        incidents_list: List of incidents từ nhiều time ranges
    
    Returns:
        Aggregated summary dict
    """
    if not incidents_list:
        return None
    
    # Group incidents by IP
    ip_groups = defaultdict(lambda: {
        'total_attempts': 0,
        'usernames': set(),
        'severities': [],
        'first_seen': None,
        'last_seen': None,
        'attack_count': 0
    })
    
    for incident in incidents_list:
        ip = incident['source_ip']
        summary = incident.get('summary', {})
        
        ip_groups[ip]['total_attempts'] += incident['attempts']
        ip_groups[ip]['usernames'].update(incident['usernames'])
        ip_groups[ip]['severities'].append(incident['severity'])
        ip_groups[ip]['attack_count'] += 1
        
        # Track first/last seen
        first = summary.get('first_seen', 'N/A')
        last = summary.get('last_seen', 'N/A')
        
        if first != 'N/A':
            if not ip_groups[ip]['first_seen'] or first < ip_groups[ip]['first_seen']:
                ip_groups[ip]['first_seen'] = first
        
        if last != 'N/A':
            if not ip_groups[ip]['last_seen'] or last > ip_groups[ip]['last_seen']:
                ip_groups[ip]['last_seen'] = last
    
    # Tạo aggregated summary
    aggregated = {
        'total_attackers': len(ip_groups),
        'total_attempts': sum(g['total_attempts'] for g in ip_groups.values()),
        'attackers': []
    }
    
    # Sort by attempts (nhiều nhất trước)
    sorted_ips = sorted(ip_groups.items(), key=lambda x: x[1]['total_attempts'], reverse=True)
    
    for ip, data in sorted_ips:
        # Tính severity tổng hợp (lấy cao nhất)
        severity_order = {'low': 1, 'medium': 2, 'high': 3}
        max_severity = max(data['severities'], key=lambda s: severity_order.get(s, 0))
        
        aggregated['attackers'].append({
            'ip': ip,
            'total_attempts': data['total_attempts'],
            'unique_usernames': len(data['usernames']),
            'usernames': ', '.join(list(data['usernames'])[:10]),
            'severity': max_severity,
            'attack_count': data['attack_count'],
            'first_seen': data['first_seen'] or 'N/A',
            'last_seen': data['last_seen'] or 'N/A'
        })
    
    return aggregated


def format_aggregated_for_ai(aggregated, time_range_desc="Custom period"):
    """
    Format aggregated data cho AI (siêu tiết kiệm token!)
    
    Args:
        aggregated: Dict từ aggregate_incidents()
        time_range_desc: Mô tả time range (ví dụ: "Last 24 hours", "Nov 19-20")
    
    Returns:
        Text summary cho AI
    """
    ai_text = f"""🚨 SSH Brute Force Attack Summary
Time Period: {time_range_desc}

📊 Overview:
- Total Attackers: {aggregated['total_attackers']}
- Total Attempts: {aggregated['total_attempts']}

🎯 Top Attackers:
"""
    
    # Chỉ lấy top 5 attackers (tiết kiệm token)
    for i, attacker in enumerate(aggregated['attackers'][:5], 1):
        # Format ngắn gọn: IP | Attempts | Severity | Usernames
        ai_text += f"{i}. {attacker['ip']} | {attacker['total_attempts']} attempts | {attacker['severity'].upper()} | Users: {attacker['usernames']}\n"
    
    if len(aggregated['attackers']) > 5:
        ai_text += f"... and {len(aggregated['attackers']) - 5} more attackers\n"
    
    return ai_text


# Test code
if __name__ == "__main__":
    from generator import generate_ssh_bruteforce_log
    from analyze import analyze_ssh_log
    import random
    
    print("🧪 Testing Time Filter & Aggregation\n")
    
    # Configuration: Số groups và attempts cho mỗi group
    NUM_GROUPS = 2  # Thay đổi số này để tạo nhiều/ít groups
    
    # Attempts cho mỗi group (có thể customize)
    ATTEMPTS_PER_GROUP = [
        random.randint(50, 150),  # Group 1: random 50-150
        random.randint(100, 200)  # Group 2: random 100-200
    ]
    
    # Test 1: Generate logs
    print(f"1️⃣ Generating {NUM_GROUPS} separate attack logs...")
    logs = []
    log_info = []
    
    for i in range(NUM_GROUPS):
        attempts = ATTEMPTS_PER_GROUP[i]
        duration = random.randint(2, 5)  # Random duration 2-5 minutes
        
        log = generate_ssh_bruteforce_log(attempts=attempts, duration_minutes=duration)
        logs.append(log)
        log_info.append({'attempts': attempts, 'duration': duration})
        
        print(f"   Log {i+1}: {attempts} attempts over {duration} minutes")
    
    # Test 2: Analyze each log
    print(f"\n2️⃣ Analyzing each log separately...")
    all_incidents = []
    for i, log in enumerate(logs, 1):
        incidents = analyze_ssh_log(log)
        all_incidents.extend(incidents)
        
        if incidents:
            inc = incidents[0]
            print(f"   Log {i}: Found {len(incidents)} incident(s)")
            print(f"           IP: {inc['source_ip']}, Attempts: {inc['attempts']}, Severity: {inc['severity'].upper()}")
    
    # Test 3: Aggregate
    print(f"\n3️⃣ Aggregating {len(all_incidents)} incidents...")
    aggregated = aggregate_incidents(all_incidents)
    
    print(f"\n📊 Aggregated Results:")
    print(f"   Total Attackers: {aggregated['total_attackers']}")
    print(f"   Total Attempts: {aggregated['total_attempts']}")
    
    # Show each attacker (ngắn gọn)
    for i, attacker in enumerate(aggregated['attackers'], 1):
        print(f"   {i}. {attacker['ip']} → {attacker['total_attempts']} attempts ({attacker['severity'].upper()})")
    
    # Test 4: Format for AI
    print(f"\n4️⃣ Formatted for AI:\n")
    print("="*60)
    ai_text = format_aggregated_for_ai(aggregated, f"Test Period ({NUM_GROUPS} logs)")
    print(ai_text)
    print("="*60)
    
    # Token comparison
    total_raw_tokens = sum(len(log.split()) for log in logs) * 1.3
    ai_tokens = len(ai_text.split()) * 1.3
    
    print(f"\n💡 Token Savings:")
    print(f"   Raw logs: ~{total_raw_tokens:.0f} tokens")
    print(f"   Aggregated: ~{ai_tokens:.0f} tokens")
    print(f"   ✅ Saved: {((total_raw_tokens - ai_tokens) / total_raw_tokens * 100):.1f}%")
    
    print(f"\n📝 Configuration used:")
    print(f"   Number of groups: {NUM_GROUPS}")
    print(f"   Attempts per group: {ATTEMPTS_PER_GROUP}")
    print(f"   Total raw log lines: {sum(info['attempts'] for info in log_info)}")
