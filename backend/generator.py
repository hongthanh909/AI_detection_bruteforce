# Bước 1: Import
from datetime import datetime, timedelta
import random

# Bước 2: Define function
def generate_ssh_bruteforce_log(attempts=100, duration_minutes=5):
    """Generate SSH brute force log"""
    
    # Bước 3: Tạo attacker IP
    attacker_ip = f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}"
    
    # Bước 4: List usernames
    usernames = ['root', 'admin', 'user', 'test', 'guest']
    
    # Bước 5: Tính interval
    start_time = datetime.now()
    interval_seconds = (duration_minutes * 60) / attempts
    
    # Bước 6: Loop tạo log lines
    log_lines = []
    for i in range(attempts):
        # Timestamp
        current_time = start_time + timedelta(seconds=i * interval_seconds)
        timestamp_str = current_time.strftime('%b %d %H:%M:%S')
        
        # Random data
        username = random.choice(usernames)
        pid = random.randint(10000, 99999)
        source_port = random.randint(50000, 65535)
        
        # Tạo dòng log
        log_line = f"{timestamp_str} server sshd[{pid}]: Failed password for {username} from {attacker_ip} port {source_port} ssh2"
        log_lines.append(log_line)
    
    # Bước 7: Join
    log_content = '\n'.join(log_lines)
    return log_content

# Bước 8: Test
if __name__ == "__main__":
    log = generate_ssh_bruteforce_log(attempts=10, duration_minutes=1)
    print(log)
    print(f"\nGenerated {len(log.split(chr(10)))} lines")
