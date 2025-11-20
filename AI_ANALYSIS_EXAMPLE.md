# 🧠 AI Phân tích gì từ Aggregated Data?

## 📊 Input cho AI (Aggregated):

```
🚨 SSH Brute Force Attack Summary
Time Period: Nov 19, 2024 (Full Day)

📊 Overview:
- Total Attackers: 3
- Total Attempts: 850

🎯 Top Attackers:

1. IP: 185.44.12.9
   - Attempts: 500
   - Severity: HIGH
   - Usernames: root, admin, ubuntu, test, guest, user
   - Period: 08:00 → 18:00

2. IP: 103.45.67.89
   - Attempts: 250
   - Severity: MEDIUM
   - Usernames: root, admin
   - Period: 14:00 → 16:00

3. IP: 45.67.89.10
   - Attempts: 100
   - Severity: MEDIUM
   - Usernames: root
   - Period: 10:00 → 12:00
```

---

## 🤖 AI sẽ phân tích:

### **1. Mức độ nguy hiểm (Threat Level)**

**IP 185.44.12.9:**
- ✅ 500 attempts = HIGH severity
- ✅ Tấn công 10 giờ liên tục = Persistent attack
- ✅ Thử 6 usernames khác nhau = Sophisticated attacker
- 🚨 **Kết luận**: Đây là bot tự động, nguy hiểm cao!

**IP 103.45.67.89:**
- ⚠️ 250 attempts = MEDIUM severity
- ⚠️ Tấn công 2 giờ = Short burst attack
- ⚠️ Chỉ thử 2 usernames = Less sophisticated
- 🔍 **Kết luận**: Có thể là script đơn giản

**IP 45.67.89.10:**
- ℹ️ 100 attempts = MEDIUM severity
- ℹ️ Chỉ thử username "root" = Targeted attack
- 🔍 **Kết luận**: Có thể là manual attack hoặc script cũ

---

### **2. Hành vi tấn công (Attack Pattern)**

**Pattern Recognition:**

```
IP 185.44.12.9:
  Usernames: root, admin, ubuntu, test, guest, user
  ↓
  AI phân tích: "Thử các username phổ biến theo thứ tự"
  ↓
  Kết luận: "Đây là dictionary attack với wordlist chuẩn"
```

```
IP 103.45.67.89:
  Usernames: root, admin
  ↓
  AI phân tích: "Chỉ tập trung vào admin accounts"
  ↓
  Kết luận: "Targeted attack vào privileged accounts"
```

---

### **3. Xu hướng tấn công (Trend Analysis)**

**Time-based Analysis:**

```
08:00 → IP 185.44.12.9 bắt đầu
10:00 → IP 45.67.89.10 tham gia
14:00 → IP 103.45.67.89 tham gia
18:00 → IP 185.44.12.9 kết thúc

AI phân tích:
- "Có sự phối hợp giữa các IPs?"
- "Hay là các bot độc lập?"
- "Có pattern theo giờ không?" (ví dụ: tấn công vào giờ hành chính)
```

---

### **4. Khuyến nghị hành động (Actionable Recommendations)**

**AI sẽ đưa ra:**

```
🚨 URGENT - Cần xử lý ngay:
1. Block IP 185.44.12.9 (HIGH severity, persistent attack)
   → Thêm vào firewall blacklist
   → Check xem có IP nào đã login thành công không

⚠️ MEDIUM Priority:
2. Monitor IP 103.45.67.89 và 45.67.89.10
   → Nếu tiếp tục tấn công → Block
   → Setup rate limiting

🛡️ LONG-TERM:
3. Disable password authentication, chỉ dùng SSH key
4. Change SSH port từ 22 → custom port
5. Setup fail2ban với threshold thấp hơn
6. Enable 2FA cho tất cả accounts
```

---

## 🎯 Tại sao gộp cùng IP KHÔNG bị nhầm?

### **Trường hợp 1: Cùng IP, cùng hành vi**
```
Log 1: IP 1.2.3.4 → 200 attempts, usernames: root, admin
Log 2: IP 1.2.3.4 → 150 attempts, usernames: ubuntu, test

Gộp lại:
IP 1.2.3.4 → 350 attempts, usernames: root, admin, ubuntu, test

AI phân tích: "Cùng attacker, thử nhiều username khác nhau"
✅ Đúng! Không bị nhầm!
```

### **Trường hợp 2: Cùng IP, khác hành vi (RẤT HIẾM)**
```
Log 1: IP 1.2.3.4 → 200 attempts, rate: 5 att/sec (fast)
Log 2: IP 1.2.3.4 → 150 attempts, rate: 0.1 att/sec (slow)

Gộp lại:
IP 1.2.3.4 → 350 attempts, rate: 0.5 att/sec (average)

AI phân tích: "Attacker thay đổi tốc độ để tránh detection"
✅ Vẫn đúng! Đây là advanced evasion technique!
```

### **Trường hợp 3: Shared IP (NAT) - Có thể nhầm?**
```
Ví dụ: IP công ty 203.0.113.1 (nhiều người dùng chung)

Log 1: User A quên password → 5 attempts
Log 2: User B quên password → 5 attempts

Gộp lại: 10 attempts

AI phân tích: "10 attempts, LOW severity"
✅ Không sao! Vì threshold là >10 attempts mới cảnh báo
```

---

## 💡 Best Practice: Khi nào KHÔNG nên gộp?

### **Trường hợp cần phân tích riêng:**

1. **Forensics chi tiết** (điều tra sau incident)
   → Cần xem từng log riêng để timeline chính xác

2. **Legal evidence** (bằng chứng pháp lý)
   → Cần giữ nguyên raw logs, không được modify

3. **Advanced threat hunting** (săn threat phức tạp)
   → Cần phân tích correlation giữa các IPs

### **Nhưng với SSH Brute Force Detection:**
✅ Gộp cùng IP là **BEST PRACTICE** vì:
- Tiết kiệm token (95%)
- AI vẫn phân tích chính xác
- Dễ thấy big picture (tổng quan)
- Ưu tiên threats lớn nhất

---

## 🎓 Tóm tắt:

| Câu hỏi | Trả lời |
|---------|---------|
| AI phân tích cái gì? | Threat level, attack pattern, trends, recommendations |
| Gộp cùng IP có bị nhầm không? | KHÔNG! Vì cùng IP = cùng attacker trong SSH brute force |
| Khi nào nên gộp? | Daily/Weekly reports, trend analysis |
| Khi nào KHÔNG nên gộp? | Forensics, legal evidence, advanced hunting |

---

## 🚀 Kết luận:

**Aggregation là best practice trong SOC vì:**
1. ✅ Tiết kiệm 95% tokens
2. ✅ AI vẫn phân tích chính xác
3. ✅ Focus vào threats lớn nhất
4. ✅ Dễ đọc, dễ hiểu cho analyst

**Không sợ nhầm vì:**
1. ✅ Cùng IP = cùng attacker (trong SSH context)
2. ✅ Gộp usernames, timestamps → AI thấy full picture
3. ✅ Sample logs vẫn được giữ lại để reference
