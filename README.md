# 🔐 SSH Brute Force Detector

AI-powered tool để phát hiện và phân tích SSH brute force attacks.

## ✨ Features

- 🎯 **Generate** fake SSH logs để test
- 🔍 **Analyze** logs để phát hiện attacks
- 🤖 **AI Analysis** với Groq AI (2 modes: Single & Aggregated)
- 📊 **REST API** với FastAPI
- ⚡ **Optimize** tiết kiệm 95% tokens khi gọi AI

## 🏗️ Tech Stack

- **Backend**: Python, FastAPI
- **AI**: Groq AI (Llama 3.3 70B)
- **API Docs**: Swagger UI (tự động)

## 📦 Installation

### 1. Clone repository

```bash
git clone https://github.com/your-username/ssh-brute-force-detector.git
cd ssh-brute-force-detector
```

### 2. Install dependencies

```bash
pip install -r backend/requirements.txt
```

### 3. Setup Groq API Key

Tạo file `.env`:

```bash
GROQ_API_KEY=your_groq_api_key_here
```

Lấy API key tại: https://console.groq.com/keys

## 🚀 Usage

### Start API Server

```bash
cd ssh-brute-force-detector
python main.py
```

Server sẽ chạy tại: `http://localhost:8080`

### API Documentation

Mở browser: `http://localhost:8080/docs`

## 📖 API Endpoints

### 1. Generate Fake Logs

```bash
POST /api/simulate
{
  "attempts": 150,
  "duration": 5
}
```

### 2. Analyze Logs

```bash
POST /api/analyze
{
  "log_content": "Nov 19 10:00:00 server sshd..."
}
```

### 3. AI Analysis (Single)

```bash
POST /api/ai/single
{
  "incident": {...}
}
```

### 4. AI Analysis (Aggregated)

```bash
POST /api/ai/aggregated
{
  "incidents": [...],
  "time_range": "Last 24 hours"
}
```

## 🎯 How It Works

```
1. Generate/Upload logs
   ↓
2. Analyzer phát hiện attacks
   ↓
3. Aggregate incidents (optional)
   ↓
4. AI phân tích & đưa ra khuyến nghị
```

## 💡 Token Optimization

- **Raw logs**: ~5,000 tokens
- **Optimized**: ~250 tokens
- **Savings**: 95%! 🎉

## 📊 Example Output

### Analyzer Output:
```json
{
  "incidents": [
    {
      "source_ip": "185.44.12.9",
      "attempts": 150,
      "severity": "high",
      "usernames": ["root", "admin"]
    }
  ]
}
```

### AI Analysis:
```
🚨 Mức độ nguy hiểm: CAO
🛡️ Khuyến nghị: Block IP ngay, enable 2FA
🔍 Hành vi: Bot tự động, thử password phổ biến
```

## 🗂️ Project Structure

```
ssh-brute-force-detector/
├── main.py              # FastAPI app
├── generator.py         # Generate fake logs
├── analyze.py           # Analyze logs
├── time_filter.py       # Aggregate incidents
├── ai_service.py        # Groq AI integration
├── .env                 # API keys (not in git)
├── .gitignore          # Git ignore file
└── backend/
    └── requirements.txt # Dependencies
```

## 🔧 Development

### Run Tests

```bash
python test_generator.py
python time_filter.py
python ai_service.py
```

### Test API

Dùng Swagger UI: `http://localhost:8080/docs`

## 📝 TODO / Future Enhancements

- [ ] Frontend (React dashboard)
- [ ] Database (lưu history)
- [ ] Real-time monitoring
- [ ] Deploy lên cloud
- [ ] Support nhiều loại attacks (web, malware...)

## 🤝 Contributing

Pull requests are welcome!

## 📄 License

MIT License

## 👤 Author

**Your Name**
- GitHub: [@your-username](https://github.com/your-username)
- LinkedIn: [Your LinkedIn](https://linkedin.com/in/your-profile)

## 🙏 Acknowledgments

- [Groq AI](https://groq.com) - Fast AI inference
- [FastAPI](https://fastapi.tiangolo.com) - Modern web framework
- [Python](https://python.org) - Programming language

---

⭐ Star this repo if you find it helpful!
