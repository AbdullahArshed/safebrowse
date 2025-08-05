# SafeBrowse - URL Safety Checker with AI Chatbot

A comprehensive web-based URL safety checker with an AI-powered chatbot interface, built with Django and designed for Google Cloud Platform deployment.

## 🔥 Features

### 🛡️ Comprehensive URL Security Analysis
- **SSL/TLS Certificate Validation** - Check certificate validity, expiration, and security
- **Malware & Phishing Detection** - Integrated with Google Safe Browsing API
- **Domain Reputation Analysis** - WHOIS lookup, domain age, and suspicious pattern detection
- **DNS Security Validation** - SPF, DKIM, DMARC records analysis
- **Port Scanning** - Detect potentially dangerous open ports
- **Blacklist Checking** - Cross-reference against known malicious domains
- **Mixed Content Detection** - Find HTTP resources on HTTPS sites
- **Certificate Chain Analysis** - Validate SSL certificate authenticity

### 🤖 AI-Powered Chatbot
- **Natural Language Processing** - Powered by OpenAI GPT
- **Conversational URL Checking** - Just send a URL in chat to get analysis
- **Context-Aware Responses** - Maintains conversation context
- **Real-time Analysis** - Instant security assessments through chat

### 👤 User Management
- **Secure Authentication** - JWT-based authentication system
- **User Profiles** - Track scanning history and preferences
- **Usage Statistics** - Monitor scan counts and activity
- **Session Management** - Persistent chat sessions

### 📊 Reporting & Analytics
- **Detailed Security Reports** - Comprehensive analysis results
- **Risk Scoring** - 0-100 safety score for each URL
- **Historical Data** - Access previous scan results
- **Export Capabilities** - Download reports for compliance

## 🏗️ Technology Stack

### Backend
- **Django 4.2** - Web framework
- **Django REST Framework** - API development
- **PostgreSQL/SQLite** - Database
- **Celery** - Asynchronous task processing
- **Redis** - Caching and message broker

### Frontend
- **Bootstrap 5** - Minimal UI framework
- **jQuery** - JavaScript interactions
- **WebSocket Support** - Real-time chat updates

### AI & APIs
- **OpenAI GPT** - Natural language processing
- **Google Safe Browsing API** - Malware/phishing detection
- **DNS Lookups** - Domain analysis
- **SSL Certificate Analysis** - Security validation

### Google Cloud Platform
- **Cloud Run** - Container deployment
- **Cloud SQL** - Managed PostgreSQL
- **Cloud Storage** - File and log storage
- **Cloud Logging** - Application monitoring
- **IAM** - Security and access management

## 🚀 Quick Start

### Prerequisites
- Python 3.9+
- OpenAI API Key
- Google Safe Browsing API Key (optional but recommended)

### Installation

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd safebrowse
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Configure environment variables**
   ```bash
   cp .env.example .env
   # Edit .env with your API keys
   ```

4. **Run migrations**
   ```bash
   python manage.py migrate
   ```

5. **Create superuser**
   ```bash
   python manage.py createsuperuser
   ```

6. **Start development server**
   ```bash
   python manage.py runserver
   ```

7. **Access the application**
   - Main Chat Interface: http://localhost:8000/
   - Admin Panel: http://localhost:8000/admin/
   - API Documentation: http://localhost:8000/api/

## 🌐 Deployment on Google Cloud Platform

### App Engine Deployment

1. **Install Google Cloud CLI**
   ```bash
   # Follow official installation guide
   ```

2. **Initialize project**
   ```bash
   gcloud init
   gcloud app create
   ```

3. **Deploy application**
   ```bash
   gcloud app deploy
   ```

### Cloud Run Deployment

1. **Build and deploy**
   ```bash
   gcloud builds submit --tag gcr.io/[PROJECT-ID]/safebrowse
   gcloud run deploy --image gcr.io/[PROJECT-ID]/safebrowse --platform managed
   ```

## 📱 Usage

### Chat Interface
1. Navigate to the main page
2. Register or login to your account
3. Start chatting with the SafeBrowse bot
4. Send any URL to get instant security analysis
5. Ask questions about web security

### API Usage
```python
import requests

# Check URL safety
response = requests.post('https://your-app.com/safety/api/check/', {
    'url': 'https://example.com',
    'check_type': 'comprehensive'
}, headers={'Authorization': 'Bearer YOUR_JWT_TOKEN'})

result = response.json()
print(f"Safety Level: {result['safety_level']}")
print(f"Safety Score: {result['safety_score']}/100")
```

## 🔧 Configuration

### Environment Variables
```bash
# Required
OPENAI_API_KEY=your_openai_api_key
SECRET_KEY=your_django_secret_key

# Optional but recommended
GOOGLE_SAFE_BROWSING_API_KEY=your_safe_browsing_key
GOOGLE_CLIENT_ID=your_google_client_id
GOOGLE_CLIENT_SECRET=your_google_client_secret

# Database
DATABASE_URL=postgresql://user:pass@localhost/dbname

# GCP
GOOGLE_CLOUD_PROJECT=your_project_id
GCP_STORAGE_BUCKET_NAME=your_bucket_name
```

### Security Settings
- All communications use HTTPS in production
- JWT tokens for API authentication
- Rate limiting on API endpoints
- Input validation and sanitization
- CORS protection

## 🧪 Testing

```bash
# Run all tests
python manage.py test

# Run specific app tests
python manage.py test authentication
python manage.py test chatbot
python manage.py test safety_checker

# Test URL checking
python manage.py shell
>>> from safety_checker.safety_engine.main_checker import MainSafetyChecker
>>> checker = MainSafetyChecker()
>>> result = checker.quick_check('https://google.com', user)
```

## 📊 Monitoring & Logging

### Google Cloud Logging
- Application logs automatically sent to Cloud Logging
- Error tracking and performance monitoring
- Custom metrics for security analysis

### Built-in Analytics
- User activity tracking
- API usage statistics
- Security scan metrics
- Performance monitoring

## 🛠️ Development

### Project Structure
```
safebrowse/
├── authentication/          # User management
├── chatbot/                # AI chatbot functionality
├── safety_checker/         # URL security analysis
│   └── safety_engine/      # Security check modules
├── templates/              # HTML templates
├── static/                 # CSS, JS, images
├── safebrowse_project/     # Django project settings
├── requirements.txt        # Python dependencies
├── app.yaml               # App Engine config
├── Dockerfile             # Container config
└── README.md              # This file
```

### Adding New Security Checks
1. Create a new module in `safety_checker/safety_engine/`
2. Implement the check logic
3. Register in `main_checker.py`
4. Add to models and admin interface

## 🔐 Security Considerations

- API keys stored securely in environment variables
- Rate limiting to prevent abuse
- Input validation on all endpoints
- HTTPS enforcement in production
- Regular security updates

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Submit a pull request

## 📞 Support

For support and questions:
- Create an issue on GitHub
- Check the documentation
- Review the API endpoints

## 🚨 Disclaimer

This tool is for educational and security research purposes. Always verify results with multiple security tools and services. The developers are not responsible for any decisions made based on the analysis results.