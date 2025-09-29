# SpiderFoot API Wrapper

A professional FastAPI-based wrapper for SpiderFoot OSINT automation, providing secure API endpoints for managing reconnaissance scans.

## 📋 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Architecture](#architecture)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [API Endpoints](#api-endpoints)
- [Authentication](#authentication)
- [Error Handling](#error-handling)
- [Contributing](#contributing)
- [License](#license)

## 🔍 Overview

This API wrapper simplifies interaction with SpiderFoot by providing a RESTful interface with API key authentication. It enables automated OSINT scanning, status monitoring, and data export capabilities.

## ✨ Features

- **Secure Authentication**: API key-based authentication for all endpoints
- **Scan Management**: Start, stop, and monitor SpiderFoot scans
- **Flexible Configuration**: Environment-based configuration (local/production)
- **Data Export**: Export scan results in JSON format
- **Multiple Scan Support**: Retrieve and export multiple scans simultaneously
- **Error Handling**: Comprehensive error handling and validation
- **Type Safety**: Pydantic models for request validation

## 🏗 Architecture

```
spiderfoot-api-wrapper/
├── config/
│   ├── local.py          # Local environment configuration
│   └── prod.py           # Production environment configuration
├── core/
│   └── setting.py        # Configuration management
├── scan_exports_json/    # Exported scan results directory
├── main.py               # FastAPI application
├── validation.py         # Pydantic models and validation
├── requirements.txt      # Python dependencies
└── README.md            # Documentation
```

## 📦 Prerequisites

- Python 3.8+
- SpiderFoot instance (running locally or remotely)
- API access to SpiderFoot

## 🚀 Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd spiderfoot-api-wrapper
```

2. Create a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

## ⚙️ Configuration

### Environment Variables

Create configuration files in the `config/` directory:

**config/local.py**
```python
SPIDERFOOT_API_KEY = "your-secure-api-key"
SPIDERFOOT_BASE_URL = "http://localhost:5001"
DEBUG = True
```

**config/prod.py**
```python
SPIDERFOOT_API_KEY = "your-production-api-key"
SPIDERFOOT_BASE_URL = "https://your-spiderfoot-instance.com"
DEBUG = False
```

### Configuration Loading

The application automatically loads the appropriate configuration based on your environment. Modify `core/setting.py` to customize configuration management.

## 💻 Usage

### Starting the Server

```bash
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

The API will be available at `http://localhost:8000`

### Interactive API Documentation

Access the auto-generated API documentation:
- Swagger UI: `http://localhost:8000/docs`
- ReDoc: `http://localhost:8000/redoc`

## 📡 API Endpoints

### 1. Start a Scan

**POST** `/scan`

Initiates a new SpiderFoot scan.

**Headers:**
```
x-api-key: your-api-key
Content-Type: application/json
```

**Request Body:**
```json
{
  "scan_name": "Example Scan",
  "target": "example.com",
  "use_case": "Footprint",
  "modules": "sfp_dnsresolve,sfp_whois"
}
```

**cURL Example:**
```bash
curl -X POST "http://localhost:8000/scan" \
  -H "x-api-key: your-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "scan_name": "Example Scan",
    "target": "example.com",
    "use_case": "Footprint",
    "modules": "sfp_dnsresolve,sfp_whois"
  }'
```

**Response:**
```json
{
  "status": "success",
  "scan_name": "Example Scan",
  "target": "\"example.com\"",
  "modules": ["sfp_dnsresolve", "sfp_whois"],
  "spiderfoot_response": { ... }
}
```

### 2. Check Scan Status

**POST** `/scanstatus/{scan_id}`

Retrieves the status of a specific scan.

**Headers:**
```
x-api-key: your-api-key
```

**cURL Example:**
```bash
curl -X POST "http://localhost:8000/scanstatus/abc123" \
  -H "x-api-key: your-api-key"
```

**Response:**
```json
{
  "status": "success",
  "scan_id": "abc123",
  "message": "Scan status",
  "spiderfoot_response": { ... }
}
```

### 3. Stop a Scan

**GET** `/stopscan/{scan_id}`

Stops a running scan.

**Headers:**
```
x-api-key: your-api-key
```

**cURL Example:**
```bash
curl -X GET "http://localhost:8000/stopscan/abc123" \
  -H "x-api-key: your-api-key"
```

**Response:**
```json
{
  "status": "success",
  "scan_id": "abc123",
  "message": "Scan arrêté avec succès",
  "spiderfoot_response": { ... }
}
```

### 4. List All Scans

**GET** `/scanlist`

Retrieves a list of all scans.

**Headers:**
```
x-api-key: your-api-key
```

**cURL Example:**
```bash
curl -X GET "http://localhost:8000/scanlist" \
  -H "x-api-key: your-api-key"
```

**Response:**
```json
{
  "status": "success",
  "scan_count": 5,
  "scans": [ ... ]
}
```

### 5. Export Multiple Scans

**GET** `/scanexportjsonmulti?ids=scan1,scan2`

Exports multiple scan results as JSON.

**Headers:**
```
x-api-key: your-api-key
```

**Query Parameters:**
- `ids`: Comma-separated list of scan IDs

**cURL Example:**
```bash
curl -X GET "http://localhost:8000/scanexportjsonmulti?ids=scan1&ids=scan2&ids=scan3" \
  -H "x-api-key: your-api-key"
```

**Alternative (single query parameter):**
```bash
curl -X GET "http://localhost:8000/scanexportjsonmulti?ids=scan1,scan2,scan3" \
  -H "x-api-key: your-api-key"
```

**Response:**
```json
{
  "status": "success",
  "scan_ids": ["scan1", "scan2"],
  "file": "scan_exports_json/multi_export_scan1_scan2.json",
  "event_count": 150,
  "data": [ ... ]
}
```

## 🔐 Authentication

All endpoints require authentication via the `x-api-key` header:

```bash
curl -H "x-api-key: your-api-key" http://localhost:8000/scanlist
```

**Unauthorized Response (403):**
```json
{
  "error": "Invalid or missing API key."
}
```

## 🛠 Error Handling

The API provides detailed error responses:

| Status Code | Description |
|------------|-------------|
| 200 | Success |
| 403 | Invalid or missing API key |
| 404 | Resource not found |
| 500 | Internal server error |

**Error Response Format:**
```json
{
  "detail": "Error description"
}
```

## 🤝 Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🔗 Resources

- [SpiderFoot Documentation](https://www.spiderfoot.net/documentation/)
- [FastAPI Documentation](https://fastapi.tiangolo.com/)
- [Pydantic Documentation](https://docs.pydantic.dev/)

## 📧 Support

For issues and questions, please open an issue on the GitHub repository.

---

**Note**: Ensure SpiderFoot is properly configured and running before using this API wrapper.