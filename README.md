# Multi-threaded HTTP Server

A Python implementation of a multi-threaded HTTP server using socket programming for Computer Networks assignment.

## Features

- **Multi-threading**: Thread pool with configurable size (default: 10)
- **HTTP/1.1 Support**: Keep-alive connections, proper headers
- **File Serving**: HTML files, binary downloads (PNG, JPEG, TXT)
- **JSON Upload**: POST endpoint for JSON file uploads
- **Security**: Path traversal protection, Host header validation
- **Error Handling**: Complete HTTP error code support (400, 403, 404, 405, 415, 500, 503)

## Usage

```bash
# Start server with defaults (localhost:8080)
python server.py

# Specify port
python server.py 8081

# Specify host and port
python server.py 8081 0.0.0.0

# Specify port, host, and thread pool size
python server.py 8081 0.0.0.0 20
```

## Testing

### HTML Files

- `http://localhost:8080/` → serves index.html
- `http://localhost:8080/about.html` → serves about page
- `http://localhost:8080/contact.html` → serves contact page

### Binary Downloads

- `http://localhost:8080/sample.txt` → downloads text file
- `http://localhost:8080/logo.png` → downloads PNG image
- `http://localhost:8080/photo.jpg` → downloads JPEG image

### JSON Upload

```bash
curl -X POST http://localhost:8080/upload \
  -H "Content-Type: application/json" \
  -H "Host: localhost:8080" \
  -d '{"message": "Hello Server", "timestamp": "2024-10-05"}'
```

## Project Structure

```
project/
├── server.py           # Main server implementation
├── README.md          # This file
├── requirements.md    # Assignment requirements
└── resources/         # Static files directory
    ├── index.html     # Default home page
    ├── about.html     # About page
    ├── contact.html   # Contact page
    ├── sample.txt     # Sample text file
    ├── logo.png       # Sample PNG image
    ├── photo.jpg      # Sample JPEG image
    └── uploads/       # JSON upload directory
```

## Implementation Details

- **Thread Pool**: Fixed-size thread pool processes client connections
- **Keep-Alive**: HTTP/1.1 connections maintained for multiple requests
- **Binary Transfer**: Files served with proper Content-Disposition headers
- **Security**: Path validation prevents directory traversal attacks
- **Logging**: Comprehensive request/response logging with timestamps

## Assignment Requirements Met

✅ Multi-threaded architecture with thread pool  
✅ Socket programming with TCP  
✅ HTTP request parsing and validation  
✅ GET requests for HTML and binary files  
✅ POST requests for JSON uploads  
✅ Security features (path traversal, host validation)  
✅ Connection management (keep-alive, timeouts)  
✅ Complete HTTP error handling  
✅ Comprehensive logging  
✅ Binary file transfer capability
