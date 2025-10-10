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

### Thread Pool Architecture

- A bounded `queue.Queue` (capacity 100) holds pending sockets when all worker threads are busy.
- A configurable pool of worker threads (default: 10) pulls from the queue and calls `handle_client`.
- Active thread counts are tracked with a mutex to log pool saturation and maintain visibility into concurrency levels.
- When the queue is full, the server returns `503 Service Unavailable` with a `Retry-After` header as required.

### Binary Transfer Pipeline

- GET requests pass through `handle_get_request`, which inspects the extension and enforces the supported MIME types.
- Binary assets (`.png`, `.jpg`, `.jpeg`, `.txt`) stream in 8 KB chunks directly from disk via `send_response(..., file_path=...)` so large files do not load entirely into memory.
- Each binary response includes `Content-Type: application/octet-stream` and a `Content-Disposition` attachment header to trigger downloads.
- HTML files remain in-memory and are served with `text/html; charset=utf-8` while respecting content-length and keep-alive headers.

### Security Measures

- **Path Traversal Defense**: `is_safe_path` normalizes incoming paths, rejects attempts containing `..`, mixed separators, or colon-prefixed absolute paths, and ensures the resolved path stays inside the `resources/` directory.
- **Host Validation**: Every request must supply a `Host` header that matches the bound interface/port (e.g., `localhost:8080`). Violations are logged and responded to with 400/403.
- **Request Validation**: Methods other than GET/POST receive a 405, requests exceeding header limits are dropped, and malformed lines yield 400.
- **Connection Governance**: Each persistent socket enforces a 30-second idle timeout and a 100-request maximum, closing connections when limits are reached.

### Logging Coverage

- Startup: address, thread pool size, and resource root
- Queue Activity: warnings when saturated, per-connection queue position, and worker assignment lines
- Request Lifecycle: method/URL, host validation results, transfer totals, and connection persistence decisions

### Known Limitations

- TLS/HTTPS is not implemented; traffic is plaintext HTTP only.
- The server assumes request headers fit within the initial 8 KB read window.
- JSON uploads are written prettified and may lose original key ordering.
- No automatic MIME type inference beyond the required extensions.

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

## Sample Assets

- `/resources/index.html`, `/about.html`, `/contact.html`
- `/resources/logo.png`, `/photo.jpg`, `/sample.txt`
- `/resources/sample_payload.json` — example POST body for the upload endpoint

## Author

Built for Computer Networks assignment - October 2025
