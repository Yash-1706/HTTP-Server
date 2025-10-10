import socket
import threading 
import os
from datetime import datetime, timezone
import mimetypes 
import queue
import uuid
import json
import sys
import time
import signal

# Server configuration
HOST = "127.0.0.1"
PORT = 8080
RESOURCE_DIR = "resources"
MAX_THREADS = 10
QUEUE_MAX_SIZE = 100
CONNECTION_QUEUE = queue.Queue(maxsize=QUEUE_MAX_SIZE)
ACTIVE_THREADS = 0
THREAD_LOCK = threading.Lock()
SERVER_RUNNING = True

def log(message):
    """Log with timestamp"""
    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {message}")
    
def get_content_type(file_path):
    """Get content type and binary flag for file extension"""
    ext = os.path.splitext(file_path)[1].lower()
    if ext == ".html":
        return "text/html; charset=utf-8", False
    elif ext in [".txt", ".png", ".jpg", ".jpeg"]:
        return "application/octet-stream", True
    else: 
        return None, None
    
def make_upload_filename():
    """Generate unique filename for uploads"""
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    rand = uuid.uuid4().hex[:8]
    return f"upload_{ts}_{rand}.json"

def get_http_date():
    """Get current time in HTTP date format"""
    return datetime.now(timezone.utc).strftime('%a, %d %b %Y %H:%M:%S GMT')

def ensure_upload_dir():
    """Create uploads directory if needed"""
    upload_dir = os.path.join(RESOURCE_DIR, "uploads")
    os.makedirs(upload_dir, exist_ok=True)
    return upload_dir

def parse_headers(header_lines):
    """Parse HTTP headers into dictionary"""
    headers = {}
    for line in header_lines:
        if not line.strip():
            continue
        parts = line.split(":", 1)
        if len(parts) == 2:
            key = parts[0].strip().lower()
            val = parts[1].strip()
            headers[key] = val
    return headers
    
def recv_all_body(conn, initial_body, content_length):
    """Read exact number of bytes for request body"""
    body = initial_body
    to_read = content_length - len(body)
    while to_read > 0:
        chunk = conn.recv(min(8192, to_read))
        if not chunk:
            break
        body += chunk
        to_read -= len(chunk)
    return body

def recv_request(conn):
    """Receive and parse complete HTTP request"""
    data = b""
    # Read until complete headers
    while b"\r\n\r\n" not in data and len(data) < 8192:
        chunk = conn.recv(8192 - len(data))
        if not chunk:
            return None, None, None, None
        data += chunk
    
    if b"\r\n\r\n" not in data:
        return None, None, None, None
    
    # Split headers and body
    idx = data.find(b"\r\n\r\n")
    header_data = data[:idx].decode("utf-8", errors="ignore")
    body_start = data[idx+4:]
    
    # Parse request line and headers
    lines = header_data.split("\r\n")
    if not lines:
        return None, None, None, None
        
    request_line = lines[0]
    headers = parse_headers(lines[1:])
    
    # Get body if content-length specified
    content_length = headers.get("content-length")
    if content_length:
        try:
            content_length = int(content_length)
            body = recv_all_body(conn, body_start, content_length)
        except:
            body = body_start
    else:
        body = body_start
    
    return request_line, headers, body, lines[0]

def is_safe_path(path, resource_dir):
    """Validate path to prevent directory traversal"""
    # Remove query string
    if '?' in path:
        path = path.split('?')[0]
    
    # Check for dangerous patterns
    dangerous = ['..',  './', '//', '\\', '%2e%2e', '%2f', '%5c']
    path_lower = path.lower()
    for pattern in dangerous:
        if pattern in path_lower:
            return False, None
    
    # Normalize path
    normalized = os.path.normpath(path.lstrip('/'))
    
    # Additional checks
    if '..' in normalized or normalized.startswith('/') or ':' in normalized:
        return False, None
    
    full_path = os.path.join(resource_dir, normalized)
    
    # Verify path stays within resource directory
    try:
        real_resource = os.path.realpath(resource_dir)
        real_requested = os.path.realpath(full_path)
        if not real_requested.startswith(real_resource):
            return False, None
    except:
        return False, None
    
    return True, full_path

def validate_host_header(headers, expected_host, expected_port):
    """Validate Host header for security"""
    host_header = headers.get('host')
    if not host_header:
        return False  # Host header required
    
    # Valid host values
    valid_hosts = [
        f"{expected_host}:{expected_port}",
        f"localhost:{expected_port}"
    ]
    
    # If binding to 0.0.0.0, accept localhost and 127.0.0.1
    if expected_host == "0.0.0.0":
        valid_hosts.extend([
            f"127.0.0.1:{expected_port}",
            f"localhost:{expected_port}"
        ])
    
    is_valid = host_header in valid_hosts
    log(f"[Thread-{threading.current_thread().name}] Host validation: {host_header} {'✓' if is_valid else '✗'}")
    return is_valid

def should_keep_alive(headers, version):
    """Check if connection should stay alive"""
    connection = headers.get('connection', '').lower()
    
    if version == "HTTP/1.1":
        # HTTP/1.1 defaults to keep-alive
        return connection != 'close'
    else:
        # HTTP/1.0 defaults to close
        return connection == 'keep-alive'

def handle_get_request(conn, path, headers):
    """Handle GET requests for static files"""
    # Remove query parameters from path
    if '?' in path:
        path = path.split('?')[0]

    # Default to index.html for root
    if path == "/":
        path = "/index.html"

    # Security check
    is_safe, file_path = is_safe_path(path, RESOURCE_DIR)
    if not is_safe:
        log(f"[Thread-{threading.current_thread().name}] Security violation: Path traversal attempt - {path}")
        return {
            "status": 403,
            "text": "Forbidden",
            "body": b"403 Forbidden: Access Denied"
        }

    # Check file exists
    if not os.path.exists(file_path) or not os.path.isfile(file_path):
        return {
            "status": 404,
            "text": "Not Found",
            "body": b"404 Not Found"
        }

    # Check content type
    content_type, is_binary = get_content_type(file_path)
    if content_type is None:
        return {
            "status": 415,
            "text": "Unsupported Media Type",
            "body": b"415 Unsupported Media Type"
        }

    try:
        file_size = os.path.getsize(file_path)
        file_name = os.path.basename(file_path)
        extra_headers = []

        if is_binary:
            extra_headers.append(f'Content-Disposition: attachment; filename="{file_name}"')
            log(f"[Thread-{threading.current_thread().name}] Sending binary file: {file_name} ({file_size} bytes)")
            return {
                "status": 200,
                "text": "OK",
                "body": None,
                "content_type": content_type,
                "extra_headers": extra_headers,
                "file_path": file_path
            }

        with open(file_path, "rb") as f:
            file_data = f.read()

        log(f"[Thread-{threading.current_thread().name}] Serving HTML: {file_name} ({file_size} bytes)")
        return {
            "status": 200,
            "text": "OK",
            "body": file_data,
            "content_type": content_type,
            "extra_headers": extra_headers
        }

    except Exception as e:
        log(f"[Thread-{threading.current_thread().name}] File read error: {e}")
        return {
            "status": 500,
            "text": "Internal Server Error",
            "body": b"500 Internal Server Error"
        }

def handle_post_request(conn, path, headers, body):
    """Handle POST requests for JSON uploads"""
    # Only accept /upload endpoint
    if path != "/upload":
        return {
            "status": 404,
            "text": "Not Found",
            "body": b"404 Not Found"
        }
    
    # Check content type
    content_type_header = headers.get("content-type", "")
    if not content_type_header.lower().startswith("application/json"):
        return {
            "status": 415,
            "text": "Unsupported Media Type",
            "body": b"415 Unsupported Media Type: Expected application/json"
        }
    
    # Parse JSON
    try:
        json_text = body.decode("utf-8")
        parsed = json.loads(json_text)
    except Exception as e:
        log(f"[Thread-{threading.current_thread().name}] JSON parse error: {e}")
        return {
            "status": 400,
            "text": "Bad Request",
            "body": b"400 Bad Request: Invalid JSON"
        }
    
    # Save to file
    try:
        upload_dir = ensure_upload_dir()
        filename = make_upload_filename()
        filepath = os.path.join(upload_dir, filename)
        
        with open(filepath, "w", encoding="utf-8") as fout:
            json.dump(parsed, fout, indent=2, ensure_ascii=False)
        
        # Create response
        resp_body_obj = {
            "status": "success",
            "message": "File created successfully",
            "filepath": f"/uploads/{filename}"
        }
        resp_body = json.dumps(resp_body_obj).encode("utf-8")
        
        log(f"[Thread-{threading.current_thread().name}] Created file: {filename}")
        return {
            "status": 201,
            "text": "Created",
            "body": resp_body,
            "content_type": "application/json",
            "extra_headers": []
        }
        
    except Exception as e:
        log(f"[Thread-{threading.current_thread().name}] File write error: {e}")
        return {
            "status": 500,
            "text": "Internal Server Error",
            "body": b"500 Internal Server Error"
        }

def send_response(conn, status_code, status_text, body=b"", content_type=None, extra_headers=None, keep_alive=False, file_path=None):
    """Send HTTP response with proper headers, optionally streaming file content."""
    if file_path is not None:
        try:
            body_length = os.path.getsize(file_path)
        except OSError as exc:
            log(f"[Thread-{threading.current_thread().name}] File size error: {exc}")
            body = b"500 Internal Server Error"
            status_code = 500
            status_text = "Internal Server Error"
            file_path = None
            body_length = len(body)
    else:
        if body is None:
            body = b""
        body_length = len(body)

    headers = [
        f"HTTP/1.1 {status_code} {status_text}",
        f"Content-Length: {body_length}",
        f"Date: {get_http_date()}",
        "Server: Multi-threaded HTTP Server",
        f"Connection: {'keep-alive' if keep_alive else 'close'}"
    ]

    if content_type:
        headers.append(f"Content-Type: {content_type}")
    else:
        headers.append("Content-Type: text/plain")

    if keep_alive:
        headers.append("Keep-Alive: timeout=30, max=100")

    if status_code == 503:
        headers.append("Retry-After: 30")

    if extra_headers:
        headers.extend(extra_headers)

    header_str = "\r\n".join(headers) + "\r\n\r\n"
    conn.sendall(header_str.encode())

    if file_path is not None:
        with open(file_path, "rb") as fp:
            while True:
                chunk = fp.read(8192)
                if not chunk:
                    break
                conn.sendall(chunk)
    else:
        conn.sendall(body)

    log(f"[Thread-{threading.current_thread().name}] Response: {status_code} {status_text} ({body_length} bytes transferred)")

def handle_client(conn, addr):
    """Handle client connection with keep-alive support"""
    global ACTIVE_THREADS
    thread_name = threading.current_thread().name
    
    # Update active thread count
    with THREAD_LOCK:
        ACTIVE_THREADS += 1
        log(f"Thread pool status: {ACTIVE_THREADS}/{MAX_THREADS} active")
    
    try:
        log(f"[Thread-{thread_name}] Connection from {addr[0]}:{addr[1]}")
        
        # Connection parameters
        request_count = 0
        max_requests = 100
        timeout = 30
        
        # Set socket timeout
        conn.settimeout(timeout)
        
        while request_count < max_requests and SERVER_RUNNING:
            try:
                # Receive request
                request_line, headers, body, raw_request = recv_request(conn)
                if not request_line:
                    break
                
                log(f"[Thread-{thread_name}] Request: {request_line}")
                
                # Parse request line
                try:
                    method, path, version = request_line.split()
                except ValueError:
                    send_response(conn, 400, "Bad Request", b"400 Bad Request")
                    break
                
                # Validate Host header
                if not validate_host_header(headers, HOST, PORT):
                    if 'host' not in headers:
                        send_response(conn, 400, "Bad Request", b"400 Bad Request: Missing Host header")
                    else:
                        send_response(conn, 403, "Forbidden", b"403 Forbidden: Invalid Host header")
                    break
                
                # Check if connection should be kept alive
                keep_alive = should_keep_alive(headers, version)
                
                # Route request by method
                if method == "GET":
                    response = handle_get_request(conn, path, headers)
                elif method == "POST":
                    response = handle_post_request(conn, path, headers, body)
                else:
                    response = {
                        "status": 405,
                        "text": "Method Not Allowed",
                        "body": b"405 Method Not Allowed"
                    }

                status_code = response.get("status", 500)
                status_text = response.get("text", "Internal Server Error")
                resp_body = response.get("body")
                content_type = response.get("content_type")
                extra_headers = response.get("extra_headers")
                file_path = response.get("file_path")

                send_response(
                    conn,
                    status_code,
                    status_text,
                    resp_body,
                    content_type,
                    extra_headers,
                    keep_alive,
                    file_path=file_path
                )
                
                log(f"[Thread-{thread_name}] Connection: {'keep-alive' if keep_alive else 'close'}")
                
                request_count += 1
                
                # Close if not keep-alive
                if not keep_alive:
                    break
                    
            except socket.timeout:
                log(f"[Thread-{thread_name}] Connection timeout")
                break
            except Exception as e:
                log(f"[Thread-{thread_name}] Request handling error: {e}")
                try:
                    send_response(conn, 500, "Internal Server Error", b"500 Internal Server Error")
                except:
                    pass
                break
                
    except Exception as e:
        log(f"[Thread-{thread_name}] Connection error: {e}")
    finally:
        # Update active thread count
        with THREAD_LOCK:
            ACTIVE_THREADS -= 1
            log(f"Thread pool status: {ACTIVE_THREADS}/{MAX_THREADS} active")
        try:
            conn.close()
            log(f"[Thread-{thread_name}] Connection closed")
        except:
            pass

def worker():
    """Worker thread function to process connections"""
    while SERVER_RUNNING:
        try:
            item = CONNECTION_QUEUE.get(timeout=1)
        except queue.Empty:
            continue
        try:
            conn, addr = item
        except Exception:
            CONNECTION_QUEUE.task_done()
            continue

        try:
            if conn is None:  # Shutdown signal
                break

            log(f"Connection dequeued, assigned to Thread-{threading.current_thread().name} (client {addr[0]}:{addr[1]})")
            handle_client(conn, addr)
        except Exception as e:
            log(f"Worker thread error: {e}")
        finally:
            CONNECTION_QUEUE.task_done()

def signal_handler(signum, frame):
    """Handle shutdown signals gracefully"""
    global SERVER_RUNNING
    log("\nShutting down server...")
    SERVER_RUNNING = False
    # Add shutdown signals to queue
    for _ in range(MAX_THREADS):
        try:
            CONNECTION_QUEUE.put((None, None), timeout=1)
        except queue.Full:
            break
    sys.exit(0)

def start_server():
    """Start the HTTP server"""
    global SERVER_RUNNING
    
    # Set up signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Create resource directories
    os.makedirs(RESOURCE_DIR, exist_ok=True)
    os.makedirs(os.path.join(RESOURCE_DIR, "uploads"), exist_ok=True)
    
    # Create and bind socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((HOST, PORT))
        server_socket.listen(QUEUE_MAX_SIZE)
        server_socket.settimeout(1)  # Allow periodic checking of SERVER_RUNNING
        
        log(f"HTTP Server started on http://{HOST}:{PORT}")
        log(f"Thread pool size: {MAX_THREADS}")
        log(f"Serving files from '{RESOURCE_DIR}' directory")
        log("Press Ctrl+C to stop the server")
        
        # Start worker threads
        threads = []
        for i in range(MAX_THREADS):
            t = threading.Thread(target=worker, name=f"{i+1}", daemon=True)
            t.start()
            threads.append(t)
        
        # Accept connections
        while SERVER_RUNNING:
            try:
                conn, addr = server_socket.accept()
                
                if CONNECTION_QUEUE.full():
                    log("Warning: Thread pool saturated, returning 503")
                    send_response(conn, 503, "Service Unavailable",
                                  b"503 Service Unavailable: Server too busy")
                    conn.close()
                    continue

                queue_position = CONNECTION_QUEUE.qsize() + 1
                CONNECTION_QUEUE.put((conn, addr))
                with THREAD_LOCK:
                    current_active = ACTIVE_THREADS
                if current_active >= MAX_THREADS:
                    log("Warning: Thread pool saturated, queuing connection")
                log(f"Queued connection from {addr[0]}:{addr[1]} (position {queue_position}/{QUEUE_MAX_SIZE})")
                        
            except socket.timeout:
                continue
            except Exception as e:
                if SERVER_RUNNING:
                    log(f"Accept error: {e}")
        
        # Wait for threads to finish
        log("Waiting for threads to complete...")
        for t in threads:
            t.join(timeout=2)
        log("Server stopped")

if __name__ == "__main__":
    # Parse command line arguments
    if len(sys.argv) > 1:
        PORT = int(sys.argv[1])
    if len(sys.argv) > 2:
        HOST = sys.argv[2]
    if len(sys.argv) > 3:
        MAX_THREADS = int(sys.argv[3])
    
    start_server()
    