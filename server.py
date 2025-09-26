import socket
import threading 
import os
from datetime import datetime
import mimetypes 
import queue
import uuid
import json
import argparse 

HOST = "127.0.0.1"
PORT = 8080
RESOURCE_DIR = "resources"
MAX_THREADS = 10
CONNECTION_QUEUE = queue.Queue()

def log(message):
    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {message}")
    
def get_content_type(file_path):
    ext = os.path.splitext(file_path)[1].lower()
    if ext == ".html":
        return "text/html; charset=utf-8", False
    elif ext in [".txt", ".png", ".jpg", ".jpeg"]:
        return "application/octet-stream", True
    else: 
        return None, None
    
def make_upload_filename():
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    rand = uuid.uuid4().hex[:8]
    return f"upload_{ts}_{rand}.json"

def ensure_upload_dir():
    """
    Ensure the uploads directory exists and return its path.
    """
    upload_dir = os.path.join(RESOURCE_DIR, "uploads")
    os.makedirs(upload_dir, exist_ok=True)
    return upload_dir

def parse_arguments():
    """
    Parse command line arguments for server configuration.
    """
    parser = argparse.ArgumentParser(description="Multi-threaded HTTP Server")
    parser.add_argument("--host", default="127.0.0.1", help="Host to bind the server (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8080, help="Port to bind the server (default:8080)")
    parser.add_argument("--threads", type=int, default=10, help="Maximum number of worker threads (default: 10)")
    parser.add_argument("--resource-dir", default="resources", help="Directory to serve static files from (default: resources)")
    return parser.parse_args()
    

def parse_headers(header_lines):
    """
    header_lines: list of header lines (after request line).
    returns dict of headers with lower-case keys.
    """
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
    """
    Read exactly content_length bytes. initial_body is bytes already read (may be b'').
    """
    body = initial_body
    to_read = content_length - len(body)
    while to_read > 0:
        chunk = conn.recv(min(8192, to_read))
        if not chunk:
            break
        body += chunk
        to_read -= len(chunk)
    return body

def is_safe_path(path, resource_dir):
    """
    Check if the requested is safe and doesn't contain path traversal attempts.
    Returns (is_safe: bool, normalized_path: str)
    """
    
    if '?' in path:
        path = path.split('?')[0]
        
    normalized = os.path.normpath(path.lstrip('/'))
    
    if '..' in normalized or normalized.startswith('/') or ':' in normalized:
        return False, None
    
    full_path = os.path.join(resource_dir, normalized)
    
    try:
        real_resource = os.path.realpath(resource_dir)
        real_requested = os.path.realpath(full_path)
        if not real_requested.startswith(real_resource):
            return False, None
    except:
        return False, None
    
    return True, full_path

def validate_host_header(headers, expected_host, expected_port):
    """
    Validate the Host header to prevent Host header injection attacks.
    """
    host_header = headers.get('host')
    if not host_header:
        return True
    
    expected_hosts = [
        f"{expected_host}:{expected_port}",
        expected_host if expected_port == 80 else f"{expected_host}:{expected_port}"
    ]
    
    return host_header in expected_hosts

def handle_client(conn, addr):
    try:
        log(f"[Thread-{threading.current_thread().name}] Connection from {addr}")

        data = conn.recv(8192)
        if not data:
            return
        try:
            text = data.decode("utf-8", errors="ignore")
        except Exception:
            text = data.decode(errors="ignore")

        if "\r\n\r\n" in text:
            head_text, possible_body = text.split("\r\n\r\n", 1)
            header_lines = head_text.split("\r\n")
            request_line = header_lines[0]
            headers = parse_headers(header_lines[1:])
            body_bytes = possible_body.encode("utf-8", errors="ignore")
        else:
            full = data
            while b"\r\n\r\n" not in full and len(full) < 65536:
                more = conn.recv(8192)
                if not more:
                    break
                full += more
            if b"\r\n\r\n" in full:
                idx = full.find(b"\r\n\r\n")
                head = full[:idx].decode("utf-8", errors="ignore")
                request_line_and = head.split("\r\n")
                request_line = request_line_and[0]
                headers = parse_headers(request_line_and[1:])
                body_bytes = full[idx+4:]
            else:
                response = "HTTP/1.1 400 Bad Request\r\n\r\n"
                conn.sendall(response.encode())
                return

        log(f"[Thread-{threading.current_thread().name}] Request: {request_line}")

        try:
            method, path, version = request_line.split()
        except ValueError:
            response = "HTTP/1.1 400 Bad Request\r\n\r\n"
            conn.sendall(response.encode())
            return

        if method not in ["GET", "POST"]:
            response = "HTTP/1.1 405 Method Not Allowed\r\n\r\n405 Method Not Allowed"
            conn.sendall(response.encode())
            return

        if method == "GET":
            if not validate_host_header(headers, HOST, PORT):
                response = "HTTP/1.1 400 Bad Request\r\n\r\n400 Bad Request: Invalid Host header"
                conn.sendall(response.encode())
                return
            
            if path == "/":
                path = "/index.html"
                
            is_safe, file_path = is_safe_path(path, RESOURCE_DIR)
            if not is_safe:
                log(f"[Thread-{threading.current_thread().name}] Path traversal attempt blocked: {path}")
                response = "HTTP/1.1 403 Forbidden\r\n\r\n403 Forbidden: Access Denied"
                conn.sendall(response.encode())
                return
            
            if not os.path.exists(file_path):
                response = "HTTP/1.1 404 Not Found\r\n\r\n 404 Not Found"
                conn.sendall(response.encode())
                return
            
            try:
                content_type, is_binary = get_content_type(file_path)
                if content_type is None:
                    response = "HTTP/1.1 415 Unsupported Media Type\r\n\r\n415 Unsupported Media Type"
                    conn.sendall(response.encode())
                    return
                
                mode = "rb" if is_binary else "r"
                encoding = None if is_binary else "utf-8"
                
                with open(file_path, mode, encoding=encoding) as f:
                    file_data = f.read()
                    
                if not is_binary:
                    file_data = file_data.encode("utf-8")
                    
                headers_out = [
                    "HTTP/1.1 200 OK",
                    f"Content-Type: {content_type}",
                    f"Content-Length: {len(file_data)}",
                    "Server: Multi-threaded HTTP Server",
                    "Connection: close"
                ]
                
                if is_binary:
                    filename = os.path.basename(file_path)
                    headers_out.append(f'Content-Disposition: attachment; filename="{filename}"')
            
                header_str = "\r\n".join(headers_out) + "\r\n\r\n"
                conn.sendall(header_str.encode() + file_data)
                log(f"[Thread-{threading.current_thread().name}] Served: {file_path}")
                return
            
            except Exception as e:
                log(f"[Thread-{threading.current_thread().name}] File read error: {e}")
                response = "HTTP/1.1 500 Internal Server Error\r\n\r\n500 Internal Server Error"
                conn.sendall(response.encode())
                return
            
        if method == "POST":
            if not validate_host_header(headers, HOST, PORT):
                response = "HTTP/1.1 400 Bad Request\r\n\r\n400 Bad Request: Invalid Host header"
                conn.sendall(response.encode())
                return
            
            if path != "/upload":
                response = "HTTP/1.1 404 Not Found\r\n\r\n404 Not Found"
                conn.sendall(response.encode())
                return

            content_type_header = headers.get("content-type")
            if not content_type_header:
                response = "HTTP/1.1 400 Bad Request\r\n\r\n400 Bad Request: Missing Content-Type"
                conn.sendall(response.encode())
                return

            if not content_type_header.lower().startswith("application/json"):
                response = "HTTP/1.1 415 Unsupported Media Type\r\n\r\n415 Unsupported Media Type: Expected application/json"
                conn.sendall(response.encode())
                return

            content_length = headers.get("content-length")
            if not content_length:
                response = "HTTP/1.1 400 Bad Request\r\n\r\n400 Bad Request: Missing Content-Length"
                conn.sendall(response.encode())
                return

            try:
                content_length = int(content_length)
            except ValueError:
                response = "HTTP/1.1 400 Bad Request\r\n\r\n400 Bad Request: Invalid Content-Length"
                conn.sendall(response.encode())
                return

            body = recv_all_body(conn, body_bytes, content_length)

            if len(body) < content_length:
                response = "HTTP/1.1 400 Bad Request\r\n\r\n400 Bad Request: Incomplete body"
                conn.sendall(response.encode())
                return

            try:
                json_text = body.decode("utf-8")
                parsed = json.loads(json_text)
            except Exception as e:
                log(f"[Thread-{threading.current_thread().name}] JSON parse error: {e}")
                response = "HTTP/1.1 400 Bad Request\r\n\r\n400 Bad Request: Invalid JSON"
                conn.sendall(response.encode())
                return

            try:
                upload_dir = ensure_upload_dir()
                filename = make_upload_filename()
                filepath = os.path.join(upload_dir, filename)
                with open(filepath, "w", encoding="utf-8") as fout:
                    json.dump(parsed, fout, indent=2, ensure_ascii=False)

                resp_body_obj = {
                    "status": "success",
                    "message": "File created successfully",
                    "filepath": f"/uploads/{filename}"
                }
                resp_body = json.dumps(resp_body_obj).encode("utf-8")

                headers_out = [
                    "HTTP/1.1 201 Created",
                    "Content-Type: application/json",
                    f"Content-Length: {len(resp_body)}",
                    "Server: Multi-threaded HTTP Server",
                    "Connection: close"
                ]
                header_str = "\r\n".join(headers_out) + "\r\n\r\n"
                conn.sendall(header_str.encode() + resp_body)
                log(f"[Thread-{threading.current_thread().name}] Saved upload: {filepath}")
                return

            except Exception as e:
                log(f"[Thread-{threading.current_thread().name}] File write error: {e}")
                response = "HTTP/1.1 500 Internal Server Error\r\n\r\n500 Internal Server Error"
                conn.sendall(response.encode())
                return

    except Exception as e:
        log(f"[Thread-{threading.current_thread().name}] Error: {e}")
    finally:
        try:
            conn.close()
        except Exception:
            pass


def worker():
    while True:
        conn, addr = CONNECTION_QUEUE.get()
        handle_client(conn, addr)
        CONNECTION_QUEUE.task_done()

def start_server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((HOST, PORT))
        server_socket.listen(50)
        
        log(f"HTTP Server started on http://{HOST}:{PORT}")
        log(f"Thread pool size: {MAX_THREADS}")
        
        for i in range(MAX_THREADS):
            t = threading.Thread(target=worker, name=f"{i+1}", daemon=True)
            t.start()
        
        while True:
            conn, addr = server_socket.accept()
            if CONNECTION_QUEUE.qsize() >= 50:
                log("Warning: Connection queue full, rejecting request")
                conn.sendall(b"HTTP/1.1 503 Service Unavailable\r\nRetry-After: 5\r\n\r\n")
                conn.close()
            else:
                CONNECTION_QUEUE.put((conn,addr))
                log(f"Queued connection from {addr}, queue size: {CONNECTION_QUEUE.qsize()}")

if __name__ == "__main__":
    args = parse_arguments()
    
    HOST = args.host
    PORT = args.port
    MAX_THREADS = args.threads
    RESOURCE_DIR = args.resource_dir
    
    os.makedirs(os.path.join(RESOURCE_DIR, "uploads"), exist_ok=True)
    start_server()