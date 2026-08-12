"""
chat_server.py
--------------
Lightweight built-in http.server backend for the Conversational Code Assistant.
Zero external framework dependencies.
"""

import json
import logging
import os
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse

from security_vulnerability.rag_client import retrieve_context
from security_vulnerability.llm_client import generate_chat_response

logger = logging.getLogger(__name__)

class ChatRequestHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):  # suppress default verbose logging
        pass

    def do_GET(self):
        # Health-check endpoint for Render
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(b'{"status": "ok"}')

    def do_OPTIONS(self):
        # Handle CORS preflight requests
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'POST, GET, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()

    def do_POST(self):
        parsed_path = urlparse(self.path)
        
        if parsed_path.path == '/api/chat':
            # Read request body
            content_length = int(self.headers.get('Content-Length', 0))
            if content_length == 0:
                self.send_error(400, "Empty request body")
                return
                
            post_data = self.rfile.read(content_length).decode('utf-8')
            
            try:
                payload = json.loads(post_data)
            except json.JSONDecodeError:
                self.send_error(400, "Invalid JSON payload")
                return

            message = payload.get("message", "")
            finding_context = payload.get("finding_context", {})
            finding_type = finding_context.get("finding_type", "unknown")
            chat_history = payload.get("chat_history", [])
            
            # 1. Retrieve grounded context
            rag_context = retrieve_context(finding_type)
            
            # 2. Generate response using Mock LLM
            bot_response = generate_chat_response(
                message=message,
                finding=finding_context,
                rag_context=rag_context,
                chat_history=chat_history
            )
            
            # Build JSON response
            response_data = {
                "response": bot_response,
                "grounding_guideline": rag_context
            }
            response_json = json.dumps(response_data).encode('utf-8')
            
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.send_header('Content-Length', str(len(response_json)))
            self.end_headers()
            
            self.wfile.write(response_json)
        else:
            self.send_error(404, "Not Found")

def run_server(port=None):
    if port is None:
        port = int(os.environ.get('PORT', 8000))
    server_address = ('', port)
    httpd = HTTPServer(server_address, ChatRequestHandler)
    print(f"Starting chat server on port {port}...")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    httpd.server_close()
    print("Server stopped.")

if __name__ == '__main__':
    run_server()
