import socket
import sys
import datetime
import threading
import json
import logging
from logging.handlers import RotatingFileHandler
import sqlite3
from pathlib import Path

class HoneypotServer:
    def __init__(self, host='0.0.0.0', ports=[21, 22, 23, 80, 443, 3306, 5432]):
        self.host = host
        self.ports = ports
        self.connections = []
        self.setup_logging()
        self.setup_database()
        
    def setup_logging(self):
        """Configure logging with rotation"""
        log_dir = Path('logs')
        log_dir.mkdir(exist_ok=True)
        
        # Setup file handler with rotation
        file_handler = RotatingFileHandler(
            'logs/honeypot.log',
            maxBytes=10485760,  # 10MB
            backupCount=5
        )
        
        # Setup console handler
        console_handler = logging.StreamHandler()
        
        # Setup formatting
        formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s'
        )
        file_handler.setFormatter(formatter)
        console_handler.setFormatter(formatter)
        
        # Configure root logger
        self.logger = logging.getLogger('honeypot')
        self.logger.setLevel(logging.INFO)
        self.logger.addHandler(file_handler)
        self.logger.addHandler(console_handler)

    def setup_database(self):
        """Initialize SQLite database for storing connection attempts"""
        try:
            self.conn = sqlite3.connect('honeypot.db', check_same_thread=False)
            self.cursor = self.conn.cursor()
            
            # Create tables if they don't exist
            self.cursor.execute('''
                CREATE TABLE IF NOT EXISTS connection_attempts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    ip_address TEXT,
                    port INTEGER,
                    data TEXT,
                    user_agent TEXT
                )
            ''')
            self.conn.commit()
        except sqlite3.Error as e:
            self.logger.error(f"Database error: {e}")
            sys.exit(1)

    def log_attempt(self, ip_address, port, data, user_agent=''):
        """Log connection attempts to database"""
        try:
            self.cursor.execute('''
                INSERT INTO connection_attempts (ip_address, port, data, user_agent)
                VALUES (?, ?, ?, ?)
            ''', (ip_address, port, data, user_agent))
            self.conn.commit()
        except sqlite3.Error as e:
            self.logger.error(f"Error logging to database: {e}")

    def generate_fake_response(self, port):
        """Generate fake service responses based on port"""
        responses = {
            21: "220 FTP server ready\r\n",
            22: "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.1\r\n",
            23: "\r\nLogin: ",
            80: (
                "HTTP/1.1 200 OK\r\n"
                "Server: Apache/2.4.41 (Ubuntu)\r\n"
                "Content-Type: text/html\r\n"
                "\r\n"
                "<html><body><h1>It works!</h1></body></html>\r\n"
            ),
            443: "HTTP/1.1 400 Bad Request\r\n\r\n",
            3306: "5.7.34-log\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
            5432: "E\x00\x00\x00\x24Too many connections\x00"
        }
        return responses.get(port, "\r\n").encode()

    def handle_connection(self, client_socket, address, port):
        """Handle individual connections"""
        timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        ip_address = address[0]
        
        try:
            # Send fake service response
            client_socket.send(self.generate_fake_response(port))
            
            # Receive data with timeout
            client_socket.settimeout(10)
            data = client_socket.recv(1024).decode('utf-8', errors='ignore')
            
            # Log the connection attempt
            self.logger.info(f"Connection from {ip_address}:{port} at {timestamp}")
            self.logger.info(f"Received data: {data}")
            
            # Store in database
            self.log_attempt(ip_address, port, data)
            
            # Keep connection alive briefly to gather more data
            client_socket.settimeout(30)
            while True:
                more_data = client_socket.recv(1024)
                if not more_data:
                    break
                data += more_data.decode('utf-8', errors='ignore')
                self.log_attempt(ip_address, port, data)
                
        except socket.timeout:
            pass
        except Exception as e:
            self.logger.error(f"Error handling connection: {e}")
        finally:
            client_socket.close()

    def start_port_listener(self, port):
        """Start listener for individual port"""
        try:
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_socket.bind((self.host, port))
            server_socket.listen(5)
            
            self.logger.info(f"Listening on port {port}")
            
            while True:
                client_socket, address = server_socket.accept()
                client_handler = threading.Thread(
                    target=self.handle_connection,
                    args=(client_socket, address, port)
                )
                client_handler.start()
                self.connections.append(client_handler)
                
        except Exception as e:
            self.logger.error(f"Error on port {port}: {e}")
            server_socket.close()

    def start(self):
        """Start the honeypot server"""
        self.logger.info("Starting honeypot server...")
        self.logger.info(f"Monitoring ports: {', '.join(map(str, self.ports))}")
        
        # Start listeners for each port
        listeners = []
        for port in self.ports:
            listener = threading.Thread(
                target=self.start_port_listener,
                args=(port,)
            )
            listener.start()
            listeners.append(listener)
        
        # Wait for all listeners
        for listener in listeners:
            listener.join()

    def stop(self):
        """Stop the honeypot server"""
        self.logger.info("Stopping honeypot server...")
        self.conn.close()
        sys.exit(0)

def main():
    # Create and start honeypot
    honeypot = HoneypotServer()
    
    try:
        honeypot.start()
    except KeyboardInterrupt:
        honeypot.logger.info("Shutting down honeypot...")
        honeypot.stop()

if __name__ == "__main__":
    main()
