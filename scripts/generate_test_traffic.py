#!/usr/bin/env python
"""
Generate test network traffic for testing the NIDS packet capture
"""
import socket
import time
import threading
import requests
import subprocess
import sys

def generate_http_traffic():
    """Generate HTTP traffic"""
    print("🌐 Generating HTTP traffic...")
    urls = [
        'http://httpbin.org/get',
        'http://httpbin.org/json',
        'http://httpbin.org/user-agent',
        'http://httpbin.org/headers'
    ]
    
    for i in range(10):
        try:
            for url in urls:
                response = requests.get(url, timeout=5)
                print(f"📡 HTTP request to {url}: {response.status_code}")
                time.sleep(1)
        except Exception as e:
            print(f"❌ HTTP request failed: {e}")
        time.sleep(2)

def generate_dns_traffic():
    """Generate DNS traffic"""
    print("🔍 Generating DNS traffic...")
    domains = [
        'google.com',
        'github.com',
        'stackoverflow.com',
        'python.org'
    ]
    
    for i in range(5):
        for domain in domains:
            try:
                result = socket.gethostbyname(domain)
                print(f"🔍 DNS lookup {domain}: {result}")
                time.sleep(0.5)
            except Exception as e:
                print(f"❌ DNS lookup failed for {domain}: {e}")
        time.sleep(3)

def generate_ping_traffic():
    """Generate ping traffic"""
    print("🏓 Generating ping traffic...")
    hosts = ['8.8.8.8', '1.1.1.1', 'google.com']
    
    for host in hosts:
        try:
            # Use ping command
            result = subprocess.run(['ping', '-c', '3', host], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                print(f"🏓 Ping to {host}: SUCCESS")
            else:
                print(f"🏓 Ping to {host}: FAILED")
        except Exception as e:
            print(f"❌ Ping to {host} failed: {e}")
        time.sleep(2)

def generate_tcp_traffic():
    """Generate TCP traffic"""
    print("🔌 Generating TCP traffic...")
    
    # Test TCP connections to common ports
    hosts_ports = [
        ('google.com', 80),
        ('github.com', 443),
        ('8.8.8.8', 53)
    ]
    
    for host, port in hosts_ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((host, port))
            if result == 0:
                print(f"🔌 TCP connection to {host}:{port}: SUCCESS")
                sock.send(b"GET / HTTP/1.1\r\nHost: " + host.encode() + b"\r\n\r\n")
                time.sleep(1)
            else:
                print(f"🔌 TCP connection to {host}:{port}: FAILED")
            sock.close()
        except Exception as e:
            print(f"❌ TCP connection to {host}:{port} failed: {e}")
        time.sleep(1)

def main():
    """Main function to generate various types of network traffic"""
    print("🚀 Starting network traffic generation...")
    print("⚠️  Make sure to start packet capture in the NIDS before running this!")
    
    # Start different types of traffic in separate threads
    threads = [
        threading.Thread(target=generate_http_traffic, daemon=True),
        threading.Thread(target=generate_dns_traffic, daemon=True),
        threading.Thread(target=generate_ping_traffic, daemon=True),
        threading.Thread(target=generate_tcp_traffic, daemon=True)
    ]
    
    # Start all threads
    for thread in threads:
        thread.start()
        time.sleep(2)  # Stagger the start times
    
    # Wait for all threads to complete
    for thread in threads:
        thread.join()
    
    print("✅ Network traffic generation completed!")
    print("📊 Check your NIDS dashboard for captured packets")

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n🛑 Traffic generation stopped by user")
    except Exception as e:
        print(f"❌ Error generating traffic: {e}")
