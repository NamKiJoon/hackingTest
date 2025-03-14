import time
import os
import json
import logging
from datetime import datetime
import threading
import queue
import signal
import sys
from scapy.all import *
import requests

# 로깅 설정
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger('TrafficMirror')

# 설정 변수 (실제 환경에 맞게 조정)
PROD_SERVER = "localhost:8080"  # 실제 운영 서버 주소를 넣어야함 ( 실제 해킹 들어올 곳 )
DEV_SERVER = "localhost:8081"   # 실제 개발 서버 주소를 넣어야함 ( 가져와서 재연 해볼곳 )
INTERFACE = "lo"                # 네트워크 인터페이스 (로컬호스트)

# 요청 큐
request_queue = queue.Queue()

class TrafficMirror:
    def __init__(self, interface, prod_server, dev_server):
        self.interface = interface
        self.prod_server = prod_server
        self.dev_server = dev_server
        self.running = False
        self.capture_thread = None
        self.replay_thread = None
        
        # 서버 주소에서 IP와 포트 분리
        self.prod_ip, self.prod_port = self._parse_server_address(prod_server)
        self.dev_ip, self.dev_port = self._parse_server_address(dev_server)
    
    def _parse_server_address(self, address):
        """서버 주소에서 IP와 포트 추출"""
        if ':' in address:
            ip, port = address.split(':')
            return ip, int(port)
        return address, 80  # 기본 HTTP 포트
    
    def start(self):
        """모든 서비스 시작"""
        self.running = True
        
        # 캡처 및 재연 스레드 시작
        self.capture_thread = threading.Thread(target=self.capture_traffic)
        self.replay_thread = threading.Thread(target=self.replay_requests)
        
        self.capture_thread.daemon = True
        self.replay_thread.daemon = True
        
        self.capture_thread.start()
        self.replay_thread.start()
        
        logger.info(f"트래픽 미러링 시작: {self.prod_server} -> {self.dev_server}")
        
        # 신호 핸들러 등록
        signal.signal(signal.SIGINT, self.stop)
        signal.signal(signal.SIGTERM, self.stop)
    
    def stop(self, signum=None, frame=None):
        """모든 서비스 중지"""
        self.running = False
        logger.info("트래픽 미러링 종료 중...")
        sys.exit(0)
    
    def capture_traffic(self):
        """운영 서버로 향하는 트래픽 캡처"""
        logger.info(f"{self.interface} 인터페이스에서 {self.prod_ip}:{self.prod_port}로 향하는 트래픽 캡처 시작")
        
        # BPF 필터: 운영 서버의 IP 및 포트로 가는 트래픽만 캡처
        capture_filter = f"dst host {self.prod_ip} and dst port {self.prod_port}"
        
        try:
            # 패킷 캡처 및 처리를 위한 콜백 함수 설정
            sniff(iface=self.interface, filter=capture_filter, prn=self.process_packet, store=False)
        except Exception as e:
            logger.error(f"캡처 중 오류 발생: {e}")
    
    def process_packet(self, packet):
        """캡처된 패킷 처리"""
        if not self.running:
            return
        
        # HTTP 요청 캡처 (TCP 패킷 중 특정 포트로 가는 패킷)
        if TCP in packet and packet[TCP].dport == self.prod_port:
            if Raw in packet:
                try:
                    payload = packet[Raw].load.decode('utf-8', 'ignore')
                    
                    # HTTP 요청인지 확인
                    if payload.startswith(('GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS')):
                        # 요청 라인 및 헤더 분석
                        request_lines = payload.split('\r\n')
                        method, path, version = request_lines[0].split(' ')
                        
                        headers = {}
                        body = ""
                        header_end = False
                        
                        for i, line in enumerate(request_lines[1:]):
                            if not line:
                                header_end = True
                                if i + 2 < len(request_lines):
                                    body = '\r\n'.join(request_lines[i+2:])
                                break
                            
                            if not header_end and ': ' in line:
                                key, value = line.split(': ', 1)
                                headers[key] = value
                        
                        # 요청 정보 구성
                        request_info = {
                            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f'),
                            'src_ip': packet[IP].src if IP in packet else "unknown",
                            'method': method,
                            'path': path,
                            'headers': headers,
                            'body': body
                        }
                        
                        # 큐에 요청 정보 추가
                        request_queue.put(request_info)
                        logger.info(f"캡처됨: {method} {path}")
                except Exception as e:
                    logger.error(f"패킷 처리 중 오류: {e}")
    
    def replay_requests(self):
        """캡처된 요청을 개발 서버에 재연"""
        logger.info(f"개발 서버({self.dev_server})에 요청 재연 시작")
        
        while self.running:
            try:
                # 큐에서 요청 가져오기
                if not request_queue.empty():
                    req = request_queue.get()
                    
                    # 약간의 지연 (운영 서버보다 약간 늦게 요청)
                    time.sleep(0.1)
                    
                    # 요청 재구성
                    url = f"http://{self.dev_server}{req['path']}"
                    
                    # 호스트 헤더 수정
                    headers = req['headers'].copy()
                    if 'Host' in headers:
                        headers['Host'] = self.dev_server
                    
                    # 추가 디버깅 헤더 
                    headers['X-Mirrored-From'] = self.prod_server
                    headers['X-Original-Source'] = req['src_ip']
                    
                    # 로그
                    logger.info(f"재연 중: {req['method']} {url}")
                    
                    # 메소드에 따라 요청 실행
                    try:
                        if req['method'] == 'GET':
                            resp = requests.get(url, headers=headers, timeout=5)
                        elif req['method'] == 'POST':
                            resp = requests.post(url, headers=headers, data=req['body'], timeout=5)
                        elif req['method'] == 'PUT':
                            resp = requests.put(url, headers=headers, data=req['body'], timeout=5)
                        elif req['method'] == 'DELETE':
                            resp = requests.delete(url, headers=headers, timeout=5)
                        elif req['method'] == 'HEAD':
                            resp = requests.head(url, headers=headers, timeout=5)
                        elif req['method'] == 'OPTIONS':
                            resp = requests.options(url, headers=headers, timeout=5)
                        else:
                            logger.warning(f"지원되지 않는 HTTP 메소드: {req['method']}")
                            continue
                        
                        logger.info(f"응답: {resp.status_code} ({len(resp.content)} 바이트)")
                        
                    except Exception as e:
                        logger.error(f"요청 재연 중 오류: {e}")
                    
                    # 큐 작업 완료 표시
                    request_queue.task_done()
                else:
                    # 큐가 비어있으면 잠시 대기
                    time.sleep(0.1)
                    
            except Exception as e:
                logger.error(f"재연 스레드 오류: {e}")

def main():
    # 환경 변수에서 설정 로드 (없으면 기본값 사용)
    prod_server = os.environ.get('PROD_SERVER', PROD_SERVER)
    dev_server = os.environ.get('DEV_SERVER', DEV_SERVER)
    interface = os.environ.get('NETWORK_INTERFACE', INTERFACE)
    
    # 서비스 시작
    mirror = TrafficMirror(interface, prod_server, dev_server)
    mirror.start()
    
    # 메인 스레드가 종료되지 않도록 대기
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        mirror.stop()
        logger.info("프로그램이 사용자에 의해 종료되었습니다.")

if __name__ == "__main__":
    main()