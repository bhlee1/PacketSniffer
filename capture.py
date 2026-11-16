"""
capture.py - 캡처 모듈

Windows : raw socket 을 내 IP 주소에 bind 한 뒤 SIO_RCVALL 을 켠다.
          그 인터페이스를 지나는 모든 IP 패킷(송신 포함)을 IP 헤더부터 받는다.
Linux   : (개발·테스트용) AF_PACKET 으로 프레임을 받아 이더넷 헤더 14바이트를 떼어낸다.

관리자(root) 권한으로 실행해야 한다.
"""
import socket
import sys

IS_WINDOWS = sys.platform.startswith("win")


def get_local_ip():
    """외부로 나가는 경로에 쓰이는 내 IP 주소를 알아낸다. (패킷은 보내지 않는다)"""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 53))
        return s.getsockname()[0]
    except OSError:
        return socket.gethostbyname(socket.gethostname())
    finally:
        s.close()


class Capture:
    def __init__(self, local_ip=None):
        self.local_ip = local_ip or get_local_ip()
        if IS_WINDOWS:
            # ① 소켓 생성, 내 IP 주소에 bind
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            self.sock.bind((self.local_ip, 0))
            self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            # ② SIO_RCVALL 켜기: 모든 IP 패킷 수신
            self.sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        else:
            self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                                      socket.htons(0x0003))          # ETH_P_ALL
        # 타임아웃을 두어 Ctrl+C 가 바로 처리되게 한다.
        self.sock.settimeout(0.5)

    def packets(self):
        """③ 패킷 수신: IP 헤더부터 시작하는 바이트열을 하나씩 돌려준다."""
        while True:
            try:
                data, addr = self.sock.recvfrom(65535)
            except socket.timeout:
                yield None                      # 호출한 쪽이 종료 조건을 검사할 기회
                continue
            if IS_WINDOWS:
                yield data
                continue
            # Linux: addr = (인터페이스, 프로토콜, 패킷 종류, 하드웨어 종류, 주소)
            ifname, _, pkttype = addr[0], addr[1], addr[2]
            if ifname == "lo" and pkttype == 4:  # 루프백은 같은 패킷이 두 번 보인다
                continue
            if len(data) < 14 or data[12:14] != b"\x08\x00":   # IPv4 만
                continue
            yield data[14:]

    def close(self):
        if IS_WINDOWS:
            try:
                self.sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            except OSError:
                pass
        self.sock.close()
