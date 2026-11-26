"""
traceroute.py - raw socket traceroute (강의자료 Chapter 5, 5-88 / 5-89)

실행 (관리자 권한 cmd)
  python traceroute.py 8.8.8.8          ICMP Echo 방식 (Windows tracert 와 동일)
  python traceroute.py -U 8.8.8.8       UDP 방식 (강의 방식, 목적 포트 33434 부터)
  python traceroute.py -U -v 8.8.8.8    응답 패킷의 헤더 필드 출력

옵션
  -U           UDP 프로브 사용 (기본: ICMP Echo Request)
  -q N         TTL 마다 보낼 프로브 수 (기본 3)
  -m N         최대 TTL (기본 30)
  -w SEC       프로브당 응답 대기 시간 (기본 2초)
  -i IP        내 IP 주소 (Windows 에서 ICMP 소켓을 bind 할 주소, 생략하면 자동)
  --rcvall     ICMP 수신을 SIO_RCVALL 캡처로 받는다 (Windows UDP 모드는 자동으로 켜진다)
  -v           응답의 IP / ICMP 헤더 필드 출력

동작
  TTL=1 부터 프로브를 보내고, 중간 라우터의 ICMP Time Exceeded(11/0) 로 경로를 알아낸다.
  ICMP 모드: 목적지의 Echo Reply(0) 를 받으면 종료. 매칭은 ICMP id + seq.
  UDP  모드: 목적지의 Port Unreachable(3/3) 을 받으면 종료.
             매칭은 ICMP 본문 속 원본 UDP 헤더의 (출발 포트, 목적 포트).
"""
import argparse
import os
import socket
import struct
import sys
import time

import parser as P
from capture import IS_WINDOWS, Capture, get_local_ip

UDP_BASE_PORT = 33434


def checksum(data):
    """인터넷 체크섬: 16비트 단위 1의 보수 합의 1의 보수"""
    if len(data) % 2:
        data += b"\x00"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF


def echo_request(ident, seq, payload=b"traceroute-probe"):
    """ICMP Echo Request(Type 8): Type, Code, Checksum, ID, Seq + 데이터"""
    head = struct.pack("!BBHHH", 8, 0, 0, ident, seq)
    csum = checksum(head + payload)
    return struct.pack("!BBHHH", 8, 0, csum, ident, seq) + payload


def match(pkt, mode, key):
    """
    수신한 IP 패킷이 보낸 프로브의 응답인지 판별한다.
    key: ICMP 모드 (id, seq), UDP 모드 (출발 포트, 목적 포트)
    반환: (ip, icmp, 목적지 도달 여부) 또는 None
    """
    ip = P.parse_ip(pkt)
    if ip is None or ip["proto"] != P.PROTO_ICMP:
        return None
    icmp = P.parse_icmp(ip["payload"])
    if icmp is None:
        return None
    t, o = icmp["type"], icmp.get("original") or {}
    if mode == "icmp":
        if t == 0 and (icmp["id"], icmp["seq"]) == key:
            return ip, icmp, True
        if t in (3, 11) and o.get("proto") == P.PROTO_ICMP and (o.get("id"), o.get("seq")) == key:
            return ip, icmp, t == 3
    else:
        if t in (3, 11) and o.get("proto") == P.PROTO_UDP and (o.get("sport"), o.get("dport")) == key:
            return ip, icmp, t == 3
    return None


def open_icmp_receiver(local_ip, rcvall):
    """ICMP 응답을 받을 소켓. recvfrom 결과는 IP 헤더부터 시작한다."""
    if rcvall:
        return Capture(local_ip)
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    if IS_WINDOWS:                      # Windows raw socket 은 bind 해야 수신한다
        s.bind((local_ip, 0))
    return s


def recv_packet(rx, timeout):
    """timeout 초 안에 패킷 하나를 받는다. 없으면 None"""
    if isinstance(rx, Capture):
        rx.sock.settimeout(timeout)
        return next(rx.packets())
    rx.settimeout(timeout)
    try:
        return rx.recvfrom(65535)[0]
    except socket.timeout:
        return None


def show_verbose(ip, icmp):
    print("        [IP ] %s -> %s  TTL=%d  ID=0x%04x  TotalLen=%d" % (
        ip["src"], ip["dst"], ip["ttl"], ip["id"], ip["total_len"]))
    print("        [ICMP] %s  Type=%d Code=%d  Checksum=0x%04x" % (
        icmp["type_name"], icmp["type"], icmp["code"], icmp["checksum"]))
    if "id" in icmp:
        print("               ID=%d  Seq=%d" % (icmp["id"], icmp["seq"]))
    o = icmp.get("original")
    if o:
        print("               Original: %s -> %s  Protocol=%d  TTL=%d" % (
            o["src"], o["dst"], o["proto"], o["ttl"]), end="")
        if "seq" in o:
            print("  ICMP ID=%d Seq=%d" % (o["id"], o["seq"]))
        elif "sport" in o:
            print("  Ports %d -> %d" % (o["sport"], o["dport"]))
        else:
            print()


def main():
    ap = argparse.ArgumentParser(description="raw socket traceroute (ICMP / UDP)")
    ap.add_argument("target")
    ap.add_argument("-U", dest="udp", action="store_true")
    ap.add_argument("-q", dest="probes", type=int, default=3)
    ap.add_argument("-m", dest="max_ttl", type=int, default=30)
    ap.add_argument("-w", dest="wait", type=float, default=2.0)
    ap.add_argument("-i", dest="ip")
    ap.add_argument("--rcvall", action="store_true")
    ap.add_argument("-v", dest="verbose", action="store_true")
    args = ap.parse_args()

    try:
        dst = socket.gethostbyname(args.target)
    except OSError:
        sys.exit("주소를 알 수 없다: %s" % args.target)
    local_ip = args.ip or get_local_ip()
    mode = "udp" if args.udp else "icmp"
    # Windows raw ICMP 소켓은 UDP 프로브에 대한 ICMP 오류(11, 3)를 받지 못한다 (11/26 실측)
    rcvall = args.rcvall or (args.udp and IS_WINDOWS)

    try:
        rx = open_icmp_receiver(local_ip, rcvall)
        if args.udp:
            tx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            tx.bind(("", 0))
            sport = tx.getsockname()[1]
        elif rcvall:                        # RCVALL 소켓은 IP_HDRINCL 이라 송신용 ICMP 소켓을 따로 연다
            tx = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        else:
            tx = rx
    except PermissionError:
        sys.exit("raw socket 생성 실패: 관리자 권한으로 실행하라")
    except OSError as e:
        sys.exit("소켓 생성 실패: %s (관리자 권한, -i 내IP주소 확인)" % e)

    ident = os.getpid() & 0xFFFF
    print("traceroute to %s (%s), %d hops max, %s probes (%s mode)" % (
        args.target, dst, args.max_ttl, args.probes, mode.upper()))

    seq, reached = 0, False
    try:
        for ttl in range(1, args.max_ttl + 1):
            tx.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
            cols, routers, details = [], [], []
            for _ in range(args.probes):
                seq += 1
                if args.udp:
                    key = (sport, UDP_BASE_PORT + seq - 1)   # 프로브마다 목적 포트 +1
                    tx.sendto(b"\x00" * 32, (dst, key[1]))
                else:
                    key = (ident, seq)
                    tx.sendto(echo_request(ident, seq), (dst, 0))
                t0 = time.perf_counter()
                hit = None
                while hit is None:
                    left = args.wait - (time.perf_counter() - t0)
                    if left <= 0:
                        break
                    pkt = recv_packet(rx, left)
                    if pkt is not None:
                        hit = match(pkt, mode, key)
                if hit is None:
                    cols.append("    *   ")
                    continue
                ip, icmp, done = hit
                cols.append("%5.1f ms" % ((time.perf_counter() - t0) * 1000))
                if ip["src"] not in routers:
                    routers.append(ip["src"])
                details.append((ip, icmp))
                reached = reached or done
            print("%2d  %s  %s" % (ttl, "  ".join(cols),
                                    ", ".join(routers) or "Request timed out."))
            if args.verbose:
                for ip, icmp in details:
                    show_verbose(ip, icmp)
            if reached:
                break
    except KeyboardInterrupt:
        pass
    finally:
        rx.close()
        if tx is not rx:
            tx.close()
    print("Trace complete." if reached else "Destination not reached.")


if __name__ == "__main__":
    main()
