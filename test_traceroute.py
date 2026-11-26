"""traceroute.py 매칭 로직 자체 검사 (관리자 권한 불필요): python test_traceroute.py"""
import socket
import struct

import traceroute as T


def ip_hdr(src, dst, proto, payload, ttl=64):
    return struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 1, 0, ttl, proto, 0,
                       socket.inet_aton(src), socket.inet_aton(dst)) + payload


def icmp_error(router, me, itype, code, original):
    body = struct.pack("!BBHI", itype, code, 0, 0) + original[:28]
    return ip_hdr(router, me, 1, body)


ME, DST, R1 = "10.0.0.2", "8.8.8.8", "10.0.0.1"
probe_icmp = ip_hdr(ME, DST, 1, T.echo_request(77, 5), ttl=1)
probe_udp = ip_hdr(ME, DST, 17, struct.pack("!HHHH", 50000, 33436, 40, 0) + b"\x00" * 32, ttl=1)

# 체크섬: 올바른 Echo Request 를 다시 합하면 0
assert T.checksum(T.echo_request(77, 5)) == 0

# ICMP 모드
reply = ip_hdr(DST, ME, 1, struct.pack("!BBHHH", 0, 0, 0, 77, 5) + b"x")
assert T.match(reply, "icmp", (77, 5))[2] is True
assert T.match(reply, "icmp", (77, 6)) is None
te = icmp_error(R1, ME, 11, 0, probe_icmp)
ip, icmp, done = T.match(te, "icmp", (77, 5))
assert ip["src"] == R1 and icmp["type"] == 11 and done is False

# UDP 모드
te = icmp_error(R1, ME, 11, 0, probe_udp)
assert T.match(te, "udp", (50000, 33436))[2] is False
pu = icmp_error(DST, ME, 3, 3, probe_udp)
assert T.match(pu, "udp", (50000, 33436))[2] is True
assert T.match(pu, "udp", (50000, 33437)) is None      # 목적 포트 불일치
assert T.match(pu, "icmp", (77, 5)) is None            # 모드 불일치

# 쓰레기 입력
for junk in (b"", b"\x45", b"\x00" * 40, te[:25], bytes(range(256))):
    assert T.match(junk, "udp", (50000, 33436)) is None

print("ok")
