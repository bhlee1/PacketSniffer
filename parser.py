"""
parser.py - 헤더 해석 모듈

raw socket 으로 받은 바이트열을 계층별로 해석한다.
  IP -> TCP / UDP / ICMP -> HTTP / DNS
헤더 값은 네트워크 바이트 순서(빅 엔디언)이므로 struct.unpack('!...') 으로 읽는다.
모든 parse_* 함수는 해석에 실패하면 None 을 돌려준다.
"""
import socket
import struct

PROTO_ICMP, PROTO_TCP, PROTO_UDP = 1, 6, 17
PROTO_NAME = {1: "ICMP", 6: "TCP", 17: "UDP"}

# ---------------------------------------------------------------- IP
def parse_ip(pkt):
    """IPv4 헤더(기본 20바이트) 해석"""
    if len(pkt) < 20:
        return None
    ver_ihl, tos, total, ident, frag, ttl, proto, csum, src, dst = \
        struct.unpack("!BBHHHBBH4s4s", pkt[:20])
    version, ihl = ver_ihl >> 4, (ver_ihl & 0x0F) * 4     # IHL 은 4바이트 단위
    if version != 4 or ihl < 20 or len(pkt) < ihl:
        return None
    end = total if ihl <= total <= len(pkt) else len(pkt)
    return {
        "version": version, "ihl": ihl, "tos": tos, "total_len": total,
        "id": ident, "df": bool(frag & 0x4000), "mf": bool(frag & 0x2000),
        "frag_off": (frag & 0x1FFF) * 8, "ttl": ttl, "proto": proto,
        "checksum": csum, "src": socket.inet_ntoa(src), "dst": socket.inet_ntoa(dst),
        "payload": pkt[ihl:end],
    }


# ---------------------------------------------------------------- TCP
TCP_FLAGS = [(0x02, "SYN"), (0x10, "ACK"), (0x08, "PSH"),
             (0x01, "FIN"), (0x04, "RST"), (0x20, "URG")]
FIN, SYN, RST, ACK = 0x01, 0x02, 0x04, 0x10


def parse_tcp(seg):
    """TCP 헤더(기본 20바이트) 해석"""
    if len(seg) < 20:
        return None
    sport, dport, seq, ack, off, flags, win, csum, urg = \
        struct.unpack("!HHIIBBHHH", seg[:20])
    hlen = (off >> 4) * 4                                 # Data Offset 은 4바이트 단위
    if hlen < 20 or len(seg) < hlen:
        return None
    return {
        "sport": sport, "dport": dport, "seq": seq, "ack": ack, "hdr_len": hlen,
        "flags": flags, "flag_names": [n for bit, n in TCP_FLAGS if flags & bit],
        "window": win, "checksum": csum, "urgent": urg, "payload": seg[hlen:],
    }


class TcpTracker:
    """
    TCP 연결별 상태를 기억해 연결설정 / 데이터 전송 / 연결해제 단계를 판별한다.
    초기 순서 번호(ISN)를 저장해 상대 Seq, Ack 도 계산한다.
    """

    def __init__(self):
        self.conns = {}

    def update(self, src, dst, tcp):
        """반환: (상대 Seq, 상대 Ack 또는 None, 단계 설명)"""
        me, peer = (src, tcp["sport"]), (dst, tcp["dport"])
        key = (me, peer) if me <= peer else (peer, me)
        fl, seq, ack, plen = tcp["flags"], tcp["seq"], tcp["ack"], len(tcp["payload"])

        if (fl & SYN) and not (fl & ACK):                  # 새 연결 시작
            self.conns[key] = {"isn": {}, "state": 0, "fin_seq": {}, "fin_cnt": 0,
                               "client": me}
        c = self.conns.setdefault(key, {"isn": {}, "state": 3, "fin_seq": {},
                                        "fin_cnt": 0, "client": me})
        c["isn"].setdefault(me, seq)
        # 상대가 보낸 FIN 을 이 세그먼트가 확인하는가? (Ack = 상대 FIN Seq + 1)
        acks_fin = bool(fl & ACK) and peer in c["fin_seq"] and \
            ack == (c["fin_seq"][peer] + 1) & 0xFFFFFFFF

        if fl & RST:
            phase = "Connection reset (RST): abnormal termination"
        elif (fl & SYN) and not (fl & ACK):
            phase, c["state"] = "Connection setup 1/3 (SYN): client requests connection", 1
        elif (fl & SYN) and (fl & ACK):
            phase, c["state"] = "Connection setup 2/3 (SYN+ACK): server accepts", 2
        elif fl & FIN:
            c["fin_cnt"] += 1
            c["fin_seq"][me] = (seq + plen) & 0xFFFFFFFF
            if acks_fin:
                phase = "Connection release (FIN+ACK): FIN #%d, also ACKs peer FIN" % c["fin_cnt"]
            else:
                phase = "Connection release (FIN): FIN #%d, %s close" % (
                    c["fin_cnt"], "active" if c["fin_cnt"] == 1 else "passive")
        elif plen > 0:
            phase = "Data transfer: %d bytes of payload" % plen
            if c["state"] == 2:
                c["state"] = 3
        elif c["state"] == 2 and me == c["client"]:
            phase, c["state"] = "Connection setup 3/3 (ACK): connection established", 3
        elif acks_fin:
            phase = "Connection release (ACK): acknowledges peer FIN"
            if me in c["fin_seq"]:
                phase += ", connection closed"
        else:
            phase = "Acknowledgement only (ACK): no payload"

        rel_seq = (seq - c["isn"][me]) & 0xFFFFFFFF
        rel_ack = None
        if (fl & ACK) and peer in c["isn"]:
            rel_ack = (ack - c["isn"][peer]) & 0xFFFFFFFF
        return rel_seq, rel_ack, phase


# ---------------------------------------------------------------- UDP
def parse_udp(seg):
    """UDP 헤더(8바이트) 해석"""
    if len(seg) < 8:
        return None
    sport, dport, length, csum = struct.unpack("!HHHH", seg[:8])
    return {"sport": sport, "dport": dport, "length": length,
            "checksum": csum, "payload": seg[8:]}


# ---------------------------------------------------------------- ICMP
ICMP_TYPE = {0: "Echo Reply", 3: "Destination Unreachable",
             8: "Echo Request", 11: "Time Exceeded"}


def parse_icmp(msg):
    """
    ICMP 메시지 해석.
    Time Exceeded(11), Destination Unreachable(3) 는 본문에
    '오류를 일으킨 원본 IP 헤더 + 그 뒤 8바이트' 를 담고 있으므로 함께 해석한다.
    """
    if len(msg) < 8:
        return None
    itype, code, csum = struct.unpack("!BBH", msg[:4])
    r = {"type": itype, "code": code, "checksum": csum,
         "type_name": ICMP_TYPE.get(itype, "type %d" % itype)}
    if itype in (0, 8):
        r["id"], r["seq"] = struct.unpack("!HH", msg[4:8])
        r["data_len"] = len(msg) - 8
    elif itype in (3, 11):
        inner = parse_ip(msg[8:])
        if inner:
            o = {"src": inner["src"], "dst": inner["dst"],
                 "proto": inner["proto"], "ttl": inner["ttl"]}
            l4 = inner["payload"]
            if inner["proto"] == PROTO_ICMP and len(l4) >= 8:
                o["icmp_type"], _, _, o["id"], o["seq"] = struct.unpack("!BBHHH", l4[:8])
            elif inner["proto"] in (PROTO_UDP, PROTO_TCP) and len(l4) >= 4:
                o["sport"], o["dport"] = struct.unpack("!HH", l4[:4])
            r["original"] = o
    return r


# ---------------------------------------------------------------- HTTP
HTTP_METHODS = (b"GET ", b"POST ", b"HEAD ", b"PUT ", b"DELETE ",
                b"OPTIONS ", b"PATCH ", b"CONNECT ", b"TRACE ")


def parse_http(data):
    """
    HTTP/1.x 메시지의 시작 줄과 헤더 필드 해석.
    시작 줄이 없는 세그먼트(본문 조각)는 {'kind': 'data'} 를 돌려준다.
    """
    if not data:
        return None
    is_req = data.startswith(HTTP_METHODS)
    is_res = data.startswith(b"HTTP/")
    if not (is_req or is_res):
        return {"kind": "data", "length": len(data)}

    head, sep, body = data.partition(b"\r\n\r\n")
    lines = head.decode("iso-8859-1").split("\r\n")
    parts = lines[0].split(" ", 2) + ["", ""]
    r = {"headers": [], "body_len": len(body) if sep else 0}
    if is_req:
        r.update(kind="request", method=parts[0], uri=parts[1], version=parts[2])
    else:
        r.update(kind="response", version=parts[0], status=parts[1], reason=parts[2])
    for line in lines[1:]:
        name, colon, value = line.partition(":")
        if colon:
            r["headers"].append((name.strip(), value.strip()))
    return r


# ---------------------------------------------------------------- DNS
DNS_TYPE = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX",
            16: "TXT", 28: "AAAA", 33: "SRV", 41: "OPT", 65: "HTTPS"}
DNS_RCODE = {0: "NoError", 1: "FormErr", 2: "ServFail", 3: "NXDomain",
             4: "NotImp", 5: "Refused"}


def _dns_name(msg, off):
    """
    DNS 이름 읽기. 압축 포인터(상위 2비트가 11)를 따라간다.
    반환: (이름, 원래 위치에서 이름이 끝난 다음 오프셋)
    """
    labels, end, jumps = [], None, 0
    while True:
        if off >= len(msg):
            raise ValueError("name out of range")
        n = msg[off]
        if n == 0:
            if end is None:
                end = off + 1
            break
        if n & 0xC0 == 0xC0:                               # 압축 포인터
            if off + 1 >= len(msg) or jumps > 16:
                raise ValueError("bad pointer")
            if end is None:
                end = off + 2
            off = ((n & 0x3F) << 8) | msg[off + 1]
            jumps += 1
            continue
        if n > 63 or off + 1 + n > len(msg):
            raise ValueError("bad label")
        labels.append(msg[off + 1:off + 1 + n].decode("ascii", "replace"))
        off += 1 + n
    return (".".join(labels) or "."), end


def _dns_rdata(msg, off, rtype, rdlen):
    rd = msg[off:off + rdlen]
    if rtype == 1 and rdlen == 4:
        return "addr=" + socket.inet_ntoa(rd)
    if rtype == 28 and rdlen == 16:
        return "addr=" + socket.inet_ntop(socket.AF_INET6, rd)
    if rtype in (2, 5, 12):
        return "name=" + _dns_name(msg, off)[0]
    if rtype == 15 and rdlen > 2:
        return "pref=%d exchange=%s" % (struct.unpack("!H", rd[:2])[0],
                                        _dns_name(msg, off + 2)[0])
    return "rdlen=%d" % rdlen


def parse_dns(msg):
    """DNS 메시지 해석: 헤더 12바이트, Question, Answer/Authority/Additional"""
    if len(msg) < 12:
        return None
    tid, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", msg[:12])
    r = {
        "id": tid, "flags": flags, "qr": flags >> 15, "opcode": (flags >> 11) & 0xF,
        "aa": (flags >> 10) & 1, "tc": (flags >> 9) & 1, "rd": (flags >> 8) & 1,
        "ra": (flags >> 7) & 1, "rcode": flags & 0xF,
        "rcode_name": DNS_RCODE.get(flags & 0xF, "?"),
        "counts": (qd, an, ns, ar), "questions": [], "records": [], "error": None,
    }
    try:
        off = 12
        for _ in range(qd):
            name, off = _dns_name(msg, off)
            qtype, qclass = struct.unpack("!HH", msg[off:off + 4])
            off += 4
            r["questions"].append((name, DNS_TYPE.get(qtype, str(qtype)), qclass))
        for i in range(an + ns + ar):
            section = "Answer" if i < an else "Authority" if i < an + ns else "Additional"
            name, off = _dns_name(msg, off)
            rtype, rclass, ttl, rdlen = struct.unpack("!HHIH", msg[off:off + 10])
            off += 10
            if off + rdlen > len(msg):
                raise ValueError("rdata out of range")
            r["records"].append((section, name, DNS_TYPE.get(rtype, str(rtype)),
                                 ttl, _dns_rdata(msg, off, rtype, rdlen)))
            off += rdlen
    except (ValueError, struct.error) as e:
        r["error"] = "malformed message (%s)" % e
    return r
