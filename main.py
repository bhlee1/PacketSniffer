"""
main.py - 필터, 출력, 로그 저장

실행 (관리자 권한 cmd)
  python main.py                    HTTP(80), DNS(53), ICMP 패킷 출력
  python main.py -o log.txt         화면 출력을 파일에도 저장
  python main.py --proto icmp       ICMP 만 출력 (traceroute 분석)
  python main.py -p 80              80번 포트만 출력
  python main.py -a                 모든 TCP/UDP/ICMP 출력

옵션
  -i IP        캡처할 내 IP 주소 (생략하면 자동 선택)
  -p PORT ...  출력할 TCP/UDP 포트 (기본 80 53)
  --proto ...  출력할 프로토콜: tcp udp icmp (기본 전부)
  -a           포트 필터 끄기
  -c N         N개 출력 후 종료
  -o FILE      로그 파일 저장
  -x           응용 계층 데이터 앞부분을 16진수로 출력
"""
import argparse
import sys
import time

import parser as P
from capture import Capture

HTTP_PORT, DNS_PORT = 80, 53
LINE = "=" * 70


class Output:
    """화면과 로그 파일에 동시에 쓴다."""

    def __init__(self, path):
        self.file = open(path, "w", encoding="utf-8") if path else None

    def __call__(self, text=""):
        print(text)
        if self.file:
            self.file.write(text + "\n")

    def close(self):
        if self.file:
            self.file.close()


def hexdump(out, data, limit=64):
    for i in range(0, min(len(data), limit), 16):
        chunk = data[i:i + 16]
        hexs = " ".join("%02x" % b for b in chunk)
        text = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        out("      %04x  %-47s  %s" % (i, hexs, text))
    if len(data) > limit:
        out("      ... (%d bytes more)" % (len(data) - limit))


def direction(ip, local_ip):
    """출발지 IP 가 내 IP 면 송신, 목적지 IP 가 내 IP 면 수신"""
    if ip["src"] == ip["dst"]:
        return "LOCAL"
    if ip["src"] == local_ip:
        return "SEND"
    if ip["dst"] == local_ip:
        return "RECV"
    return "OTHER"


def show_ip(out, ip):
    out("[IP ] %s -> %s" % (ip["src"], ip["dst"]))
    out("      Version=%d  HeaderLen=%d  TOS=0x%02x  TotalLen=%d  ID=0x%04x" % (
        ip["version"], ip["ihl"], ip["tos"], ip["total_len"], ip["id"]))
    out("      Flags=[%s%s]  FragOffset=%d  TTL=%d  Protocol=%d(%s)  Checksum=0x%04x" % (
        "DF" if ip["df"] else "", "MF" if ip["mf"] else "", ip["frag_off"], ip["ttl"],
        ip["proto"], P.PROTO_NAME.get(ip["proto"], "other"), ip["checksum"]))


def show_tcp(out, ip, tcp, tracker):
    rel_seq, rel_ack, phase = tracker.update(ip["src"], ip["dst"], tcp)
    out("[TCP] SrcPort=%d -> DstPort=%d" % (tcp["sport"], tcp["dport"]))
    out("      Seq=%d (relative %d)" % (tcp["seq"], rel_seq))
    if tcp["flags"] & P.ACK:
        out("      Ack=%d%s" % (tcp["ack"], "" if rel_ack is None else " (relative %d)" % rel_ack))
    else:
        out("      Ack=%d (not valid, ACK flag off)" % tcp["ack"])
    out("      HeaderLen=%d  Flags=[%s]  Window=%d  Checksum=0x%04x  Urgent=%d" % (
        tcp["hdr_len"], " ".join(tcp["flag_names"]), tcp["window"],
        tcp["checksum"], tcp["urgent"]))
    out("      >> " + phase)


def show_udp(out, udp):
    out("[UDP] SrcPort=%d -> DstPort=%d" % (udp["sport"], udp["dport"]))
    out("      Length=%d  Checksum=0x%04x  (payload %d bytes)" % (
        udp["length"], udp["checksum"], len(udp["payload"])))


def show_icmp(out, ip, icmp):
    out("[ICMP] %s  Type=%d Code=%d  Checksum=0x%04x" % (
        icmp["type_name"], icmp["type"], icmp["code"], icmp["checksum"]))
    if "id" in icmp:
        out("      ID=%d  Seq=%d  Data=%d bytes" % (icmp["id"], icmp["seq"], icmp["data_len"]))
    o = icmp.get("original")
    if o:
        out("      Original packet: %s -> %s  Protocol=%d(%s)  TTL=%d" % (
            o["src"], o["dst"], o["proto"], P.PROTO_NAME.get(o["proto"], "other"), o["ttl"]))
        if "seq" in o:
            out("      Original ICMP  : Type=%d  ID=%d  Seq=%d" % (o["icmp_type"], o["id"], o["seq"]))
        elif "sport" in o:
            out("      Original ports : %d -> %d" % (o["sport"], o["dport"]))
    # traceroute 관점의 해석
    if icmp["type"] == 8:
        out("      >> traceroute/ping probe: sent with IP TTL=%d" % ip["ttl"])
    elif icmp["type"] == 11:
        out("      >> TTL expired at router %s (it reports back with Time Exceeded)" % ip["src"])
    elif icmp["type"] == 0:
        out("      >> destination %s reached" % ip["src"])


def show_http(out, http):
    if http["kind"] == "data":
        out("[HTTP] Continuation data (body segment), %d bytes" % http["length"])
        return
    if http["kind"] == "request":
        out("[HTTP] Request")
        out("      Method      : " + http["method"])
        out("      Request-URI : " + http["uri"])
        out("      Version     : " + http["version"])
    else:
        out("[HTTP] Response")
        out("      Version     : " + http["version"])
        out("      Status-Code : " + http["status"])
        out("      Reason      : " + http["reason"])
    out("      Header fields:")
    for name, value in http["headers"][:40]:
        out("        %s: %s" % (name, value))
    out("      Body        : %d bytes in this segment" % http["body_len"])


def show_dns(out, dns):
    out("[DNS] " + ("Response" if dns["qr"] else "Query"))
    out("      Transaction ID : 0x%04x" % dns["id"])
    out("      Flags          : 0x%04x (QR=%d Opcode=%d AA=%d TC=%d RD=%d RA=%d RCODE=%d %s)" % (
        dns["flags"], dns["qr"], dns["opcode"], dns["aa"], dns["tc"], dns["rd"],
        dns["ra"], dns["rcode"], dns["rcode_name"]))
    out("      Questions=%d  Answers=%d  Authority=%d  Additional=%d" % dns["counts"])
    for name, qtype, qclass in dns["questions"]:
        out("      Question   : %s  type=%s class=%d" % (name, qtype, qclass))
    for section, name, rtype, ttl, rdata in dns["records"]:
        out("      %-10s : %s  type=%s ttl=%d  %s" % (section, name, rtype, ttl, rdata))
    if dns["error"]:
        out("      (%s)" % dns["error"])


def main():
    ap = argparse.ArgumentParser(description="raw socket packet sniffer")
    ap.add_argument("-i", dest="ip")
    ap.add_argument("-p", dest="ports", type=int, nargs="+", default=[HTTP_PORT, DNS_PORT])
    ap.add_argument("--proto", nargs="+", choices=["tcp", "udp", "icmp"],
                    default=["tcp", "udp", "icmp"])
    ap.add_argument("-a", dest="all_ports", action="store_true")
    ap.add_argument("-c", dest="count", type=int, default=0)
    ap.add_argument("-o", dest="log")
    ap.add_argument("-x", dest="hex", action="store_true")
    args = ap.parse_args()

    try:
        cap = Capture(args.ip)
    except PermissionError:
        sys.exit("raw socket 생성 실패: 관리자 권한으로 실행하라")
    except OSError as e:
        sys.exit("캡처 시작 실패: %s (관리자 권한, -i 내IP주소 확인)" % e)

    out = Output(args.log)
    tracker = P.TcpTracker()
    stat = dict(ip=0, tcp=0, udp=0, icmp=0, shown=0, SEND=0, RECV=0, http=0, dns=0)
    ports = set(args.ports)
    port_ok = lambda s, d: args.all_ports or s in ports or d in ports

    out("Packet sniffer (raw socket)  local IP: %s" % cap.local_ip)
    out("filter: proto=%s  ports=%s   (Ctrl+C to stop)" % (
        ",".join(args.proto), "all" if args.all_ports else sorted(ports)))

    try:
        for pkt in cap.packets():
            if args.count and stat["shown"] >= args.count:
                break
            if pkt is None:
                continue
            ip = P.parse_ip(pkt)                           # ④ IP 헤더 해석
            if ip is None:
                continue
            stat["ip"] += 1
            if ip["frag_off"]:                             # 첫 조각이 아니면 L4 헤더 없음
                continue

            # ⑤ 전송 계층 해석: Protocol 값으로 분기
            proto, l4, app, kind = ip["proto"], None, None, None
            if proto == P.PROTO_TCP:
                l4 = P.parse_tcp(ip["payload"])
                if l4 is None:
                    continue
                stat["tcp"] += 1
                if "tcp" not in args.proto or not port_ok(l4["sport"], l4["dport"]):
                    continue
                if HTTP_PORT in (l4["sport"], l4["dport"]):
                    kind = "http"
            elif proto == P.PROTO_UDP:
                l4 = P.parse_udp(ip["payload"])
                if l4 is None:
                    continue
                stat["udp"] += 1
                if "udp" not in args.proto or not port_ok(l4["sport"], l4["dport"]):
                    continue
                if DNS_PORT in (l4["sport"], l4["dport"]):
                    kind = "dns"
            elif proto == P.PROTO_ICMP:
                l4 = P.parse_icmp(ip["payload"])
                if l4 is None:
                    continue
                stat["icmp"] += 1
                if "icmp" not in args.proto:
                    continue
            else:
                continue

            # ⑦ 송신·수신 표시 후 출력
            d = direction(ip, cap.local_ip)
            stat["shown"] += 1
            if d in stat:
                stat[d] += 1
            t = time.time()
            stamp = time.strftime("%H:%M:%S", time.localtime(t)) + ".%03d" % (t * 1000 % 1000)
            out()
            out(LINE)
            out("#%d  [%s]  time=%s  captured=%d bytes" % (stat["shown"], d, stamp, len(pkt)))
            out("-" * 70)
            show_ip(out, ip)
            if proto == P.PROTO_TCP:
                show_tcp(out, ip, l4, tracker)
            elif proto == P.PROTO_UDP:
                show_udp(out, l4)
            else:
                show_icmp(out, ip, l4)

            # ⑥ 응용 계층 해석: 포트 번호로 분기
            data = l4.get("payload", b"")
            if data and kind == "http":
                app = P.parse_http(data)
                if app["kind"] != "data":
                    stat["http"] += 1
                show_http(out, app)
            elif data and kind == "dns":
                app = P.parse_dns(data)
                if app:
                    stat["dns"] += 1
                    show_dns(out, app)
                else:
                    out("[DNS] Truncated message (%d bytes)" % len(data))
            if args.hex and data:
                hexdump(out, data)
            sys.stdout.flush()
    except KeyboardInterrupt:
        pass
    finally:
        cap.close()

    out()
    out(LINE)
    out("Capture summary")
    out("  IPv4 packets  : %d  (TCP %d, UDP %d, ICMP %d)" % (
        stat["ip"], stat["tcp"], stat["udp"], stat["icmp"]))
    out("  displayed     : %d  (SEND %d, RECV %d)" % (stat["shown"], stat["SEND"], stat["RECV"]))
    out("  HTTP messages : %d" % stat["http"])
    out("  DNS messages  : %d" % stat["dns"])
    out.close()


if __name__ == "__main__":
    main()
