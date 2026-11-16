# PacketSniffer

Python 표준 라이브러리만으로 만든 **raw socket 기반 패킷 스니퍼**입니다.
내 PC의 네트워크 인터페이스를 지나는 IPv4 패킷(송신·수신 모두)을 캡처해서
IP → TCP / UDP / ICMP → HTTP / DNS 순서로 헤더를 해석해 보여줍니다.
네트워크 계층 구조와 프로토콜 헤더를 공부하거나, ping / traceroute / DNS / HTTP 통신을 눈으로 확인하는 용도입니다.

## 요구 사항

- Python 3.8 이상 (외부 패키지 설치 없음)
- **관리자 권한** (raw socket 생성에 필요)
- Windows 10/11 (기본 대상). Linux(root)에서도 개발·테스트용으로 동작합니다.

## 파일 구성

| 파일 | 역할 |
|------|------|
| `main.py` | 실행 진입점. 옵션 처리, 필터링, 화면/로그 출력, 요약 통계 |
| `capture.py` | 캡처 모듈. raw socket 생성, 패킷 수신 |
| `parser.py` | 헤더 해석 모듈. IP, TCP, UDP, ICMP, HTTP, DNS 파싱 |

## 사용법

**반드시 관리자 권한으로 실행한 터미널(cmd / PowerShell)에서 실행하세요.**

```bash
python main.py                    # HTTP(80), DNS(53) 포트의 TCP/UDP + ICMP 출력
python main.py -o log.txt         # 화면 출력을 log.txt 에도 저장
python main.py --proto icmp       # ICMP 만 출력 (ping, traceroute 분석)
python main.py -p 80              # 80번 포트만 출력
python main.py -a                 # 포트 필터 없이 모든 TCP/UDP/ICMP 출력
python main.py -a -c 20 -x        # 모든 패킷 20개만 출력, 페이로드 hexdump 포함
```

종료는 `Ctrl+C` 입니다. 종료 시 캡처 요약(패킷 수, 송/수신 수, HTTP/DNS 메시지 수)이 출력됩니다.

### 옵션

| 옵션 | 설명 |
|------|------|
| `-i IP` | 캡처할 내 IP 주소. 생략하면 외부로 나가는 경로의 IP를 자동 선택 |
| `-p PORT ...` | 출력할 TCP/UDP 포트 (기본값: `80 53`). 여러 개 가능 |
| `--proto ...` | 출력할 프로토콜 `tcp` `udp` `icmp` (기본값: 전부) |
| `-a` | 포트 필터 끄기 (모든 포트 출력) |
| `-c N` | N개 출력 후 자동 종료 |
| `-o FILE` | 출력 내용을 로그 파일에도 저장 (UTF-8) |
| `-x` | 응용 계층 데이터 앞 64바이트를 16진수로 출력 |

> 포트 필터(`-p`, `-a`)는 TCP/UDP에만 적용되고, ICMP는 `--proto`로만 거를 수 있습니다.

## 동작 방식

1. **캡처 (`capture.py`)**
   - Windows: raw socket을 내 IP에 `bind`하고 `SIO_RCVALL`을 켜서 해당 인터페이스의 모든 IP 패킷을 IP 헤더부터 수신합니다.
   - Linux: `AF_PACKET`으로 프레임을 받아 이더넷 헤더 14바이트를 제거합니다.
   - 소켓 타임아웃(0.5초)을 두어 `Ctrl+C`가 바로 반응합니다.
2. **IP 해석** — 버전, 헤더 길이, TTL, 프로토콜, 플래그(DF/MF), 조각 오프셋, 출발지/목적지 주소 등.
3. **전송 계층 해석** — IP의 Protocol 값(1/6/17)으로 ICMP / TCP / UDP 분기.
4. **응용 계층 해석** — 포트 번호로 분기 (80 → HTTP, 53 → DNS).
5. **방향 표시** — 출발지가 내 IP면 `SEND`, 목적지가 내 IP면 `RECV`.

### 지원하는 해석

- **IP**: IPv4 헤더 전 필드
- **TCP**: 플래그(SYN/ACK/PSH/FIN/RST/URG), Seq/Ack(절대값 + 상대값), 윈도우 등.
  `TcpTracker`가 연결별 상태를 기억해 **3-way handshake / 데이터 전송 / 연결 해제(FIN)** 단계를 표시합니다.
- **UDP**: 포트, 길이, 체크섬
- **ICMP**: Echo Request/Reply, Time Exceeded, Destination Unreachable.
  오류 메시지에 포함된 원본 패킷 정보도 해석하며, traceroute 관점의 설명(`TTL expired at router ...`)을 함께 보여줍니다.
- **HTTP/1.x**: 요청(Method, URI, Version)·응답(Status, Reason), 헤더 필드, 본문 길이
- **DNS**: Query/Response, 플래그, Question, Answer/Authority/Additional 레코드 (A, AAAA, CNAME, MX, NS, PTR 등, 이름 압축 포인터 지원)

### 출력 예시 (형태)

```
======================================================================
#1  [SEND]  time=14:03:21.512  captured=60 bytes
----------------------------------------------------------------------
[IP ] 192.168.0.10 -> 8.8.8.8
      Version=4  HeaderLen=20  TOS=0x00  TotalLen=60  ID=0x1a2b
      Flags=[DF]  FragOffset=0  TTL=128  Protocol=17(UDP)  Checksum=0x0000
[UDP] SrcPort=51234 -> DstPort=53
      Length=40  Checksum=0xabcd  (payload 32 bytes)
[DNS] Query
      Transaction ID : 0x1234
      Question   : example.com  type=A class=1
```

## 활용 예시

- **traceroute 분석**: `tracert example.com`을 실행하면서 `python main.py --proto icmp` 로 TTL 값이 늘어나며 Time Exceeded가 돌아오는 과정 관찰
- **DNS 확인**: `nslookup example.com` 실행 후 `python main.py -p 53` 으로 질의/응답 확인
- **HTTP 확인**: `curl http://example.com` 과 함께 `python main.py -p 80` 으로 요청/응답 헤더 확인
- **TCP 연결 과정 학습**: `python main.py -p 80` 에서 `>> Connection setup 1/3 ...` 같은 단계 표시 확인

## 제한 사항 / 주의

- **IPv4 전용**입니다. IPv6는 해석하지 않습니다.
- HTTPS(443) 등 암호화된 통신은 내용을 볼 수 없습니다. HTTP 해석은 평문 HTTP/1.x(80번 포트)만 지원합니다.
- IP 단편화된 패킷은 첫 조각만 해석하고 나머지는 건너뜁니다. TCP 재조립도 하지 않습니다.
- Windows의 raw socket 방식 특성상 일부 환경(VPN, 가상 어댑터, 일부 보안 프로그램)에서는 패킷이 보이지 않을 수 있습니다. 이 경우 `-i` 로 사용 중인 어댑터의 IP를 직접 지정하세요.
- `parser.py`는 파이썬 옛 표준 모듈 `parser`와 이름이 같습니다. Python 3.10 이상에서는 문제없지만, 3.9 이하에서는 충돌 가능성이 있습니다.
- **본인 소유 PC / 허가된 네트워크에서만 사용하세요.** 타인의 통신을 무단으로 캡처하는 것은 법적 문제가 될 수 있습니다. 로그 파일에는 HTTP 헤더(쿠키 등) 같은 민감한 정보가 담길 수 있으니 Git에 올리지 마세요. `.gitignore`에 `log*.txt`, `*.log`, `*.pcap` 등이 이미 등록되어 있으니 로그 파일 이름을 `log*.txt` 형태(예: `log.txt`)로 지정하세요.

## 트러블슈팅

| 증상 | 해결 |
|------|------|
| `raw socket 생성 실패: 관리자 권한으로 실행하라` | 터미널을 "관리자 권한으로 실행"으로 다시 열기 |
| `캡처 시작 실패: ...` | 관리자 권한 확인, `-i 내IP주소` 로 IP 직접 지정 |
| 아무 패킷도 안 나옴 | `-a` 로 포트 필터 해제, `-i` 로 올바른 어댑터 IP 지정, 방화벽/보안 프로그램 확인 |
