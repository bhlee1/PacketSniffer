# CLAUDE.md — PacketSniffer 프로젝트 지침

Claude Code에서 이어서 작업할 때 이 파일을 먼저 읽는다.
개인정보(학번 등)는 이 파일과 공개 저장소에 넣지 않는다.

## 1. 프로젝트 개요
- 과목: 컴퓨터네트워크설계 (2팀)
- 과제: raw socket 으로 패킷을 캡처하고 IP / TCP·UDP / 응용 계층 헤더를 분석한다.
- 필수: 송신과 수신을 모두 캡처한다. HTTP, DNS 를 처리한다.
- 선택: e-mail, traceroute, BitTorrent. 우리 팀은 **traceroute** 를 선택했다.
- 환경: **Windows 10/11 + Python 3 (표준 라이브러리 socket, struct만 사용)**
- 외부 라이브러리를 추가하지 않는다.
- 비교 검증: Wireshark(Npcap) 캡처와 출력을 대조한다.

## 2. 제출물과 마감
- 설계계획서: PPT 5쪽. 11/13 19:00. 제출 완료.
- 설계보고서: PPT 8쪽 + 소스파일. **11/27 19:00**. eclass 업로드.
- 보고서 포함 내용: 목표, 설계 환경, 설계내용 및 결과, 기대효과.

## 3. 파일 역할
| 파일 | 역할 |
|---|---|
| capture.py | 소켓 생성·수신. Windows: raw socket + `SIO_RCVALL`. Linux: AF_PACKET (테스트용) |
| parser.py | IP / TCP / UDP / ICMP / HTTP / DNS 해석. `TcpTracker` 로 연결 단계 판별 |
| main.py | 캡처 실행, SEND/RECV/LOCAL 방향 표시, 요약, 로그 저장 |
| traceroute.py | ICMP 모드(기본)와 UDP 모드(`-U`, 강의 방식). Windows UDP 모드는 RCVALL 수신 자동 사용 |
| test_traceroute.py | 응답 매칭 자체 검사 (관리자 권한 불필요) |

제출물 (git 미추적, `.gitignore` 의 `*.pptx` 등으로 제외):
`설계보고서_2팀.pptx` (8쪽, 슬라이드 노트에 대본), `design*.pptx` (같은 파일, 제출용 이름), `소스파일_2팀.zip`, `발표대본.md`

## 4. 실행 방법 (관리자 권한 필수)
```
# 스니퍼 (Windows: 관리자 cmd)
python main.py                 # 기본: 포트 80, 53
python main.py -a              # 모든 포트 (traceroute UDP 프로브도 보임)
python main.py -p 8080         # 포트 지정
python main.py --proto icmp    # ICMP만
python main.py -c 50 -o log.txt
python main.py -x              # 페이로드 hex 덤프

# traceroute
python traceroute.py 8.8.8.8          # ICMP Echo 방식 (Windows tracert 와 동일)
python traceroute.py -U 8.8.8.8       # UDP 방식 (강의 방식)
python traceroute.py -U -v 8.8.8.8    # 헤더 필드 출력
```
- 두 창을 동시에 띄운다: 한쪽은 `main.py -a --proto icmp` (또는 `-a`), 다른 쪽은 traceroute.
- 이렇게 하면 프로브 송신과 ICMP 응답 수신이 스니퍼에 같이 찍힌다.

## 5. traceroute 두 방식 (강의자료 Chapter 5, 슬라이드 5-88, 5-89 기준)
| 구분 | ICMP 모드 (기본) | UDP 모드 (`-U`) |
|---|---|---|
| 프로브 | ICMP Echo Request (Type 8) | UDP, 목적 포트 33434부터 프로브마다 +1 |
| 중간 라우터 응답 | ICMP Type 11 Code 0 (Time Exceeded) | 동일 |
| 목적지 응답 | ICMP Type 0 (Echo Reply) | ICMP Type 3 Code 3 (Port Unreachable) |
| 종료 조건 | 목적지에서 Echo Reply 수신 | 목적지에서 Type 3 Code 3 수신 |
| 응답 매칭 | ICMP id + seq | 본문 속 원본 UDP 의 (출발 포트, 목적 포트) |
- TTL 마다 프로브 3개를 보낸다 (`-q`).
- ICMP 오류 본문은 원본 IP 헤더 + 원본 데이터 앞 8바이트다. 매칭에 이 값을 쓴다.
- Windows `tracert` 는 ICMP 방식이고, `-d` 없이 실행하면 DNS PTR 질의(UDP 53)도 보낸다.

## 6. 검증 상태
**검증됨 (Linux 샌드박스, root)**
- 스니퍼: HTTP 12 TCP 세그먼트와 단계 판별, DNS 질의/응답, ICMP Echo/Time Exceeded.
- 파서: 비정상 입력 fuzz 테스트 통과.
- traceroute ICMP 모드: 루프백 Echo Reply, 8.8.8.8 hop 1 Time Exceeded.
- traceroute UDP 모드: 루프백 Type 3 Code 3 으로 종료, 합성 패킷 매칭 (Type 11, Type 3, 포트 불일치, 쓰레기 입력).

**검증됨 (11/26, Windows 11 + Python 3.15, 관리자, 공용 네트워크, 8.8.8.8)**
- `test_traceroute.py` (합성 패킷 매칭 검사) 통과.
- `SIO_RCVALL` 로 송신 패킷까지 캡처된다.
- 방화벽 규칙 없이: 송신 전부, 수신 DNS 는 캡처됨. 수신 TCP(HTTP 응답), Echo Reply 외 수신 ICMP(Time Exceeded) 는 안 보임.
  같은 시각 `tracert -d` 는 hop 2~9 응답 → 패킷은 도착하는데 Windows 방화벽이 raw socket 전달을 막음.
- python.exe 인바운드 허용 규칙 추가 → 스니퍼에 HTTP Request/Response, Echo Reply 수신됨. Time Exceeded 는 여전히 안 보임.
- ICMPv4 Type 11, 3 인바운드 허용 규칙까지 추가 → 전부 정상:
  - ICMP 모드: hop 2~8 Time Exceeded, hop 9 Echo Reply 로 종료.
  - UDP 모드 (`-U`, `-U --rcvall` 둘 다): hop 2~8 Time Exceeded, hop 9 Type 3 Code 3 (포트 33450, 33451) 로 종료.
  - 스니퍼 `-a --proto icmp`: Type 8/0/11/3 모두 SEND/RECV 로 표시, 3/3 해석 문구 출력.
- hop 1 은 `tracert` 에서도 `*` (공유기가 응답 안 함, 정상).
- 단독 실행 시 UDP 모드는 전 hop `*`: Windows raw ICMP socket 은 UDP 프로브에 대한 ICMP 11/3 을 못 받는다
  (ICMP 프로브의 11 은 받음). 위 결과는 스니퍼(SIO_RCVALL)를 같이 띄워서 받은 것이었다.
  → Windows UDP 모드는 RCVALL 수신을 자동 사용하도록 수정. 단독 실행으로 hop 9 Type 3 Code 3 까지 확인.
- Windows raw socket 은 수신 SYN+ACK 를 내 3번째 ACK 보다 늦게 넘겨줄 때가 있다 → `TcpTracker` 가 이 순서도 3/3 으로 판별하도록 수정. 실측 확인.
- Wireshark 4.6.9 대조 (같은 시간 tshark 캡처): DNS ID·응답 주소, HTTP GET / 200 OK, UDP 모드 ICMP 11/3 이 스니퍼 출력과 일치.
- `tracert -d` 대조: hop 2~9 라우터 IP 가 ICMP 모드 결과와 일치.
- 설계보고서용 실행 화면·Wireshark 캡처 완료 (11/26). PPT 5쪽 HTTP 응답 화면은 요청 화면과 다른 실행 세션(포트 56155) — 슬라이드에 명시함.
- 규칙은 테스트 후 삭제했다. 시연·로그 수집 때는 README "방화벽 설정" 대로 다시 추가한다.

**미검증**
- 팀원 PC, 사설망(공유기 뒤) 환경. 다른 보안 프로그램이 있으면 결과가 다를 수 있다.
- 루프백은 Windows raw socket 으로 캡처되지 않는다 (정상). 외부 주소로 테스트한다.

## 7. 알려진 제약
- Windows 는 raw socket 으로 TCP 송신을 막는다. 캡처만 하고 송신은 일반 소켓/브라우저로 한다.
- HTTP 는 평문 HTTP/1.1 만 해석한다. HTTPS 는 암호화되어 본문을 못 본다.
- IPv4 만 지원한다.
- HTTP 테스트는 평문 사이트(예: `http://example.com`)를 쓴다.
- HTTP/1.1 요청 후 응답이 안 보이면: 관리자 권한, 바인딩한 NIC IP(`-i`), 포트 필터(`-a`)를 순서대로 확인한다.

## 8. 남은 작업 (우선순위 순)
1. **eclass 업로드 (11/27 19:00 마감)**: 설계보고서 PPT + `소스파일_2팀.zip`. 사람이 직접 한다.
2. 발표 리허설. 대본 약 2,800자, 7~10분. 시연하려면 관리자 cmd + README "방화벽 설정" 규칙을 먼저 추가한다.
3. (선택) 팀원 PC 에서 한 번 실행해 본다 (§6 미검증).
4. (선택) `log.txt` 파일 저장: 결과 화면 캡처는 끝났지만 `-o log.txt` 로 저장한 로그 파일은 없다.
   필요하면 `python main.py -a -o log.txt` 로 만든다 (`.gitignore` 로 제외됨).

**완료 (11/26)**
- Windows 실기 검증, Wireshark·tracert 대조 (§6).
- 설계보고서 PPT 8쪽: 표지 / 목표 / 환경 / 설계 내용 / 결과① HTTP·DNS / 결과② traceroute / 검증 / 기대효과. 실제 실행 화면 사용, 맑은 고딕.
- 소스파일 압축: capture.py, parser.py, main.py, traceroute.py, test_traceroute.py, README.md. 커밋 `f134a29` 기준, 개인정보 없음 확인.
- 발표 대본 (UDP 모드, 실측 중 해결한 문제 3가지 반영): `발표대본.md` + PPT 슬라이드 노트.

## 9. 작업 규칙
- 코드는 표준 라이브러리만 쓴다. Windows 와 Linux 둘 다 import 에러 없이 돌아야 한다.
- 헤더 해석은 `struct.unpack('!...')` 를 쓴다. 길이는 IHL×4, Data Offset×4 로 계산한다.
- 모든 `parse_*` 는 실패 시 None 을 돌려준다. 예외로 프로그램이 죽으면 안 된다.
- 수정 후 Linux 에서 `sudo python3 traceroute.py -U 127.0.0.1` 같은 루프백 테스트로 회귀를 확인한다.
- 실행해 보지 않은 동작은 "미검증" 으로 표시한다. 추측으로 단정하지 않는다.
- 학번·이름 등 개인정보는 코드, README, 커밋 메시지에 넣지 않는다. 표지/제출 문서에만 쓴다.
- PPT 한글 폰트는 맑은 고딕. 글자 크기를 작게 줄이지 않는다.

## 10. GitHub 상태
- 원격: https://github.com/bhlee1/PacketSniffer (공개, `main`). 11/26 push 완료.
- push 전 확인: `git log -p` 에 학번·이름이 없는지, `.gitignore` 에 `log.txt`, `*.log` 가 제외되는지.
