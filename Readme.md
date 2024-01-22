# FakeWiFiBeam
원하는 WiFi이름들로 도배해버릴 수 있는 툴
### 사용방법
```
1. git clone
2. $make
3. 동일폴더에 beacon-flood 생성되었는지 확인
4. ssid_list.txt를 수정해 본인이 원하는 wifi목록을 엔터를 구분해 입력
5. $sudo beacon-flood <무선랜인터페이스> ssid_list.txt
6. 정상 실행시 Veacon Flooding... 출력
7. 30초동안 ssid_list.txt의 와이파이들이 표시됨
```

### 원리
802.11의 비콘프레임을 덤핑해서, ssid태그를 수정. 패킷 리플레이 진행.