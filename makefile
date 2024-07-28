# Makefile for building send-tcp and pcap programs

# 컴파일러 설정
CC = gcc
CFLAGS = -Wall -Wextra -O2
LDFLAGS = -lpcap -lnet

# 빌드 대상
TARGETS = send-tcp pcap

# 소스 파일 설정
SEND_TCP_SRC = send-tcp.c
PCAP_SRC = pcap.c

# 빌드 규칙
all: $(TARGETS)

# send-tcp 실행 파일 빌드 규칙
send-tcp: $(SEND_TCP_SRC)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# pcap 실행 파일 빌드 규칙
pcap: $(PCAP_SRC)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# 정리 규칙
clean:
	rm -f $(TARGETS) *.o

# phony 타겟
.PHONY: all clean
