import argparse
import socket
import random
import time
import gzip
import io
from urllib.parse import urlparse, parse_qs
from scapy.all import (
    IP, TCP, sniff, send, sr1,
    wrpcap, rdpcap, Raw
)

XSS_PATTERNS = [
    "<script",
    "onerror=",
    "onload=",
    "alert("
]


# -------------------------------
# ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ
# -------------------------------

def resolve_hostname(hostname):
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        return None


def parse_url_http_only(url):
    if not url.startswith("http://"):
        url = "http://" + url

    parsed = urlparse(url)
    return parsed.hostname, parsed.path or "/", parsed.query


def decompress_if_needed(headers, body):
    if "content-encoding: gzip" in headers.lower():
        try:
            buf = io.BytesIO(body)
            return gzip.GzipFile(fileobj=buf).read()
        except:
            return body
    return body


# -------------------------------
# ОТПРАВКА HTTP ЗАПРОСА
# -------------------------------

def send_http_request(host, path, query=""):
    dst_ip = resolve_hostname(host)
    if not dst_ip:
        print("Не удалось разрешить hostname")
        return

    port = 80
    sport = random.randint(1025, 65000)

    http_req = (
        f"GET {path}?{query} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Connection: close\r\n\r\n"
    )

    syn = IP(dst=dst_ip) / TCP(sport=sport, dport=port, flags="S")
    syn_ack = sr1(syn, timeout=5, verbose=False)

    if not syn_ack or not syn_ack.haslayer(TCP):
        print("TCP handshake не выполнен")
        return

    ack = IP(dst=dst_ip) / TCP(
        sport=sport,
        dport=port,
        seq=syn_ack.ack,
        ack=syn_ack.seq + 1,
        flags="A"
    )
    send(ack, verbose=False)

    packet = IP(dst=dst_ip) / TCP(
        sport=sport,
        dport=port,
        seq=syn_ack.ack,
        ack=syn_ack.seq + 1,
        flags="PA"
    ) / http_req

    send(packet, verbose=False)


# -------------------------------
# ПЕРЕХВАТ ТРАФИКА
# -------------------------------

def capture_traffic(hostname, timeout, output):
    ip = resolve_hostname(hostname)
    if not ip:
        print("Не удалось разрешить hostname")
        return

    print(f"[+] Перехват трафика для {hostname} ({ip})")

    packets = sniff(
        filter=f"tcp and host {ip} and port 80",
        timeout=timeout
    )

    if output:
        wrpcap(output, packets)
        print(f"[+] Сохранено в {output}")

    return packets


# -------------------------------
# АНАЛИЗ ПАКЕТОВ
# -------------------------------

def analyze_packets(packets):
    print("\n[+] Анализ HTTP-трафика\n")

    for pkt in packets:
        if not pkt.haslayer(Raw):
            continue

        data = pkt[Raw].load
        try:
            text = data.decode("utf-8", errors="ignore")
        except:
            continue

        if not ("HTTP" in text or "GET" in text or "POST" in text):
            continue

        # HTTP REQUEST
        if text.startswith(("GET", "POST")):
            line = text.splitlines()[0]
            print(f"[HTTP REQUEST] {line}")

            parsed = urlparse(line.split()[1])
            params = parse_qs(parsed.query)

            for k, v in params.items():
                for value in v:
                    for pattern in XSS_PATTERNS:
                        if pattern in value.lower():
                            print("  [!] XSS payload найден в параметре:")
                            print(f"      {k} = {value}")

        # HTTP RESPONSE
        if text.startswith("HTTP/"):
            headers, _, body = data.partition(b"\r\n\r\n")
            body = decompress_if_needed(
                headers.decode("utf-8", errors="ignore"),
                body
            )

            body_text = body.decode("utf-8", errors="ignore").lower()

            for pattern in XSS_PATTERNS:
                if pattern in body_text:
                    print("  [!] ОТРАЖЁННАЯ XSS В ОТВЕТЕ")
                    print(f"      Найден паттерн: {pattern}")
                    break


# -------------------------------
# АНАЛИЗ PCAP
# -------------------------------

def analyze_pcap(file):
    packets = rdpcap(file)
    analyze_packets(packets)


# -------------------------------
# MAIN
# -------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="XSS-анализ HTTP-трафика с помощью Scapy"
    )

    parser.add_argument("--send", help="Отправить HTTP-запрос (http://)")
    parser.add_argument("--capture", help="Перехват трафика для хоста")
    parser.add_argument("--timeout", type=int, default=60)
    parser.add_argument("--output", help="pcap файл")
    parser.add_argument("--analyze", help="анализ pcap файла")

    args = parser.parse_args()

    if args.send:
        host, path, query = parse_url_http_only(args.send)
        send_http_request(host, path, query)

    if args.capture:
        capture_traffic(args.capture, args.timeout, args.output)

    if args.analyze:
        analyze_pcap(args.analyze)


if __name__ == "__main__":
    main()
