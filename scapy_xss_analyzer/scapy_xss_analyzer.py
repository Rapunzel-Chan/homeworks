import argparse
import os
import socket
import random
import time
import gzip
from urllib.parse import urlparse
from scapy.packet import Raw
from scapy.layers.inet import IP, TCP
from scapy.sendrecv import sr1, send
from scapy.all import sniff, wrpcap, rdpcap


def resolve_hostname(hostname):
    """Разрешает доменное имя в IP-адрес."""
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror as e:
        print(f"Ошибка разрешения доменного имени '{hostname}': {e}")
        return None


def parse_url(url_arg):
    """Парсит URL и извлекает hostname, path и scheme."""
    if not url_arg.startswith('http://') and not url_arg.startswith('https://'):
        url_arg = 'http://' + url_arg

    try:
        parsed = urlparse(url_arg)
        hostname = parsed.hostname
        path = parsed.path if parsed.path else '/'
        scheme = parsed.scheme or 'http'
        return hostname, path, scheme
    except Exception as e:
        print(f"Ошибка парсинга URL: {e}")
        return None, None, None


def send_http_request(hostname, path, custom_request=None):
    """Отправляет HTTP-запрос через Scapy (ручная сборка TCP)."""
    dest_ip = resolve_hostname(hostname)
    if not dest_ip:
        return None

    port = 80
    client_sport = random.randint(1025, 65500)

    if custom_request:
        http_request_str = custom_request
    else:
        http_request_str = f'GET {path} HTTP/1.1\r\nHost: {hostname}\r\nConnection: close\r\n\r\n'

    print(f"[+] Установка TCP-соединения с {dest_ip}:{port}...")

    # 1. SYN
    syn = IP(dst=dest_ip) / TCP(sport=client_sport, dport=port, flags='S')
    syn_ack = sr1(syn, timeout=5, verbose=False)

    if not syn_ack or not syn_ack.haslayer(TCP) or syn_ack[TCP].flags != 0x12:
        print(f"[-] Не удалось установить соединение (нет SYN-ACK).")
        return None

    # 2. ACK (Handshake complete)
    client_seq = syn_ack[TCP].ack
    client_ack = syn_ack[TCP].seq + 1
    ack_packet = IP(dst=dest_ip) / TCP(
        sport=client_sport,
        dport=port,
        seq=client_seq,
        ack=client_ack,
        flags='A'
    )
    send(ack_packet, verbose=False)

    time.sleep(0.1)

    # 3. PSH + ACK (данные)
    http_packet = IP(dst=dest_ip) / TCP(
        sport=client_sport,
        dport=port,
        seq=client_seq,
        ack=client_ack,
        flags='PA'
    ) / http_request_str

    send(http_packet, verbose=False)
    print("[+] HTTP-запрос отправлен.")

    return dest_ip, port, client_sport


def capture_traffic(hostname, timeout=30, output_file=None):
    """Перехватывает HTTP-трафик для указанного хоста."""
    dest_ip = resolve_hostname(hostname)
    if not dest_ip:
        return None

    # Жестко задаем интерфейс, который мы нашли ранее (enp0s3)
    iface = 'enp0s3'

    print(f"[!] Цель {hostname}. Прослушивание интерфейса: {iface}")
    print(f"[*] Фильтр: весь TCP порт 80 (без привязки к IP)")

    print(f"[*] Начало перехвата трафика (таймаут {timeout} сек)...")
    print("[!] В это время открывайте сайт в браузере и взаимодействуйте с ним.")

    # ГЛАВНОЕ ИЗМЕНЕНИЕ: Слушаем просто порт 80.
    # Это решает проблему, когда Google отдает разные IP для скрипта и браузера.
    bpf_filter = "tcp port 80"

    packets = sniff(filter=bpf_filter, timeout=timeout, iface=iface)

    print(f"[*] Перехват завершен. Пакетов захвачено: {len(packets)}")

    if output_file and packets:
        wrpcap(output_file, packets)
        print(f"[+] Трафик сохранен в {output_file}")

    return packets


def analyze_packets(packets):
    """Анализирует пакеты, выводит первые 10, считает все."""
    if not packets:
        print("[-] Нет пакетов для анализа")
        return

    total_http_count = 0
    displayed_count = 0
    xss_found_count = 0
    max_display = 10

    for pkt in packets:
        if pkt.haslayer(Raw):
            payload = pkt['Raw'].load
            try:
                text = payload.decode('utf-8', errors='ignore')

                # Поиск XSS для статистики
                is_xss = False
                if '<script>' in text or '%3Cscript%3E' in text or 'onerror=' in text or 'javascript:' in text or 'alert(' in text:
                    xss_found_count += 1
                    is_xss = True

                # Парсинг
                headers_str = ""
                body_bytes = b""

                if b'\r\n\r\n' in payload:
                    parts = payload.split(b'\r\n\r\n', 1)
                    headers_str = parts[0].decode('utf-8', errors='ignore')
                    body_bytes = parts[1]
                else:
                    headers_str = text

                is_req = text.startswith('GET ') or text.startswith('POST ')
                is_resp = text.startswith('HTTP/')

                if is_req or is_resp:
                    total_http_count += 1

                    if displayed_count < max_display:
                        print(f"\n{'=' * 10} ПАКЕТ #{total_http_count} {'=' * 10}")

                        if is_req:
                            print("[ТИП] ЗАПРОС")
                            parts = text.split('\r\n')[0].split(' ')
                            if len(parts) >= 2:
                                print(f"Метод: {parts[0]}")
                                print(f"URL:    {parts[1]}")
                        else:
                            print("[ТИП] ОТВЕТ")
                            parts = text.split('\r\n')[0].split(' ', 2)
                            if len(parts) >= 2:
                                print(f"Статус: {parts[1]} {parts[2] if len(parts) > 2 else ''}")

                        print("--- Заголовки ---")
                        for h in headers_str.split('\r\n')[1:]:
                            if h.strip(): print(f"  {h}")

                        is_gzip = 'Content-Encoding: gzip' in headers_str
                        body_display = ""

                        if body_bytes:
                            if is_gzip:
                                try:
                                    body_display = gzip.decompress(body_bytes).decode('utf-8', errors='ignore')
                                except:
                                    body_display = "[СЖАТО GZIP: Ошибка распаковки]"
                            else:
                                body_display = body_bytes.decode('utf-8', errors='ignore')

                            print("--- Тело (фрагмент) ---")
                            print(body_display[:300] if len(body_display) > 300 else body_display)
                            if is_xss:
                                print(">>> ВНИМАНИЕ: XSS ПАЙЛОАД <<<")

                        displayed_count += 1

            except Exception:
                pass

    # Финальная статистика
    print(f"\n[+] Анализ завершен.")
    print(f"    Всего HTTP пакетов: {total_http_count}")
    print(f"    Пакетов с XSS payload: {xss_found_count}")


def analyze_saved_traffic(pcap_file):
    """Анализирует сохраненный трафик из .pcap файла."""
    print(f"[*] Загрузка трафика из файла: {pcap_file}")
    try:
        packets = rdpcap(pcap_file)
        analyze_packets(packets)
    except Exception as e:
        print(f"Ошибка чтения файла: {e}")


def main():
    parser = argparse.ArgumentParser(
        description='Анализ XSS-уязвимостей с использованием Scapy',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument('--send', metavar='URL', help='Отправить HTTP-запрос')
    parser.add_argument('--capture', metavar='HOSTNAME', help='Перехватить трафик')
    parser.add_argument('--analyze', metavar='PCAP_FILE', help='Проанализировать трафик')
    parser.add_argument('--timeout', type=int, default=30, help='Таймаут перехвата')
    parser.add_argument('--output', metavar='FILE', help='Файл для сохранения .pcap')
    parser.add_argument('--request', metavar='HTTP_REQUEST', help='Кастомный запрос')

    args = parser.parse_args()

    if not any([args.send, args.capture, args.analyze]):
        parser.print_help()
        return

    if args.send:
        hostname, path, scheme = parse_url(args.send)
        if hostname:
            send_http_request(hostname, path, args.request)

    if args.capture:
        if os.geteuid() != 0:
            print("[-] ВНИМАНИЕ: Для перехвата нужны права root (sudo).")
        packets = capture_traffic(args.capture, args.timeout, args.output)
        if packets:
            print("\n[*] Автоматический анализ перехваченного трафика...")
            analyze_packets(packets)

    if args.analyze:
        analyze_saved_traffic(args.analyze)


if __name__ == '__main__':
    main()
