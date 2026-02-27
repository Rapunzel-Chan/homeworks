import pyshark
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from datetime import datetime
import os
import asyncio
import threading
from dotenv import load_dotenv

load_dotenv()

# --- КОНФИГУРАЦИЯ ---
PCAP_FILE = os.getenv('PCAP_FILE_PATH')
OUTPUT_DIR = 'analysis_results'

# Создаем папку для результатов
os.makedirs(OUTPUT_DIR, exist_ok=True)

print(f"[1] Загрузка данных из файла: {PCAP_FILE}")

# --- ИСПРАВЛЕНИЕ: создаем event loop принудительно ---
try:
    loop = asyncio.get_running_loop()
except RuntimeError:
    # Нет запущенного цикла - создаем новый
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)


# --- ФУНКЦИЯ АНАЛИЗА ---
def analyze():
    """Синхронная функция для анализа"""
    dns_requests = []
    connections = []
    packet_count = 0

    # Убеждаемся, что event loop существует
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        asyncio.set_event_loop(asyncio.new_event_loop())

    # Загружаем дамп
    cap = pyshark.FileCapture(PCAP_FILE, keep_packets=False)

    print("[2] Извлечение DNS-запросов и IP-соединений...")

    # Обычный цикл for
    for packet in cap:
        packet_count += 1
        try:
            # --- Извлечение DNS-запросов ---
            if hasattr(packet, 'dns') and hasattr(packet.dns, 'qry_name'):
                # Проверяем, что это запрос (не ответ)
                if hasattr(packet.dns, 'flags_response') and int(packet.dns.flags_response) == 0:
                    dns_requests.append({
                        'time': packet.sniff_time,
                        'domain': packet.dns.qry_name.lower(),
                        'src_ip': packet.ip.src if hasattr(packet, 'ip') else 'N/A',
                        'dst_ip': packet.ip.dst if hasattr(packet, 'ip') else 'N/A',
                        'query_type': packet.dns.qry_type if hasattr(packet.dns, 'qry_type') else 'N/A'
                    })

            # --- Извлечение информации о соединениях ---
            if hasattr(packet, 'ip'):
                protocol = 'Other'
                src_port = None
                dst_port = None

                if hasattr(packet, 'tcp'):
                    protocol = 'TCP'
                    src_port = packet.tcp.srcport
                    dst_port = packet.tcp.dstport
                elif hasattr(packet, 'udp'):
                    protocol = 'UDP'
                    src_port = packet.udp.srcport
                    dst_port = packet.udp.dstport

                if src_port and dst_port:
                    connections.append({
                        'time': packet.sniff_time,
                        'src_ip': packet.ip.src,
                        'dst_ip': packet.ip.dst,
                        'protocol': protocol,
                        'src_port': src_port,
                        'dst_port': dst_port,
                        'length': int(packet.length) if hasattr(packet, 'length') else 0
                    })

        except AttributeError:
            continue
        except Exception as e:
            print(f"Ошибка при обработке пакета {packet_count}: {e}")

    cap.close()
    print(f"Обработано пакетов: {packet_count}")
    print(f"Найдено DNS-запросов: {len(dns_requests)}")
    print(f"Найдено соединений (TCP/UDP): {len(connections)}")

    return dns_requests, connections, packet_count


# --- ЗАПУСК АНАЛИЗА ---
dns_requests, connections, packet_count = analyze()

# --- ДАЛЬШЕ КАК БЫЛО ---
print("[3] Анализ данных и создание визуализаций...")

# Создаем DataFrame'ы
df_dns = pd.DataFrame(dns_requests)
df_connections = pd.DataFrame(connections)

# Сохраняем в CSV
if not df_dns.empty:
    dns_csv_path = os.path.join(OUTPUT_DIR, 'dns_requests.csv')
    df_dns.to_csv(dns_csv_path, index=False)
    print(f"DNS-запросы сохранены в {dns_csv_path}")

if not df_connections.empty:
    conn_csv_path = os.path.join(OUTPUT_DIR, 'connections.csv')
    df_connections.to_csv(conn_csv_path, index=False)
    print(f"Соединения сохранены в {conn_csv_path}")

# --- ВИЗУАЛИЗАЦИЯ 1: DNS по времени ---
if not df_dns.empty:
    df_dns['time'] = pd.to_datetime(df_dns['time'])
    df_dns['minute'] = df_dns['time'].dt.floor('1min')
    dns_by_time = df_dns.groupby('minute').size()

    plt.figure(figsize=(12, 5))
    dns_by_time.plot(kind='line', marker='.', color='blue')
    plt.title('Активность DNS-запросов во времени')
    plt.xlabel('Время')
    plt.ylabel('Количество запросов')
    plt.grid(True, linestyle='--', alpha=0.7)
    plt.tight_layout()
    dns_time_plot_path = os.path.join(OUTPUT_DIR, 'dns_timeline.png')
    plt.savefig(dns_time_plot_path, dpi=150)
    plt.show()
    print(f"График DNS-запросов сохранён: {dns_time_plot_path}")

    # Топ-10 доменов
    top_domains = df_dns['domain'].value_counts().head(10)
    print("\nТоп-10 самых частых DNS-запросов:")
    print(top_domains.to_string())

    plt.figure(figsize=(10, 6))
    sns.barplot(x=top_domains.values, y=top_domains.index, palette='viridis')
    plt.title('Топ-10 самых запрашиваемых доменов')
    plt.xlabel('Количество запросов')
    plt.tight_layout()
    top_domains_plot_path = os.path.join(OUTPUT_DIR, 'top_domains.png')
    plt.savefig(top_domains_plot_path, dpi=150)
    plt.show()

# --- ВИЗУАЛИЗАЦИЯ 2: Топ IP-адресов ---
if not df_connections.empty:
    top_src_ips = df_connections['src_ip'].value_counts().head(10)
    print("\nТоп-10 самых активных источников (IP):")
    print(top_src_ips.to_string())

    plt.figure(figsize=(10, 6))
    sns.barplot(x=top_src_ips.values, y=top_src_ips.index, hue=top_src_ips.index, palette='rocket', legend=False)
    plt.title('Топ-10 самых активных IP-адресов (источники)')
    plt.xlabel('Количество пакетов')
    plt.tight_layout()
    top_ips_plot_path = os.path.join(OUTPUT_DIR, 'top_talkers.png')
    plt.savefig(top_ips_plot_path, dpi=150)
    plt.show()

# --- СОХРАНЕНИЕ ОТЧЕТА ---
report_lines = []
report_lines.append("==========================================")
report_lines.append("ОТЧЁТ О ФОРЕНЗИКЕ СЕТЕВОГО ДАМПА")
report_lines.append(f"Дата анализа: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
report_lines.append(f"Исследуемый файл: {PCAP_FILE}")
report_lines.append("==========================================")
report_lines.append("\n--- НАЙДЕННЫЕ АРТЕФАКТЫ ---")
report_lines.append(f"Всего обработано пакетов: {packet_count}")
report_lines.append(f"Всего DNS-запросов: {len(dns_requests)}")
report_lines.append(f"Всего TCP/UDP соединений: {len(connections)}")

report_lines.append("\n--- ПОДОЗРИТЕЛЬНЫЕ АКТИВНОСТИ ---")
if not df_dns.empty and len(df_dns) > 0:
    most_freq_domain = df_dns['domain'].value_counts().idxmax() if len(df_dns) > 0 else "N/A"
    freq_count = df_dns['domain'].value_counts().max() if len(df_dns) > 0 else 0
    report_lines.append(f"- Самая частая DNS-активность: домен '{most_freq_domain}' встретился {freq_count} раз.")

if not df_connections.empty:
    suspicious_ports = df_connections[df_connections['dst_port'].astype(int) > 30000]
    if not suspicious_ports.empty:
        report_lines.append(f"- Обнаружены соединения на нестандартные высокие порты (>30000).")

    external_conns = df_connections[~df_connections['dst_ip'].str.startswith(('192.168.', '10.', '127.0.0.'))]
    if not external_conns.empty:
        report_lines.append(
            f"- Зафиксированы соединения с внешними ресурсами. Количество уникальных внешних IP: {external_conns['dst_ip'].nunique()}")

report_lines.append("\n--- ПРЕДВАРИТЕЛЬНЫЙ ВЫВОД ---")
if len(dns_requests) > 100:
    report_lines.append("Обнаружена высокая DNS-активность. Рекомендуется углублённый анализ.")
else:
    report_lines.append("Явных признаков компрометации не обнаружено.")

report_lines.append("\n--- РЕКОМЕНДАЦИИ ---")
report_lines.append("1. Проверить IP-адреса и домены из отчёта в VirusTotal.")
report_lines.append("2. Проанализировать временные ряды на предмет строгой периодичности.")
report_lines.append("3. При возможности, изучить содержимое подозрительных соединений.")

report_path = os.path.join(OUTPUT_DIR, 'forensic_report.txt')
with open(report_path, 'w', encoding='utf-8') as f:
    f.write('\n'.join(report_lines))

print(f"\n[4] Анализ завершен! Отчет сохранен: {report_path}")
print(f"Все результаты в папке: {OUTPUT_DIR}")
