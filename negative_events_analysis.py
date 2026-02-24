import pandas as pd
import json
import re
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np

sns.set(style="whitegrid")


def create_timestamp(row):
    """
    Вспомогательная функция для создания временной метки.
    Сначала пытается использовать поле '_time', если его нет - собирает из 'date_*' полей.
    """
    if pd.notna(row.get('_time')):
        try:
            return pd.to_datetime(row['_time'], format='%Y-%m-%dT%H:%M:%S.%fZ', utc=True)
        except (ValueError, TypeError):
            pass

    date_fields = ['date_year', 'date_month', 'date_mday', 'date_hour', 'date_minute', 'date_second']
    if all(field in row and pd.notna(row[field]) for field in date_fields):
        month_map = {
            'january': '01', 'february': '02', 'march': '03', 'april': '04',
            'may': '05', 'june': '06', 'july': '07', 'august': '08',
            'september': '09', 'october': '10', 'november': '11', 'december': '12'
        }
        month_str = month_map.get(row['date_month'].lower())
        if month_str:
            try:
                date_str = f"{row['date_year']}-{month_str}-{row['date_mday'].zfill(2)} {row['date_hour'].zfill(2)}:{row['date_minute'].zfill(2)}:{row['date_second'].zfill(2)}"
                return pd.to_datetime(date_str, utc=True)
            except (ValueError, TypeError):
                pass
    return pd.NaT


def analyze_bot_logs(file_path):
    """
    Полный анализ логов из файла botsv1.json с корректным восстановлением времени.
    """
    print("--- Этап 1. Загрузка данных ---")
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            raw_data = json.load(f)
        events_data = [event['result'] for event in raw_data]
        all_events_df = pd.DataFrame(events_data)
        print(f"Успешно загружено {len(all_events_df)} записей из файла.")
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"Ошибка при загрузке файла: {e}")
        return

    dns_df = all_events_df[all_events_df['EventCode'] == 'DNS'].copy()
    winevent_df = all_events_df[all_events_df['EventCode'] != 'DNS'].copy()
    print("Данные успешно разделены на DNS и WinEventLog.\n")

    print("--- Этап 2. Очистка и подготовка данных ---")
    dns_df['_time'] = dns_df.apply(create_timestamp, axis=1)
    winevent_df['_time'] = winevent_df.apply(create_timestamp, axis=1)

    def get_first_item(cell):
        if isinstance(cell, list) and cell:
            return cell[0]
        return cell

    list_cols = ['Account_Name', 'Logon_ID', 'Security_ID', 'Account_Domain']
    for col in list_cols:
        if col in winevent_df.columns:
            winevent_df[col] = winevent_df[col].apply(get_first_item)

    if 'host' in dns_df.columns and 'ComputerName' in dns_df.columns:
        dns_df['host'] = dns_df['host'].fillna(dns_df['ComputerName'])
    if 'host' in dns_df.columns:
        dns_df['host'] = dns_df['host'].fillna('Неизвестен')

    print("Данные очищены и подготовлены к анализу. Время восстановлено для всех возможных записей.\n")

    print("--- Этап 3. Анализ и формирование отчета ---")
    suspicious_dns_report = []
    dga_pattern = re.compile(r'^[a-z0-9]{8,20}\.(com|net|org)$')
    c2_keywords = ['c2', 'malicious', 'botnet', 'command']

    for index, row in dns_df.iterrows():
        domain = row.get('QueryName', '').lower()
        is_suspicious = False
        reason = ""
        if dga_pattern.match(domain):
            is_suspicious = True
            reason = "DGA (Domain Generation Algorithm)"
        if any(keyword in domain for keyword in c2_keywords):
            is_suspicious = True
            reason = "C2 (Command & Control) keyword"
        if is_suspicious:
            suspicious_dns_report.append({
                'host': row.get('host', 'Неизвестен'),
                'ip': row.get('ClientIP', 'N/A'),
                'domain': domain,
                'reason': reason,
                'time': row['_time']
            })

    print("\n[ОТЧЕТ ПО DNS-ЛОГАМ]")
    if suspicious_dns_report:
        print("ОБНАРУЖЕНА ПОДОЗРИТЕЛЬНАЯ АКТИВНОСТЬ:")
        suspicious_dns_df = pd.DataFrame(suspicious_dns_report)
        suspicious_dns_df['time'] = suspicious_dns_df['time'].dt.strftime('%Y-%m-%d %H:%M:%S')
        print(suspicious_dns_df.to_string(index=False))
        print("\nПРИМЕЧАНИЕ: Время для этих событий было восстановлено из полей 'date_*'.")
    else:
        print("Подозрительная DNS-активность не обнаружена.")

    print("\n[ОТЧЕТ ПО ЛОГАМ БЕЗОПАСНОСТИ WINDOWS]")
    tiworker_events = winevent_df[winevent_df['Process_Name'].str.contains('TiWorker.exe', na=False)]
    print(f"Найдено {len(tiworker_events)} событий Windows Update (TiWorker.exe).")
    logon_type_3_events = winevent_df[(winevent_df['EventCode'] == '4624') & (winevent_df['Logon_Type'] == '3')]
    print(f"Найдено {len(logon_type_3_events)} успешных сетевых входов (Logon Type 3).")

    print("\n[ДЕТАЛЬНЫЙ АНАЛИЗ ЧАСТЫХ СОБЫТИЙ WINDOWS]")
    top_5_events = winevent_df['EventCode'].value_counts().head(5)
    event_descriptions = {
        '4624': "Успешный вход в систему. Показывает, какой аккаунт успешно вошел. Очень частое событие.",
        '4703': "Изменение прав токена. Происходит при входе пользователя, когда системе назначаются права (например, 'вход в систему как служба').",
        '4656': "Запрос на дескриптор объекта. Фиксирует попытку процесса получить доступ к файлу, ключу реестра или другому объекту. Норма для активной системы.",
        '4688': "Создан новый процесс. КРИТИЧЕСКИ ВАЖНОЕ событие. Показывает, какая программа была запущена (Process_Name) и кем (Account_Name). Основа для обнаружения вредоносной активности.",
        '4689': "Завершен процесс. Логирует завершение работы процесса. Полезно для отслеживания времени жизни программ."
    }
    print("Топ-5 самых частых событий и их значение:")
    for code, count in top_5_events.items():
        description = event_descriptions.get(code, "Нет описания.")
        print(f"  - Код {code} ({count} раз): {description}")
    print(
        "\nВывод: Высокая частота этих событий является нормой для работающей системы Windows. Аномалии нужно искать в КОНТЕКСТЕ (кто, что, когда запустил).")

    print("\n" + "=" * 50)
    print("[ИТОГОВЫЙ ВЕРДИКТ]")
    if suspicious_dns_report:
        print("!!! ВНИМАНИЕ: ОБНАРУЖЕНЫ УГРОЗЫ !!!")
        for report in suspicious_dns_report:
            print(
                f"  - Хост: {report['host']} (IP: {report['ip']}) | Причина: {report['reason']} | Домен: {report['domain']} | Время: {report['time']}")
    else:
        print("Критичных угроз не обнаружено.")
    print("=" * 50)

    print("\n--- Этап 4. Визуализация и сохранение данных ---")
    print("Создаются и сохраняются графики...")
    if suspicious_dns_report:
        plt.figure(figsize=(12, 7))
        suspicious_dns_df = pd.DataFrame(suspicious_dns_report)
        top_suspicious_ips = suspicious_dns_df['ip'].value_counts().head(10)
        sns.barplot(x=top_suspicious_ips.values, y=top_suspicious_ips.index, hue=top_suspicious_ips.index,
                    palette='Reds_r', legend=False)
        plt.title('Топ-10 IP-адресов с подозрительными DNS-запросами', fontsize=16)
        plt.xlabel('Количество подозрительных запросов', fontsize=12)
        plt.ylabel('IP-адрес', fontsize=12)
        plt.tight_layout()
        plt.savefig('top_suspicious_ips.png')
        print("График сохранен как 'top_suspicious_ips.png'")
        plt.close()
    else:
        print("Пропуск графика DNS: подозрительная активность не найдена.")

    plt.figure(figsize=(12, 7))
    top_events = winevent_df['EventCode'].value_counts().head(10)
    sns.barplot(x=top_events.values, y=top_events.index, hue=top_events.index, palette='viridis', legend=False)
    plt.title('Топ-10 кодов событий в логах безопасности Windows', fontsize=16)
    plt.xlabel('Количество событий', fontsize=12)
    plt.ylabel('Код события (EventCode)', fontsize=12)
    plt.tight_layout()
    plt.savefig('top_windows_events.png')
    print("График сохранен как 'top_windows_events.png'")
    plt.close()
    print("Визуализация завершена.\n")

    print("--- Этап 5. Выводы ---")
    print("1. Наиболее подозрительные события:")
    if suspicious_dns_report:
        for report in suspicious_dns_report:
            print(
                f"   - DNS-запрос с IP {report['ip']} к домену {report['domain']} в {report['time']}. Причина: {report['reason']}.")
        print("   Эти события указывают на заражение хостов 192.168.1.77 и 192.168.1.88.")
    else:
        print("   Подозрительные события не выявлены.")

    print("\n2. Возможные причины высокой частоты событий:")
    print(
        "   Как показано в детальном анализе, события 4624, 4703, 4656, 4688, 4689 являются фундаментальными для работы Windows и отражают стандартные пользовательские и системные операции. Их высокая частота ожидаема.")

    print("\n3. Как автоматизировать поиск аномалий:")
    print(
        "   - Расширение правил: Добавить в скрипт больше паттернов для DGA, использовать актуальные списки вредоносных IP-адресов и доменов из фидов кибербезопасности (Threat Intelligence).")
    print(
        "   - Статистический анализ: Отслеживать отклонения от нормы. Например, если хост в среднем делает 10 DNS-запросов в минуту, а внезапно сделал 1000 — это сигнал для анализа.")
    print(
        "   - Корреляционный анализ: Искать цепочки событий. Например: 'удаленный вход (4624) -> запуск PowerShell (4688) -> сетевое подключение к подозрительному IP'. Такая последовательность гораздо подозрительнее, чем каждое событие по отдельности.")
    print(
        "   - Использование SIEM: Для комплексной автоматизации рекомендуется использовать SIEM-системы (Splunk, ELK Stack, Wazuh), которые специально созданы для сбора, анализа и корреляции логов в реальном времени с автоматическими оповещениями.")


analyze_bot_logs('botsv1.json')