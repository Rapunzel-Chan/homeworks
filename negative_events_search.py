import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import json
import os
import re
from datetime import datetime



plt.style.use('ggplot')

# --- Константы ---
WIN_AND_LOG_FILE = 'botsv1.json'
# DNS_LOG_FILE = 'dns_logs.json'
# PLOT_STYLE = 'whitegrid'
# FIGURE_SIZE = (16, 10)


# --- Функции для работы с Windows-логами ---

def load_and_normalize_win_logs(filepath: str) -> pd.DataFrame | None:
    """Загружает и нормализует логи Windows."""
    if not os.path.exists(filepath):
        print(f"ОШИБКА: Файл {filepath} не найден.")
        return None
    with open(filepath, 'r', encoding='utf-8') as f:
        raw_logs = json.load(f)

    df = pd.DataFrame([entry['result'] for entry in raw_logs if 'result' in entry])

    if df.empty:
        print("ОШИБКА: Не удалось извлечь данные из файла.")
        return None

    # --- Нормализация ---
    df['_time'] = df['_time'].str.replace(r'\s[A-Z]{3,4}$', '', regex=True)
    df['_time'] = pd.to_datetime(df['_time'], format='%Y-%m-%d %H:%M:%S.%f', errors='coerce')
    df['EventCode'] = pd.to_numeric(df['EventCode'], errors='coerce')

    # Заполняем пропуски для безопасного доступа
    df.fillna({'user': 'N/A', 'src_ip': 'N/A', 'Process_Name': 'N/A', 'host': 'N/A'}, inplace=True)

    print(f"Загружено и нормализовано {len(df)} записей из {filepath}.")
    return df


def analyze_win_security_events(df: pd.DataFrame) -> pd.DataFrame:
    """
    Проводит комплексный анализ логов безопасности, ищет различные типы подозрительных событий.
    """
    print("\n--- Комплексный анализ событий безопасности Windows ---")

    # Список системных аккаунтов, которые часто имеют привилегии по умолчанию
    system_accounts = ["NT AUTHORITY\\SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE", "ANONYMOUS LOGON"]

    # 1. Неудачные попытки входа (Event ID 4625)
    failed_logons = df[df['EventCode'] == 4625]

    # 2. Создание новых пользователей (Event ID 4720)
    user_creation = df[df['EventCode'] == 4720]

    # 3. Эскалация привилегий (Event ID 4672) для НЕ системных аккаунтов
    privilege_escalation_raw = df[df['EventCode'] == 4672]
    privilege_escalation = privilege_escalation_raw[~privilege_escalation_raw['user'].isin(system_accounts)]

    # 4. Использование явных учетных данных (Event ID 4648)
    explicit_credential_logon = df[df['EventCode'] == 4648]

    # 5. Подозрительное создание процессов (Event ID 4688), где имя процесса не указано
    process_creation = df[df['EventCode'] == 4688]
    suspicious_processes = process_creation[process_creation['Process_Name'] == 'N/A']

    # Собираем все найденные события в один DataFrame для удобства
    all_suspicious = pd.DataFrame()

    findings = {
        "Неудачные входы (ID 4625)": failed_logons,
        "Создание пользователей (ID 4720)": user_creation,
        "Эскалация привилегий (ID 4672)": privilege_escalation,
        "Использование явных учетных данных (ID 4648)": explicit_credential_logon,
        "Подозрительные процессы (ID 4688)": suspicious_processes,
    }

    for category, data in findings.items():
        if not data.empty:
            print(f"\n--- !!! {category.upper()} (найдено: {len(data)}) !!! ---")
            # Добавляем категорию в данные для будущего графика
            data['Category'] = category
            all_suspicious = pd.concat([all_suspicious, data], ignore_index=True)

            # Выбираем наиболее релевантные колонки для вывода
            cols_to_show = ['_time', 'host', 'user', 'src_ip', 'Process_Name']
            print(data[cols_to_show].sort_values('_time', ascending=False).to_string(index=False))

    if all_suspicious.empty:
        print("\nПодозрительные события не обнаружены.")

    return all_suspicious


def plot_win_stats(suspicious_df: pd.DataFrame):
    """Строит график количества подозрительных событий по их категориям."""
    if suspicious_df.empty:
        print("\nНет данных для построения графика.")
        return

    fig, ax = plt.subplots(figsize=FIGURE_SIZE)
    sns.set_style(PLOT_STYLE)

    # Считаем количество событий в каждой категории
    event_counts = suspicious_df['Category'].value_counts()

    # Строим столбчатую диаграмму
    sns.barplot(x=event_counts.values, y=event_counts.index, ax=ax, hue=event_counts.index, palette='flare',
                legend=False)

    ax.set_title('Количество подозрительных событий по категориям', fontsize=18)
    ax.set_xlabel('Количество событий', fontsize=12)
    ax.set_ylabel('Категория события', fontsize=12)

    plt.yticks(fontsize=11)
    plt.xticks(fontsize=11)
    plt.tight_layout(pad=2.0)

    plot_filename = 'plot_suspicious_events_by_category.png'
    plt.savefig(plot_filename)
    print(f"\nГрафик по категориям подозрительных событий сохранен как '{plot_filename}'")
    plt.close(fig)


# --- Функции для работы с DNS-логами ---

def load_and_normalize_dns_logs(filepath: str) -> pd.DataFrame | None:
    """Загружает и нормализует DNS-логи."""
    if not os.path.exists(filepath):
        print(f"ОШИБКА: Файл {filepath} не найден.")
        return None
    with open(filepath, 'r', encoding='utf-8') as f:
        raw_logs = json.load(f)

    df = pd.DataFrame(raw_logs)
    df['timestamp'] = pd.to_datetime(df['timestamp'])

    print(f"Загружено и нормализовано {len(df)} записей из {filepath}.")
    return df


def analyze_dns_logs(df: pd.DataFrame):
    """Анализирует DNS-логи на предмет подозрительной активности."""
    print("\n--- Анализ DNS-логов ---")

    # 1. Общая статистика по доменам
    domain_counts = df['queried_domain'].value_counts()
    print("Топ-10 самых запрашиваемых доменов:")
    print(domain_counts.head(10))

    # 2. Поиск признаков DGA (Domain Generation Algorithm)
    nxdomain_domains = df[df['response_code'] == 'NXDOMAIN']
    if not nxdomain_domains.empty:
        print(f"\n!!! ВНИМАНИЕ: Обнаружено {len(nxdomain_domains)} запросов к несуществующим доменам (NXDOMAIN) !!!")
        print("Это может быть признаком DGA. Клиенты, генерирующие такие запросы:")
        print(nxdomain_domains['client_ip'].value_counts())
    else:
        print("\nЗапросы к несуществующим доменам (NXDOMAIN) не обнаружены.")

    # 3. Поиск "маячения" (beaconing)
    domain_total_counts = df['queried_domain'].value_counts()
    rare_domains = domain_total_counts[domain_total_counts < 5].index
    beacon_candidates = df[df['queried_domain'].isin(rare_domains)]

    if not beacon_candidates.empty:
        print("\n--- Анализ на 'маячение' (beaconing) ---")
        beacon_stats = beacon_candidates.groupby(['client_ip', 'queried_domain']).size().reset_index(name='count')
        potential_beacons = beacon_stats[beacon_stats['count'] > 1].sort_values(by='count', ascending=False)
        if not potential_beacons.empty:
            print("\n!!! ВНИМАНИЕ: Обнаружены потенциальные 'маячки' !!!")
            print(potential_beacons)
        else:
            print("Потенциальные 'маячки' не обнаружены.")
    else:
        print("\nРедкие домены для анализа на 'маячение' не найдены.")

    return domain_counts.head(10), nxdomain_domains


# ИСПРАВЛЕНИЕ: Удалена вторая (старая) версия функции plot_dns_stats.
# Оставлена только эта, исправленная версия.

def plot_dns_stats(top_domains: pd.Series, nxdomain_domains: pd.DataFrame):
    """Строит графики для анализа DNS-логов."""
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=FIGURE_SIZE)
    sns.set_style(PLOT_STYLE)

    # График 1: Топ доменов
    if not top_domains.empty:
        sns.barplot(x=top_domains.values, y=top_domains.index, ax=ax1, hue=top_domains.index, palette='Blues_r', legend=False)
        ax1.set_title('Топ-10 запрашиваемых доменов')
        ax1.set_xlabel('Количество запросов')
    else:
        ax1.text(0.5, 0.5, 'Данные о запросах отсутствуют', ha='center', va='center', fontsize=12)
        ax1.set_title('Топ-10 запрашиваемых доменов')

    # График 2: NXDOMAIN запросы по IP
    if not nxdomain_domains.empty:
        nxdomain_by_ip = nxdomain_domains['client_ip'].value_counts()
        sns.barplot(x=nxdomain_by_ip.values, y=nxdomain_by_ip.index, ax=ax2, hue=nxdomain_by_ip.index, palette='Purples_r', legend=False)
        ax2.set_title('NXDOMAIN запросы по IP-адресам')
        ax2.set_xlabel('Количество запросов')
    else:
        ax2.text(0.5, 0.5, 'NXDOMAIN запросы отсутствуют', ha='center', va='center', fontsize=12)
        ax2.set_title('NXDOMAIN запросы по IP-адресам')

    plt.tight_layout()
    plt.savefig('plot_dns_analysis.png')
    print("\nГрафик по DNS-логам сохранен как 'plot_dns_analysis.png'")
    plt.close(fig)


# --- Главная функция ---

def main():
    """Оркестрирует весь процесс анализа."""
    # --- Часть 1: Анализ Windows Event Logs ---
    win_df = load_and_normalize_win_logs(WIN_LOG_FILE)
    if win_df is not None:
        # 1. Проводим комплексный анализ и собираем все подозрительные события
        suspicious_df = analyze_win_security_events(win_df)

        # 2. Строим график на основе найденных данных
        plot_win_stats(suspicious_df)

        print("\n--- ИТОГ ---")
        print("События, не помеченные как подозрительные (например, успешные входы),")
        print("могут быть нормальной активностью. Однако отмеченные выше события")
        print("являются высокоприоритетными индикаторами, требующими внимания.")

    # --- Часть 2: Анализ DNS-логов ---
    dns_df = load_and_normalize_dns_logs(DNS_LOG_FILE)
    if dns_df is not None:
        top_domains, nxdomains = analyze_dns_logs(dns_df)
        plot_dns_stats(top_domains, nxdomains)


if __name__ == "__main__":
    main()