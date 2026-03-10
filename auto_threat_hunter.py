import os
import json
import requests
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from datetime import datetime
from collections import Counter
from dotenv import load_dotenv

load_dotenv()
VT_API_KEY = os.getenv("API_KEY_VT")


class ThreatHunter:
    def __init__(self):
        self.threats = []
        self.report_dir = "threat_report"
        self.cvss_data = []
        os.makedirs(self.report_dir, exist_ok=True)

    def check_virustotal(self, file_hash="44d88612fea8a8f36de82e1278abb02f"):
        """Проверка файла через VirusTotal - каждый детект как отдельная угроза"""
        print("[1/5] Проверка VirusTotal...")

        if not VT_API_KEY:
            print("  ❌ Нет API ключа VirusTotal")
            return []

        url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        headers = {"x-apikey": VT_API_KEY}

        try:
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                data = response.json()
                attributes = data["data"]["attributes"]
                stats = attributes["last_analysis_stats"]
                results = attributes.get("last_analysis_results", {})

                threats = []

                # 1. Общая статистика как одна угроза
                threats.append({
                    "source": "VirusTotal",
                    "type": "file_scan_summary",
                    "indicator": file_hash,
                    "file_name": attributes.get('meaningful_name', 'unknown'),
                    "severity": "HIGH" if stats['malicious'] > 5 else "MEDIUM",
                    "total_malicious": stats['malicious'],
                    "total_suspicious": stats['suspicious'],
                    "total_detects": stats['malicious'] + stats['suspicious']
                })

                # 2. Каждый антивирусный детект как отдельная угроза
                malicious_count = 0
                for vendor, result in results.items():
                    if result.get('category') in ['malicious', 'suspicious']:
                        threat = {
                            "source": "VirusTotal",
                            "type": "antivirus_detection",
                            "vendor": vendor,
                            "indicator": f"{vendor}: {result.get('result', 'unknown')}",
                            "file_hash": file_hash,
                            "file_name": attributes.get('meaningful_name', 'unknown'),
                            "category": result.get('category'),
                            "result": result.get('result'),
                            "severity": "HIGH" if result.get('category') == 'malicious' else "MEDIUM",
                            "timestamp": datetime.now().isoformat()
                        }
                        threats.append(threat)
                        malicious_count += 1

                print(
                    f"  ✅ VirusTotal: {stats['malicious']} вредоносных, {stats['suspicious']} подозрительных детектов")
                print(f"     Преобразовано в {len(threats)} угроз ({malicious_count} отдельных детектов)")
                return threats
            else:
                print(f"  ❌ Ошибка VirusTotal API: {response.status_code}")
                return []

        except Exception as e:
            print(f"  ❌ Ошибка VirusTotal: {e}")
            return []

    def analyze_dns_logs(self, filepath):
        """Анализ DNS-логов на подозрительную активность"""
        print(f"[2/5] Анализ DNS-логов из {filepath}...")

        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                dns_logs = json.load(f)

            df = pd.DataFrame(dns_logs)

            suspicious_domains = []
            for _, row in df.iterrows():
                domain = row.get('queried_domain', '')

                # Признаки подозрительности:
                if (row.get('response_code') == 'NXDOMAIN' or
                        'evil' in domain.lower() or
                        'c2.' in domain.lower() or
                        len(domain) > 30):
                    suspicious_domains.append({
                        "source": "DNS Logs",
                        "type": "suspicious_domain",
                        "indicator": domain,
                        "client_ip": row.get('client_ip'),
                        "response_code": row.get('response_code'),
                        "timestamp": row.get('timestamp'),
                        "severity": "HIGH" if 'c2.' in domain.lower() else "MEDIUM"
                    })

            print(f"  ✅ Найдено подозрительных доменов: {len(suspicious_domains)}")
            return suspicious_domains

        except Exception as e:
            print(f"  ❌ Ошибка анализа DNS: {e}")
            return []

    def analyze_suricata_events(self, filepath):
        """Анализ событий Suricata на критические атаки"""
        print(f"[3/5] Анализ Suricata событий из {filepath}...")

        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                data = json.load(f)

            events = data.get('events', [])
            df = pd.DataFrame(events)

            # Классифицируем события по типу
            threat_signatures = {
                'MALWARE-CNC': 'command_and_control',
                'EXPLOIT': 'exploit_attempt',
                'INDICATOR-COMPROMISE': 'compromise_indicator',
                'NETBIOS': 'network_scan'
            }

            threats = []
            for _, row in df.iterrows():
                sig = row.get('signature', '')
                for keyword, threat_type in threat_signatures.items():
                    if keyword in sig:
                        threats.append({
                            "source": "Suricata IDS",
                            "type": threat_type,
                            "indicator": sig,
                            "timestamp": row.get('timestamp'),
                            "severity": "HIGH" if 'MALWARE' in keyword else "MEDIUM"
                        })
                        break

            print(f"  ✅ Найдено событий безопасности: {len(threats)}")
            return threats

        except Exception as e:
            print(f"  ❌ Ошибка анализа Suricata: {e}")
            return []

    def analyze_windows_events(self, filepath):
        """Анализ Windows Event Logs на подозрительные события"""
        print(f"[4/5] Анализ Windows событий из {filepath}...")

        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                data = json.load(f)

            windows_threats = []

            # Подозрительные Event IDs
            suspicious_events = {
                '4624': 'Successful Logon',
                '4625': 'Failed Logon',
                '4688': 'Process Creation',
                '4689': 'Process Exit',
                '4703': 'Token Right Adjusted',
                '4656': 'Object Access'
            }

            for item in data:
                result = item.get('result', {})
                event_code = result.get('EventCode')

                if str(event_code) in suspicious_events:
                    threat = {
                        "source": "Windows Events",
                        "type": "windows_security",
                        "indicator": f"Event {event_code}: {suspicious_events[str(event_code)]}",
                        "host": result.get('ComputerName', 'unknown'),
                        "user": result.get('Account_Name', 'unknown'),
                        "timestamp": f"{result.get('date_year')}-{result.get('date_month')}-{result.get('date_mday')}",
                        "severity": "MEDIUM"
                    }

                    if event_code in ['4625', '4688']:
                        threat['severity'] = "HIGH"

                    windows_threats.append(threat)

            print(f"  ✅ Найдено Windows событий: {len(windows_threats)}")
            return windows_threats

        except Exception as e:
            print(f"  ❌ Ошибка анализа Windows событий: {e}")
            return []

    def check_vulners_vulnerabilities(self, software_list=None):
        """Поиск уязвимостей через Vulners API с CVSS фильтрацией"""
        print(f"[5/5] Поиск уязвимостей в Vulners...")

        vulners_api_key = os.getenv("API_KEY_VULNERS")

        if not vulners_api_key:
            print("  ⚠️ Vulners API ключ не обнаружен. Используется симуляция поиска уязвимостей.")
            return self._simulate_vulners_data()

        try:
            import vulners
            vulners_api = vulners.VulnersApi(api_key=vulners_api_key)

            if software_list is None:
                software_list = [
                    "openssl", "apache", "nginx",
                    "windows", "linux", "chrome"
                ]

            all_vulnerabilities = []
            cvss_scores = []

            for software in software_list:
                print(f"    Проверка {software}...")

                results = vulners_api.search.search_bulletins(
                    software,
                    limit=10,
                    fields=["id", "title", "description", "cvss", "published", "type"]
                )

                for item in results:
                    cvss = item.get('cvss', {}).get('score', 0)
                    if cvss >= 7.0:
                        vuln = {
                            "source": "Vulners API",
                            "type": "vulnerability",
                            "indicator": item.get('id', 'Unknown'),
                            "software": software,
                            "cvss_score": cvss,
                            "title": item.get('title', '')[:100],
                            "published": item.get('published', ''),
                            "severity": "HIGH" if cvss >= 9.0 else "MEDIUM",
                            "description": item.get('description', '')[:200]
                        }
                        all_vulnerabilities.append(vuln)
                        cvss_scores.append(cvss)

            if all_vulnerabilities:
                self.cvss_data = cvss_scores

            print(f"  ✅ Найдено критических уязвимостей: {len(all_vulnerabilities)}")
            return all_vulnerabilities

        except Exception as e:
            print(f"  ❌ Ошибка Vulners API: {e}")
            print(f"  ⚠️ Используется симуляция данных...")
            return self._simulate_vulners_data()

    def _simulate_vulners_data(self):
        """Симуляция данных Vulners при отсутствии API ключа или ошибке"""
        print("    🔄 Симуляция поиска уязвимостей (демо-режим)")

        simulated_vulns = [
            {
                "source": "Vulners API (симуляция)",
                "type": "vulnerability",
                "indicator": "CVE-2024-12345",
                "software": "openssl",
                "cvss_score": 9.8,
                "title": "OpenSSL Remote Code Execution Vulnerability",
                "published": "2024-01-15",
                "severity": "HIGH",
                "description": "Critical vulnerability in OpenSSL allowing remote code execution"
            },
            {
                "source": "Vulners API (симуляция)",
                "type": "vulnerability",
                "indicator": "CVE-2024-67890",
                "software": "apache",
                "cvss_score": 8.5,
                "title": "Apache HTTP Server Path Traversal",
                "published": "2024-02-20",
                "severity": "HIGH",
                "description": "Path traversal vulnerability in Apache HTTP Server"
            },
            {
                "source": "Vulners API (симуляция)",
                "type": "vulnerability",
                "indicator": "CVE-2024-54321",
                "software": "windows",
                "cvss_score": 7.8,
                "title": "Windows Kernel Privilege Escalation",
                "published": "2024-03-10",
                "severity": "MEDIUM",
                "description": "Local privilege escalation in Windows kernel"
            }
        ]

        print(f"    ✅ Симулировано уязвимостей: {len(simulated_vulns)}")
        self.cvss_data = [v['cvss_score'] for v in simulated_vulns]
        return simulated_vulns

    def send_telegram_alert(self, threat):
        """Отправка уведомления в Telegram о критической угрозе"""
        telegram_token = os.getenv("TELEGRAM_BOT_TOKEN")
        chat_id = os.getenv("TELEGRAM_CHAT_ID")

        if not telegram_token or not chat_id:
            print("  📱 Telegram токен не обнаружен. Имитация отправки уведомления:")
            self._simulate_telegram_notification(threat)
            return
        try:

            message = self._format_telegram_message(threat)

            url = f"https://api.telegram.org/bot{telegram_token}/sendMessage"
            payload = {
                "chat_id": chat_id,
                "text": message,
                "parse_mode": "HTML",
                "disable_web_page_preview": True
            }

            response = requests.post(url, json=payload, timeout=10)

            if response.status_code == 200:
                print(f"  ✅ Уведомление в Telegram отправлено")
            else:
                print(f"  ⚠️ Ошибка отправки в Telegram (код {response.status_code})")
                self._simulate_telegram_notification(threat)

        except Exception as e:
            print(f"  ⚠️ Ошибка отправки в Telegram: {e}")
            self._simulate_telegram_notification(threat)

    def _format_telegram_message(self, threat):
        """Форматирует сообщение для Telegram с HTML разметкой"""
        message = f"<b>🚨 КРИТИЧЕСКАЯ УГРОЗА ОБНАРУЖЕНА!</b>\n\n"
        message += f"<b>📋 Тип угрозы:</b> {threat['type']}\n"
        message += f"<b>🔍 Индикатор:</b> <code>{threat['indicator']}</code>\n"

        if 'cvss_score' in threat:
            if threat['cvss_score'] >= 9.0:
                score_emoji = "🔴 КРИТИЧЕСКАЯ"
            elif threat['cvss_score'] >= 7.0:
                score_emoji = "🟠 ВЫСОКАЯ"
            else:
                score_emoji = "🟡 СРЕДНЯЯ"
            message += f"<b>📊 CVSS:</b> {threat['cvss_score']} ({score_emoji})\n"

        if 'client_ip' in threat:
            message += f"<b>🌐 IP-адрес:</b> <code>{threat['client_ip']}</code>\n"
        if 'software' in threat:
            message += f"<b>💻 Программное обеспечение:</b> {threat['software']}\n"
        if 'source' in threat:
            message += f"<b>📁 Источник:</b> {threat['source']}\n"
        if 'description' in threat:
            desc = threat['description'][:200] + "..." if len(threat['description']) > 200 else threat['description']
            message += f"<b>📝 Описание:</b> {desc}\n"

        message += f"\n⏱ <i>{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</i>"
        return message

    def _simulate_telegram_notification(self, threat):
        """Имитация отправки уведомления в Telegram"""
        print("    📱 [ИМИТАЦИЯ] Уведомление Telegram:")
        print(f"    ┌─{'─' * 60}─┐")
        print(f"    │ 🚨 КРИТИЧЕСКАЯ УГРОЗА!                           │")
        print(f"    ├─{'─' * 60}─┤")
        print(f"    │ 📋 Тип: {threat['type'][:45]:<45}│")
        print(f"    │ 🔍 Индикатор: {str(threat['indicator'])[:45]:<45}│")
        if 'cvss_score' in threat:
            print(f"    │ 📊 CVSS: {threat['cvss_score']} ({self._get_cvss_level(threat['cvss_score']):<20}) │")
        if 'client_ip' in threat:
            print(f"    │ 🌐 IP: {threat['client_ip']:<49}│")
        if 'software' in threat:
            print(f"    │ 💻 ПО: {threat['software'][:45]:<45}│")
        if 'source' in threat:
            print(f"    │ 📁 Источник: {threat['source'][:42]:<42}│")
        print(f"    └─{'─' * 60}─┘")

    def _get_cvss_level(self, score):
        """Возвращает уровень критичности по CVSS"""
        if score >= 9.0:
            return "КРИТИЧЕСКАЯ"
        elif score >= 7.0:
            return "ВЫСОКАЯ"
        else:
            return "СРЕДНЯЯ"

    def respond_to_threats(self, all_threats):
        """Имитация реагирования на угрозы"""
        print("\n" + "=" * 60)
        print("🚨 РЕАГИРОВАНИЕ НА УГРОЗЫ")
        print("=" * 60)

        if not all_threats:
            print("  ✅ Угроз не обнаружено")
            return

        # Группируем угрозы
        high_threats = [t for t in all_threats if t.get('severity') == 'HIGH']
        medium_threats = [t for t in all_threats if t.get('severity') == 'MEDIUM']

        # Группируем по источникам
        vt_threats = [t for t in all_threats if t['source'] == 'VirusTotal']
        vt_malicious = len(
            [t for t in vt_threats if t.get('type') == 'antivirus_detection' and t.get('category') == 'malicious'])
        vt_suspicious = len(
            [t for t in vt_threats if t.get('type') == 'antivirus_detection' and t.get('category') == 'suspicious'])

        print(f"\n  ⚠️  Найдено угроз: {len(all_threats)}")
        print(f"     🔴 Критических: {len(high_threats)}")
        print(f"     🟡 Средних: {len(medium_threats)}")

        # Детальная статистика VirusTotal
        if vt_threats:
            print(f"\n  🦠 VirusTotal детекты:")
            print(f"     🔴 Вредоносных: {vt_malicious}")
            print(f"     🟡 Подозрительных: {vt_suspicious}")
            print(f"     📊 Всего детектов: {len(vt_threats)}")

        vt_detections = [t for t in vt_threats if
                         t.get('type') == 'antivirus_detection' and t.get('category') == 'malicious']
        if vt_detections:
            print(f"\n  🔥 ТОП-5 самых опасных детектов VirusTotal:")
            for i, threat in enumerate(vt_detections[:5]):
                print(f"     {i + 1}. {threat.get('vendor')}: {threat.get('result')}")

        # Остальные критические угрозы
        other_high = [t for t in high_threats if t['source'] != 'VirusTotal']
        if other_high:
            print(f"\n  🚨 Другие критические угрозы:")
            shown_high = set()
            for threat in other_high:
                key = f"{threat['type']}_{threat['indicator']}"
                if key not in shown_high:
                    print(f"     • {threat['type']}: {threat['indicator'][:50]}")
                    shown_high.add(key)

    def create_report(self, all_threats):
        """Создание отчета и графиков"""
        print("\n📊 Создание отчета...")

        report = {
            "generated": datetime.now().isoformat(),
            "total_threats": len(all_threats),
            "threats_by_source": dict(Counter([t['source'] for t in all_threats])),
            "threats_by_severity": dict(Counter([t['severity'] for t in all_threats])),
            "threats_by_type": dict(Counter([t['type'] for t in all_threats])),
            "threats": all_threats
        }

        report_path = os.path.join(self.report_dir, "threat_report.json")
        with open(report_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=4, ensure_ascii=False)
        print(f"  ✅ Отчет сохранен: {report_path}")

        # Создаем все графики
        self.create_visualization(all_threats)
        self.create_pie_chart(all_threats)
        self.create_cvss_chart(all_threats)
        self.export_to_csv(all_threats)
        self.print_summary(all_threats)

    def create_visualization(self, threats):
        """Базовая визуализация результатов"""
        if not threats:
            return

        sns.set_style("darkgrid")

        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 6))

        # График 1: Угрозы по источникам
        sources = [t['source'] for t in threats]
        source_counts = Counter(sources)

        colors = sns.color_palette("husl", len(source_counts))
        ax1.bar(source_counts.keys(), source_counts.values(), color=colors)
        ax1.set_title('Угрозы по источникам', fontsize=14, fontweight='bold')
        ax1.set_xlabel('Источник')
        ax1.set_ylabel('Количество')
        ax1.tick_params(axis='x', rotation=45)

        # График 2: Угрозы по типу
        types = [t['type'] for t in threats]
        type_counts = Counter(types).most_common(5)  # Топ-5 типов

        if type_counts:
            types_names, types_counts = zip(*type_counts)
            colors2 = sns.color_palette("viridis", len(types_names))
            ax2.bar(types_names, types_counts, color=colors2)
            ax2.set_title('Топ-5 типов угроз', fontsize=14, fontweight='bold')
            ax2.set_xlabel('Тип угрозы')
            ax2.set_ylabel('Количество')
            ax2.tick_params(axis='x', rotation=45)

        plt.tight_layout()

        viz_path = os.path.join(self.report_dir, "threat_visualization.png")
        plt.savefig(viz_path, dpi=300, bbox_inches='tight')
        plt.close()
        print(f"  ✅ График сохранен: {viz_path}")

    def create_pie_chart(self, threats):
        """Создает круговую диаграмму распределения угроз"""
        if not threats:
            return

        plt.figure(figsize=(8, 8))
        severity_counts = Counter([t['severity'] for t in threats])

        colors = {'HIGH': 'red', 'MEDIUM': 'orange', 'LOW': 'yellow'}
        pie_colors = [colors.get(s, 'gray') for s in severity_counts.keys()]

        plt.pie(severity_counts.values(),
                labels=severity_counts.keys(),
                autopct='%1.1f%%',
                colors=pie_colors,
                startangle=90,
                explode=[0.05 if s == 'HIGH' else 0 for s in severity_counts.keys()])

        plt.title('Распределение угроз по критичности', fontsize=14, fontweight='bold')

        pie_path = os.path.join(self.report_dir, "threat_severity_pie.png")
        plt.savefig(pie_path, dpi=300, bbox_inches='tight')
        plt.close()
        print(f"  ✅ Круговая диаграмма сохранена: {pie_path}")

    def create_cvss_chart(self, threats):
        """Создает график распределения CVSS баллов"""
        cvss_threats = [t for t in threats if 'cvss_score' in t]

        if not cvss_threats:
            print("  ⚠️ Нет данных CVSS для графика")
            return

        plt.figure(figsize=(10, 6))

        cvss_scores = [t['cvss_score'] for t in cvss_threats]
        software_names = [t.get('software', 'unknown') for t in cvss_threats]

        # Цветовая градация по критичности
        colors = ['red' if s >= 9.0 else 'orange' if s >= 7.0 else 'yellow' for s in cvss_scores]

        plt.barh(software_names, cvss_scores, color=colors)
        plt.xlabel('CVSS Score')
        plt.title('Распределение CVSS баллов уязвимостей')
        plt.xlim(0, 10)

        # Добавляем вертикальные линии для порогов
        plt.axvline(x=7.0, color='orange', linestyle='--', alpha=0.7, label='Порог HIGH (7.0)')
        plt.axvline(x=9.0, color='red', linestyle='--', alpha=0.7, label='Порог CRITICAL (9.0)')
        plt.legend()

        cvss_path = os.path.join(self.report_dir, "cvss_distribution.png")
        plt.tight_layout()
        plt.savefig(cvss_path, dpi=300, bbox_inches='tight')
        plt.close()
        print(f"  ✅ CVSS график сохранен: {cvss_path}")

    def export_to_csv(self, threats):
        """Экспорт угроз в CSV для дополнительного анализа"""
        if not threats:
            return

        df = pd.DataFrame(threats)

        for col in df.columns:
            if df[col].apply(lambda x: isinstance(x, dict)).any():
                df[col] = df[col].apply(lambda x: str(x) if isinstance(x, dict) else x)

        csv_path = os.path.join(self.report_dir, "threats_detailed.csv")
        df.to_csv(csv_path, index=False, encoding='utf-8')
        print(f"  ✅ CSV отчет сохранен: {csv_path}")

    def print_summary(self, threats):
        """Печатает красивый итоговый summary"""
        print("\n" + "=" * 60)
        print("📊 ИТОГОВАЯ СТАТИСТИКА")
        print("=" * 60)

        sources = Counter([t['source'] for t in threats])
        types = Counter([t['type'] for t in threats])
        severity = Counter([t['severity'] for t in threats])

        print(f"\n📁 Источники данных:")
        for source, count in sources.most_common():
            print(f"   • {source}: {count} угроз")

        print(f"\n🔴 Критических угроз: {severity.get('HIGH', 0)}")
        print(f"🟡 Средних угроз: {severity.get('MEDIUM', 0)}")

        print(f"\n📈 Топ-5 типов угроз:")
        for threat_type, count in types.most_common(5):
            print(f"   • {threat_type}: {count}")

        print(f"\n📊 ВСЕГО УГРОЗ: {len(threats)}")


def main():
    print("=" * 60)
    print("🔍 АВТОМАТИЗИРОВАННЫЙ МОНИТОРИНГ УГРОЗ")
    print("=" * 60 + "\n")

    hunter = ThreatHunter()
    all_threats = []

    # Источник 1: VirusTotal
    vt_threats = hunter.check_virustotal()
    all_threats.extend(vt_threats)

    # Источник 2: DNS логи
    if os.path.exists('dns_logs.json'):
        dns_threats = hunter.analyze_dns_logs('dns_logs.json')
        all_threats.extend(dns_threats)

    # Источник 3: Suricata события
    if os.path.exists('events.json'):
        suricata_threats = hunter.analyze_suricata_events('events.json')
        all_threats.extend(suricata_threats)

    # Источник 4: Windows Event Logs
    if os.path.exists('botsv1.json'):
        windows_threats = hunter.analyze_windows_events('botsv1.json')
        all_threats.extend(windows_threats)

    # Источник 5: Vulners API
    vulners_threats = hunter.check_vulners_vulnerabilities()
    all_threats.extend(vulners_threats)

    # Реагирование
    hunter.respond_to_threats(all_threats)

    # Отправка Telegram для критических угроз
    for threat in all_threats:
        if threat.get('severity') == 'HIGH':
            hunter.send_telegram_alert(threat)

    # Отчет и визуализация
    hunter.create_report(all_threats)

    print("\n" + "=" * 60)
    print("✅ АНАЛИЗ ЗАВЕРШЕН")
    print(f"📁 Все отчеты сохранены в папке '{hunter.report_dir}'")
    print("=" * 60)


if __name__ == "__main__":
    main()
