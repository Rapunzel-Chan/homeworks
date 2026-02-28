import os
import requests
import json

from dotenv import load_dotenv

load_dotenv()

API_KEY = os.getenv("API_KEY_VT")
# Хэш тестового файла EICAR (безвредный, используется для тестирования антивирусов)
FILE_HASH = "44d88612fea8a8f36de82e1278abb02f"
OUTPUT_FILE = "virustotal_report.json"


def check_by_virus_total():
    """Запускает скрипт для проверки работы СЗИ"""

    # 1. Проверка наличия API-ключа
    if not API_KEY:
        print("=" * 50)
        print("ОШИБКА: API ключ не найден!")
        print("Пожалуйста, задайте переменную окружения API_KEY_VT.")
        print("=" * 50)
        return

    # 2. Формирование запроса
    url = f"https://www.virustotal.com/api/v3/files/{FILE_HASH}"
    headers = {"x-apikey": API_KEY}

    print(f"Запрашиваю информацию для хэша: {FILE_HASH}...")

    # 3. Выполнение HTTP-запроса
    try:
        response = requests.get(url, headers=headers)
    except requests.exceptions.RequestException as e:
        print(f"Ошибка при подключении к API: {e}")
        return

    # 4. Обработка ответа
    if response.status_code == 200:
        print("Запрос выполнен успешно (статус 200).")
        data = response.json()

        # ПОЛНЫЙ JSON-ОТВЕТ
        print("\n--- ПОЛНЫЙ JSON-ОТВЕТ ---")
        print(json.dumps(data, indent=4, ensure_ascii=False))

        # СТАТУС СКАНИРОВАНИЯ
        try:
            attributes = data["data"]["attributes"]
            stats = attributes["last_analysis_stats"]

            print("\n" + "=" * 60)
            print("СТАТУС СКАНИРОВАНИЯ ФАЙЛА")
            print("=" * 60)

            print(f"\n📁 Имя файла: {attributes.get('meaningful_name', 'Неизвестно')}")
            print(f"📦 Тип файла: {attributes.get('type_description', 'Неизвестно')}")
            print(f"⚖️ Размер: {attributes.get('size', 0)} байт")
            print(f"🔍 SHA256: {attributes.get('sha256', 'Неизвестно')}")

            print("\n📊 РЕЗУЛЬТАТЫ СКАНИРОВАНИЯ:")
            print(f"   🔴 Вредоносных:      {stats['malicious']}")
            print(f"   🟡 Подозрительных:    {stats['suspicious']}")
            print(f"   🟢 Безопасных:        {stats['harmless']}")
            print(f"   ⚪ Неопределенных:    {stats['undetected']}")

            # ПРАВИЛА ФИЛЬТРАЦИИ (из результатов сканирования)
            print("\n" + "=" * 60)
            print("ПРАВИЛА ФИЛЬТРАЦИИ ТРАФИКА")
            print("=" * 60)

            scan_results = attributes.get("last_analysis_results", {})
            rules_found = False

            for vendor, result in scan_results.items():
                # Проверяем разные поля, где могут быть правила
                rule_name = result.get('rule_name') or result.get('result')  # Смотрим оба поля!

                if result.get("category") == "malicious" and rule_name:
                    rules_found = True
                    print(f"\n🛡️ {vendor}:")
                    print(f"   Правило: {rule_name}")
                    print(f"   Категория: {result.get('category')}")

                    # Если есть дополнительная информация
                    if result.get('engine_version'):
                        print(f"   Версия: {result.get('engine_version')}")

            if not rules_found:
                print("\n❌ Правила детектирования не найдены")
                print("\n💡 Отладка: покажем первые 3 результата для примера:")
                count = 0
                for vendor, result in list(scan_results.items())[:3]:
                    print(f"\n   {vendor}:")
                    print(f"      category: {result.get('category')}")
                    print(f"      result: {result.get('result')}")
                    print(f"      rule_name: {result.get('rule_name')}")
                    count += 1

            print("\n" + "=" * 60)

        except KeyError as e:
            print(f"\n❌ Не удалось найти статистику в ответе: {e}")

        # Сохранение JSON в файл
        try:
            with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=4, ensure_ascii=False)
            print(f"\n✓ Отчёт сохранён в файл '{OUTPUT_FILE}'")
        except IOError as e:
            print(f"\n✗ Ошибка при сохранении файла: {e}")

    elif response.status_code == 404:
        print(f"Ошибка 404: Файл с хэшем {FILE_HASH} не найден в базе VirusTotal.")
    else:
        print(f"Ошибка HTTP: {response.status_code}")
        print("Текст ответа сервера:")
        print(response.text)


if __name__ == "__main__":
    check_by_virus_total()
