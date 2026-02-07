import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import json


def analyze_security_events(json_file_path):
    """
    Загружает данные из JSON, анализирует и визуализирует распределение событий.
    """
    try:
        # Этап 2: Загрузка данных из файла JSON в датафрейм
        print(f"Загрузка данных из файла: {json_file_path}...")
        with open(json_file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        df = pd.DataFrame(data['events'])

        print("Данные успешно загружены. Вот первые 5 строк:")
        print(df.head())

        # Этап 2 (продолжение): Анализ данных
        signature_counts = df['signature'].value_counts()
        print("\nРаспределение событий по типам:")
        print(signature_counts)

        # Этап 3: Визуализация данных
        print("\nПостроение графика...")
        plt.figure(figsize=(12, 8))  # Увеличим размер для лучшей читаемости
        sns.countplot(data=df, y='signature', order=signature_counts.index, palette='viridis', hue='signature',
                      legend=False)

        plt.title("Распределение типов событий безопасности", fontsize=16)
        plt.xlabel("Количество событий", fontsize=12)
        plt.ylabel("Тип события (Signature)", fontsize=12)
        plt.tight_layout()  # Автоматически подгоняет элементы, чтобы они не накладывались

        # Сохраняем график в файл
        plt.savefig('event_distribution.png')
        print("График сохранен как 'event_distribution.png'")

        plt.show()

    except FileNotFoundError:
        print(f"ОШИБКА: Файл не найден по пути: {json_file_path}")
    except Exception as e:
        print(f"Произошла непредвиденная ошибка: {e}")


if __name__ == "__main__":
    events_file = 'events.json'
    analyze_security_events(events_file)
