# Анализ событий информационной безопасности

Приложение для этого проекта представляет собой скрипт на Python для анализа данных из файла events.json. Скрипт загружает
события безопасности, анализирует их распределение по типам и строит наглядный график

## Описание проекта
Скрипт vizualisation.py выполняет следующие действия:

- Загружает данные о событиях ИБ из файла events.json.
- Использует библиотеку Pandas для создания DataFrame.
- Группирует события по полю signature и подсчитывает их количество.
- Визуализирует полученные данные с помощью библиотеки Seaborn, сохраняя график в файл event_distribution.png.

## Описание проекта

- Python 3
- Pandas — для обработки и анализа данных.
- Matplotlib & Seaborn — для визуализации.
- Poetry — для управления зависимостями.

## Установка:

1. Клонируйте репозиторий:

```
git clone -b develop https://github.com/Rapunzel-Chan/homeworks.git
```

2. Установите зависимости:

```
pip install -r requirements.txt
```

## Использование:

1. Переключитесь на проект:

```
cd homeworks
```

2. Создайте виртуальное окружение:

```
python -m venv venv
```

3. Активируйте виртуальное окружение:

- Windows:

```
.\venv\Scripts\activate
```

- Linux/macOS:

```
source venv/bin/activate
```

4. Создайте .env файл в корне проекта и заполните данные на примере .env.example.

5. Запустите файл main.py:
- Для запуска приветствия

```
python main.py 
```
- Для запуска скрипта для анализа данных о нарушениях безопасности
```
python vizualisation.py
```

## Пример правильного ответа приложения:
После запуска скрипта из vizualisation.py

```
Загрузка данных из файла: events.json...
Данные успешно загружены. Вот первые 5 строк:
             timestamp                                          signature
0  2023-08-21T08:00:00  MALWARE-CNC Win.Trojan.Jadtre variant outbound...
1  2023-08-21T09:00:00  EXPLOIT Remote Windows Win32k elevation of pri...
2  2023-08-21T10:00:00            EXPLOIT Java JRE to Oracle WebLogic RCE
3  2023-08-21T11:00:00          NETBIOS DCERPC NCACN-IP-TCP interfaces BO
4  2023-08-21T12:00:00  MALWARE-CNC User-Agent known malicious connect...

Распределение событий по типам:
signature
MALWARE-CNC Win.Trojan.Jadtre variant outbound connection       12
EXPLOIT Remote Windows Win32k elevation of privilege attempt    11
... (и так далее)

Построение графика...
График сохранен как 'event_distribution.png'
```

Также в корне проекта появится файл event_distribution.png с графиком распределения.

## Сокрытие чувствительных данных

Список переменных окружений находится в .env.example. Заполните данные для правильной работы приложения.

## Создатель

В случае возникновения вопросов, нахождения багов или предложений по улучшению кода, можно обратиться к разработчику
по e-mail: rapuncel.chan24@gmail.com.
