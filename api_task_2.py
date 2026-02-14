import os
import requests
from dotenv import load_dotenv

load_dotenv()

api_key = os.getenv("API_KEY")
weather_url = "https://api.openweathermap.org/data/2.5/weather"
city = input("Введите название города: ").upper()


def get_current_weather():
    """Принимает название города и выдает текущую температуру и описание погоды"""
    params = {
        'q': city,
        'appid': api_key,
        'units': 'metric',
        'lang': 'ru'
    }
    try:
        response = requests.get(weather_url, params=params)
        response.raise_for_status()
        weather_data = response.json()
        current_temperature = weather_data['main']['temp']
        weather_description = weather_data['weather'][0]['description']
        city_name = city.title()

        print(f"Погода в городе {city_name}")
        print(f"Текущая температура: {current_temperature}")
        print(f"Описание погоды: {weather_description}")

    except requests.exceptions.HTTPError as http_error:
        if response.status_code == 404:
            print(f"{city} не найден.")
        else:
            print(f"Возникла ошибка: {http_error}.")

    except requests.exceptions.RequestException as e:
        print(f"Возникла ошибка: {e}.")

    except KeyError:
        print("Ответ от сервера не получен.")


if __name__ == "__main__":
    get_current_weather()
