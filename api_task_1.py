import requests

JSON_URL = 'https://dummyjson.com/posts'

def get_first_five_posts():
    """Функция для вывода заголовка и тела 5ти постов"""
    try:
        response = requests.get(JSON_URL)
        response.raise_for_status()
        data = response.json()
        posts = data.get('posts')
        first_5_posts = posts[:5]

        for i, post in enumerate(first_5_posts, 1):
            print(f"\n Пост № {i}")
            print(f"Заголовок: {post.get('title')}")
            print(f"Тело: {post.get('body')}\n")

    except requests.exceptions.RequestException as e:
        print(f"Возникла ошибка: {e}")

if __name__ == "__main__":
    get_first_five_posts()