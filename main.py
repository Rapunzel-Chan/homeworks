

def get_greetings(name):
    """Функция выдаёт приветствие по имени пользователя"""
    return f"Приветствуем Вас в нашем веселом сообществе, {name}"


if __name__ == "__main__":
    user_name=input("Введите здесь ваше имя:")
    print(get_greetings(user_name))