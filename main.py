

def get_greetings(name:str) -> str:
    """Функция выдаёт приветствие по имени пользователя"""
    if name:
        return f"Приветствуем Вас в нашем веселом сообществе, {name}!"
    else:
        return "Приветствуем Вас в нашем веселом сообществе, Путник"


if __name__ == "__main__":
    user_name=input("Введите здесь ваше имя:")
    print(get_greetings(user_name))