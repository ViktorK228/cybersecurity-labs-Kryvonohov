def caesar_encrypt(text, shift):
    """Шифрування методом Цезаря"""
    ua_alphabet = 'абвгґдеєжзиіїйклмнопрстуфхцчшщьюя'
    en_alphabet = 'abcdefghijklmnopqrstuvwxyz'
    result = []
    
    for char in text:
        if char.lower() in ua_alphabet:
            is_upper = char.isupper()
            index = ua_alphabet.index(char.lower())
            new_index = (index + shift) % len(ua_alphabet)
            new_char = ua_alphabet[new_index]
            result.append(new_char.upper() if is_upper else new_char)
        elif char.lower() in en_alphabet:
            is_upper = char.isupper()
            index = en_alphabet.index(char.lower())
            new_index = (index + shift) % len(en_alphabet)
            new_char = en_alphabet[new_index]
            result.append(new_char.upper() if is_upper else new_char)
        else:
            result.append(char)
    
    return ''.join(result)


def caesar_decrypt(text, shift):
    """Розшифрування методом Цезаря"""
    return caesar_encrypt(text, -shift)


def vigenere_encrypt(text, key):
    """Шифрування методом Віженера"""
    ua_alphabet = 'абвгґдеєжзиіїйклмнопрстуфхцчшщьюя'
    en_alphabet = 'abcdefghijklmnopqrstuvwxyz'
    result = []
    key = key.lower()
    key_index = 0
    
    for char in text:
        if char.lower() in ua_alphabet:
            is_upper = char.isupper()
            char_pos = ua_alphabet.index(char.lower())
            # Визначаємо, до якого алфавіту належить символ ключа
            if key[key_index % len(key)] in ua_alphabet:
                key_pos = ua_alphabet.index(key[key_index % len(key)])
            else:
                key_pos = en_alphabet.index(key[key_index % len(key)]) % len(ua_alphabet)
            new_pos = (char_pos + key_pos) % len(ua_alphabet)
            new_char = ua_alphabet[new_pos]
            result.append(new_char.upper() if is_upper else new_char)
            key_index += 1
        elif char.lower() in en_alphabet:
            is_upper = char.isupper()
            char_pos = en_alphabet.index(char.lower())
            # Визначаємо, до якого алфавіту належить символ ключа
            if key[key_index % len(key)] in en_alphabet:
                key_pos = en_alphabet.index(key[key_index % len(key)])
            else:
                key_pos = ua_alphabet.index(key[key_index % len(key)]) % len(en_alphabet)
            new_pos = (char_pos + key_pos) % len(en_alphabet)
            new_char = en_alphabet[new_pos]
            result.append(new_char.upper() if is_upper else new_char)
            key_index += 1
        else:
            result.append(char)
    
    return ''.join(result)


def vigenere_decrypt(text, key):
    """Розшифрування методом Віженера"""
    ua_alphabet = 'абвгґдеєжзиіїйклмнопрстуфхцчшщьюя'
    en_alphabet = 'abcdefghijklmnopqrstuvwxyz'
    result = []
    key = key.lower()
    key_index = 0
    
    for char in text:
        if char.lower() in ua_alphabet:
            is_upper = char.isupper()
            char_pos = ua_alphabet.index(char.lower())
            # Визначаємо, до якого алфавіту належить символ ключа
            if key[key_index % len(key)] in ua_alphabet:
                key_pos = ua_alphabet.index(key[key_index % len(key)])
            else:
                key_pos = en_alphabet.index(key[key_index % len(key)]) % len(ua_alphabet)
            new_pos = (char_pos - key_pos) % len(ua_alphabet)
            new_char = ua_alphabet[new_pos]
            result.append(new_char.upper() if is_upper else new_char)
            key_index += 1
        elif char.lower() in en_alphabet:
            is_upper = char.isupper()
            char_pos = en_alphabet.index(char.lower())
            # Визначаємо, до якого алфавіту належить символ ключа
            if key[key_index % len(key)] in en_alphabet:
                key_pos = en_alphabet.index(key[key_index % len(key)])
            else:
                key_pos = ua_alphabet.index(key[key_index % len(key)]) % len(en_alphabet)
            new_pos = (char_pos - key_pos) % len(en_alphabet)
            new_char = en_alphabet[new_pos]
            result.append(new_char.upper() if is_upper else new_char)
            key_index += 1
        else:
            result.append(char)
    
    return ''.join(result)


def print_comparison(original, caesar_result, vigenere_result, caesar_key, vigenere_key):
    """Виведення порівняльної таблиці"""
    print("\n" + "="*70)
    print("ПОРІВНЯЛЬНИЙ АНАЛІЗ")
    print("="*70)
    print(f"{'Параметр':<30} | {'Цезар':<15} | {'Віженер':<15}")
    print("-"*70)
    print(f"{'Ключ':<30} | {caesar_key:<15} | {vigenere_key:<15}")
    print(f"{'Довжина результату':<30} | {len(caesar_result):<15} | {len(vigenere_result):<15}")
    print(f"{'Складність підбору':<30} | {'33 варіанти':<15} | {'Дуже висока':<15}")
    print("="*70)
    
    print("\nВИСНОВКИ:")
    print("Цезар: простий, але легко зламати (тільки 33 варіанти)")
    print("Віженер: складніший і надійніший для класичного шифрування")


def caesar_menu():
    """Меню для шифру Цезаря"""
    print("\n--- ШИФР ЦЕЗАРЯ ---")
    text = input("Введіть текст: ")
    shift = int(input("Введіть зсув (число): "))
    
    encrypted = caesar_encrypt(text, shift)
    print(f"\nЗашифровано: {encrypted}")
    
    decrypted = caesar_decrypt(encrypted, shift)
    print(f"Розшифровано: {decrypted}")
    
    return text, encrypted, shift


def vigenere_menu():
    """Меню для шифру Віженера"""
    print("\n--- ШИФР ВІЖЕНЕРА ---")
    text = input("Введіть текст: ")
    key = input("Введіть ключ (слово): ")
    
    encrypted = vigenere_encrypt(text, key)
    print(f"\nЗашифровано: {encrypted}")
    
    decrypted = vigenere_decrypt(encrypted, key)
    print(f"Розшифровано: {decrypted}")
    
    return text, encrypted, key


def compare_menu():
    """Меню для порівняння обох шифрів"""
    print("\n--- ПОРІВНЯННЯ ШИФРІВ ---")
    text = input("Введіть текст: ")
    
    print("\nДля шифру Цезаря:")
    caesar_shift = int(input("Введіть зсув (число): "))
    
    print("\nДля шифру Віженера:")
    vigenere_key = input("Введіть ключ (слово): ")
    
    caesar_result = caesar_encrypt(text, caesar_shift)
    vigenere_result = vigenere_encrypt(text, vigenere_key)
    
    print(f"\nОригінал: {text}")
    print(f"Цезар:    {caesar_result}")
    print(f"Віженер:  {vigenere_result}")
    
    print_comparison(text, caesar_result, vigenere_result, caesar_shift, vigenere_key)


def main():
    """Головне меню програми"""
    while True:
        print("\n" + "="*50)
        print("ПРОГРАМА ШИФРУВАННЯ")
        print("="*50)
        print("1. Шифр Цезаря")
        print("2. Шифр Віженера")
        print("3. Порівняти обидва шифри")
        print("0. Вихід")
        print("="*50)
        
        choice = input("Виберіть опцію (0-3): ")
        
        if choice == '1':
            caesar_menu()
        elif choice == '2':
            vigenere_menu()
        elif choice == '3':
            compare_menu()
        elif choice == '0':
            print("\nДо побачення!")
            break
        else:
            print("\nНевірний вибір. Спробуйте ще раз.")


if __name__ == "__main__":
    main()
