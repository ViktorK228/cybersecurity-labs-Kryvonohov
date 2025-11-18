import hashlib
import os
import json
import base64

class EmailSymmetricSystem:
    """Система симетричного шифрування електронних повідомлень"""

    def __init__(self):
        self.keys_file = "symmetric_key.json"

    def generate_key(self, email, birthdate):
        """
        Генерація симетричного ключа на основі Email та дати.
        Секретне слово прибрано.
        """
        # Формуємо рядок даних
        data = email + birthdate

        # Генеруємо хеш (SHA256)
        key_hash_bytes = hashlib.sha256(data.encode('utf-8')).digest()
        key_hex = key_hash_bytes.hex()

        return key_hash_bytes, key_hex

    def save_key(self, email, key_hex):
        """Збереження ключа у файл"""
        key_data = {
            "email": email,
            "secret_key": key_hex
        }
        with open(self.keys_file, 'w', encoding='utf-8') as f:
            json.dump(key_data, f, ensure_ascii=False, indent=4)

    def load_key(self):
        """Завантаження ключа з файлу"""
        if not os.path.exists(self.keys_file):
            return None

        with open(self.keys_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
            return bytes.fromhex(data['secret_key']), data['email']

    def encrypt_message(self, message, key_bytes):
        """Шифрування XOR + Base64"""
        if isinstance(message, str):
            message_bytes = message.encode('utf-8')
        else:
            message_bytes = message

        encrypted_bytes = bytearray()

        for i, byte in enumerate(message_bytes):
            key_byte = key_bytes[i % len(key_bytes)]
            encrypted_bytes.append(byte ^ key_byte)

        return base64.b64encode(encrypted_bytes).decode('utf-8')

    def decrypt_message(self, encrypted_base64, key_bytes):
        """Розшифрування XOR"""
        try:
            encrypted_bytes = base64.b64decode(encrypted_base64)
            decrypted_bytes = bytearray()

            for i, byte in enumerate(encrypted_bytes):
                key_byte = key_bytes[i % len(key_bytes)]
                decrypted_bytes.append(byte ^ key_byte)

            return decrypted_bytes.decode('utf-8')
        except Exception:
            return None

# --- Інтерфейс ---

def show_menu():
    print("\n" + "=" * 70)
    print("EMAIL-ШИФРАТОР (СИМЕТРИЧНЕ ШИФРУВАННЯ)")
    print("=" * 70)
    print("1. Згенерувати ключ (Логін)")
    print("2. Написати зашифрований лист")
    print("3. Прочитати вхідний лист")
    print("4. Вихід")
    print("=" * 70)

def generate_key_menu(system):
    print("\n" + "-" * 70)
    print("ГЕНЕРАЦІЯ КЛЮЧА")
    print("-" * 70)

    email = input("Введіть Email: ").strip()
    birthdate = input("Введіть дату/рік народження: ").strip()

    if not email or not birthdate:
        print("\nПомилка: Всі поля мають бути заповнені!")
        return

    # Генерація без секретного слова
    key_bytes, key_hex = system.generate_key(email, birthdate)
    system.save_key(email, key_hex)

    print("\nКлюч успішно згенеровано!")
    print(f"Користувач: {email}")
    # Виводимо повний ключ
    print(f"Ключ сесії (SHA256): {key_hex}")
    print("Ключ збережено у 'symmetric_key.json'")

def encrypt_menu(system):
    print("\n" + "-" * 70)
    print("ШИФРУВАННЯ")
    print("-" * 70)

    key_data = system.load_key()
    if not key_data:
        print("\nПомилка: Спочатку згенеруйте ключ (пункт 1)!")
        return

    key_bytes, email = key_data
    print(f"Відправник: {email}")

    message = input("\nВведіть текст повідомлення:\n> ")

    if not message:
        print("Повідомлення порожнє!")
        return

    encrypted_msg = system.encrypt_message(message, key_bytes)

    print("\n--- РЕЗУЛЬТАТ ---")
    print(f"Зашифровані дані:\n{encrypted_msg}")

    save = input("\nЗберегти у файл 'email.txt'? (y/n): ")
    if save.lower() == 'y':
        with open('email.txt', 'w', encoding='utf-8') as f:
            f.write(encrypted_msg)
        print("Повідомлення збережено!")

def decrypt_menu(system):
    print("\n" + "-" * 70)
    print("РОЗШИФРУВАННЯ")
    print("-" * 70)

    key_data = system.load_key()
    if not key_data:
        print("\nПомилка: Немає ключа (пункт 1)!")
        return

    key_bytes, email = key_data
    print(f"Отримувач: {email}")

    print("\nДжерело:")
    print("1. Ввести вручну")
    print("2. Завантажити з 'email.txt'")

    choice = input("Ваш вибір: ").strip()

    ciphertext = ""
    if choice == "1":
        ciphertext = input("Вставте шифр: ").strip()
    elif choice == "2":
        if os.path.exists('email.txt'):
            with open('email.txt', 'r', encoding='utf-8') as f:
                ciphertext = f.read().strip()
            print(f"Завантажено: {ciphertext}")
        else:
            print("Файл не знайдено.")
            return

    if ciphertext:
        decrypted_msg = system.decrypt_message(ciphertext, key_bytes)

        print("\n" + "=" * 70)
        if decrypted_msg:
            print("ТЕКСТ ПОВІДОМЛЕННЯ:")
            print(f"> {decrypted_msg}")
        else:
            print("ПОМИЛКА: Не вдалося розшифрувати (невірний ключ або дані).")
        print("=" * 70)

def main():
    system = EmailSymmetricSystem()
    while True:
        show_menu()
        choice = input("\nОберіть дію: ").strip()
        if choice == "1":
            generate_key_menu(system)
        elif choice == "2":
            encrypt_menu(system)
        elif choice == "3":
            decrypt_menu(system)
        elif choice == "4":
            break
        else:
            print("Невірний вибір.")

if __name__ == "__main__":
    main()