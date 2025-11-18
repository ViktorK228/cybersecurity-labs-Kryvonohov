import hashlib
import os
import json


class DigitalSignatureSystem:
    """Спрощена система цифрових підписів"""

    def __init__(self):
        self.MODULO = 1000007
        self.PUBLIC_KEY_MULTIPLIER = 7
        self.keys_file = "keys.json"

    def generate_keys(self, name, birthdate, secret_word):
        """
        Генерація пари ключів (приватний та публічний)

        Args:
            name: ім'я
            birthdate: дата народження (формат: DDMMYYYY)
            secret_word: секретне слово

        Returns:
            tuple: (приватний_ключ, публічний_ключ, хеш_даних)
        """
        # Створюємо приватний ключ з персональних даних
        data = name + birthdate + secret_word
        private_key_hash = hashlib.sha256(data.encode()).hexdigest()

        # Конвертуємо хеш у число
        private_key = int(private_key_hash, 16) % self.MODULO

        # Генеруємо публічний ключ (спрощена математика)
        public_key = (private_key * self.PUBLIC_KEY_MULTIPLIER) % self.MODULO

        return private_key, public_key, private_key_hash

    def save_keys(self, name, private_key, public_key, private_key_hash):
        """Збереження ключів у файл"""
        keys_data = {
            "name": name,
            "private_key": private_key,
            "public_key": public_key,
            "private_key_hash": private_key_hash
        }
        with open(self.keys_file, 'w', encoding='utf-8') as f:
            json.dump(keys_data, f, ensure_ascii=False, indent=4)

    def load_keys(self):
        """Завантаження ключів з файлу"""
        if not os.path.exists(self.keys_file):
            return None

        with open(self.keys_file, 'r', encoding='utf-8') as f:
            return json.load(f)

    def calculate_document_hash(self, document_content):
        """
        Обчислення хешу документу

        Args:
            document_content: вміст документу (текст або байти)

        Returns:
            str: SHA256 хеш документу
        """
        if isinstance(document_content, str):
            document_content = document_content.encode()

        return hashlib.sha256(document_content).hexdigest()

    def create_signature(self, document_content, private_key):
        """
        Створення цифрового підпису

        Args:
            document_content: вміст документу
            private_key: приватний ключ

        Returns:
            str: цифровий підпис (hex)
        """
        # Обчислюємо хеш документу
        doc_hash = self.calculate_document_hash(document_content)

        # Конвертуємо хеш у число
        hash_number = int(doc_hash, 16)

        # "Шифруємо" хеш приватним ключем (спрощене шифрування через XOR)
        signature = hash_number ^ private_key

        return hex(signature)

    def verify_signature(self, document_content, signature, private_key):
        """
        Перевірка цифрового підпису

        Args:
            document_content: вміст документу
            signature: цифровий підпис
            private_key: приватний ключ (для розшифрування)

        Returns:
            bool: True якщо підпис дійсний, False якщо підроблений
        """
        # Обчислюємо хеш поточного документу
        current_hash = self.calculate_document_hash(document_content)

        # Конвертуємо підпис назад у число
        signature_number = int(signature, 16)

        # "Розшифровуємо" підпис приватним ключем
        decrypted_hash_number = signature_number ^ private_key
        decrypted_hash = hex(decrypted_hash_number)[2:].zfill(64)

        # Порівнюємо хеші
        return decrypted_hash == current_hash


def show_menu():
    """Відображення головного меню"""
    print("\n" + "=" * 70)
    print("СИСТЕМА ЦИФРОВИХ ПІДПИСІВ")
    print("=" * 70)
    print("1. Згенерувати ключ")
    print("2. Підписати документ")
    print("3. Перевірити підпис")
    print("4. Завершити програму")
    print("=" * 70)


def generate_key_menu(dss):
    """Меню генерації ключів"""
    print("\n" + "-" * 70)
    print("ГЕНЕРАЦІЯ КЛЮЧІВ")
    print("-" * 70)

    name = input("Введіть ім'я: ").strip()
    birthdate = input("Введіть дату народження (DDMMYYYY): ").strip()
    secret_word = input("Введіть секретне слово: ").strip()

    if not name or not birthdate or not secret_word:
        print("\nПомилка: Всі поля повинні бути заповнені!")
        return

    if len(birthdate) != 8 or not birthdate.isdigit():
        print("\nПомилка: Дата народження повинна бути у форматі DDMMYYYY!")
        return

    private_key, public_key, private_key_hash = dss.generate_keys(name, birthdate, secret_word)
    dss.save_keys(name, private_key, public_key, private_key_hash)

    print("\nКлючі успішно згенеровані та збережені!")
    print(f"Ім'я: {name}")
    print(f"Хеш персональних даних (SHA256): {private_key_hash}")
    print(f"Приватний ключ: {private_key}")
    print(f"Публічний ключ: {public_key}")


def sign_document_menu(dss):
    """Меню підписання документу"""
    print("\n" + "-" * 70)
    print("ПІДПИСАННЯ ДОКУМЕНТУ")
    print("-" * 70)

    # Перевірка наявності ключів
    keys = dss.load_keys()
    if not keys:
        print("\nПомилка: Спочатку згенеруйте ключі (пункт 1)!")
        return

    print(f"Використовуються ключі користувача: {keys['name']}")

    # Введення шляху до файлу
    file_path = input("\nВведіть шлях до файлу для підписання: ").strip()

    if not os.path.exists(file_path):
        print(f"\nПомилка: Файл '{file_path}' не знайдено!")
        return

    try:
        # Читання файлу
        with open(file_path, 'rb') as f:
            document_content = f.read()

        # Створення підпису
        signature = dss.create_signature(document_content, keys['private_key'])

        # Збереження підпису
        signature_file = file_path + ".sig"
        with open(signature_file, 'w') as f:
            f.write(signature)

        # Обчислення хешу
        doc_hash = dss.calculate_document_hash(document_content)

        print("\nДокумент успішно підписано!")
        print(f"Файл документу: {file_path}")
        print(f"Хеш документу (SHA256): {doc_hash}")
        print(f"Цифровий підпис: {signature}")
        print(f"Підпис збережено у файл: {signature_file}")

    except Exception as e:
        print(f"\nПомилка при підписанні документу: {e}")


def verify_signature_menu(dss):
    """Меню перевірки підпису"""
    print("\n" + "-" * 70)
    print("ПЕРЕВІРКА ПІДПИСУ")
    print("-" * 70)

    # Перевірка наявності ключів
    keys = dss.load_keys()
    if not keys:
        print("\nПомилка: Спочатку згенеруйте ключі (пункт 1)!")
        return

    print(f"Використовуються ключі користувача: {keys['name']}")

    # Введення шляху до файлу
    file_path = input("\nВведіть шлях до файлу для перевірки: ").strip()

    if not os.path.exists(file_path):
        print(f"\nПомилка: Файл '{file_path}' не знайдено!")
        return

    # Перевірка наявності файлу підпису
    signature_file = file_path + ".sig"
    if not os.path.exists(signature_file):
        print(f"\nПомилка: Файл підпису '{signature_file}' не знайдено!")
        return

    try:
        # Читання файлу
        with open(file_path, 'rb') as f:
            document_content = f.read()

        # Читання підпису
        with open(signature_file, 'r') as f:
            signature = f.read().strip()

        # Перевірка підпису
        is_valid = dss.verify_signature(document_content, signature, keys['private_key'])

        # Обчислення хешу
        doc_hash = dss.calculate_document_hash(document_content)

        print("\n" + "=" * 70)
        print("РЕЗУЛЬТАТ ПЕРЕВІРКИ")
        print("=" * 70)
        print(f"Файл документу: {file_path}")
        print(f"Хеш документу (SHA256): {doc_hash}")
        print(f"Цифровий підпис: {signature}")
        print("-" * 70)

        if is_valid:
            print("СТАТУС: Підпис ДІЙСНИЙ")
            print("Документ не змінювався після підписання")
        else:
            print("СТАТУС: Підпис ПІДРОБЛЕНИЙ")
            print("Документ було змінено після підписання або підпис не відповідає!")

        print("=" * 70)

    except Exception as e:
        print(f"\nПомилка при перевірці підпису: {e}")


def main():
    """Головна функція програми"""
    dss = DigitalSignatureSystem()

    while True:
        show_menu()
        choice = input("\nВиберіть дію (1-4): ").strip()

        if choice == "1":
            generate_key_menu(dss)
        elif choice == "2":
            sign_document_menu(dss)
        elif choice == "3":
            verify_signature_menu(dss)
        elif choice == "4":
            print("\nЗавершення роботи програми...")
            break
        else:
            print("\nПомилка: Невірний вибір! Виберіть пункт від 1 до 4.")

    print("Дякуємо за використання системи цифрових підписів!")


if __name__ == "__main__":
    main()