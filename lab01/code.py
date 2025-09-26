import re
from datetime import datetime

class PasswordSecurityAnalyzer:
    """Клас для аналізу безпеки пароля на основі різних критеріїв."""
    def __init__(self):
        # Список дуже поширених і небезпечних паролів (зламані паролі)
        self.common_passwords = [
            "password", "123456", "qwerty", "admin", "letmein", 
            "welcome", "monkey", "dragon", "master", "secret"
        ]
        
        # Список поширених словникових слів
        self.common_words = [
            "love", "money", "baby", "angel", "princess", "sunshine"
        ]

    def analyze_password(self, password, personal_data):
        """
        Основна функція аналізу пароля.
        Розраховує загальний бал безпеки та формує рекомендації.
        """
        # 1. Перевірка на наявність персональних даних
        personal_issues = self._check_personal_data(password, personal_data)
        # 2. Розрахунок початкового балу складності (на основі довжини та типів символів)
        complexity_score = self._calculate_complexity(password)
        # 3. Перевірка на наявність небезпечних шаблонів (послідовності, повторення, поширені паролі)
        patterns = self._check_patterns(password)
        # 4. Перевірка на наявність словникових слів
        words = self._check_words(password)
        
        # Загальний бал (1-10) - починається з балу складності
        total_score = complexity_score
        # Зниження балу за персональні дані (найбільший штраф)
        total_score -= len(personal_issues) * 1.5
        # Зниження балу за небезпечні шаблони
        total_score -= len(patterns) * 1
        # Зниження балу за словникові слова
        total_score -= len(words) * 0.5
        # Обмеження загального балу від 1 до 10
        total_score = max(1, min(10, round(total_score)))
        
        # Формування рекомендацій
        recommendations = self._get_recommendations(
            password, personal_issues, patterns, words
        )
        
        return {
            "password": password,
            "personal_issues": personal_issues,
            "complexity_score": complexity_score,
            "patterns": patterns,
            "words": words,
            "total_score": total_score,
            "security_level": self._get_security_level(total_score),
            "recommendations": recommendations
        }

    def _check_personal_data(self, password, personal_data):
        """Перевірка на наявність імені та дати народження користувача у паролі."""
        issues = []
        password_lower = password.lower()
        
        # Перевірка імені
        if personal_data.get("name"):
            name = personal_data["name"].lower()
            if name in password_lower:
                issues.append(f"Містить ім'я: {personal_data['name']}")
        
        # Перевірка дати народження
        if personal_data.get("birth_date"):
            birth_date = personal_data["birth_date"]
            year = str(birth_date.year)
            # Форматування дня та місяця з нулем, якщо потрібно
            month = f"{birth_date.month:02d}"
            day = f"{birth_date.day:02d}"
            
            if year in password:
                issues.append(f"Містить рік народження: {year}")
            # Перевірка комбінацій день+місяць та місяць+день
            if f"{day}{month}" in password or f"{month}{day}" in password:
                issues.append("Містить день/місяць народження")
        
        return issues

    def _calculate_complexity(self, password):
        """
        Розрахунок початкового балу складності (макс. 7) на основі:
        - Довжини (макс. 3 бали)
        - Наявності різних типів символів (макс. 4 бали: малі/великі літери, цифри, спецсимволи)
        """
        score = 0
        
        # Бали за довжину
        length = len(password)
        if length >= 12:
            score += 3
        elif length >= 8:
            score += 2
        elif length >= 6:
            score += 1
        
        # Бали за типи символів (регулярні вирази)
        if re.search(r'[a-zа-я]', password): # Малі літери (латиниця/кирилиця)
            score += 1
        if re.search(r'[A-ZА-Я]', password): # Великі літери (латиниця/кирилиця)
            score += 1
        if re.search(r'\d', password):       # Цифри
            score += 1
        # Спеціальні символи
        if re.search(r'[!@#$%^&*()_+\-=\[\]{}|;\':",./<>?]', password):
            score += 1
        
        return min(score, 7) # Обмеження максимального балу складності

    def _check_patterns(self, password):
        """Перевірка небезпечних шаблонів: послідовності, повторення та поширені паролі."""
        patterns = []
        password_lower = password.lower()
        
        # Послідовності (123, abc, qwe, йцу)
        if re.search(r'123|abc|qwe|йцу', password_lower):
            patterns.append("Послідовні символи")
        
        # Повторення символів (мінімум 3 однакові символи підряд, напр. 'aaa')
        if re.search(r'(.)\1{2,}', password):
            patterns.append("Повторення символів")
        
        # Поширені (зламані) паролі
        for common in self.common_passwords:
            if common in password_lower:
                patterns.append(f"Поширений пароль: {common}")
                break # Достатньо одного збігу
        
        return patterns

    def _check_words(self, password):
        """Перевірка на наявність простих словникових слів (з визначеного списку)."""
        words = []
        password_lower = password.lower()
        
        for word in self.common_words:
            # Перевіряємо, чи слово є в паролі і має довжину більше 3 символів
            if word in password_lower and len(word) > 3:
                words.append(word)
        
        return words

    def _get_security_level(self, score):
        """Визначення текстового рівня безпеки за загальним балом."""
        if score >= 8:
            return "Високий"
        elif score >= 6:
            return "Середній"
        elif score >= 4:
            return "Низький"
        else:
            return "Дуже низький"

    def _get_recommendations(self, password, personal_issues, patterns, words):
        """Формування списку конкретних рекомендацій для покращення пароля."""
        recommendations = []
        
        # Рекомендації на основі виявлених проблем
        if personal_issues:
            recommendations.append("Уникайте персональних даних у паролі")
        
        # Рекомендації для підвищення складності
        if len(password) < 12:
            recommendations.append("Збільште довжину до мінімум 12 символів")
        
        if not re.search(r'[A-ZА-Я]', password):
            recommendations.append("Додайте великі літери")
        
        if not re.search(r'[a-zа-я]', password):
            recommendations.append("Додайте малі літери")
        
        if not re.search(r'\d', password):
            recommendations.append("Додайте цифри")
        
        if not re.search(r'[!@#$%^&*()_+\-=\[\]{}|;\':",./<>?]', password):
            recommendations.append("Додайте спеціальні символи")
        
        # Рекомендації на основі шаблонів/слів
        if patterns:
            recommendations.append("Уникайте поширених шаблонів")
        
        if words:
            recommendations.append("Уникайте словникових слів")
        
        return recommendations

    def print_report(self, results):
        """Виведення відформатованого звіту аналізу пароля."""
        print("=" * 50)
        print("АНАЛІЗ БЕЗПЕКИ ПАРОЛЯ")
        print("=" * 50)
        
        # Загальна інформація
        print(f"Пароль: {'*' * len(results['password'])}") # Пароль приховано
        print(f"Загальний бал: {results['total_score']}/10")
        print(f"Рівень безпеки: {results['security_level']}")
        print(f"Бал складності: {results['complexity_score']}/7")
        
        # Деталі проблем
        if results["personal_issues"]:
            print("\nПроблеми з персональними даними:")
            for issue in results["personal_issues"]:
                print(f"  - {issue}")
        
        if results["patterns"]:
            print("\nНебезпечні шаблони:")
            for pattern in results["patterns"]:
                print(f"  - {pattern}")
        
        if results["words"]:
            print("\nСловникові слова:")
            for word in results["words"]:
                print(f"  - {word}")
        
        # Рекомендації
        print("\nРекомендації:")
        if results["recommendations"]:
            for rec in results["recommendations"]:
                print(f"  - {rec}")
        else:
            print("  - Пароль має високий рівень безпеки")


def parse_date(date_string):
    """
    Парсинг рядка дати у об'єкт date з datetime.
    Підтримує кілька поширених форматів.
    """
    formats = ['%d.%m.%Y', '%d/%m/%Y', '%Y-%m-%d']
    
    for fmt in formats:
        try:
            return datetime.strptime(date_string, fmt).date()
        except ValueError:
            continue
    
    # Якщо жоден формат не підійшов
    raise ValueError(f"Неправильний формат дати: {date_string}")


def main():
    """Основна програма для взаємодії з користувачем."""
    analyzer = PasswordSecurityAnalyzer()
    
    print("АНАЛІЗАТОР БЕЗПЕКИ ПАРОЛІВ")
    print("=" * 30)
    
    # Введення пароля
    password = input("Введіть пароль: ")
    
    # Введення персональних даних
    personal_data = {}
    
    print("\nВведіть персональні дані (Enter - пропустити):")
    
    name = input("Ім'я: ").strip()
    if name:
        personal_data["name"] = name
    
    birth_date = input("Дата народження (дд.мм.рррр): ").strip()
    if birth_date:
        try:
            # Парсинг дати за допомогою допоміжної функції
            personal_data["birth_date"] = parse_date(birth_date)
        except ValueError as e:
            print(f"Помилка: {e}")
            # Можна продовжити без дати, якщо парсинг не вдався
    
    # Аналіз
    print("\nАналіз...")
    results = analyzer.analyze_password(password, personal_data)
    
    # Результат
    print()
    analyzer.print_report(results)


# Демо приклад
def demo():
    """Демонстраційна функція з тестовим паролем і даними."""
    print("ДЕМОНСТРАЦІЙНИЙ ПРИКЛАД")
    print("=" * 30)
    
    analyzer = PasswordSecurityAnalyzer()
    
    # Тестові дані, що містять ім'я та рік народження в паролі
    password = "ivan1995"
    personal_data = {
        "name": "Іван",
        "birth_date": datetime(1995, 3, 15).date()
    }
    
    print(f"Пароль: {password}")
    print(f"Ім'я: {personal_data['name']}")
    print(f"Дата народження: 15.03.1995")
    
    results = analyzer.analyze_password(password, personal_data)
    analyzer.print_report(results)


if __name__ == "__main__":
    # Виконання демонстрації
    demo()
    print("\n" + "=" * 50)
    
    # Запуск основної програми
    main()
