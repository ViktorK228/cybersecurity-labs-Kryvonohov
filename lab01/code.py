import re
from datetime import datetime

class PasswordSecurityAnalyzer:
    """Клас для аналізу безпеки пароля на основі різних критеріїв."""
    def __init__(self):
        # Список дуже поширених і небезпечних паролів
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
        # 2. Розрахунок балу складності
        complexity_score = self._calculate_complexity(password)
        # 3. Перевірка на наявність небезпечних шаблонів
        patterns = self._check_patterns(password)
        # 4. Перевірка на наявність словникових слів
        words = self._check_words(password)
        # 5. Аналіз кількості символів
        length_analysis = self._analyze_length(password)
        
        # Загальний бал (1-10)
        total_score = complexity_score
        # Штрафи
        total_score -= len(personal_issues) * 1.5
        total_score -= len(patterns) * 1
        total_score -= len(words) * 0.5
        
        # Бонус/штраф за довжину
        if length_analysis['length'] >= 16:
            total_score += 1
        elif length_analysis['length'] < 8:
            total_score -= 2
        
        # Обмеження від 1 до 10
        total_score = max(1, min(10, round(total_score, 1)))
        
        # Формування рекомендацій
        recommendations = self._get_recommendations(
            password, personal_issues, patterns, words, length_analysis
        )
        
        return {
            "password": password,
            "personal_issues": personal_issues,
            "complexity_score": complexity_score,
            "patterns": patterns,
            "words": words,
            "length_analysis": length_analysis,
            "total_score": total_score,
            "security_level": self._get_security_level(total_score),
            "recommendations": recommendations
        }

    def _check_personal_data(self, password, personal_data):
        """Перевірка на наявність імені та дати народження у паролі."""
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
            month = f"{birth_date.month:02d}"
            day = f"{birth_date.day:02d}"
            
            if year in password:
                issues.append(f"Містить рік народження: {year}")
            if f"{day}{month}" in password or f"{month}{day}" in password:
                issues.append("Містить день/місяць народження")
        
        return issues

    def _analyze_length(self, password):
        """Детальний аналіз довжини пароля."""
        length = len(password)
        
        if length >= 16:
            status = "Відмінно"
            level = "Дуже довгий"
        elif length >= 12:
            status = "Добре"
            level = "Довгий"
        elif length >= 8:
            status = "Нормально"
            level = "Середній"
        elif length >= 6:
            status = "Погано"
            level = "Короткий"
        else:
            status = "Дуже погано"
            level = "Дуже короткий"
        
        return {
            "length": length,
            "status": status,
            "level": level
        }

    def _calculate_complexity(self, password):
        """
        Розрахунок балу складності (макс. 8) на основі:
        - Довжини (макс. 4 бали)
        - Наявності різних типів символів (макс. 4 бали)
        """
        score = 0
        
        # Бали за довжину (більше балів за довші паролі)
        length = len(password)
        if length >= 16:
            score += 4
        elif length >= 12:
            score += 3
        elif length >= 8:
            score += 2
        elif length >= 6:
            score += 1
        
        # Бали за типи символів
        if re.search(r'[a-zа-яґєії]', password):
            score += 1
        if re.search(r'[A-ZА-ЯҐЄІЇ]', password):
            score += 1
        if re.search(r'\d', password):
            score += 1
        if re.search(r'[!@#$%^&*()_+\-=\[\]{}|;\':",./<>?]', password):
            score += 1
        
        return min(score, 8)

    def _check_patterns(self, password):
        """Перевірка небезпечних шаблонів."""
        patterns = []
        password_lower = password.lower()
        
        # Послідовності
        if re.search(r'123|abc|qwe|йцу', password_lower):
            patterns.append("Послідовні символи")
        
        # Повторення
        if re.search(r'(.)\1{2,}', password):
            patterns.append("Повторення символів")
        
        # Поширені паролі
        for common in self.common_passwords:
            if common in password_lower:
                patterns.append(f"Поширений пароль: {common}")
                break
        
        return patterns

    def _check_words(self, password):
        """Перевірка на словникові слова."""
        words = []
        password_lower = password.lower()
        
        for word in self.common_words:
            if word in password_lower and len(word) > 3:
                words.append(word)
        
        return words

    def _get_security_level(self, score):
        """Визначення рівня безпеки за загальним балом."""
        if score >= 8:
            return "Високий"
        elif score >= 6:
            return "Середній"
        elif score >= 4:
            return "Низький"
        else:
            return "Дуже низький"

    def _get_recommendations(self, password, personal_issues, patterns, words, length_analysis):
        """Формування рекомендацій для покращення пароля."""
        recommendations = []
        
        # Рекомендації на основі проблем
        if personal_issues:
            recommendations.append("Уникайте персональних даних у паролі")
        
        # Рекомендації за довжиною
        if length_analysis['length'] < 8:
            recommendations.append("КРИТИЧНО: Збільште довжину до мінімум 8 символів")
        elif length_analysis['length'] < 12:
            recommendations.append("Збільште довжину до мінімум 12 символів")
        elif length_analysis['length'] < 16:
            recommendations.append("Рекомендується 16+ символів для максимальної безпеки")
        
        # Рекомендації для складності
        if not re.search(r'[A-ZА-ЯҐЄІЇ]', password):
            recommendations.append("Додайте великі літери")
        
        if not re.search(r'[a-zа-яґєії]', password):
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
        print("\n" + "=" * 60)
        print("АНАЛІЗ БЕЗПЕКИ ПАРОЛЯ")
        print("=" * 60)
        
        # Загальна інформація
        print(f"Пароль: {'*' * len(results['password'])}")
        print(f"Довжина: {results['length_analysis']['length']} символів ({results['length_analysis']['level']})")
        print(f"Статус довжини: {results['length_analysis']['status']}")
        print(f"\nЗагальний бал: {results['total_score']}/10")
        print(f"Рівень безпеки: {results['security_level']}")
        print(f"Бал складності: {results['complexity_score']}/8")
        
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
        
        print("=" * 60)


def parse_date(date_string):
    """Парсинг рядка дати у об'єкт date."""
    formats = ['%d.%m.%Y', '%d/%m/%Y', '%Y-%m-%d']
    
    for fmt in formats:
        try:
            return datetime.strptime(date_string, fmt).date()
        except ValueError:
            continue
    
    raise ValueError(f"Неправильний формат дати: {date_string}")


def analyze_custom_password():
    """Аналіз пароля з введенням користувача."""
    analyzer = PasswordSecurityAnalyzer()
    
    print("\n--- АНАЛІЗ ВЛАСНОГО ПАРОЛЯ ---")
    
    # Введення пароля
    password = input("\nВведіть пароль для аналізу: ")
    
    # Введення персональних даних
    personal_data = {}
    
    print("\nВведіть персональні дані (Enter - пропустити):")
    
    name = input("Ім'я: ").strip()
    if name:
        personal_data["name"] = name
    
    birth_date = input("Дата народження (дд.мм.рррр): ").strip()
    if birth_date:
        try:
            personal_data["birth_date"] = parse_date(birth_date)
        except ValueError as e:
            print(f"Помилка: {e}")
    
    # Аналіз
    print("\nАналіз...")
    results = analyzer.analyze_password(password, personal_data)
    analyzer.print_report(results)


def demo_weak_password():
    """Демонстрація аналізу слабкого пароля."""
    print("\n--- ДЕМОНСТРАЦІЯ: СЛАБКИЙ ПАРОЛЬ ---")
    
    analyzer = PasswordSecurityAnalyzer()
    
    password = "ivan1995"
    personal_data = {
        "name": "Іван",
        "birth_date": datetime(1995, 3, 15).date()
    }
    
    print(f"\nПароль: {password}")
    print(f"Ім'я: {personal_data['name']}")
    print(f"Дата народження: 15.03.1995")
    
    results = analyzer.analyze_password(password, personal_data)
    analyzer.print_report(results)


def demo_strong_password():
    """Демонстрація аналізу сильного пароля."""
    print("\n--- ДЕМОНСТРАЦІЯ: СИЛЬНИЙ ПАРОЛЬ ---")
    
    analyzer = PasswordSecurityAnalyzer()
    
    password = "Kx9!mP#2wQ@7zL$5"
    personal_data = {
        "name": "Петро",
        "birth_date": datetime(1990, 5, 20).date()
    }
    
    print(f"\nПароль: {password}")
    print(f"Ім'я: {personal_data['name']}")
    print(f"Дата народження: 20.05.1990")
    
    results = analyzer.analyze_password(password, personal_data)
    analyzer.print_report(results)


def compare_passwords():
    """Порівняння декількох паролів."""
    print("\n--- ПОРІВНЯННЯ ПАРОЛІВ ---")
    
    analyzer = PasswordSecurityAnalyzer()
    personal_data = {}
    
    passwords = []
    print("\nВведіть паролі для порівняння (мінімум 2):")
    
    for i in range(1, 4):
        password = input(f"Пароль {i} (Enter - завершити): ").strip()
        if not password:
            break
        passwords.append(password)
    
    if len(passwords) < 2:
        print("Потрібно ввести мінімум 2 паролі для порівняння.")
        return
    
    print("\n" + "=" * 60)
    print("РЕЗУЛЬТАТИ ПОРІВНЯННЯ")
    print("=" * 60)
    
    results_list = []
    for i, password in enumerate(passwords, 1):
        result = analyzer.analyze_password(password, personal_data)
        results_list.append(result)
        print(f"\nПароль {i}: {'*' * len(password)}")
        print(f"  Довжина: {result['length_analysis']['length']} ({result['length_analysis']['level']})")
        print(f"  Загальний бал: {result['total_score']}/10")
        print(f"  Рівень безпеки: {result['security_level']}")
    
    # Визначення найкращого
    best = max(results_list, key=lambda x: x['total_score'])
    best_index = results_list.index(best) + 1
    
    print("\n" + "=" * 60)
    print(f"НАЙКРАЩИЙ ПАРОЛЬ: Пароль {best_index}")
    print(f"Бал: {best['total_score']}/10")
    print("=" * 60)


def main():
    """Головна функція з меню."""
    while True:
        print("\n" + "=" * 60)
        print("АНАЛІЗАТОР БЕЗПЕКИ ПАРОЛІВ")
        print("=" * 60)
        print("1. Аналіз власного пароля")
        print("2. Демонстрація: слабкий пароль")
        print("3. Демонстрація: сильний пароль")
        print("4. Порівняння паролів")
        print("0. Вихід")
        print("=" * 60)
        
        choice = input("Виберіть опцію (0-4): ")
        
        if choice == '1':
            analyze_custom_password()
        elif choice == '2':
            demo_weak_password()
        elif choice == '3':
            demo_strong_password()
        elif choice == '4':
            compare_passwords()
        elif choice == '0':
            print("\nДо побачення!")
            break
        else:
            print("\nНевірний вибір. Спробуйте ще раз.")


if __name__ == "__main__":
    main()
