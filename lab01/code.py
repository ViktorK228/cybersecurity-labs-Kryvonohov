import re
from datetime import datetime

class PasswordSecurityAnalyzer:
    def __init__(self):
        self.common_passwords = [
            "password", "123456", "qwerty", "admin", "letmein", 
            "welcome", "monkey", "dragon", "master", "secret"
        ]
        
        self.common_words = [
            "love", "money", "baby", "angel", "princess", "sunshine"
        ]

    def analyze_password(self, password, personal_data):
        """Основна функція аналізу пароля"""
        personal_issues = self._check_personal_data(password, personal_data)
        complexity_score = self._calculate_complexity(password)
        patterns = self._check_patterns(password)
        words = self._check_words(password)
        
        # Загальний бал (1-10)
        total_score = complexity_score
        total_score -= len(personal_issues) * 1.5
        total_score -= len(patterns) * 1
        total_score -= len(words) * 0.5
        total_score = max(1, min(10, round(total_score)))
        
        # Рекомендації
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
        """Перевірка персональних даних у паролі"""
        issues = []
        password_lower = password.lower()
        
        # Ім'я
        if personal_data.get("name"):
            name = personal_data["name"].lower()
            if name in password_lower:
                issues.append(f"Містить ім'я: {personal_data['name']}")
        
        # Дата народження
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

    def _calculate_complexity(self, password):
        """Розрахунок складності пароля"""
        score = 0
        
        # Довжина
        length = len(password)
        if length >= 12:
            score += 3
        elif length >= 8:
            score += 2
        elif length >= 6:
            score += 1
        
        # Типи символів
        if re.search(r'[a-zа-я]', password):
            score += 1
        if re.search(r'[A-ZА-Я]', password):
            score += 1
        if re.search(r'\d', password):
            score += 1
        if re.search(r'[!@#$%^&*()_+\-=\[\]{}|;\':",./<>?]', password):
            score += 1
        
        return min(score, 7)

    def _check_patterns(self, password):
        """Перевірка небезпечних шаблонів"""
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
        """Перевірка словникових слів"""
        words = []
        password_lower = password.lower()
        
        for word in self.common_words:
            if word in password_lower and len(word) > 3:
                words.append(word)
        
        return words

    def _get_security_level(self, score):
        """Рівень безпеки"""
        if score >= 8:
            return "Високий"
        elif score >= 6:
            return "Середній"
        elif score >= 4:
            return "Низький"
        else:
            return "Дуже низький"

    def _get_recommendations(self, password, personal_issues, patterns, words):
        """Рекомендації для покращення"""
        recommendations = []
        
        if personal_issues:
            recommendations.append("Уникайте персональних даних у паролі")
        
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
        
        if patterns:
            recommendations.append("Уникайте поширених шаблонів")
        
        if words:
            recommendations.append("Уникайте словникових слів")
        
        return recommendations

    def print_report(self, results):
        """Виведення звіту"""
        print("=" * 50)
        print("АНАЛІЗ БЕЗПЕКИ ПАРОЛЯ")
        print("=" * 50)
        
        print(f"Пароль: {'*' * len(results['password'])}")
        print(f"Загальний бал: {results['total_score']}/10")
        print(f"Рівень безпеки: {results['security_level']}")
        print(f"Бал складності: {results['complexity_score']}/7")
        
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
        
        print("\nРекомендації:")
        if results["recommendations"]:
            for rec in results["recommendations"]:
                print(f"  - {rec}")
        else:
            print("  - Пароль має високий рівень безпеки")


def parse_date(date_string):
    """Парсинг дати"""
    formats = ['%d.%m.%Y', '%d/%m/%Y', '%Y-%m-%d']
    
    for fmt in formats:
        try:
            return datetime.strptime(date_string, fmt).date()
        except ValueError:
            continue
    
    raise ValueError(f"Неправильний формат дати: {date_string}")


def main():
    """Основна програма"""
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
            personal_data["birth_date"] = parse_date(birth_date)
        except ValueError as e:
            print(f"Помилка: {e}")
    
    # Аналіз
    print("\nАналіз...")
    results = analyzer.analyze_password(password, personal_data)
    
    # Результат
    print()
    analyzer.print_report(results)


# Демо приклад
def demo():
    """Демонстраційний приклад"""
    print("ДЕМОНСТРАЦІЙНИЙ ПРИКЛАД")
    print("=" * 30)
    
    analyzer = PasswordSecurityAnalyzer()
    
    # Тестові дані
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
    # Демо
    demo()
    print("\n" + "=" * 50)
    
    # Основна програма
    main()
