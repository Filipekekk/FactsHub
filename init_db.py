# init_db.py
import mysql.connector
from mysql.connector import Error
from werkzeug.security import generate_password_hash
import os

DB_CONFIG_SERVER = {
    'host': os.environ.get('DB_HOST'),
    'user': os.environ.get('DB_USER'),
    'password': os.environ.get('DB_PASSWORD')
}

DB_CONFIG = {
    'host': os.environ.get('DB_HOST'),
    'user': os.environ.get('DB_USER'),
    'password': os.environ.get('DB_PASSWORD'),
    'database': os.environ.get('DB_NAME')
}

def main():
    try:
        # 1) Utworz baze, jesli nie istnieje
        temp_conn = mysql.connector.connect(**DB_CONFIG_SERVER)
        temp_cursor = temp_conn.cursor()
        temp_cursor.execute("CREATE DATABASE IF NOT EXISTS facts_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci")
        temp_cursor.close()
        temp_conn.close()

        # 2) Polacz z baza
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor()

        # 3) Tabele (bez DROP; IF NOT EXISTS)
        cursor.execute('''CREATE TABLE IF NOT EXISTS users (
            id INT PRIMARY KEY AUTO_INCREMENT,
            username VARCHAR(50) UNIQUE NOT NULL,
            email VARCHAR(100) UNIQUE NOT NULL,
            password_hash VARCHAR(255) NOT NULL,
            rola ENUM('user', 'moderator', 'admin') DEFAULT 'user',
            data_rejestracji TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;''')

        cursor.execute('''CREATE TABLE IF NOT EXISTS categories (
            id INT PRIMARY KEY AUTO_INCREMENT,
            nazwa VARCHAR(50) UNIQUE NOT NULL
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;''')

        cursor.execute('''CREATE TABLE IF NOT EXISTS facts (
            id INT PRIMARY KEY AUTO_INCREMENT,
            tytul VARCHAR(200) NOT NULL,
            tresc TEXT NOT NULL,
            zrodlo VARCHAR(500),
            kategoria_id INT,
            data_dodania TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            data_publikacji TIMESTAMP NULL,
            status ENUM('roboczy', 'oczekujacy', 'opublikowany', 'odrzucony') DEFAULT 'oczekujacy',
            user_id_autora INT,
            FOREIGN KEY(kategoria_id) REFERENCES categories(id),
            FOREIGN KEY(user_id_autora) REFERENCES users(id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;''')

        cursor.execute('''CREATE TABLE IF NOT EXISTS comments (
            id INT PRIMARY KEY AUTO_INCREMENT,
            fact_id INT NOT NULL,
            user_id INT,
            pseudonim_goscia VARCHAR(50),
            tresc TEXT NOT NULL,
            data_dodania TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            parent_comment_id INT,
            FOREIGN KEY(fact_id) REFERENCES facts(id) ON DELETE CASCADE,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY(parent_comment_id) REFERENCES comments(id) ON DELETE CASCADE
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;''')

        cursor.execute('''CREATE TABLE IF NOT EXISTS reactions (
            id INT PRIMARY KEY AUTO_INCREMENT,
            comment_id INT,
            fact_id INT,
            user_id INT,
            typ_reakcji VARCHAR(20),
            FOREIGN KEY(comment_id) REFERENCES comments(id) ON DELETE CASCADE,
            FOREIGN KEY(fact_id) REFERENCES facts(id) ON DELETE CASCADE,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;''')

        # 4) Seed tylko jesli pusto
        cursor.execute("SELECT COUNT(*) FROM categories")
        (cat_count,) = cursor.fetchone()
        if cat_count == 0:
            categories = ['Historia', 'Nauka', 'Kosmos', 'Natura', 'Technologia', 'Zwierzęta', 'Zdrowie']
            for cat in categories:
                cursor.execute("INSERT INTO categories (nazwa) VALUES (%s)", (cat,))

        cursor.execute("SELECT COUNT(*) FROM users")
        (user_count,) = cursor.fetchone()
        if user_count == 0:
            admin_pass = generate_password_hash('admin123')
            user_pass = generate_password_hash('user123')
            cursor.execute("INSERT INTO users (username, email, password_hash, rola) VALUES (%s, %s, %s, %s)",
                           ('admin', 'admin@factshub.pl', admin_pass, 'admin'))
            cursor.execute("INSERT INTO users (username, email, password_hash, rola) VALUES (%s, %s, %s, %s)",
                           ('testuser', 'user@factshub.pl', user_pass, 'user'))
            cursor.execute("INSERT INTO users (username, email, password_hash, rola) VALUES (%s, %s, %s, %s)",
                           ('moderator', 'moderator@factshub.pl', user_pass, 'moderator'))

        cursor.execute("SELECT COUNT(*) FROM facts")
        (facts_count,) = cursor.fetchone()
        if facts_count == 0:
            sample_facts = [
                ('Słonie mają niezwykłą pamięć', 'Słonie mogą zapamiętać mapy terenu i pamiętać je przez wiele lat.',
                 'https://en.wikipedia.org/wiki/Elephant', 6, 'opublikowany', 1),
                ('Okapi mają fioletowy język', 'Okapi posiadają fioletowy język, którym mogą się umyć.',
                 'https://en.wikipedia.org/wiki/Okapi', 6, 'opublikowany', 1),
                ('Mózg ośmiornicy w ramionach', 'Dwie trzecie neuronów ośmiornicy znajduje się w jej ramionach.',
                 'https://en.wikipedia.org/wiki/Octopus', 6, 'opublikowany', 1),
                ('Naukowcy odkryli nowy gatunek papugi', 'W 2024 roku naukowcy odkryli nowy gatunek papugi w Amazonce.',
                 'https://example.com/papuga', 6, 'oczekujacy', 2),
            ]
            for tytul, tresc, zrodlo, kategoria_id, status, autor_id in sample_facts:
                if status == 'opublikowany':
                    cursor.execute('''INSERT INTO facts
                        (tytul, tresc, zrodlo, kategoria_id, status, user_id_autora, data_publikacji)
                        VALUES (%s, %s, %s, %s, %s, %s, NOW())''',
                        (tytul, tresc, zrodlo, kategoria_id, status, autor_id))
                else:
                    cursor.execute('''INSERT INTO facts
                        (tytul, tresc, zrodlo, kategoria_id, status, user_id_autora)
                        VALUES (%s, %s, %s, %s, %s, %s)''',
                        (tytul, tresc, zrodlo, kategoria_id, status, autor_id))

            cursor.execute("INSERT INTO comments (fact_id, user_id, tresc) VALUES (%s, %s, %s)",
                           (1, 2, 'Niesamowite!'))

        conn.commit()
        cursor.close()
        conn.close()
        print("✅ Database initialized (no reset).")
        print("📝 Admin: admin@factshub.pl / admin123")
        print("📝 User: user@factshub.pl / user123")
        print("📝 Moderator: moderator@factshub.pl / user123")
    except Error as e:
        print(f"❌ Error: {e}")

if __name__ == '__main__':
    main()
