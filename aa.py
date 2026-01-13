from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix
from datetime import datetime, timedelta
import mysql.connector
from mysql.connector import Error
import os
import logging
from logging.handlers import RotatingFileHandler
from flask_talisman import Talisman
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# --- 1. KONFIGURACJA APLIKACJI I PROXY ---
app = Flask(__name__)

# x_for=2 -> Odkopuje IP spod ALB i spod Cloudflare (dociera do klienta)
# x_proto=2 -> Sprawdza czy na początku było HTTPS (ważne dla ciasteczek Secure)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=2, x_proto=2, x_host=1, x_prefix=1)

app.secret_key = os.environ.get('SECRET_KEY')

# --- 2. KONFIGURACJA BEZPIECZEŃSTWA ---

# Konfiguracja Sesji - Wygasa po 1 godzinie
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=1)

# Bezpieczne Ciasteczka
app.config.update(
    SESSION_COOKIE_HTTPONLY=True, # JavaScript nie ma dostępu do sesji (Ochrona XSS)
    SESSION_COOKIE_SECURE=True,   # Ciasteczko tylko po HTTPS
    SESSION_COOKIE_SAMESITE='Lax' # Ochrona przed CSRF
)

# Talisman: Wymuszenie HTTPS + Podstawowe nagłówki
# force_https=False -> Nie przekierowuje HTTP na HTTPS (wyłączone przez fakt używania Cloudflare)
talisman = Talisman(app, content_security_policy=None, force_https=False)

# --- 3. DODATKOWE NAGŁÓWKI (HARDENING) ---
@app.after_request
def add_security_headers(response):
    # Ochrona przed MIME sniffing
    response.headers['X-Content-Type-Options'] = 'nosniff'
    # Ochrona przed Clickjackingiem
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    # Blokada XSS (stare przeglądarki)
    response.headers['X-XSS-Protection'] = '1; mode=block'
    # Blokada dostępu do wrażliwych funkcji przeglądarki
    response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
    # Ograniczenie przesyłania nagłówka Referer
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    
    # Ukrywanie informacji o serwerze (Security by Obscurity)
    # Usuwamy nagłówek 'Server: Werkzeug/X.X.X Python/X.X.X'
    response.headers.pop('Server', None)
    
    return response

# --- 4. LOGOWANIE I LIMITER ---

# Logowanie do pliku
LOG_FILE = os.environ.get('LOG_FILE')
if LOG_FILE:
    try:
        file_handler = logging.FileHandler(LOG_FILE)
        file_handler.setLevel(logging.INFO)
        formatter = logging.Formatter('%(asctime)s [%(levelname)s] [SECURITY] %(message)s')
        file_handler.setFormatter(formatter)
        app.logger.addHandler(file_handler)
        app.logger.setLevel(logging.INFO)
        print(f"✅ Logowanie do pliku włączone: {LOG_FILE}")
    except Exception as e:
        print(f"⚠️ Nie udało się otworzyć pliku logów: {e}")

# Rate Limiter (Ochrona przed Brute-Force)
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["2000 per day", "500 per hour"],
    storage_uri="memory://"
)

# --- 5. BAZA DANYCH ---

DB_CONFIG = {
    'host': os.environ.get('DB_HOST'),
    'user': os.environ.get('DB_USER'),
    'password': os.environ.get('DB_PASSWORD'),
    'database': os.environ.get('DB_NAME')
}

def get_db_connection():
    return mysql.connector.connect(**DB_CONFIG)

# --- 6. ENDPOINTY (LOGIKA APLIKACJI) ---

@app.route('/')
def index():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute('''SELECT f.*, c.nazwa as kategoria 
                      FROM facts f 
                      LEFT JOIN categories c ON f.kategoria_id = c.id 
                      WHERE f.status = 'opublikowany' 
                      ORDER BY RAND() LIMIT 1''')
    fact_of_day = cursor.fetchone()

    cursor.execute('''SELECT f.*, c.nazwa as kategoria 
                      FROM facts f 
                      LEFT JOIN categories c ON f.kategoria_id = c.id 
                      WHERE f.status = 'opublikowany' 
                      ORDER BY f.data_publikacji DESC LIMIT 5''')
    recent_facts = cursor.fetchall()
    cursor.close()
    conn.close()
    return render_template('index.html', fact_of_day=fact_of_day, recent_facts=recent_facts,
                           current_user=session.get('user_id'))

@app.route('/register', methods=['POST'])
@limiter.limit("3 per hour")
def register():
    data = request.json
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')

    if not all([username, email, password]):
        return jsonify({'error': 'Wszystkie pola są wymagane'}), 400

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        password_hash = generate_password_hash(password)
        # Domyślna rola to 'user'
        cursor.execute("INSERT INTO users (username, email, password_hash, rola) VALUES (%s, %s, %s, 'user')",
                       (username, email, password_hash))
        conn.commit()
        cursor.close()
        conn.close()
        app.logger.info(f"New user registered: {username} (IP: {request.remote_addr})")
        return jsonify({'success': 'Rejestracja udana! Zaloguj się.'}), 201
    except Error:
        return jsonify({'error': 'Email lub nazwa użytkownika już istnieje'}), 400

@app.route('/login', methods=['POST'])
@limiter.limit("5 per minute")
def login():
    data = request.json
    email = data.get('email')
    password = data.get('password')

    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()

        if user and check_password_hash(user['password_hash'], password):
            session.permanent = True # Włącz wygasanie sesji po czasie (1h)
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['rola'] = user['rola']
            cursor.close()
            conn.close()
            app.logger.info(f"Successful login for user: {user['username']} from IP: {request.remote_addr}")
            return jsonify({'success': 'Zalogowano pomyślnie'}), 200

        cursor.close()
        conn.close()
        app.logger.warning(f"Failed login attempt for email: {email} from IP: {request.remote_addr}")
        return jsonify({'error': 'Nieprawidłowe dane logowania'}), 401
    except Error as e:
        return jsonify({'error': str(e)}), 500

@app.route('/logout')
def logout():
    user = session.get('username')
    session.clear()
    if user:
        app.logger.info(f"User logged out: {user}")
    return redirect(url_for('index'))

@app.route('/archive')
def archive():
    page = request.args.get('page', 1, type=int)
    category = request.args.get('category', '')
    sort = request.args.get('sort', 'newest')

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT * FROM categories ORDER BY nazwa")
    categories = cursor.fetchall()

    query = "SELECT f.*, c.nazwa as kategoria FROM facts f LEFT JOIN categories c ON f.kategoria_id = c.id WHERE f.status = 'opublikowany'"
    params = []

    if category:
        query += " AND c.id = %s"
        params.append(category)

    if sort == 'newest':
        query += " ORDER BY f.data_publikacji DESC"
    else:
        query += " ORDER BY f.data_publikacji ASC"

    limit = 10
    offset = (page - 1) * limit
    
    query += " LIMIT %s OFFSET %s"
    params.append(limit)
    params.append(offset)

    cursor.execute(query, params)
    facts = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template('archive.html', facts=facts, categories=categories, current_page=page,
                           current_user=session.get('user_id'))

@app.route('/api/random-fact')
def random_fact():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute('''SELECT f.*, c.nazwa as kategoria 
                      FROM facts f 
                      LEFT JOIN categories c ON f.kategoria_id = c.id 
                      WHERE f.status = 'opublikowany' 
                      ORDER BY RAND() LIMIT 1''')
    fact = cursor.fetchone()
    cursor.close()
    conn.close()
    return jsonify(fact)

# --- NOWE FUNKCJE (KOMENTARZE ZAGNIEŻDŻONE, REAKCJE, ZDJĘCIA) ---

@app.route('/api/fact/<int:fact_id>')
def get_fact(fact_id):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    # Pobierz fakt
    cursor.execute('''SELECT f.*, c.nazwa as kategoria, u.username as autor
                      FROM facts f 
                      LEFT JOIN categories c ON f.kategoria_id = c.id
                      LEFT JOIN users u ON f.user_id_autora = u.id
                      WHERE f.id = %s''', (fact_id,))
    fact = cursor.fetchone()
    
    if not fact:
        cursor.close()
        conn.close()
        return jsonify({'error': 'Fakt nie znaleziony'}), 404

    # Pobierz WSZYSTKIE komentarze + moje reakcje
    user_id = session.get('user_id')
    cursor.execute('''
        SELECT 
            c.*, 
            u.username,
            (SELECT COUNT(*) FROM reactions r WHERE r.comment_id = c.id) as total_reactions,
            (SELECT typ_reakcji FROM reactions r WHERE r.comment_id = c.id AND r.user_id = %s) as my_reaction
        FROM comments c
        LEFT JOIN users u ON c.user_id = u.id
        WHERE c.fact_id = %s
        ORDER BY c.data_dodania ASC
    ''', (user_id, fact_id))
    
    comments = cursor.fetchall()
    cursor.close()
    conn.close()
    return jsonify({'fact': fact, 'comments': comments})

@app.route('/api/comment', methods=['POST'])
@limiter.limit("10 per minute")
def add_comment():
    data = request.json
    fact_id = data.get('fact_id')
    tresc = data.get('tresc')
    parent_id = data.get('parent_id') # Obsługa odpowiedzi
    image_url = data.get('image_url') # Obsługa zdjęć

    if not tresc or len(tresc.strip()) == 0:
        return jsonify({'error': 'Komentarz nie może być pusty'}), 400

    user_id = session.get('user_id')
    pseudonim = 'Gość'

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('''INSERT INTO comments (fact_id, user_id, pseudonim_goscia, tresc, parent_comment_id, image_url)
                         VALUES (%s, %s, %s, %s, %s, %s)''',
                       (fact_id, user_id, pseudonim if not user_id else None, tresc, parent_id, image_url))
        conn.commit()
        cursor.close()
        conn.close()
        app.logger.info(f"Comment added to fact {fact_id} from IP {request.remote_addr}")
        return jsonify({'success': 'Komentarz dodany'}), 201
    except Error as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/reaction', methods=['POST'])
def add_reaction():
    if not session.get('user_id'):
        return jsonify({'error': 'Musisz być zalogowany'}), 401
        
    data = request.json
    comment_id = data.get('comment_id')
    typ = data.get('typ')

    valid_types = ['like', 'love', 'haha', 'wow', 'sad']
    if typ not in valid_types:
         return jsonify({'error': 'Nieznany typ reakcji'}), 400

    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        # Logika Toggle (Dodaj/Zmień/Usuń)
        cursor.execute("SELECT * FROM reactions WHERE user_id = %s AND comment_id = %s", 
                       (session['user_id'], comment_id))
        existing = cursor.fetchone()

        if existing:
            if existing['typ_reakcji'] == typ:
                # Kliknął to samo -> Cofnij
                cursor.execute("DELETE FROM reactions WHERE id = %s", (existing['id'],))
                msg = 'Reakcja cofnięta'
            else:
                # Kliknął co innego -> Zmień
                cursor.execute("UPDATE reactions SET typ_reakcji = %s WHERE id = %s", (typ, existing['id']))
                msg = 'Reakcja zmieniona'
        else:
            # Nowa
            cursor.execute("INSERT INTO reactions (comment_id, user_id, typ_reakcji) VALUES (%s, %s, %s)",
                           (comment_id, session['user_id'], typ))
            msg = 'Reakcja dodana'

        conn.commit()
        cursor.close()
        conn.close()
        return jsonify({'success': msg}), 200
    except Error as e:
        return jsonify({'error': str(e)}), 500

@app.route('/submit-fact', methods=['GET', 'POST'])
def submit_fact():
    if not session.get('user_id'):
        return redirect(url_for('index'))
    if request.method == 'GET':
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM categories ORDER BY nazwa")
        categories = cursor.fetchall()
        cursor.close()
        conn.close()
        return render_template('submit_fact.html', categories=categories, current_user=session.get('user_id'))
    
    data = request.form
    tytul = data.get('tytul')
    tresc = data.get('tresc')
    zrodlo = data.get('zrodlo')
    kategoria_id = data.get('kategoria_id')

    if not all([tytul, tresc, kategoria_id]):
        return jsonify({'error': 'Wszystkie pola są wymagane'}), 400
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        if session.get('rola') in ['admin', 'moderator']:
            cursor.execute('''INSERT INTO facts (tytul, tresc, zrodlo, kategoria_id, user_id_autora, status, data_publikacji)
                             VALUES (%s, %s, %s, %s, %s, %s, NOW())''',
                           (tytul, tresc, zrodlo, kategoria_id, session['user_id'], 'opublikowany'))
            msg = 'Fakt opublikowany!'
        else:
            cursor.execute('''INSERT INTO facts (tytul, tresc, zrodlo, kategoria_id, user_id_autora, status)
                             VALUES (%s, %s, %s, %s, %s, %s)''',
                           (tytul, tresc, zrodlo, kategoria_id, session['user_id'], 'oczekujacy'))
            msg = 'Fakt wysłany do moderacji!'
        conn.commit()
        cursor.close()
        conn.close()
        app.logger.info(f"Fact submitted by user {session['user_id']} (Status: {msg})")
        return jsonify({'success': msg}), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/profile')
def profile():
    if not session.get('user_id'):
        return redirect(url_for('index'))
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM users WHERE id = %s", (session['user_id'],))
    user = cursor.fetchone()
    cursor.execute('''SELECT f.*, c.nazwa as kategoria FROM facts f 
                      LEFT JOIN categories c ON f.kategoria_id = c.id
                      WHERE f.user_id_autora = %s 
                      ORDER BY f.data_dodania DESC''', (session['user_id'],))
    facts = cursor.fetchall()
    cursor.close()
    conn.close()
    return render_template('profile.html', user=user, facts=facts, current_user=session.get('user_id'))

@app.route('/admin')
def admin():
    if not session.get('user_id') or session.get('rola') not in ['admin', 'moderator']:
        app.logger.warning(f"Unauthorized admin access attempt from user {session.get('user_id')}")
        return redirect(url_for('index'))
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute('''SELECT f.*, c.nazwa as kategoria, u.username as autor FROM facts f 
                      LEFT JOIN categories c ON f.kategoria_id = c.id
                      LEFT JOIN users u ON f.user_id_autora = u.id
                      WHERE f.status IN ('oczekujacy', 'odrzucony') 
                      ORDER BY f.data_dodania DESC''')
    pending_facts = cursor.fetchall()
    pending_count = len([f for f in pending_facts if f['status'] == 'oczekujacy'])
    cursor.close()
    conn.close()
    return render_template('admin.html', pending_facts=pending_facts, pending_count=pending_count,
                           current_user=session.get('user_id'))

@app.route('/api/approve-fact/<int:fact_id>', methods=['POST'])
def approve_fact(fact_id):
    if not session.get('user_id') or session.get('rola') not in ['admin', 'moderator']:
        return jsonify({'error': 'Brak uprawnień'}), 403
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('''UPDATE facts SET status = 'opublikowany', data_publikacji = NOW() 
                         WHERE id = %s''', (fact_id,))
        conn.commit()
        cursor.close()
        conn.close()
        app.logger.info(f"Fact {fact_id} approved by moderator {session['user_id']}")
        return jsonify({'success': 'Fakt zatwierdzony'}), 200
    except Error as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/reject-fact/<int:fact_id>', methods=['POST'])
def reject_fact(fact_id):
    if not session.get('user_id') or session.get('rola') not in ['admin', 'moderator']:
        return jsonify({'error': 'Brak uprawnień'}), 403
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('''UPDATE facts SET status = 'odrzucony' WHERE id = %s''', (fact_id,))
        conn.commit()
        cursor.close()
        conn.close()
        app.logger.info(f"Fact {fact_id} rejected by moderator {session['user_id']}")
        return jsonify({'success': 'Fakt odrzucony'}), 200
    except Error as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    debug_mode = os.environ.get('FLASK_DEBUG', 'False') == 'True'
    app.run(debug=debug_mode, host='0.0.0.0', port=5000)