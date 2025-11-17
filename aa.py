from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import mysql.connector
from mysql.connector import Error
import os

app = Flask(__name__)
app.secret_key = 'your-secret-key-change-in-production-12345'

DB_CONFIG = {
    'host': os.environ.get('DB_HOST'),
    'user': os.environ.get('DB_USER'),
    'password': os.environ.get('DB_PASSWORD'),
    'database': os.environ.get('DB_NAME')
}

def get_db_connection():
    return mysql.connector.connect(**DB_CONFIG)


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
        cursor.execute("INSERT INTO users (username, email, password_hash) VALUES (%s, %s, %s)",
                       (username, email, password_hash))
        conn.commit()
        cursor.close()
        conn.close()
        return jsonify({'success': 'Rejestracja udana! Zaloguj się.'}), 201
    except Error:
        return jsonify({'error': 'Email lub nazwa użytkownika już istnieje'}), 400


@app.route('/login', methods=['POST'])
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
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['rola'] = user['rola']
            cursor.close()
            conn.close()
            return jsonify({'success': 'Zalogowano pomyślnie'}), 200

        cursor.close()
        conn.close()
        return jsonify({'error': 'Nieprawidłowe dane logowania'}), 401
    except Error as e:
        return jsonify({'error': str(e)}), 500


@app.route('/logout')
def logout():
    session.clear()
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

    if category:
        query += " AND c.id = " + str(int(category))

    if sort == 'newest':
        query += " ORDER BY f.data_publikacji DESC"
    else:
        query += " ORDER BY f.data_publikacji ASC"

    limit = 10
    offset = (page - 1) * limit
    query += f" LIMIT {limit} OFFSET {offset}"

    cursor.execute(query)
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


@app.route('/api/fact/<int:fact_id>')
def get_fact(fact_id):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

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

    cursor.execute('''SELECT c.*, u.username, COUNT(DISTINCT r.id) as likes
                      FROM comments c
                      LEFT JOIN users u ON c.user_id = u.id
                      LEFT JOIN reactions r ON c.id = r.comment_id AND r.typ_reakcji = 'like'
                      WHERE c.fact_id = %s AND c.parent_comment_id IS NULL
                      GROUP BY c.id
                      ORDER BY c.data_dodania DESC''', (fact_id,))
    comments = cursor.fetchall()

    cursor.close()
    conn.close()
    return jsonify({'fact': fact, 'comments': comments})


@app.route('/api/comment', methods=['POST'])
def add_comment():
    data = request.json
    fact_id = data.get('fact_id')
    tresc = data.get('tresc')

    if not tresc or len(tresc.strip()) == 0:
        return jsonify({'error': 'Komentarz nie może być pusty'}), 400

    user_id = session.get('user_id')
    pseudonim = 'Gość'

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('''INSERT INTO comments (fact_id, user_id, pseudonim_goscia, tresc)
                         VALUES (%s, %s, %s, %s)''',
                       (fact_id, user_id, pseudonim if not user_id else None, tresc))
        conn.commit()
        cursor.close()
        conn.close()
        return jsonify({'success': 'Komentarz dodany'}), 201
    except Error as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/reaction', methods=['POST'])
def add_reaction():
    if not session.get('user_id'):
        return jsonify({'error': 'Musisz być zalogowany'}), 401

    data = request.json
    comment_id = data.get('comment_id')

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('''INSERT INTO reactions (comment_id, user_id, typ_reakcji)
                         VALUES (%s, %s, %s)''',
                       (comment_id, session['user_id'], 'like'))
        conn.commit()
        cursor.close()
        conn.close()
        return jsonify({'success': 'Polubienie dodane'}), 201
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
        return jsonify({'success': 'Fakt odrzucony'}), 200
    except Error as e:
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)