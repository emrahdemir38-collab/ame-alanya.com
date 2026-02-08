"""
Öğrenci-Öğretmen Soru Sorma Sistemi Blueprint
Öğrenciler deneme sorularında yardım isteyebilir, öğretmenler cevaplayabilir
"""
from flask import Blueprint, request, jsonify
from flask_login import login_required, current_user
import psycopg2
from psycopg2.extras import RealDictCursor
import os
import logging

logger = logging.getLogger(__name__)

question_asks_bp = Blueprint('question_asks', __name__, url_prefix='/api/question-asks')

def get_db():
    return psycopg2.connect(os.environ.get('DATABASE_URL'))

VALID_REASONS = [
    "Bilgi Eksikliği",
    "Soruyu Yanlış Anlama",
    "Diğer"
]

@question_asks_bp.route('/create', methods=['POST'])
@login_required
def create_question_ask():
    """Öğrenci öğretmene soru sorar"""
    if current_user.role != 'student':
        return jsonify({"error": "Sadece öğrenciler soru sorabilir"}), 403
    
    data = request.get_json()
    required_fields = ['teacher_id', 'practice_exam_id', 'subject', 'question_number', 'reason']
    
    if not all(field in data for field in required_fields):
        return jsonify({"error": "Eksik alanlar"}), 400
    
    if data['reason'] not in VALID_REASONS:
        return jsonify({"error": f"Geçersiz neden. Geçerli seçenekler: {', '.join(VALID_REASONS)}"}), 400
    
    conn = get_db()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    
    try:
        cur.execute("""
            SELECT id FROM practice_exams 
            WHERE id = %s AND student_id = %s
        """, (data['practice_exam_id'], current_user.id))
        
        if not cur.fetchone():
            return jsonify({"error": "Deneme bulunamadı veya size ait değil"}), 404
        
        cur.execute("""
            SELECT u.id, u.full_name FROM users u
            WHERE u.id = %s AND u.role = 'teacher'
            AND (
                %s IN (
                    SELECT student_id FROM teacher_students WHERE teacher_id = u.id
                )
                OR (
                    SELECT class_name FROM users WHERE id = %s
                ) IN (
                    SELECT class_name FROM teacher_classes WHERE teacher_id = u.id
                )
            )
        """, (data['teacher_id'], current_user.id, current_user.id))
        
        teacher = cur.fetchone()
        if not teacher:
            return jsonify({"error": "Bu öğretmene soru soramazsınız"}), 403
        
        cur.execute("""
            INSERT INTO question_asks 
            (student_id, teacher_id, practice_exam_id, subject, question_number, reason, student_note, status)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING id
        """, (
            current_user.id,
            data['teacher_id'],
            data['practice_exam_id'],
            data['subject'],
            data['question_number'],
            data['reason'],
            data.get('student_note'),
            'pending'
        ))
        
        ask_id = cur.fetchone()['id']
        conn.commit()
        
        return jsonify({
            "success": True,
            "message": f"Sorunuz {teacher['full_name']} öğretmenine gönderildi",
            "ask_id": ask_id
        }), 201
    except Exception as e:
        conn.rollback()
        logger.error(f"Create question ask error: {e}")
        return jsonify({"error": "Soru gönderilirken hata oluştu"}), 500
    finally:
        cur.close()
        conn.close()

@question_asks_bp.route('/student/me', methods=['GET'])
@login_required
def get_my_questions():
    """Öğrencinin sorduğu soruları getirir"""
    if current_user.role != 'student':
        return jsonify({"error": "Yetkisiz erişim"}), 403
    
    conn = get_db()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    
    try:
        cur.execute("""
            SELECT 
                qa.*,
                pe.exam_number,
                t.full_name as teacher_name
            FROM question_asks qa
            JOIN practice_exams pe ON qa.practice_exam_id = pe.id
            JOIN users t ON qa.teacher_id = t.id
            WHERE qa.student_id = %s
            ORDER BY qa.created_at DESC
        """, (current_user.id,))
        
        questions = cur.fetchall()
        
        return jsonify({
            "success": True,
            "total": len(questions),
            "pending": sum(1 for q in questions if q['status'] == 'pending'),
            "answered": sum(1 for q in questions if q['status'] == 'answered'),
            "questions": [dict(q) for q in questions]
        })
    except Exception as e:
        logger.error(f"Get student questions error: {e}")
        return jsonify({"error": "Sorular yüklenirken hata oluştu"}), 500
    finally:
        cur.close()
        conn.close()

@question_asks_bp.route('/teacher/me', methods=['GET'])
@login_required
def get_teacher_questions():
    """Öğretmene gelen soruları getirir"""
    if current_user.role != 'teacher':
        return jsonify({"error": "Yetkisiz erişim"}), 403
    
    status_filter = request.args.get('status', 'all')
    
    conn = get_db()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    
    try:
        where_clause = "qa.teacher_id = %s"
        params = [current_user.id]
        
        if status_filter in ['pending', 'answered']:
            where_clause += " AND qa.status = %s"
            params.append(status_filter)
        
        cur.execute(f"""
            SELECT 
                qa.*,
                pe.exam_number,
                s.full_name as student_name,
                s.class_name as student_class
            FROM question_asks qa
            JOIN practice_exams pe ON qa.practice_exam_id = pe.id
            JOIN users s ON qa.student_id = s.id
            WHERE {where_clause}
            ORDER BY qa.status ASC, qa.created_at DESC
        """, params)
        
        questions = cur.fetchall()
        
        return jsonify({
            "success": True,
            "total": len(questions),
            "pending": sum(1 for q in questions if q['status'] == 'pending'),
            "answered": sum(1 for q in questions if q['status'] == 'answered'),
            "questions": [dict(q) for q in questions]
        })
    except Exception as e:
        logger.error(f"Get teacher questions error: {e}")
        return jsonify({"error": "Sorular yüklenirken hata oluştu"}), 500
    finally:
        cur.close()
        conn.close()

@question_asks_bp.route('/<int:ask_id>/respond', methods=['PUT'])
@login_required
def respond_to_question(ask_id):
    """Öğretmen soruya cevap verir"""
    if current_user.role != 'teacher':
        return jsonify({"error": "Sadece öğretmenler cevap verebilir"}), 403
    
    data = request.get_json()
    
    if 'teacher_response' not in data or not data['teacher_response'].strip():
        return jsonify({"error": "Cevap alanı boş olamaz"}), 400
    
    conn = get_db()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    
    try:
        cur.execute("""
            SELECT * FROM question_asks 
            WHERE id = %s AND teacher_id = %s
        """, (ask_id, current_user.id))
        
        question = cur.fetchone()
        if not question:
            return jsonify({"error": "Soru bulunamadı veya size ait değil"}), 404
        
        cur.execute("""
            UPDATE question_asks 
            SET teacher_response = %s,
                status = 'answered',
                answered_at = CURRENT_TIMESTAMP
            WHERE id = %s
        """, (data['teacher_response'], ask_id))
        
        conn.commit()
        
        return jsonify({
            "success": True,
            "message": "Cevabınız gönderildi"
        }), 200
    except Exception as e:
        conn.rollback()
        logger.error(f"Respond to question error: {e}")
        return jsonify({"error": "Cevap gönderilirken hata oluştu"}), 500
    finally:
        cur.close()
        conn.close()

@question_asks_bp.route('/practice-exams/my-exams', methods=['GET'])
@login_required
def get_my_practice_exams():
    """Öğrencinin deneme sınavlarını getirir"""
    if current_user.role != 'student':
        return jsonify({"error": "Yetkisiz erişim"}), 403
    
    conn = get_db()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    
    try:
        cur.execute("""
            SELECT 
                id,
                exam_number,
                COALESCE(turkce_net, 0) + COALESCE(matematik_net, 0) + COALESCE(fen_net, 0) + 
                COALESCE(sosyal_net, 0) + COALESCE(ingilizce_net, 0) + COALESCE(din_net, 0) as total_net,
                lgs_score,
                created_at
            FROM practice_exams
            WHERE student_id = %s
            ORDER BY exam_number ASC
        """, (current_user.id,))
        
        exams = cur.fetchall()
        
        return jsonify({
            "success": True,
            "total": len(exams),
            "exams": [dict(e) for e in exams]
        })
    except Exception as e:
        logger.error(f"Get practice exams error: {e}")
        return jsonify({"error": "Denemeler yüklenirken hata oluştu"}), 500
    finally:
        cur.close()
        conn.close()

@question_asks_bp.route('/teachers/my-teachers', methods=['GET'])
@login_required
def get_my_teachers():
    """Öğrencinin atanmış öğretmenlerini getirir"""
    if current_user.role != 'student':
        return jsonify({"error": "Yetkisiz erişim"}), 403
    
    conn = get_db()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    
    try:
        cur.execute("""
            SELECT DISTINCT u.id, u.full_name, u.username
            FROM users u
            WHERE u.role = 'teacher' AND (
                u.id IN (
                    SELECT teacher_id FROM teacher_students WHERE student_id = %s
                )
                OR u.id IN (
                    SELECT tc.teacher_id 
                    FROM teacher_classes tc
                    WHERE tc.class_name = (SELECT class_name FROM users WHERE id = %s)
                )
            )
            ORDER BY u.full_name
        """, (current_user.id, current_user.id))
        
        teachers = cur.fetchall()
        
        return jsonify({
            "success": True,
            "total": len(teachers),
            "teachers": [dict(t) for t in teachers]
        })
    except Exception as e:
        logger.error(f"Get teachers error: {e}")
        return jsonify({"error": "Öğretmenler yüklenirken hata oluştu"}), 500
    finally:
        cur.close()
        conn.close()
