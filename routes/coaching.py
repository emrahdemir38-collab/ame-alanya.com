"""
Koçluk ve İletişim Sistemi Blueprint
- Konu Tekrar Talepleri (Öğrenci → Öğretmen)
- Veli Mesajları (Veli → Öğretmen)
- Öğretmen Notları (Öğretmen → Öğrenci/Veli)
"""
from flask import Blueprint, request, jsonify
from flask_login import login_required, current_user
import psycopg2
from psycopg2.extras import RealDictCursor
import os
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

coaching_bp = Blueprint('coaching', __name__, url_prefix='/api/coaching')

def get_db():
    return psycopg2.connect(os.environ.get('DATABASE_URL'))

@coaching_bp.route('/topic-requests', methods=['GET'])
@login_required
def get_topic_requests():
    """Konu tekrar taleplerini getir"""
    conn = get_db()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    
    try:
        if current_user.role == 'student':
            cur.execute("""
                SELECT tr.*, u.full_name as teacher_name
                FROM topic_requests tr
                LEFT JOIN users u ON tr.teacher_id = u.id
                WHERE tr.student_id = %s
                ORDER BY tr.created_at DESC
            """, (current_user.id,))
        elif current_user.role == 'teacher':
            cur.execute("""
                SELECT tr.*, u.full_name as student_name, u.class_name
                FROM topic_requests tr
                JOIN users u ON tr.student_id = u.id
                WHERE tr.teacher_id = %s OR tr.teacher_id IS NULL
                ORDER BY 
                    CASE tr.status 
                        WHEN 'pending' THEN 1
                        WHEN 'answered' THEN 2
                        ELSE 3
                    END,
                    tr.created_at DESC
            """, (current_user.id,))
        else:
            return jsonify({"error": "Yetkisiz erişim"}), 403
        
        requests_list = cur.fetchall()
        return jsonify({
            "success": True,
            "requests": [{
                "id": r['id'],
                "student_id": r['student_id'],
                "student_name": r.get('student_name'),
                "class_name": r.get('class_name'),
                "teacher_name": r.get('teacher_name'),
                "subject": r['subject'],
                "topic": r['topic'],
                "request_message": r['request_message'],
                "teacher_response": r.get('teacher_response'),
                "status": r['status'],
                "created_at": r['created_at'].isoformat(),
                "responded_at": r['responded_at'].isoformat() if r.get('responded_at') else None
            } for r in requests_list]
        })
    except Exception as e:
        logger.error(f"Get topic requests error: {e}")
        return jsonify({"error": "İşlem sırasında hata oluştu"}), 500
    finally:
        cur.close()
        conn.close()

@coaching_bp.route('/topic-requests', methods=['POST'])
@login_required
def create_topic_request():
    """Öğrenci konu tekrar talebi oluşturur"""
    if current_user.role != 'student':
        return jsonify({"error": "Sadece öğrenciler talep oluşturabilir"}), 403
    
    data = request.get_json()
    required_fields = ['subject', 'topic', 'request_message']
    
    if not all(field in data for field in required_fields):
        return jsonify({"error": "Eksik alanlar"}), 400
    
    conn = get_db()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    
    try:
        cur.execute("""
            INSERT INTO topic_requests 
            (student_id, teacher_id, subject, topic, request_message, status)
            VALUES (%s, %s, %s, %s, %s, 'pending')
            RETURNING id
        """, (
            current_user.id,
            data.get('teacher_id'),
            data['subject'],
            data['topic'],
            data['request_message']
        ))
        
        request_id = cur.fetchone()['id']
        conn.commit()
        
        return jsonify({
            "success": True,
            "message": "Talep oluşturuldu",
            "request_id": request_id
        }), 201
    except Exception as e:
        conn.rollback()
        logger.error(f"Create topic request error: {e}")
        return jsonify({"error": "İşlem sırasında hata oluştu"}), 500
    finally:
        cur.close()
        conn.close()

@coaching_bp.route('/topic-requests/<int:request_id>/respond', methods=['POST'])
@login_required
def respond_topic_request(request_id):
    """Öğretmen talebi yanıtlar"""
    if current_user.role != 'teacher':
        return jsonify({"error": "Sadece öğretmenler yanıtlayabilir"}), 403
    
    data = request.get_json()
    if 'response' not in data:
        return jsonify({"error": "Yanıt gerekli"}), 400
    
    conn = get_db()
    cur = conn.cursor()
    
    try:
        cur.execute("""
            UPDATE topic_requests 
            SET teacher_response = %s, 
                status = 'answered',
                teacher_id = %s,
                responded_at = CURRENT_TIMESTAMP
            WHERE id = %s
        """, (data['response'], current_user.id, request_id))
        
        if cur.rowcount == 0:
            conn.rollback()
            return jsonify({"error": "Talep bulunamadı"}), 404
        
        conn.commit()
        return jsonify({"success": True, "message": "Yanıt gönderildi"}), 200
    except Exception as e:
        conn.rollback()
        logger.error(f"Respond topic request error: {e}")
        return jsonify({"error": "İşlem sırasında hata oluştu"}), 500
    finally:
        cur.close()
        conn.close()

@coaching_bp.route('/parent-messages', methods=['GET'])
@login_required
def get_parent_messages():
    """Veli mesajlarını getir"""
    if current_user.role != 'teacher':
        return jsonify({"error": "Sadece öğretmenler veli mesajlarını görebilir"}), 403
    
    conn = get_db()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    
    try:
        cur.execute("""
            SELECT pm.*, u.full_name as student_name, u.class_name
            FROM parent_messages pm
            JOIN users u ON pm.student_id = u.id
            ORDER BY 
                CASE pm.status 
                    WHEN 'unread' THEN 1
                    WHEN 'read' THEN 2
                    ELSE 3
                END,
                pm.created_at DESC
        """)
        
        messages = cur.fetchall()
        return jsonify({
            "success": True,
            "messages": [{
                "id": m['id'],
                "student_id": m['student_id'],
                "student_name": m['student_name'],
                "class_name": m['class_name'],
                "parent_name": m['parent_name'],
                "parent_email": m.get('parent_email'),
                "parent_phone": m.get('parent_phone'),
                "message": m['message'],
                "teacher_response": m.get('teacher_response'),
                "status": m['status'],
                "created_at": m['created_at'].isoformat(),
                "responded_at": m['responded_at'].isoformat() if m.get('responded_at') else None
            } for m in messages]
        })
    except Exception as e:
        logger.error(f"Get parent messages error: {e}")
        return jsonify({"error": "İşlem sırasında hata oluştu"}), 500
    finally:
        cur.close()
        conn.close()

@coaching_bp.route('/parent-messages', methods=['POST'])
def create_parent_message():
    """Veli mesaj gönderir (kimlik doğrulama gerektirmez)"""
    data = request.get_json()
    required_fields = ['student_id', 'parent_name', 'message']
    
    if not all(field in data for field in required_fields):
        return jsonify({"error": "Eksik alanlar"}), 400
    
    conn = get_db()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    
    try:
        cur.execute("""
            SELECT id FROM users WHERE id = %s AND role = 'student'
        """, (data['student_id'],))
        
        if not cur.fetchone():
            return jsonify({"error": "Öğrenci bulunamadı"}), 404
        
        cur.execute("""
            INSERT INTO parent_messages 
            (student_id, parent_name, parent_email, parent_phone, message, status)
            VALUES (%s, %s, %s, %s, %s, 'unread')
            RETURNING id
        """, (
            data['student_id'],
            data['parent_name'],
            data.get('parent_email'),
            data.get('parent_phone'),
            data['message']
        ))
        
        message_id = cur.fetchone()['id']
        conn.commit()
        
        return jsonify({
            "success": True,
            "message": "Mesajınız öğretmene iletildi",
            "message_id": message_id
        }), 201
    except Exception as e:
        conn.rollback()
        logger.error(f"Create parent message error: {e}")
        return jsonify({"error": "İşlem sırasında hata oluştu"}), 500
    finally:
        cur.close()
        conn.close()

@coaching_bp.route('/parent-messages/<int:message_id>/respond', methods=['POST'])
@login_required
def respond_parent_message(message_id):
    """Öğretmen veli mesajını yanıtlar"""
    if current_user.role != 'teacher':
        return jsonify({"error": "Sadece öğretmenler yanıtlayabilir"}), 403
    
    data = request.get_json()
    if 'response' not in data:
        return jsonify({"error": "Yanıt gerekli"}), 400
    
    conn = get_db()
    cur = conn.cursor()
    
    try:
        cur.execute("""
            UPDATE parent_messages 
            SET teacher_response = %s, 
                status = 'responded',
                responded_at = CURRENT_TIMESTAMP
            WHERE id = %s
        """, (data['response'], message_id))
        
        if cur.rowcount == 0:
            conn.rollback()
            return jsonify({"error": "Mesaj bulunamadı"}), 404
        
        conn.commit()
        return jsonify({"success": True, "message": "Yanıt gönderildi"}), 200
    except Exception as e:
        conn.rollback()
        logger.error(f"Respond parent message error: {e}")
        return jsonify({"error": "İşlem sırasında hata oluştu"}), 500
    finally:
        cur.close()
        conn.close()

@coaching_bp.route('/parent-messages/<int:message_id>/mark-read', methods=['POST'])
@login_required
def mark_parent_message_read(message_id):
    """Öğretmen mesajı okundu olarak işaretle"""
    if current_user.role != 'teacher':
        return jsonify({"error": "Yetkisiz erişim"}), 403
    
    conn = get_db()
    cur = conn.cursor()
    
    try:
        cur.execute("""
            UPDATE parent_messages 
            SET status = 'read'
            WHERE id = %s AND status = 'unread'
        """, (message_id,))
        
        conn.commit()
        return jsonify({"success": True}), 200
    except Exception as e:
        conn.rollback()
        logger.error(f"Mark parent message read error: {e}")
        return jsonify({"error": "İşlem sırasında hata oluştu"}), 500
    finally:
        cur.close()
        conn.close()

@coaching_bp.route('/teacher-notes/student', methods=['GET'])
@login_required
def get_teacher_student_notes():
    """Öğretmen→Öğrenci notlarını getir"""
    conn = get_db()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    
    try:
        if current_user.role == 'student':
            cur.execute("""
                SELECT tsn.*, u.full_name as teacher_name
                FROM teacher_student_notes tsn
                JOIN users u ON tsn.teacher_id = u.id
                WHERE tsn.student_id = %s
                ORDER BY tsn.created_at DESC
            """, (current_user.id,))
        elif current_user.role == 'teacher':
            student_id = request.args.get('student_id')
            if student_id:
                cur.execute("""
                    SELECT tsn.*, u.full_name as student_name
                    FROM teacher_student_notes tsn
                    JOIN users u ON tsn.student_id = u.id
                    WHERE tsn.teacher_id = %s AND tsn.student_id = %s
                    ORDER BY tsn.created_at DESC
                """, (current_user.id, student_id))
            else:
                cur.execute("""
                    SELECT tsn.*, u.full_name as student_name, u.class_name
                    FROM teacher_student_notes tsn
                    JOIN users u ON tsn.student_id = u.id
                    WHERE tsn.teacher_id = %s
                    ORDER BY tsn.created_at DESC
                """, (current_user.id,))
        else:
            return jsonify({"error": "Yetkisiz erişim"}), 403
        
        notes = cur.fetchall()
        return jsonify({
            "success": True,
            "notes": [{
                "id": n['id'],
                "teacher_id": n['teacher_id'],
                "student_id": n['student_id'],
                "teacher_name": n.get('teacher_name'),
                "student_name": n.get('student_name'),
                "class_name": n.get('class_name'),
                "note_type": n['note_type'],
                "subject": n.get('subject'),
                "message": n['message'],
                "is_read": n['is_read'],
                "created_at": n['created_at'].isoformat()
            } for n in notes]
        })
    except Exception as e:
        logger.error(f"Get teacher student notes error: {e}")
        return jsonify({"error": "İşlem sırasında hata oluştu"}), 500
    finally:
        cur.close()
        conn.close()

@coaching_bp.route('/teacher-notes/student', methods=['POST'])
@login_required
def create_teacher_student_note():
    """Öğretmen öğrenciye not yazar"""
    if current_user.role != 'teacher':
        return jsonify({"error": "Sadece öğretmenler not yazabilir"}), 403
    
    data = request.get_json()
    required_fields = ['student_id', 'note_type', 'message']
    
    if not all(field in data for field in required_fields):
        return jsonify({"error": "Eksik alanlar"}), 400
    
    conn = get_db()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    
    try:
        cur.execute("""
            INSERT INTO teacher_student_notes 
            (teacher_id, student_id, note_type, subject, message, is_read)
            VALUES (%s, %s, %s, %s, %s, false)
            RETURNING id
        """, (
            current_user.id,
            data['student_id'],
            data['note_type'],
            data.get('subject'),
            data['message']
        ))
        
        note_id = cur.fetchone()['id']
        conn.commit()
        
        return jsonify({
            "success": True,
            "message": "Not eklendi",
            "note_id": note_id
        }), 201
    except Exception as e:
        conn.rollback()
        logger.error(f"Create teacher student note error: {e}")
        return jsonify({"error": "İşlem sırasında hata oluştu"}), 500
    finally:
        cur.close()
        conn.close()

@coaching_bp.route('/teacher-notes/parent', methods=['GET'])
@login_required
def get_teacher_parent_notes():
    """Öğretmen→Veli notlarını getir"""
    if current_user.role != 'teacher':
        return jsonify({"error": "Sadece öğretmenler erişebilir"}), 403
    
    conn = get_db()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    
    try:
        student_id = request.args.get('student_id')
        if student_id:
            cur.execute("""
                SELECT tpn.*, u.full_name as student_name
                FROM teacher_parent_notes tpn
                JOIN users u ON tpn.student_id = u.id
                WHERE tpn.teacher_id = %s AND tpn.student_id = %s
                ORDER BY tpn.created_at DESC
            """, (current_user.id, student_id))
        else:
            cur.execute("""
                SELECT tpn.*, u.full_name as student_name, u.class_name
                FROM teacher_parent_notes tpn
                JOIN users u ON tpn.student_id = u.id
                WHERE tpn.teacher_id = %s
                ORDER BY tpn.created_at DESC
            """, (current_user.id,))
        
        notes = cur.fetchall()
        return jsonify({
            "success": True,
            "notes": [{
                "id": n['id'],
                "student_id": n['student_id'],
                "student_name": n['student_name'],
                "class_name": n.get('class_name'),
                "note_type": n['note_type'],
                "message": n['message'],
                "parent_email": n.get('parent_email'),
                "is_sent": n['is_sent'],
                "created_at": n['created_at'].isoformat()
            } for n in notes]
        })
    except Exception as e:
        logger.error(f"Get teacher parent notes error: {e}")
        return jsonify({"error": "İşlem sırasında hata oluştu"}), 500
    finally:
        cur.close()
        conn.close()

@coaching_bp.route('/teacher-notes/parent', methods=['POST'])
@login_required
def create_teacher_parent_note():
    """Öğretmen veliye not yazar"""
    if current_user.role != 'teacher':
        return jsonify({"error": "Sadece öğretmenler not yazabilir"}), 403
    
    data = request.get_json()
    required_fields = ['student_id', 'note_type', 'message']
    
    if not all(field in data for field in required_fields):
        return jsonify({"error": "Eksik alanlar"}), 400
    
    conn = get_db()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    
    try:
        cur.execute("""
            INSERT INTO teacher_parent_notes 
            (teacher_id, student_id, note_type, message, parent_email, is_sent)
            VALUES (%s, %s, %s, %s, %s, false)
            RETURNING id
        """, (
            current_user.id,
            data['student_id'],
            data['note_type'],
            data['message'],
            data.get('parent_email')
        ))
        
        note_id = cur.fetchone()['id']
        conn.commit()
        
        return jsonify({
            "success": True,
            "message": "Veli notu eklendi",
            "note_id": note_id
        }), 201
    except Exception as e:
        conn.rollback()
        logger.error(f"Create teacher parent note error: {e}")
        return jsonify({"error": "İşlem sırasında hata oluştu"}), 500
    finally:
        cur.close()
        conn.close()
