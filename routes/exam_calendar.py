"""
Deneme Sınavı Takvimi API
Admin sınav tarihleri ekleyebilir, öğrenci/öğretmen görüntüleyebilir
"""

from flask import Blueprint, request, jsonify
from flask_login import login_required, current_user
from psycopg2.extras import RealDictCursor
from datetime import datetime, timedelta
import logging
import psycopg2
import os

logger = logging.getLogger(__name__)

def get_send_push_notification():
    """Lazy import to avoid circular imports"""
    from app import send_push_notification
    return send_push_notification

exam_calendar_bp = Blueprint('exam_calendar', __name__, url_prefix='/api/exam-calendar')

def get_db():
    return psycopg2.connect(os.environ.get('DATABASE_URL'))

@exam_calendar_bp.route('', methods=['POST'])
@login_required
def create_exam_date():
    """Admin sınav tarihi ekler"""
    if current_user.role != 'admin':
        return jsonify({"error": "Yetkisiz erişim"}), 403
    
    data = request.get_json()
    exam_date = data.get('exam_date') or data.get('date')
    exam_title = data.get('exam_title') or data.get('description', 'Deneme Sınavı')
    description = data.get('description', '')
    classes = data.get('classes', '')
    
    if not exam_date:
        return jsonify({"error": "Sınav tarihi gerekli"}), 400
    
    if not classes:
        return jsonify({"error": "En az bir sınıf seçilmeli"}), 400
    
    try:
        date_obj = datetime.strptime(exam_date, '%Y-%m-%d').date()
    except ValueError:
        return jsonify({"error": "Geçersiz tarih formatı (YYYY-MM-DD)"}), 400
    
    conn = get_db()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    
    try:
        cur.execute("""
            INSERT INTO exam_calendar (exam_date, exam_title, description, classes, created_by)
            VALUES (%s, %s, %s, %s, %s)
            RETURNING id, exam_date, exam_title, description, classes, created_at
        """, (date_obj, exam_title, description, classes, current_user.id))
        
        result = cur.fetchone()
        conn.commit()
        
        # Push notification gönder - öğrencilere ve öğretmenlere
        try:
            send_push = get_send_push_notification()
            target_classes_list = [c.strip() for c in classes.split(',') if c.strip()]
            formatted_date = date_obj.strftime('%d.%m.%Y')
            
            # Öğrencilere bildirim
            send_push(
                title="📅 Yeni Sınav Tarihi",
                message=f"{exam_title} - {formatted_date}",
                url="https://ameo-alanya.com/student/exam-calendar",
                target_classes=target_classes_list,
                target_role="student"
            )
            
            # Öğretmenlere bildirim
            send_push(
                title="📅 Sınav Takvimi Güncellendi",
                message=f"{exam_title} - {formatted_date} ({classes})",
                url="https://ameo-alanya.com/teacher/exam-calendar",
                target_role="teacher"
            )
            logger.info(f"📅 Sınav takvimi bildirimi gönderildi: {exam_title}")
        except Exception as notif_error:
            logger.error(f"Sınav takvimi bildirimi gönderilemedi: {notif_error}")
        
        return jsonify({
            "success": True,
            "exam": {
                "id": result['id'],
                "exam_date": str(result['exam_date']),
                "exam_title": result['exam_title'],
                "description": result['description'],
                "classes": result['classes'],
                "created_at": result['created_at'].isoformat()
            }
        }), 201
        
    except psycopg2.IntegrityError as ie:
        conn.rollback()
        if 'unique constraint' in str(ie).lower():
            return jsonify({"error": "Bu tarihte zaten bir sınav var"}), 409
        return jsonify({"error": "Veritabanı hatası"}), 500
    except Exception as e:
        conn.rollback()
        logger.error(f"Create exam calendar error: {e}")
        return jsonify({"error": "Sınav eklenirken hata oluştu"}), 500
    finally:
        cur.close()
        conn.close()

@exam_calendar_bp.route('/<int:exam_id>', methods=['DELETE'])
@login_required
def delete_exam_date(exam_id):
    """Admin sınav tarihi siler"""
    if current_user.role != 'admin':
        return jsonify({"error": "Yetkisiz erişim"}), 403
    
    conn = get_db()
    cur = conn.cursor()
    
    try:
        cur.execute("DELETE FROM exam_calendar WHERE id = %s RETURNING id", (exam_id,))
        result = cur.fetchone()
        
        if not result:
            return jsonify({"error": "Sınav bulunamadı"}), 404
        
        conn.commit()
        return jsonify({"success": True, "message": "Sınav silindi"}), 200
        
    except Exception as e:
        conn.rollback()
        logger.error(f"Delete exam calendar error: {e}")
        return jsonify({"error": "Sınav silinirken hata oluştu"}), 500
    finally:
        cur.close()
        conn.close()

@exam_calendar_bp.route('/monthly', methods=['GET'])
@login_required
def get_monthly_exams():
    """Aylık sınav takvimini döndürür (öğrenci/öğretmen/admin)"""
    year = request.args.get('year', type=int, default=datetime.now().year)
    month = request.args.get('month', type=int, default=datetime.now().month)
    
    if not (1 <= month <= 12):
        return jsonify({"error": "Geçersiz ay (1-12 arası olmalı)"}), 400
    
    try:
        start_date = datetime(year, month, 1).date()
        if month == 12:
            end_date = datetime(year + 1, 1, 1).date() - timedelta(days=1)
        else:
            end_date = datetime(year, month + 1, 1).date() - timedelta(days=1)
    except ValueError:
        return jsonify({"error": "Geçersiz tarih"}), 400
    
    conn = get_db()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    
    try:
        cur.execute("""
            SELECT id, exam_date, exam_title, description, created_at
            FROM exam_calendar
            WHERE exam_date BETWEEN %s AND %s
            ORDER BY exam_date ASC
        """, (start_date, end_date))
        
        exams = cur.fetchall()
        
        return jsonify({
            "success": True,
            "year": year,
            "month": month,
            "exams": [{
                "id": e['id'],
                "exam_date": str(e['exam_date']),
                "exam_title": e['exam_title'],
                "description": e['description'],
                "created_at": e['created_at'].isoformat()
            } for e in exams]
        }), 200
        
    except Exception as e:
        logger.error(f"Get monthly exams error: {e}")
        return jsonify({"error": "Sınav takvimi getirilirken hata oluştu"}), 500
    finally:
        cur.close()
        conn.close()
