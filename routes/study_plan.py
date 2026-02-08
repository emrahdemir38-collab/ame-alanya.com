"""
Haftalık Ders Çalışma Programı Blueprint
"""
from flask import Blueprint, request, jsonify
from flask_login import login_required, current_user
import psycopg2
from psycopg2.extras import RealDictCursor
import os
import logging

logger = logging.getLogger(__name__)

study_plan_bp = Blueprint('study_plan', __name__, url_prefix='/api/study-plan')

def get_db():
    return psycopg2.connect(os.environ.get('DATABASE_URL'))

@study_plan_bp.route('/schedule', methods=['GET'])
@login_required
def get_schedule():
    """Öğrenci kendi programını, öğretmen tüm programları görüntüler"""
    conn = get_db()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    
    try:
        if current_user.role == 'student':
            cur.execute("""
                SELECT ss.*, u.full_name as created_by_name 
                FROM study_schedules ss
                LEFT JOIN users u ON ss.created_by = u.id
                WHERE ss.student_id = %s
                ORDER BY 
                    CASE ss.day_of_week
                        WHEN 'Pazartesi' THEN 1
                        WHEN 'Salı' THEN 2
                        WHEN 'Çarşamba' THEN 3
                        WHEN 'Perşembe' THEN 4
                        WHEN 'Cuma' THEN 5
                        WHEN 'Cumartesi' THEN 6
                        WHEN 'Pazar' THEN 7
                    END,
                    ss.start_time
            """, (current_user.id,))
        elif current_user.role == 'teacher':
            class_filter = request.args.get('class_name')
            student_filter = request.args.get('student_id')
            
            if student_filter:
                cur.execute("""
                    SELECT ss.*, u.full_name as student_name, u.class_name
                    FROM study_schedules ss
                    JOIN users u ON ss.student_id = u.id
                    WHERE ss.student_id = %s AND ss.created_by = %s
                    ORDER BY 
                        CASE ss.day_of_week
                            WHEN 'Pazartesi' THEN 1
                            WHEN 'Salı' THEN 2
                            WHEN 'Çarşamba' THEN 3
                            WHEN 'Perşembe' THEN 4
                            WHEN 'Cuma' THEN 5
                            WHEN 'Cumartesi' THEN 6
                            WHEN 'Pazar' THEN 7
                        END,
                        ss.start_time
                """, (student_filter, current_user.id))
            elif class_filter:
                cur.execute("""
                    SELECT ss.*, u.full_name as student_name, u.class_name
                    FROM study_schedules ss
                    JOIN users u ON ss.student_id = u.id
                    WHERE u.class_name = %s AND ss.created_by = %s
                    ORDER BY u.full_name, 
                        CASE ss.day_of_week
                            WHEN 'Pazartesi' THEN 1
                            WHEN 'Salı' THEN 2
                            WHEN 'Çarşamba' THEN 3
                            WHEN 'Perşembe' THEN 4
                            WHEN 'Cuma' THEN 5
                            WHEN 'Cumartesi' THEN 6
                            WHEN 'Pazar' THEN 7
                        END,
                        ss.start_time
                """, (class_filter, current_user.id))
            else:
                cur.execute("""
                    SELECT ss.*, u.full_name as student_name, u.class_name
                    FROM study_schedules ss
                    JOIN users u ON ss.student_id = u.id
                    WHERE ss.created_by = %s
                    ORDER BY u.class_name, u.full_name
                """, (current_user.id,))
        else:
            return jsonify({"error": "Yetkisiz erişim"}), 403
        
        schedules = cur.fetchall()
        return jsonify({
            "success": True,
            "schedules": [{
                "id": s['id'],
                "class_id": s.get('class_id'),
                "student_id": s['student_id'],
                "student_name": s.get('student_name'),
                "class_name": s.get('class_name'),
                "day_of_week": s['day_of_week'],
                "subject": s['subject'],
                "topic": s['topic'],
                "start_time": str(s['start_time']),
                "end_time": str(s['end_time']),
                "question_count": s['question_count'],
                "notes": s.get('notes'),
                "created_by_name": s.get('created_by_name'),
                "created_at": s['created_at'].isoformat()
            } for s in schedules]
        })
    except Exception as e:
        logger.error(f"Get schedule error: {e}")
        return jsonify({"error": "Program yüklenirken hata oluştu"}), 500
    finally:
        cur.close()
        conn.close()

@study_plan_bp.route('/schedule', methods=['POST'])
@login_required
def create_schedule():
    """Öğretmen program oluşturur"""
    if current_user.role != 'teacher':
        return jsonify({"error": "Yetkisiz erişim"}), 403
    
    data = request.get_json()
    required_fields = ['student_id', 'day_of_week', 'subject', 'topic', 'start_time', 'end_time', 'question_count']
    
    if not all(field in data for field in required_fields):
        return jsonify({"error": "Eksik alanlar"}), 400
    
    conn = get_db()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    
    try:
        cur.execute("""
            INSERT INTO study_schedules 
            (student_id, day_of_week, subject, topic, start_time, end_time, question_count, notes, created_by)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING id
        """, (
            data['student_id'],
            data['day_of_week'],
            data['subject'],
            data['topic'],
            data['start_time'],
            data['end_time'],
            data['question_count'],
            data.get('notes'),
            current_user.id
        ))
        
        schedule_id = cur.fetchone()['id']
        conn.commit()
        
        return jsonify({
            "success": True,
            "message": "Program oluşturuldu",
            "schedule_id": schedule_id
        }), 201
    except Exception as e:
        conn.rollback()
        logger.error(f"Create schedule error: {e}")
        return jsonify({"error": "Program oluşturulurken hata oluştu"}), 500
    finally:
        cur.close()
        conn.close()

@study_plan_bp.route('/schedule/<int:schedule_id>', methods=['PUT'])
@login_required
def update_schedule(schedule_id):
    """Öğretmen programı günceller"""
    if current_user.role != 'teacher':
        return jsonify({"error": "Yetkisiz erişim"}), 403
    
    data = request.get_json()
    conn = get_db()
    cur = conn.cursor()
    
    try:
        cur.execute("""
            UPDATE study_schedules 
            SET day_of_week = %s, subject = %s, topic = %s, 
                start_time = %s, end_time = %s, question_count = %s, 
                notes = %s, updated_at = CURRENT_TIMESTAMP
            WHERE id = %s AND created_by = %s
        """, (
            data.get('day_of_week'),
            data.get('subject'),
            data.get('topic'),
            data.get('start_time'),
            data.get('end_time'),
            data.get('question_count'),
            data.get('notes'),
            schedule_id,
            current_user.id
        ))
        
        if cur.rowcount == 0:
            conn.rollback()
            return jsonify({"error": "Program bulunamadı veya yetkiniz yok"}), 404
        
        conn.commit()
        return jsonify({"success": True, "message": "Program güncellendi"}), 200
    except Exception as e:
        conn.rollback()
        logger.error(f"Update schedule error: {e}")
        return jsonify({"error": "Program güncellenirken hata oluştu"}), 500
    finally:
        cur.close()
        conn.close()

@study_plan_bp.route('/schedule/<int:schedule_id>', methods=['DELETE'])
@login_required
def delete_schedule(schedule_id):
    """Öğretmen programı siler"""
    if current_user.role != 'teacher':
        return jsonify({"error": "Yetkisiz erişim"}), 403
    
    conn = get_db()
    cur = conn.cursor()
    
    try:
        cur.execute("""
            DELETE FROM study_schedules 
            WHERE id = %s AND created_by = %s
        """, (schedule_id, current_user.id))
        
        if cur.rowcount == 0:
            conn.rollback()
            return jsonify({"error": "Program bulunamadı veya yetkiniz yok"}), 404
        
        conn.commit()
        return jsonify({"success": True, "message": "Program silindi"}), 200
    except Exception as e:
        conn.rollback()
        logger.error(f"Delete schedule error: {e}")
        return jsonify({"error": "Program silinirken hata oluştu"}), 500
    finally:
        cur.close()
        conn.close()
