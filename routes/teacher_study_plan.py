"""
Öğretmen Ders Çalışma Planı API
Öğretmen öğrencilere günlük ders planı oluşturur, öğrenci görüntüler
"""

from flask import Blueprint, request, jsonify
from flask_login import login_required, current_user
from psycopg2.extras import RealDictCursor
from datetime import datetime, timedelta
import logging
import psycopg2
import os

logger = logging.getLogger(__name__)

teacher_study_plan_bp = Blueprint('teacher_study_plan', __name__, url_prefix='/api/teacher-study-plan')

def get_db():
    return psycopg2.connect(os.environ.get('DATABASE_URL'))

# Geçerli dersler (günlük takiple aynı)
VALID_SUBJECTS = [
    "Matematik", "Türkçe", "Fen Bilimleri", "Sosyal Bilgiler",
    "İngilizce", "Din Kültürü", "Beden Eğitimi", "Görsel Sanatlar",
    "Müzik", "Teknoloji ve Tasarım"
]

@teacher_study_plan_bp.route('', methods=['POST'])
@login_required
def create_plan():
    """Öğretmen öğrenci için plan oluşturur"""
    if current_user.role != 'teacher':
        return jsonify({"error": "Yetkisiz erişim"}), 403
    
    data = request.get_json()
    student_id = data.get('student_id')
    plan_date = data.get('plan_date')
    subject = data.get('subject')
    question_count = data.get('question_count')
    note = data.get('note', '')
    
    # Validation
    if not all([student_id, plan_date, subject, question_count]):
        return jsonify({"error": "Tüm alanlar gerekli (student_id, plan_date, subject, question_count)"}), 400
    
    if subject not in VALID_SUBJECTS:
        return jsonify({"error": f"Geçersiz ders. Geçerli dersler: {', '.join(VALID_SUBJECTS)}"}), 400
    
    try:
        date_obj = datetime.strptime(plan_date, '%Y-%m-%d').date()
        question_count = int(question_count)
        if question_count <= 0:
            raise ValueError("Soru sayısı pozitif olmalı")
    except ValueError as ve:
        return jsonify({"error": f"Geçersiz veri: {ve}"}), 400
    
    conn = get_db()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    
    try:
        # Öğretmenin bu öğrenciye erişimi var mı kontrol et (teacher_students veya teacher_classes)
        cur.execute("""
            SELECT EXISTS (
                SELECT 1 FROM users u
                WHERE u.id = %s AND u.role = 'student'
                AND (
                    u.class_name IN (SELECT class_name FROM teacher_classes WHERE teacher_id = %s)
                    OR u.id IN (SELECT student_id FROM teacher_students WHERE teacher_id = %s)
                )
            ) AS has_access
        """, (student_id, current_user.id, current_user.id))
        
        if not cur.fetchone()['has_access']:
            return jsonify({"error": "Bu öğrenciye erişim yetkiniz yok"}), 403
        
        # Plan ekle
        cur.execute("""
            INSERT INTO teacher_study_plan 
            (student_id, teacher_id, plan_date, subject, question_count, note)
            VALUES (%s, %s, %s, %s, %s, %s)
            RETURNING id, student_id, teacher_id, plan_date, subject, question_count, note, created_at
        """, (student_id, current_user.id, date_obj, subject, question_count, note))
        
        result = cur.fetchone()
        conn.commit()
        
        return jsonify({
            "success": True,
            "plan": {
                "id": result['id'],
                "student_id": result['student_id'],
                "teacher_id": result['teacher_id'],
                "plan_date": str(result['plan_date']),
                "subject": result['subject'],
                "question_count": result['question_count'],
                "note": result['note'],
                "created_at": result['created_at'].isoformat()
            }
        }), 201
        
    except psycopg2.IntegrityError as ie:
        conn.rollback()
        if 'unique constraint' in str(ie).lower():
            return jsonify({"error": "Bu tarih ve ders için zaten plan var"}), 409
        return jsonify({"error": "Veritabanı hatası"}), 500
    except Exception as e:
        conn.rollback()
        logger.error(f"Create study plan error: {e}")
        return jsonify({"error": "Plan oluşturulurken hata oluştu"}), 500
    finally:
        cur.close()
        conn.close()

@teacher_study_plan_bp.route('/<int:plan_id>', methods=['PUT'])
@login_required
def update_plan(plan_id):
    """Öğretmen planı günceller"""
    if current_user.role != 'teacher':
        return jsonify({"error": "Yetkisiz erişim"}), 403
    
    data = request.get_json()
    subject = data.get('subject')
    question_count = data.get('question_count')
    note = data.get('note')
    
    if not all([subject, question_count]):
        return jsonify({"error": "Ders ve soru sayısı gerekli"}), 400
    
    if subject not in VALID_SUBJECTS:
        return jsonify({"error": f"Geçersiz ders"}), 400
    
    try:
        question_count = int(question_count)
        if question_count <= 0:
            raise ValueError("Soru sayısı pozitif olmalı")
    except ValueError as ve:
        return jsonify({"error": f"Geçersiz veri: {ve}"}), 400
    
    conn = get_db()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    
    try:
        # Öğretmenin planı mı kontrol et
        cur.execute("""
            SELECT teacher_id FROM teacher_study_plan WHERE id = %s
        """, (plan_id,))
        
        plan = cur.fetchone()
        if not plan:
            return jsonify({"error": "Plan bulunamadı"}), 404
        
        if plan['teacher_id'] != current_user.id:
            return jsonify({"error": "Sadece kendi planlarınızı düzenleyebilirsiniz"}), 403
        
        # Güncelle
        cur.execute("""
            UPDATE teacher_study_plan
            SET subject = %s, question_count = %s, note = %s, updated_at = CURRENT_TIMESTAMP
            WHERE id = %s
            RETURNING id, plan_date, subject, question_count, note, updated_at
        """, (subject, question_count, note, plan_id))
        
        result = cur.fetchone()
        conn.commit()
        
        return jsonify({
            "success": True,
            "plan": {
                "id": result['id'],
                "plan_date": str(result['plan_date']),
                "subject": result['subject'],
                "question_count": result['question_count'],
                "note": result['note'],
                "updated_at": result['updated_at'].isoformat()
            }
        }), 200
        
    except psycopg2.IntegrityError as ie:
        conn.rollback()
        if 'unique constraint' in str(ie).lower():
            return jsonify({"error": "Bu tarih ve ders için zaten plan var"}), 409
        return jsonify({"error": "Veritabanı hatası"}), 500
    except Exception as e:
        conn.rollback()
        logger.error(f"Update study plan error: {e}")
        return jsonify({"error": "Plan güncellenirken hata oluştu"}), 500
    finally:
        cur.close()
        conn.close()

@teacher_study_plan_bp.route('/<int:plan_id>', methods=['DELETE'])
@login_required
def delete_plan(plan_id):
    """Öğretmen planı siler"""
    if current_user.role != 'teacher':
        return jsonify({"error": "Yetkisiz erişim"}), 403
    
    conn = get_db()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    
    try:
        cur.execute("""
            SELECT teacher_id FROM teacher_study_plan WHERE id = %s
        """, (plan_id,))
        
        plan = cur.fetchone()
        if not plan:
            return jsonify({"error": "Plan bulunamadı"}), 404
        
        if plan['teacher_id'] != current_user.id:
            return jsonify({"error": "Sadece kendi planlarınızı silebilirsiniz"}), 403
        
        cur.execute("DELETE FROM teacher_study_plan WHERE id = %s", (plan_id,))
        conn.commit()
        
        return jsonify({"success": True, "message": "Plan silindi"}), 200
        
    except Exception as e:
        conn.rollback()
        logger.error(f"Delete study plan error: {e}")
        return jsonify({"error": "Plan silinirken hata oluştu"}), 500
    finally:
        cur.close()
        conn.close()

@teacher_study_plan_bp.route('/teacher/students', methods=['GET'])
@login_required
def get_teacher_students_plans():
    """Öğretmen kendi öğrencilerinin planlarını görür"""
    if current_user.role != 'teacher':
        return jsonify({"error": "Yetkisiz erişim"}), 403
    
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    
    if not start_date or not end_date:
        return jsonify({"error": "Başlangıç ve bitiş tarihi gerekli"}), 400
    
    try:
        start_date_obj = datetime.strptime(start_date, '%Y-%m-%d').date()
        end_date_obj = datetime.strptime(end_date, '%Y-%m-%d').date()
    except ValueError:
        return jsonify({"error": "Geçersiz tarih formatı (YYYY-MM-DD)"}), 400
    
    conn = get_db()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    
    try:
        # Öğretmenin öğrencilerini bul
        cur.execute("""
            SELECT DISTINCT u.id, u.full_name, u.class_name
            FROM users u
            WHERE u.role = 'student'
            AND u.class_name IN (
                SELECT DISTINCT target_class FROM exams WHERE teacher_id = %s
                UNION
                SELECT DISTINCT target_class FROM announcements WHERE teacher_id = %s
            )
            ORDER BY u.class_name, u.full_name
        """, (current_user.id, current_user.id))
        
        students = cur.fetchall()
        
        if not students:
            return jsonify({"success": True, "students": []}), 200
        
        student_ids = [s['id'] for s in students]
        
        # Tüm planları tek sorguda çek (N+1 optimizasyonu)
        cur.execute("""
            SELECT tsp.id, tsp.student_id, tsp.plan_date, tsp.subject, 
                   tsp.question_count, tsp.note, tsp.created_at
            FROM teacher_study_plan tsp
            WHERE tsp.student_id = ANY(%s)
            AND tsp.teacher_id = %s
            AND tsp.plan_date BETWEEN %s AND %s
            ORDER BY tsp.student_id, tsp.plan_date ASC
        """, (student_ids, current_user.id, start_date_obj, end_date_obj))
        
        all_plans = cur.fetchall()
        
        # Planları öğrenciye göre grupla
        plans_by_student = {}
        for plan in all_plans:
            sid = plan['student_id']
            if sid not in plans_by_student:
                plans_by_student[sid] = []
            plans_by_student[sid].append({
                "id": plan['id'],
                "plan_date": str(plan['plan_date']),
                "subject": plan['subject'],
                "question_count": plan['question_count'],
                "note": plan['note'],
                "created_at": plan['created_at'].isoformat()
            })
        
        results = []
        for student in students:
            results.append({
                "student_id": student['id'],
                "student_name": student['full_name'],
                "student_class": student['class_name'],
                "plans": plans_by_student.get(student['id'], [])
            })
        
        return jsonify({
            "success": True,
            "start_date": start_date,
            "end_date": end_date,
            "students": results
        }), 200
        
    except Exception as e:
        logger.error(f"Get teacher students plans error: {e}")
        return jsonify({"error": "Planlar getirilirken hata oluştu"}), 500
    finally:
        cur.close()
        conn.close()

@teacher_study_plan_bp.route('/my-plans', methods=['GET'])
@login_required
def get_student_plans():
    """Öğrenci kendi planını görür (tarih optional - verilmezse tümünü gösterir)"""
    if current_user.role != 'student':
        return jsonify({"error": "Yetkisiz erişim"}), 403
    
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    
    # Tarih parametreleri opsiyonel - verilmezse tüm planları getir
    date_filter = ""
    params = [current_user.id]
    
    if start_date and end_date:
        try:
            start_date_obj = datetime.strptime(start_date, '%Y-%m-%d').date()
            end_date_obj = datetime.strptime(end_date, '%Y-%m-%d').date()
            date_filter = "AND tsp.plan_date BETWEEN %s AND %s"
            params.extend([start_date_obj, end_date_obj])
        except ValueError:
            return jsonify({"error": "Geçersiz tarih formatı (YYYY-MM-DD)"}), 400
    
    conn = get_db()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    
    try:
        query = f"""
            SELECT tsp.id, tsp.plan_date, tsp.subject, tsp.question_count, tsp.note,
                   u.full_name as teacher_name, tsp.created_at
            FROM teacher_study_plan tsp
            JOIN users u ON tsp.teacher_id = u.id
            WHERE tsp.student_id = %s
            {date_filter}
            ORDER BY tsp.plan_date ASC, tsp.subject ASC
        """
        cur.execute(query, params)
        
        plans = cur.fetchall()
        
        response = {
            "success": True,
            "plans": [{
                "id": p['id'],
                "date": str(p['plan_date']),
                "subject": p['subject'],
                "question_count": p['question_count'],
                "note": p['note'],
                "teacher_name": p['teacher_name'],
                "created_at": p['created_at'].isoformat()
            } for p in plans]
        }
        
        if start_date and end_date:
            response["start_date"] = start_date
            response["end_date"] = end_date
        
        return jsonify(response), 200
        
    except Exception as e:
        logger.error(f"Get student plans error: {e}")
        return jsonify({"error": "Planlar getirilirken hata oluştu"}), 500
    finally:
        cur.close()
        conn.close()

@teacher_study_plan_bp.route('/subjects', methods=['GET'])
@login_required
def get_subjects():
    """Geçerli ders listesini döndürür"""
    return jsonify({
        "success": True,
        "subjects": VALID_SUBJECTS
    }), 200
