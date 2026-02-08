"""
Soru Analizi Sistemi Blueprint
Öğrenciler deneme sonrası yanlış/boş sorular ve nedenleri ekler
"""
from flask import Blueprint, request, jsonify
from flask_login import login_required, current_user
import psycopg2
from psycopg2.extras import RealDictCursor
import os
import logging

logger = logging.getLogger(__name__)

question_analysis_bp = Blueprint('question_analysis', __name__, url_prefix='/api/question-analysis')

def get_db():
    return psycopg2.connect(os.environ.get('DATABASE_URL'))

VALID_REASONS = [
    "Konu Eksik",
    "Yanlış Anlama",
    "Zaman Yetmedi",
    "Strateji Hatası",
    "Diğer"
]

@question_analysis_bp.route('/exam/<int:exam_id>', methods=['GET'])
@login_required
def get_analysis(exam_id):
    """Denemeye ait soru analizlerini getir"""
    conn = get_db()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    
    try:
        if current_user.role == 'student':
            cur.execute("""
                SELECT qa.*, pe.exam_name
                FROM question_analysis qa
                JOIN practice_exams pe ON qa.practice_exam_id = pe.id
                WHERE qa.practice_exam_id = %s AND qa.student_id = %s
                ORDER BY qa.subject, qa.question_number
            """, (exam_id, current_user.id))
        elif current_user.role == 'teacher':
            student_id = request.args.get('student_id')
            if student_id:
                cur.execute("""
                    SELECT qa.*, pe.exam_name, u.full_name as student_name
                    FROM question_analysis qa
                    JOIN practice_exams pe ON qa.practice_exam_id = pe.id
                    JOIN users u ON qa.student_id = u.id
                    WHERE qa.practice_exam_id = %s AND qa.student_id = %s 
                    AND (
                        u.class_name IN (SELECT class_name FROM teacher_classes WHERE teacher_id = %s)
                        OR u.id IN (SELECT student_id FROM teacher_students WHERE teacher_id = %s)
                    )
                    ORDER BY qa.subject, qa.question_number
                """, (exam_id, student_id, current_user.id, current_user.id))
            else:
                cur.execute("""
                    SELECT qa.*, pe.exam_name, u.full_name as student_name
                    FROM question_analysis qa
                    JOIN practice_exams pe ON qa.practice_exam_id = pe.id
                    JOIN users u ON qa.student_id = u.id
                    WHERE qa.practice_exam_id = %s
                    AND (
                        u.class_name IN (SELECT class_name FROM teacher_classes WHERE teacher_id = %s)
                        OR u.id IN (SELECT student_id FROM teacher_students WHERE teacher_id = %s)
                    )
                    ORDER BY u.full_name, qa.subject, qa.question_number
                """, (exam_id, current_user.id, current_user.id))
        elif current_user.role == 'admin':
            student_id = request.args.get('student_id')
            if student_id:
                cur.execute("""
                    SELECT qa.*, pe.exam_name, u.full_name as student_name
                    FROM question_analysis qa
                    JOIN practice_exams pe ON qa.practice_exam_id = pe.id
                    JOIN users u ON qa.student_id = u.id
                    WHERE qa.practice_exam_id = %s AND qa.student_id = %s
                    ORDER BY qa.subject, qa.question_number
                """, (exam_id, student_id))
            else:
                cur.execute("""
                    SELECT qa.*, pe.exam_name, u.full_name as student_name
                    FROM question_analysis qa
                    JOIN practice_exams pe ON qa.practice_exam_id = pe.id
                    JOIN users u ON qa.student_id = u.id
                    WHERE qa.practice_exam_id = %s
                    ORDER BY u.full_name, qa.subject, qa.question_number
                """, (exam_id,))
        else:
            return jsonify({"error": "Yetkisiz erişim"}), 403
        
        analyses = cur.fetchall()
        return jsonify({
            "success": True,
            "analyses": [{
                "id": a['id'],
                "student_id": a['student_id'],
                "student_name": a.get('student_name'),
                "subject": a['subject'],
                "question_number": a['question_number'],
                "is_wrong": a['is_wrong'],
                "is_blank": a['is_blank'],
                "reason": a['reason'],
                "notes": a.get('notes'),
                "created_at": a['created_at'].isoformat()
            } for a in analyses]
        })
    except Exception as e:
        logger.error(f"Get analysis error: {e}")
        return jsonify({"error": "Analiz yüklenirken hata oluştu"}), 500
    finally:
        cur.close()
        conn.close()

@question_analysis_bp.route('/student/<int:student_id>', methods=['GET'])
@login_required
def get_student_analysis(student_id):
    """Öğrencinin tüm soru analizlerini getir"""
    if current_user.role == 'student' and current_user.id != student_id:
        return jsonify({"error": "Yetkisiz erişim"}), 403
    
    if current_user.role not in ['student', 'teacher', 'admin']:
        return jsonify({"error": "Yetkisiz erişim"}), 403
    
    conn = get_db()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    
    if current_user.role == 'teacher':
        try:
            cur.execute("""
                SELECT EXISTS (
                    SELECT 1 FROM users u
                    WHERE u.id = %s AND (
                        u.class_name IN (SELECT class_name FROM teacher_classes WHERE teacher_id = %s)
                        OR u.id IN (SELECT student_id FROM teacher_students WHERE teacher_id = %s)
                    )
                ) AS has_access
            """, (student_id, current_user.id, current_user.id))
            if not cur.fetchone()['has_access']:
                cur.close()
                conn.close()
                return jsonify({"error": "Bu öğrenciye erişim yetkiniz yok"}), 403
        except Exception as e:
            logger.error(f"Teacher authorization check error: {e}")
            cur.close()
            conn.close()
            return jsonify({"error": "Yetki kontrolü başarısız"}), 500
    
    try:
        
        cur.execute("""
            SELECT qa.*, pe.exam_name, pe.exam_date
            FROM question_analysis qa
            JOIN practice_exams pe ON qa.practice_exam_id = pe.id
            WHERE qa.student_id = %s
            ORDER BY pe.exam_date DESC, qa.subject, qa.question_number
        """, (student_id,))
        
        analyses = cur.fetchall()
        
        reason_stats = {}
        subject_stats = {}
        
        for a in analyses:
            reason = a['reason']
            subject = a['subject']
            
            reason_stats[reason] = reason_stats.get(reason, 0) + 1
            subject_stats[subject] = subject_stats.get(subject, 0) + 1
        
        return jsonify({
            "success": True,
            "total_errors": len(analyses),
            "reason_stats": reason_stats,
            "subject_stats": subject_stats,
            "analyses": [{
                "id": a['id'],
                "exam_name": a['exam_name'],
                "exam_date": a['exam_date'].isoformat(),
                "subject": a['subject'],
                "question_number": a['question_number'],
                "is_wrong": a['is_wrong'],
                "is_blank": a['is_blank'],
                "reason": a['reason'],
                "notes": a.get('notes'),
                "created_at": a['created_at'].isoformat()
            } for a in analyses]
        })
    except Exception as e:
        logger.error(f"Get student analysis error: {e}")
        return jsonify({"error": "Öğrenci analizi yüklenirken hata oluştu"}), 500
    finally:
        cur.close()
        conn.close()

@question_analysis_bp.route('/', methods=['POST'])
@login_required
def create_analysis():
    """Öğrenci soru analizi ekler"""
    if current_user.role != 'student':
        return jsonify({"error": "Sadece öğrenciler soru analizi ekleyebilir"}), 403
    
    data = request.get_json()
    required_fields = ['practice_exam_id', 'subject', 'question_number', 'reason']
    
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
            INSERT INTO question_analysis 
            (student_id, practice_exam_id, subject, question_number, is_wrong, is_blank, reason, notes)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING id
        """, (
            current_user.id,
            data['practice_exam_id'],
            data['subject'],
            data['question_number'],
            data.get('is_wrong', False),
            data.get('is_blank', False),
            data['reason'],
            data.get('notes')
        ))
        
        analysis_id = cur.fetchone()['id']
        conn.commit()
        
        return jsonify({
            "success": True,
            "message": "Soru analizi eklendi",
            "analysis_id": analysis_id
        }), 201
    except Exception as e:
        conn.rollback()
        logger.error(f"Create analysis error: {e}")
        return jsonify({"error": "Analiz eklenirken hata oluştu"}), 500
    finally:
        cur.close()
        conn.close()

@question_analysis_bp.route('/<int:analysis_id>', methods=['PUT'])
@login_required
def update_analysis(analysis_id):
    """Öğrenci kendi analizini günceller"""
    if current_user.role != 'student':
        return jsonify({"error": "Yetkisiz erişim"}), 403
    
    data = request.get_json()
    
    if 'reason' in data and data['reason'] not in VALID_REASONS:
        return jsonify({"error": f"Geçersiz neden. Geçerli seçenekler: {', '.join(VALID_REASONS)}"}), 400
    
    conn = get_db()
    cur = conn.cursor()
    
    try:
        cur.execute("""
            UPDATE question_analysis 
            SET subject = COALESCE(%s, subject),
                question_number = COALESCE(%s, question_number),
                is_wrong = COALESCE(%s, is_wrong),
                is_blank = COALESCE(%s, is_blank),
                reason = COALESCE(%s, reason),
                notes = COALESCE(%s, notes)
            WHERE id = %s AND student_id = %s
        """, (
            data.get('subject'),
            data.get('question_number'),
            data.get('is_wrong'),
            data.get('is_blank'),
            data.get('reason'),
            data.get('notes'),
            analysis_id,
            current_user.id
        ))
        
        if cur.rowcount == 0:
            conn.rollback()
            return jsonify({"error": "Analiz bulunamadı veya size ait değil"}), 404
        
        conn.commit()
        return jsonify({"success": True, "message": "Analiz güncellendi"}), 200
    except Exception as e:
        conn.rollback()
        logger.error(f"Update analysis error: {e}")
        return jsonify({"error": "Analiz güncellenirken hata oluştu"}), 500
    finally:
        cur.close()
        conn.close()

@question_analysis_bp.route('/<int:analysis_id>', methods=['DELETE'])
@login_required
def delete_analysis(analysis_id):
    """Öğrenci kendi analizini siler"""
    if current_user.role != 'student':
        return jsonify({"error": "Yetkisiz erişim"}), 403
    
    conn = get_db()
    cur = conn.cursor()
    
    try:
        cur.execute("""
            DELETE FROM question_analysis 
            WHERE id = %s AND student_id = %s
        """, (analysis_id, current_user.id))
        
        if cur.rowcount == 0:
            conn.rollback()
            return jsonify({"error": "Analiz bulunamadı veya size ait değil"}), 404
        
        conn.commit()
        return jsonify({"success": True, "message": "Analiz silindi"}), 200
    except Exception as e:
        conn.rollback()
        logger.error(f"Delete analysis error: {e}")
        return jsonify({"error": "Analiz silinirken hata oluştu"}), 500
    finally:
        cur.close()
        conn.close()
