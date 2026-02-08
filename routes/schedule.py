"""
Ders ve Kurs Programı Modülü
Admin ve öğretmenler öğrencilerin ders/kurs programlarını girebilir
"""
from flask import Blueprint, request, jsonify, render_template
from flask_login import login_required, current_user
from psycopg2.extras import RealDictCursor
import logging
from datetime import datetime, time

logger = logging.getLogger(__name__)

schedule_bp = Blueprint('schedule', __name__)

def get_db():
    """Veritabanı bağlantısı döndürür"""
    import os
    import psycopg2
    return psycopg2.connect(os.environ.get('DATABASE_URL'))

def check_teacher_schedule_access(teacher_id, schedule_id):
    """Öğretmenin programa erişimi var mı kontrol eder (created_by)"""
    conn = get_db()
    cur = conn.cursor()
    
    try:
        cur.execute("""
            SELECT EXISTS(
                SELECT 1 FROM lesson_schedules 
                WHERE id = %s AND created_by = %s
            )
        """, (schedule_id, teacher_id))
        
        has_access = cur.fetchone()[0]
        cur.close()
        conn.close()
        return has_access
    except Exception as e:
        logger.error(f"Teacher access check error: {e}")
        cur.close()
        conn.close()
        return False

def check_time_overlap(student_id, day_of_week, start_time, end_time, exclude_id=None):
    """Aynı öğrenci için aynı günde saat çakışması var mı kontrol eder
    Canonical overlap: (existing.start < new.end AND existing.end > new.start)
    """
    conn = get_db()
    cur = conn.cursor()
    
    try:
        query = """
            SELECT COUNT(*) FROM lesson_schedules
            WHERE student_id = %s AND day_of_week = %s
            AND start_time < %s::time AND end_time > %s::time
        """
        params = [student_id, day_of_week, end_time, start_time]
        
        if exclude_id:
            query += " AND id != %s"
            params.append(exclude_id)
        
        cur.execute(query, params)
        overlap_count = cur.fetchone()[0]
        
        cur.close()
        conn.close()
        return overlap_count > 0
    except Exception as e:
        logger.error(f"Overlap check error: {e}")
        cur.close()
        conn.close()
        return True  # Hata durumunda çakışma var kabul et

# ================== ADMIN & TEACHER ENDPOINTS ==================

def create_schedule_multi_class(data):
    """Çoklu sınıfa program ataması yapar"""
    class_names = data.get('class_names', [])
    schedule_type = data.get('schedule_type', 'lesson')
    
    if schedule_type not in ['lesson', 'study']:
        return jsonify({"error": "Geçersiz program tipi"}), 400
    
    # Gün kontrolü
    valid_days = ['Pazartesi', 'Salı', 'Çarşamba', 'Perşembe', 'Cuma', 'Cumartesi', 'Pazar']
    if data.get('day_of_week') not in valid_days:
        return jsonify({"error": "Geçersiz gün"}), 400
    
    # DERS PROGRAMI: Saat zorunlu
    if schedule_type == 'lesson':
        required_fields = ['day_of_week', 'lesson_name', 'start_time', 'end_time']
        if not all(field in data for field in required_fields):
            return jsonify({"error": "Eksik alanlar (gün, ders, başlangıç ve bitiş saati gerekli)"}), 400
        
        try:
            from datetime import datetime
            start = datetime.strptime(data['start_time'], '%H:%M').time()
            end = datetime.strptime(data['end_time'], '%H:%M').time()
            if start >= end:
                return jsonify({"error": "Başlangıç saati bitiş saatinden önce olmalı"}), 400
        except ValueError:
            return jsonify({"error": "Geçersiz saat formatı (HH:MM)"}), 400
    
    # ÇALIŞMA PROGRAMI: instruction zorunlu
    elif schedule_type == 'study':
        required_fields = ['day_of_week', 'lesson_name', 'instruction']
        if not all(field in data for field in required_fields):
            return jsonify({"error": "Eksik alanlar (gün, ders ve bilgi gerekli)"}), 400
        
        if not data['instruction'].strip():
            return jsonify({"error": "Bilgi alanı boş olamaz"}), 400
    
    conn = get_db()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    
    try:
        total_insert_count = 0
        processed_classes = []
        
        for class_name in class_names:
            # Öğretmen ise, bu sınıfa erişimi var mı kontrol et
            if current_user.role == 'teacher':
                cur.execute("""
                    SELECT EXISTS(
                        SELECT 1 FROM teacher_classes 
                        WHERE teacher_id = %s AND class_name = %s
                    )
                """, (current_user.id, class_name))
                if not cur.fetchone()['exists']:
                    continue  # Bu sınıfa erişim yok, atla
            
            # Sınıftaki tüm öğrencileri al
            cur.execute("""
                SELECT id, full_name FROM users 
                WHERE role = 'student' AND class_name = %s
                ORDER BY full_name
            """, (class_name,))
            students = cur.fetchall()
            
            if not students:
                continue  # Bu sınıfta öğrenci yok, atla
            
            # Her öğrenci için program ekle
            for student in students:
                try:
                    if schedule_type == 'lesson':
                        # Çakışma kontrolü
                        if check_time_overlap(student['id'], data['day_of_week'], data['start_time'], data['end_time']):
                            continue  # Çakışma var, bu öğrenciyi atla
                        
                        cur.execute("""
                            INSERT INTO lesson_schedules 
                            (student_id, class_name, schedule_type, day_of_week, lesson_name, course_name, start_time, end_time, created_by)
                            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                        """, (
                            student['id'],
                            class_name,
                            schedule_type,
                            data['day_of_week'],
                            data['lesson_name'],
                            data.get('course_name'),
                            data['start_time'],
                            data['end_time'],
                            current_user.id
                        ))
                    else:  # schedule_type == 'study'
                        cur.execute("""
                            INSERT INTO lesson_schedules 
                            (student_id, class_name, schedule_type, day_of_week, lesson_name, instruction, created_by)
                            VALUES (%s, %s, %s, %s, %s, %s, %s)
                        """, (
                            student['id'],
                            class_name,
                            schedule_type,
                            data['day_of_week'],
                            data['lesson_name'],
                            data['instruction'],
                            current_user.id
                        ))
                    total_insert_count += 1
                except Exception as e:
                    logger.warning(f"Student {student['id']} insert failed: {e}")
                    continue
            
            processed_classes.append(class_name)
        
        conn.commit()
        
        return jsonify({
            "success": True,
            "message": f"{len(processed_classes)} sınıfa toplam {total_insert_count} öğrenciye program eklendi",
            "count": total_insert_count,
            "classes": processed_classes
        }), 201
        
    except Exception as e:
        conn.rollback()
        logger.error(f"Create multi-class schedule error: {e}")
        return jsonify({"error": "Program oluşturulurken hata oluştu"}), 500
    finally:
        cur.close()
        conn.close()

@schedule_bp.route('/schedule', methods=['POST'])
@login_required
def create_schedule():
    """Yeni ders/kurs programı oluştur (Admin veya Öğretmen)
    - student_id: Tek öğrenciye atama
    - class_name: Tek sınıfa toplu atama (bu sınıftaki tüm öğrencilere)
    - class_names: Çoklu sınıfa toplu atama (seçilen sınıflardaki tüm öğrencilere)
    - schedule_type: 'lesson' veya 'study'
    """
    if current_user.role not in ['admin', 'teacher']:
        return jsonify({"error": "Yetkisiz erişim"}), 403
    
    data = request.get_json()
    
    # student_id veya class_name/class_names'den biri olmalı
    if not data.get('student_id') and not data.get('class_name') and not data.get('class_names'):
        return jsonify({"error": "Öğrenci veya sınıf seçilmeli"}), 400
    
    # class_names varsa class_name'e çevir (çoklu sınıf desteği)
    if data.get('class_names') and isinstance(data.get('class_names'), list) and len(data.get('class_names')) > 0:
        # Çoklu sınıf modunda işlem yap
        return create_schedule_multi_class(data)
    
    schedule_type = data.get('schedule_type', 'lesson')  # Default: 'lesson'
    if schedule_type not in ['lesson', 'study']:
        return jsonify({"error": "Geçersiz program tipi"}), 400
    
    # Gün kontrolü
    valid_days = ['Pazartesi', 'Salı', 'Çarşamba', 'Perşembe', 'Cuma', 'Cumartesi', 'Pazar']
    if data['day_of_week'] not in valid_days:
        return jsonify({"error": "Geçersiz gün"}), 400
    
    # DERS PROGRAMI: Saat zorunlu, instruction opsiyonel
    if schedule_type == 'lesson':
        required_fields = ['day_of_week', 'lesson_name', 'start_time', 'end_time']
        if not all(field in data for field in required_fields):
            return jsonify({"error": "Eksik alanlar (gün, ders, başlangıç ve bitiş saati gerekli)"}), 400
        
        # Saat kontrolü (start < end)
        try:
            start = datetime.strptime(data['start_time'], '%H:%M').time()
            end = datetime.strptime(data['end_time'], '%H:%M').time()
            if start >= end:
                return jsonify({"error": "Başlangıç saati bitiş saatinden önce olmalı"}), 400
        except ValueError:
            return jsonify({"error": "Geçersiz saat formatı (HH:MM)"}), 400
    
    # ÇALIŞMA PROGRAMI: Saat YOK, instruction zorunlu
    elif schedule_type == 'study':
        required_fields = ['day_of_week', 'lesson_name', 'instruction']
        if not all(field in data for field in required_fields):
            return jsonify({"error": "Eksik alanlar (gün, ders ve bilgi gerekli)"}), 400
        
        if not data['instruction'].strip():
            return jsonify({"error": "Bilgi alanı boş olamaz (örn: '30 soru çöz')"}), 400
    
    conn = get_db()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    
    try:
        # BRANCH: Sınıfa toplu atama vs tek öğrenciye atama
        if data.get('class_name'):
            class_name = data['class_name']
            
            # Öğretmen ise, bu sınıfa erişimi var mı kontrol et
            if current_user.role == 'teacher':
                cur.execute("""
                    SELECT EXISTS(
                        SELECT 1 FROM teacher_classes 
                        WHERE teacher_id = %s AND class_name = %s
                    )
                """, (current_user.id, class_name))
                if not cur.fetchone()['exists']:
                    return jsonify({"error": "Bu sınıfa erişiminiz yok"}), 403
            
            # Sınıftaki tüm öğrencileri al
            cur.execute("""
                SELECT id, full_name FROM users 
                WHERE role = 'student' AND class_name = %s
                ORDER BY full_name
            """, (class_name,))
            students = cur.fetchall()
            
            if not students:
                return jsonify({"error": f"{class_name} sınıfında öğrenci bulunamadı"}), 404
            
            # Çakışma kontrolü SADECE DERS PROGRAMI için (çalışma programında saat olmadığı için overlap olmaz)
            if schedule_type == 'lesson':
                conflicts = []
                for student in students:
                    if check_time_overlap(
                        student['id'], 
                        data['day_of_week'], 
                        data['start_time'], 
                        data['end_time']
                    ):
                        conflicts.append(student['full_name'])
                
                if conflicts:
                    return jsonify({
                        "error": f"Çakışma tespit edildi ({len(conflicts)} öğrenci)",
                        "conflicts": conflicts[:10],  # İlk 10'u göster
                        "total_conflicts": len(conflicts)
                    }), 400
            
            # Tüm kontroller OK - bulk insert (TRANSACTION)
            insert_count = 0
            for student in students:
                if schedule_type == 'lesson':
                    cur.execute("""
                        INSERT INTO lesson_schedules 
                        (student_id, class_name, schedule_type, day_of_week, lesson_name, course_name, start_time, end_time, created_by)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """, (
                        student['id'],
                        class_name,
                        schedule_type,
                        data['day_of_week'],
                        data['lesson_name'],
                        data.get('course_name'),
                        data['start_time'],
                        data['end_time'],
                        current_user.id
                    ))
                else:  # schedule_type == 'study'
                    cur.execute("""
                        INSERT INTO lesson_schedules 
                        (student_id, class_name, schedule_type, day_of_week, lesson_name, instruction, created_by)
                        VALUES (%s, %s, %s, %s, %s, %s, %s)
                    """, (
                        student['id'],
                        class_name,
                        schedule_type,
                        data['day_of_week'],
                        data['lesson_name'],
                        data['instruction'],
                        current_user.id
                    ))
                insert_count += 1
            
            conn.commit()
            return jsonify({
                "success": True,
                "message": f"{class_name} sınıfındaki {insert_count} öğrenciye program eklendi",
                "count": insert_count
            }), 201
        
        else:
            # TEK ÖĞRENCİ ATAMA
            student_id = data['student_id']
            
            # SECURITY: Öğretmen ise, bu öğrenciye erişimi var mı kontrol et
            if current_user.role == 'teacher':
                cur.execute("""
                    SELECT u.class_name, u.full_name FROM users u WHERE u.id = %s AND u.role = 'student'
                """, (student_id,))
                student = cur.fetchone()
                
                if not student:
                    return jsonify({"error": "Öğrenci bulunamadı"}), 404
                
                # Erişim kontrolü:
                # 1. Eğer class_name varsa: teacher_classes veya teacher_students
                # 2. Eğer class_name NULL ise: SADECE teacher_students (güvenlik!)
                if student['class_name']:
                    # Class-based veya direct assignment check
                    cur.execute("""
                        SELECT EXISTS(
                            SELECT 1 FROM teacher_classes 
                            WHERE teacher_id = %s AND class_name = %s
                        ) OR EXISTS(
                            SELECT 1 FROM teacher_students 
                            WHERE teacher_id = %s AND student_id = %s
                        ) as has_access
                    """, (current_user.id, student['class_name'], current_user.id, student_id))
                else:
                    # class_name NULL - SADECE direkt atanmış öğrencilere izin ver
                    cur.execute("""
                        SELECT EXISTS(
                            SELECT 1 FROM teacher_students 
                            WHERE teacher_id = %s AND student_id = %s
                        ) as has_access
                    """, (current_user.id, student_id))
                
                if not cur.fetchone()['has_access']:
                    return jsonify({"error": "Bu öğrenciye erişiminiz yok"}), 403
            
            # Çakışma kontrolü SADECE DERS PROGRAMI için
            if schedule_type == 'lesson':
                if check_time_overlap(
                    student_id, 
                    data['day_of_week'], 
                    data['start_time'], 
                    data['end_time']
                ):
                    return jsonify({"error": "Bu saatte başka bir ders/kurs var"}), 400
            
            # INSERT: schedule_type'a göre farklı field'lar
            if schedule_type == 'lesson':
                cur.execute("""
                    INSERT INTO lesson_schedules 
                    (student_id, schedule_type, day_of_week, lesson_name, course_name, start_time, end_time, created_by)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                    RETURNING id
                """, (
                    student_id,
                    schedule_type,
                    data['day_of_week'],
                    data['lesson_name'],
                    data.get('course_name'),
                    data['start_time'],
                    data['end_time'],
                    current_user.id
                ))
            else:  # schedule_type == 'study'
                cur.execute("""
                    INSERT INTO lesson_schedules 
                    (student_id, schedule_type, day_of_week, lesson_name, instruction, created_by)
                    VALUES (%s, %s, %s, %s, %s, %s)
                    RETURNING id
                """, (
                    student_id,
                    schedule_type,
                    data['day_of_week'],
                    data['lesson_name'],
                    data['instruction'],
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

# Backward compatibility alias
@schedule_bp.route('/schedule/create', methods=['POST'])
@login_required
def create_schedule_legacy():
    """Legacy route - redirects to /schedule"""
    return create_schedule()

@schedule_bp.route('/schedule/<int:schedule_id>', methods=['PUT'])
@login_required
def update_schedule(schedule_id):
    """Ders/kurs programını güncelle (Admin veya Öğretmen)"""
    if current_user.role not in ['admin', 'teacher']:
        return jsonify({"error": "Yetkisiz erişim"}), 403
    
    data = request.get_json()
    
    conn = get_db()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    
    try:
        # Mevcut programı getir
        cur.execute("SELECT * FROM lesson_schedules WHERE id = %s", (schedule_id,))
        existing = cur.fetchone()
        
        if not existing:
            return jsonify({"error": "Program bulunamadı"}), 404
        
        # Öğretmen ise erişim kontrolü (sadece kendi oluşturduğu programları düzenleyebilir)
        if current_user.role == 'teacher':
            if not check_teacher_schedule_access(current_user.id, schedule_id):
                return jsonify({"error": "Bu programa erişiminiz yok"}), 403
        
        # Gün kontrolü
        if 'day_of_week' in data:
            valid_days = ['Pazartesi', 'Salı', 'Çarşamba', 'Perşembe', 'Cuma', 'Cumartesi', 'Pazar']
            if data['day_of_week'] not in valid_days:
                return jsonify({"error": "Geçersiz gün"}), 400
        
        # Only validate times and check overlap for LESSON type
        if existing['schedule_type'] == 'lesson':
            # Saat değişikliği varsa çakışma kontrolü
            if 'start_time' in data or 'end_time' in data or 'day_of_week' in data:
                # TIME değerlerini hemen başta normalize et (HH:MM formatına)
                raw_start = data.get('start_time', str(existing['start_time']))
                raw_end = data.get('end_time', str(existing['end_time']))
                
                new_start = raw_start[:5] if isinstance(raw_start, str) else str(raw_start)[:5]
                new_end = raw_end[:5] if isinstance(raw_end, str) else str(raw_end)[:5]
                new_day = data.get('day_of_week', existing['day_of_week'])
                
                # Saat kontrolü (start < end)
                try:
                    start_obj = datetime.strptime(new_start, '%H:%M').time()
                    end_obj = datetime.strptime(new_end, '%H:%M').time()
                    
                    if start_obj >= end_obj:
                        return jsonify({"error": "Başlangıç saati bitiş saatinden önce olmalı"}), 400
                except (ValueError, TypeError) as e:
                    logger.error(f"Time validation error: {e}")
                    return jsonify({"error": "Geçersiz saat formatı"}), 400
                
                if check_time_overlap(existing['student_id'], new_day, new_start, new_end, exclude_id=schedule_id):
                    return jsonify({"error": "Bu saatte başka bir ders/kurs var"}), 400
        
        # Güncelleme
        update_fields = []
        params = []
        
        for field in ['day_of_week', 'lesson_name', 'course_name', 'start_time', 'end_time', 'instruction']:
            if field in data:
                update_fields.append(f"{field} = %s")
                params.append(data[field])
        
        if not update_fields:
            return jsonify({"error": "Güncellenecek alan yok"}), 400
        
        params.append(schedule_id)
        query = f"UPDATE lesson_schedules SET {', '.join(update_fields)} WHERE id = %s"
        
        cur.execute(query, params)
        conn.commit()
        
        return jsonify({
            "success": True,
            "message": "Program güncellendi"
        }), 200
    except Exception as e:
        conn.rollback()
        logger.error(f"Update schedule error: {e}")
        return jsonify({"error": "Program güncellenirken hata oluştu"}), 500
    finally:
        cur.close()
        conn.close()

@schedule_bp.route('/schedule/<int:schedule_id>', methods=['DELETE'])
@login_required
def delete_schedule(schedule_id):
    """Ders/kurs programını sil (Admin veya Öğretmen)"""
    if current_user.role not in ['admin', 'teacher']:
        return jsonify({"error": "Yetkisiz erişim"}), 403
    
    conn = get_db()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    
    try:
        # Mevcut programı getir
        cur.execute("SELECT * FROM lesson_schedules WHERE id = %s", (schedule_id,))
        existing = cur.fetchone()
        
        if not existing:
            return jsonify({"error": "Program bulunamadı"}), 404
        
        # Öğretmen ise erişim kontrolü (sadece kendi oluşturduğu programları düzenleyebilir)
        if current_user.role == 'teacher':
            if not check_teacher_schedule_access(current_user.id, schedule_id):
                return jsonify({"error": "Bu programa erişiminiz yok"}), 403
        
        cur.execute("DELETE FROM lesson_schedules WHERE id = %s", (schedule_id,))
        conn.commit()
        
        return jsonify({
            "success": True,
            "message": "Program silindi"
        }), 200
    except Exception as e:
        conn.rollback()
        logger.error(f"Delete schedule error: {e}")
        return jsonify({"error": "Program silinirken hata oluştu"}), 500
    finally:
        cur.close()
        conn.close()

# ================== STUDENT & READ ENDPOINTS ==================

@schedule_bp.route('/schedule/student/<int:student_id>', methods=['GET'])
@login_required
def get_student_schedule(student_id):
    """Öğrencinin programlarını getir
    Query params:
    - schedule_type: 'lesson' veya 'study' (opsiyonel filter)
    """
    # Erişim kontrolü
    if current_user.role == 'student':
        if current_user.id != student_id:
            return jsonify({"error": "Sadece kendi programınızı görebilirsiniz"}), 403
    elif current_user.role == 'teacher':
        # Öğretmenler istediği öğrencinin programını görebilir (study_plan ile tutarlı)
        pass
    elif current_user.role != 'admin':
        return jsonify({"error": "Yetkisiz erişim"}), 403
    
    # Opsiyonel schedule_type filter
    schedule_type = request.args.get('schedule_type')
    
    conn = get_db()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    
    try:
        # schedule_type filter ekle (NULL ise tümü)
        query = """
            SELECT ls.*, u.full_name as created_by_name
            FROM lesson_schedules ls
            LEFT JOIN users u ON ls.created_by = u.id
            WHERE ls.student_id = %s
        """
        params = [student_id]
        
        if schedule_type:
            query += " AND ls.schedule_type = %s"
            params.append(schedule_type)
        
        query += """
            ORDER BY 
                CASE day_of_week
                    WHEN 'Pazartesi' THEN 1
                    WHEN 'Salı' THEN 2
                    WHEN 'Çarşamba' THEN 3
                    WHEN 'Perşembe' THEN 4
                    WHEN 'Cuma' THEN 5
                    WHEN 'Cumartesi' THEN 6
                    WHEN 'Pazar' THEN 7
                END,
                ls.start_time
        """
        
        cur.execute(query, params)
        
        schedules = cur.fetchall()
        
        # TIME objelerini string'e çevir
        for schedule in schedules:
            if schedule.get('start_time'):
                schedule['start_time'] = str(schedule['start_time'])
            if schedule.get('end_time'):
                schedule['end_time'] = str(schedule['end_time'])
        
        return jsonify({
            "success": True,
            "schedules": schedules
        }), 200
    except Exception as e:
        logger.error(f"Get student schedule error: {e}")
        return jsonify({"error": "Programlar yüklenirken hata oluştu"}), 500
    finally:
        cur.close()
        conn.close()

# ================== TEMPLATE ROUTES ==================

@schedule_bp.route('/student/lesson-schedule')
@login_required
def student_schedule_page():
    """Öğrenci ders programı sayfası"""
    if current_user.role != 'student':
        return "Yetkisiz erişim", 403
    return render_template('student_lesson_schedule.html')

@schedule_bp.route('/teacher/lesson-schedule')
@login_required
def teacher_schedule_page():
    """Öğretmen ders programı yönetim sayfası"""
    if current_user.role != 'teacher':
        return "Yetkisiz erişim", 403
    return render_template('teacher_lesson_schedule.html')

@schedule_bp.route('/admin/lesson-schedule')
@login_required
def admin_schedule_page():
    """Admin ders programı yönetim sayfası"""
    if current_user.role != 'admin':
        return "Yetkisiz erişim", 403
    return render_template('admin_lesson_schedule.html')
