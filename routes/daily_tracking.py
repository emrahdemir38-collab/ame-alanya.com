"""
Haftalık Soru Takibi (Daily Study Tracking) Blueprint
Öğrenciler günlük çalışma notlarını girebilir, öğretmenler haftalık/aylık raporları görüntüleyebilir
"""
from flask import Blueprint, request, jsonify
from flask_login import login_required, current_user
import psycopg2
from psycopg2.extras import RealDictCursor
import os
import logging
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

daily_tracking_bp = Blueprint('daily_tracking', __name__, url_prefix='/api/daily-tracking')

def get_db():
    return psycopg2.connect(os.environ.get('DATABASE_URL'))

DAYS_OF_WEEK = ['Pazartesi', 'Salı', 'Çarşamba', 'Perşembe', 'Cuma', 'Cumartesi', 'Pazar']

VALID_SUBJECTS = [
    'Türkçe', 'Matematik', 'Fen Bilimleri', 'İngilizce', 
    'Sosyal Bilgiler', 'Din Kültürü', 'Genel'
]

@daily_tracking_bp.route('/create', methods=['POST'])
@login_required
def create_tracking():
    """Öğrenci günlük çalışma kaydı oluşturur veya günceller"""
    if current_user.role != 'student':
        return jsonify({"error": "Sadece öğrenciler kayıt oluşturabilir"}), 403
    
    data = request.get_json()
    required_fields = ['date', 'day_of_week', 'subject', 'note']
    
    if not all(field in data for field in required_fields):
        return jsonify({"error": "Eksik alanlar"}), 400
    
    if data['day_of_week'] not in DAYS_OF_WEEK:
        return jsonify({"error": f"Geçersiz gün. Geçerli seçenekler: {', '.join(DAYS_OF_WEEK)}"}), 400
    
    if data['subject'] not in VALID_SUBJECTS:
        return jsonify({"error": f"Geçersiz ders. Geçerli seçenekler: {', '.join(VALID_SUBJECTS)}"}), 400
    
    try:
        date_obj = datetime.strptime(data['date'], '%Y-%m-%d').date()
    except ValueError:
        return jsonify({"error": "Geçersiz tarih formatı. YYYY-MM-DD kullanın"}), 400
    
    today = datetime.now().date()
    current_week_start = today - timedelta(days=today.weekday())
    current_week_end = current_week_start + timedelta(days=6)
    
    if date_obj < current_week_start:
        return jsonify({"error": "Geçmiş haftaların kayıtları değiştirilemez"}), 403
    
    if date_obj > current_week_end + timedelta(days=7):
        return jsonify({"error": "İleri tarihli kayıt oluşturamazsınız"}), 403
    
    conn = get_db()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    
    try:
        cur.execute("""
            SELECT id, created_at FROM daily_study_tracking
            WHERE student_id = %s AND date = %s AND subject = %s
        """, (current_user.id, data['date'], data['subject']))
        
        existing = cur.fetchone()
        
        if existing:
            record_week_start = date_obj - timedelta(days=date_obj.weekday())
            if record_week_start < current_week_start:
                return jsonify({"error": "Geçmiş haftaların kayıtları güncellenemez"}), 403
            
            cur.execute("""
                UPDATE daily_study_tracking
                SET note = %s, day_of_week = %s
                WHERE id = %s
                RETURNING id
            """, (data['note'], data['day_of_week'], existing['id']))
            
            result = cur.fetchone()
            result_id = result['id'] if result else None
            message = "Kayıt güncellendi"
        else:
            try:
                cur.execute("""
                    INSERT INTO daily_study_tracking
                    (student_id, date, day_of_week, subject, note)
                    VALUES (%s, %s, %s, %s, %s)
                    RETURNING id
                """, (
                    current_user.id,
                    data['date'],
                    data['day_of_week'],
                    data['subject'],
                    data['note']
                ))
                
                result = cur.fetchone()
                result_id = result['id'] if result else None
                message = "Kayıt oluşturuldu"
            except psycopg2.IntegrityError as ie:
                conn.rollback()
                if 'unique constraint' in str(ie).lower():
                    return jsonify({"error": "Bu tarih ve ders için zaten kayıt var"}), 409
                raise
        
        conn.commit()
        
        return jsonify({
            "success": True,
            "message": message,
            "id": result_id
        }), 200
        
    except Exception as e:
        conn.rollback()
        logger.error(f"Create tracking error: {e}")
        return jsonify({"error": "Kayıt oluşturulurken hata oluştu"}), 500
    finally:
        cur.close()
        conn.close()

@daily_tracking_bp.route('/student/week', methods=['GET'])
@login_required
def get_student_week():
    """Öğrencinin seçilen hafta için kayıtlarını getirir"""
    if current_user.role != 'student':
        return jsonify({"error": "Yetkisiz erişim"}), 403
    
    date_str = request.args.get('date')
    if not date_str:
        return jsonify({"error": "Tarih parametresi gerekli"}), 400
    
    try:
        selected_date = datetime.strptime(date_str, '%Y-%m-%d').date()
    except ValueError:
        return jsonify({"error": "Geçersiz tarih formatı"}), 400
    
    weekday = selected_date.weekday()
    week_start = selected_date - timedelta(days=weekday)
    week_end = week_start + timedelta(days=6)
    
    conn = get_db()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    
    try:
        cur.execute("""
            SELECT 
                id, date, day_of_week, subject, note, 
                created_at, updated_at
            FROM daily_study_tracking
            WHERE student_id = %s 
            AND date BETWEEN %s AND %s
            ORDER BY date ASC, subject ASC
        """, (current_user.id, week_start, week_end))
        
        records = cur.fetchall()
        
        return jsonify({
            "success": True,
            "week_start": str(week_start),
            "week_end": str(week_end),
            "records": [dict(r) for r in records]
        }), 200
        
    except Exception as e:
        logger.error(f"Get week error: {e}")
        return jsonify({"error": "Kayıtlar getirilirken hata oluştu"}), 500
    finally:
        cur.close()
        conn.close()

@daily_tracking_bp.route('/teacher/students', methods=['GET'])
@login_required
def get_teacher_students_tracking():
    """Öğretmenin öğrencilerinin haftalık/aylık kayıtlarını getirir"""
    if current_user.role != 'teacher':
        return jsonify({"error": "Sadece öğretmenler erişebilir"}), 403
    
    view_type = request.args.get('view', 'week')
    date_str = request.args.get('date')
    class_filter = request.args.get('class_name')
    
    if not date_str:
        return jsonify({"error": "Tarih parametresi gerekli"}), 400
    
    try:
        selected_date = datetime.strptime(date_str, '%Y-%m-%d').date()
    except ValueError:
        return jsonify({"error": "Geçersiz tarih formatı"}), 400
    
    conn = get_db()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    
    try:
        base_query = """
            SELECT DISTINCT u.id, u.full_name, u.class_name
            FROM users u
            WHERE u.role = 'student'
            AND (
                u.id IN (SELECT student_id FROM teacher_students WHERE teacher_id = %s)
                OR u.class_name IN (SELECT class_name FROM teacher_classes WHERE teacher_id = %s)
            )
        """
        params = [current_user.id, current_user.id]
        
        if class_filter:
            base_query += " AND u.class_name = %s"
            params.append(class_filter)
        
        base_query += " ORDER BY u.class_name, u.full_name"
        
        cur.execute(base_query, params)
        
        students = cur.fetchall()
        
        if view_type == 'week':
            weekday = selected_date.weekday()
            start_date = selected_date - timedelta(days=weekday)
            end_date = start_date + timedelta(days=6)
        else:
            start_date = selected_date.replace(day=1)
            if selected_date.month == 12:
                end_date = selected_date.replace(year=selected_date.year + 1, month=1, day=1) - timedelta(days=1)
            else:
                end_date = selected_date.replace(month=selected_date.month + 1, day=1) - timedelta(days=1)
        
        student_ids = [s['id'] for s in students]
        
        if not student_ids:
            return jsonify({
                "success": True,
                "view_type": view_type,
                "start_date": str(start_date),
                "end_date": str(end_date),
                "students": []
            }), 200
        
        cur.execute("""
            SELECT 
                dst.id, dst.student_id, dst.date, dst.day_of_week, 
                dst.subject, dst.note, dst.created_at, dst.updated_at
            FROM daily_study_tracking dst
            WHERE dst.student_id = ANY(%s)
            AND dst.date BETWEEN %s AND %s
            ORDER BY dst.student_id, dst.date ASC, dst.subject ASC
        """, (student_ids, start_date, end_date))
        
        all_records = cur.fetchall()
        
        records_by_student = {}
        for record in all_records:
            sid = record['student_id']
            if sid not in records_by_student:
                records_by_student[sid] = []
            records_by_student[sid].append(dict(record))
        
        results = []
        for student in students:
            results.append({
                "student_id": student['id'],
                "student_name": student['full_name'],
                "student_class": student['class_name'],
                "records": records_by_student.get(student['id'], [])
            })
        
        return jsonify({
            "success": True,
            "view_type": view_type,
            "start_date": str(start_date),
            "end_date": str(end_date),
            "students": results
        }), 200
        
    except Exception as e:
        logger.error(f"Get teacher students tracking error: {e}")
        return jsonify({"error": "Kayıtlar getirilirken hata oluştu"}), 500
    finally:
        cur.close()
        conn.close()

@daily_tracking_bp.route('/<int:tracking_id>', methods=['DELETE'])
@login_required
def delete_tracking(tracking_id):
    """Kayıt siler (sadece kendi kayıtlarını ve bu/gelecek haftayı silebilir)"""
    conn = get_db()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    
    try:
        cur.execute("""
            SELECT student_id, date FROM daily_study_tracking WHERE id = %s
        """, (tracking_id,))
        
        record = cur.fetchone()
        
        if not record:
            return jsonify({"error": "Kayıt bulunamadı"}), 404
        
        if current_user.role == 'student':
            if record['student_id'] != current_user.id:
                return jsonify({"error": "Sadece kendi kayıtlarınızı silebilirsiniz"}), 403
            
            today = datetime.now().date()
            current_week_start = today - timedelta(days=today.weekday())
            
            record_date = record['date']
            record_week_start = record_date - timedelta(days=record_date.weekday())
            
            if record_week_start < current_week_start:
                return jsonify({"error": "Geçmiş haftaların kayıtları silinemez"}), 403
        
        if current_user.role not in ['student', 'admin']:
            return jsonify({"error": "Yetkisiz erişim"}), 403
        
        cur.execute("DELETE FROM daily_study_tracking WHERE id = %s", (tracking_id,))
        conn.commit()
        
        return jsonify({"success": True, "message": "Kayıt silindi"}), 200
        
    except Exception as e:
        conn.rollback()
        logger.error(f"Delete tracking error: {e}")
        return jsonify({"error": "Kayıt silinirken hata oluştu"}), 500
    finally:
        cur.close()
        conn.close()

@daily_tracking_bp.route('/subjects', methods=['GET'])
@login_required
def get_subjects():
    """Geçerli ders listesini döndürür"""
    return jsonify({
        "success": True,
        "subjects": VALID_SUBJECTS
    }), 200

@daily_tracking_bp.route('/teacher/classes', methods=['GET'])
@login_required
def get_teacher_classes():
    """Öğretmenin sınıf listesini getirir"""
    if current_user.role != 'teacher':
        return jsonify({"error": "Sadece öğretmenler erişebilir"}), 403
    
    conn = get_db()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    
    try:
        cur.execute("""
            SELECT DISTINCT u.class_name, COUNT(u.id) as student_count
            FROM users u
            WHERE u.role = 'student' AND (
                u.class_name IN (SELECT class_name FROM teacher_classes WHERE teacher_id = %s)
                OR u.id IN (SELECT student_id FROM teacher_students WHERE teacher_id = %s)
            )
            AND u.class_name IS NOT NULL
            GROUP BY u.class_name
            ORDER BY u.class_name
        """, (current_user.id, current_user.id))
        
        classes = cur.fetchall()
        
        return jsonify({
            "success": True,
            "classes": [{"name": c['class_name'], "count": c['student_count']} for c in classes]
        })
    except Exception as e:
        logger.error(f"Get teacher classes error: {e}")
        return jsonify({"error": "Sınıflar yüklenirken hata oluştu"}), 500
    finally:
        cur.close()
        conn.close()

@daily_tracking_bp.route('/report', methods=['POST'])
@login_required
def generate_report():
    """Seçili öğrenciler için PDF rapor oluşturur"""
    if current_user.role != 'teacher':
        return jsonify({"error": "Sadece öğretmenler rapor oluşturabilir"}), 403
    
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont
    import io
    from flask import send_file
    
    try:
        pdfmetrics.registerFont(TTFont('DejaVu', '/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf'))
        font_name = 'DejaVu'
    except:
        font_name = 'Helvetica'
    
    data = request.get_json()
    student_ids = data.get('student_ids', [])
    start_date = data.get('start_date')
    end_date = data.get('end_date')
    
    if not student_ids:
        return jsonify({"error": "Öğrenci seçmelisiniz"}), 400
    
    conn = get_db()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    
    try:
        # GÜVENL İK: Öğretmenin sadece kendi öğrencilerine erişmesini sağla
        cur.execute("""
            SELECT u.id, u.full_name, u.class_name
            FROM users u
            WHERE u.id = ANY(%s) AND u.role = 'student'
            AND (
                u.class_name IN (SELECT class_name FROM teacher_classes WHERE teacher_id = %s)
                OR u.id IN (SELECT student_id FROM teacher_students WHERE teacher_id = %s)
            )
            ORDER BY u.class_name, u.full_name
        """, (student_ids, current_user.id, current_user.id))
        
        students = cur.fetchall()
        
        # Tüm istenen student_ids kontrol edilmeli - eksik varsa yetkisiz erişim
        if len(students) != len(student_ids):
            return jsonify({"error": "Seçili öğrencilerden bazılarına erişim yetkiniz yok"}), 403
        
        cur.execute("""
            SELECT dst.*, u.full_name, u.class_name
            FROM daily_study_tracking dst
            JOIN users u ON dst.student_id = u.id
            WHERE dst.student_id = ANY(%s)
            AND dst.date BETWEEN %s AND %s
            ORDER BY dst.date DESC, u.class_name, u.full_name
        """, (student_ids, start_date, end_date))
        
        records = cur.fetchall()
        
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=A4)
        elements = []
        styles = getSampleStyleSheet()
        
        title = Paragraph(f"<b>Günlük Takip Raporu</b><br/>{start_date} - {end_date}", styles['Title'])
        elements.append(title)
        elements.append(Spacer(1, 20))
        
        table_data = [['Öğrenci', 'Sınıf', 'Tarih', 'Gün', 'Ders', 'Not']]
        
        for record in records:
            table_data.append([
                record['full_name'][:20],
                record['class_name'] or '-',
                str(record['date']),
                record['day_of_week'],
                record['subject'],
                (record['note'] or '-')[:30]
            ])
        
        if len(table_data) == 1:
            table_data.append(['Kayıt yok', '', '', '', '', ''])
        
        t = Table(table_data)
        t.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, -1), font_name),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('FONTSIZE', (0, 1), (-1, -1), 9),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        elements.append(t)
        doc.build(elements)
        
        buffer.seek(0)
        return send_file(
            buffer,
            mimetype='application/pdf',
            as_attachment=True,
            download_name=f'gunluk_takip_{start_date}_{end_date}.pdf'
        )
        
    except Exception as e:
        logger.error(f"Generate report error: {e}")
        return jsonify({"error": f"Rapor oluştururken hata: {str(e)}"}), 500
    finally:
        cur.close()
        conn.close()
