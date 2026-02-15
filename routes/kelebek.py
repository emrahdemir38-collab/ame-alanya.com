import os
import json
import logging
import random
from io import BytesIO
from datetime import datetime
from flask import Blueprint, request, jsonify, render_template, send_file
from flask_login import login_required, current_user
import psycopg2
from psycopg2.extras import RealDictCursor
from openpyxl import Workbook, load_workbook
from openpyxl.styles import Font, Alignment, Border, Side, PatternFill
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import inch, cm
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont

logger = logging.getLogger(__name__)

try:
    pdfmetrics.registerFont(TTFont('DejaVuSans', '/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf'))
    pdfmetrics.registerFont(TTFont('DejaVuSans-Bold', '/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf'))
except Exception:
    pass

PDF_FONT = 'DejaVuSans'
PDF_FONT_BOLD = 'DejaVuSans-Bold'

kelebek_bp = Blueprint('kelebek', __name__, url_prefix='/admin/kelebek')

DEFAULT_ROOM_CAPACITIES = {
    '5A': {'desks': 17, 'capacity': 34},
    '5B': {'desks': 17, 'capacity': 34},
    '5C': {'desks': 17, 'capacity': 34},
    '5D': {'desks': 17, 'capacity': 34},
    '6A': {'desks': 16, 'capacity': 32},
    '6B': {'desks': 16, 'capacity': 32},
    '6C': {'desks': 16, 'capacity': 32},
    '6D': {'desks': 16, 'capacity': 32},
    '7A': {'desks': 14, 'capacity': 28},
    '7B': {'desks': 15, 'capacity': 30},
    '7C': {'desks': 15, 'capacity': 30},
    '7D': {'desks': 16, 'capacity': 32},
    '8A': {'desks': 14, 'capacity': 28},
    '8B': {'desks': 14, 'capacity': 28},
    '8C': {'desks': 14, 'capacity': 28},
    '8D': {'desks': 13, 'capacity': 26},
    'Yedek Sınıf': {'desks': 14, 'capacity': 28},
}

PRIORITY_EXAM_ROOMS = ['8A', '8B', '7A', '7B', '6A', '6C']
ALWAYS_STUDY_ROOMS = ['8D', '7C']


def get_db():
    from app import get_db as app_get_db
    return app_get_db()


def init_kelebek_tables(conn):
    cur = conn.cursor()
    try:
        cur.execute("""
            CREATE TABLE IF NOT EXISTS kelebek_plans (
                id SERIAL PRIMARY KEY,
                plan_name VARCHAR(200) NOT NULL,
                exam_date DATE,
                grade_levels JSONB NOT NULL,
                status VARCHAR(20) DEFAULT 'draft',
                created_by INTEGER REFERENCES users(id),
                created_at TIMESTAMP DEFAULT (CURRENT_TIMESTAMP AT TIME ZONE 'Europe/Istanbul'),
                updated_at TIMESTAMP DEFAULT (CURRENT_TIMESTAMP AT TIME ZONE 'Europe/Istanbul')
            );

            CREATE TABLE IF NOT EXISTS kelebek_rooms (
                id SERIAL PRIMARY KEY,
                plan_id INTEGER REFERENCES kelebek_plans(id) ON DELETE CASCADE,
                room_name VARCHAR(50) NOT NULL,
                desk_count INTEGER NOT NULL,
                capacity INTEGER NOT NULL,
                room_type VARCHAR(20) NOT NULL,
                grade_for_study INTEGER
            );

            CREATE TABLE IF NOT EXISTS kelebek_participants (
                id SERIAL PRIMARY KEY,
                plan_id INTEGER REFERENCES kelebek_plans(id) ON DELETE CASCADE,
                student_name VARCHAR(200) NOT NULL,
                student_no VARCHAR(20),
                class_name VARCHAR(10) NOT NULL,
                grade_level INTEGER NOT NULL,
                is_exam_taker BOOLEAN DEFAULT TRUE
            );

            CREATE TABLE IF NOT EXISTS kelebek_assignments (
                id SERIAL PRIMARY KEY,
                plan_id INTEGER REFERENCES kelebek_plans(id) ON DELETE CASCADE,
                room_id INTEGER REFERENCES kelebek_rooms(id) ON DELETE CASCADE,
                participant_id INTEGER REFERENCES kelebek_participants(id) ON DELETE CASCADE,
                desk_number INTEGER,
                seat_position VARCHAR(5),
                row_number INTEGER
            );
        """)
        conn.commit()
        logger.info("Kelebek tables created successfully")
    except Exception as e:
        conn.rollback()
        logger.error(f"Error creating kelebek tables: {e}")
        raise
    finally:
        cur.close()


@kelebek_bp.route('/')
@login_required
def kelebek_page():
    if current_user.role not in ['admin']:
        return jsonify({"error": "Yetkisiz erişim"}), 403
    return render_template('kelebek.html')


@kelebek_bp.route('/api/create-plan', methods=['POST'])
@login_required
def create_plan():
    if current_user.role not in ['admin']:
        return jsonify({"error": "Yetkisiz erişim"}), 403

    conn = None
    try:
        data = request.get_json()
        plan_name = data.get('plan_name', '').strip()
        exam_date = data.get('exam_date')
        grade_levels = data.get('grade_levels', [])

        if not plan_name:
            return jsonify({"error": "Plan adı gereklidir"}), 400
        if not grade_levels:
            return jsonify({"error": "En az bir sınıf seviyesi seçilmelidir"}), 400

        conn = get_db()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("""
            INSERT INTO kelebek_plans (plan_name, exam_date, grade_levels, created_by)
            VALUES (%s, %s, %s, %s)
            RETURNING id, plan_name, exam_date, grade_levels, status, created_at
        """, (plan_name, exam_date, json.dumps(grade_levels), current_user.id))
        plan = cur.fetchone()
        conn.commit()

        for key in ['exam_date', 'created_at']:
            if plan.get(key) and hasattr(plan[key], 'isoformat'):
                plan[key] = plan[key].isoformat()

        return jsonify({"success": True, "plan": plan})
    except Exception as e:
        if conn:
            conn.rollback()
        logger.error(f"Error creating plan: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        if conn:
            conn.close()


@kelebek_bp.route('/api/plans')
@login_required
def list_plans():
    if current_user.role not in ['admin']:
        return jsonify({"error": "Yetkisiz erişim"}), 403

    conn = None
    try:
        conn = get_db()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("""
            SELECT p.*, u.full_name as created_by_name,
                   (SELECT COUNT(*) FROM kelebek_participants WHERE plan_id = p.id) as participant_count,
                   (SELECT COUNT(*) FROM kelebek_rooms WHERE plan_id = p.id) as room_count
            FROM kelebek_plans p
            LEFT JOIN users u ON p.created_by = u.id
            ORDER BY p.created_at DESC
        """)
        plans = cur.fetchall()

        for plan in plans:
            for key in ['exam_date', 'created_at', 'updated_at']:
                if plan.get(key) and hasattr(plan[key], 'isoformat'):
                    plan[key] = plan[key].isoformat()

        return jsonify({"success": True, "plans": plans})
    except Exception as e:
        logger.error(f"Error listing plans: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        if conn:
            conn.close()


@kelebek_bp.route('/api/plan/<int:plan_id>')
@login_required
def get_plan(plan_id):
    if current_user.role not in ['admin']:
        return jsonify({"error": "Yetkisiz erişim"}), 403

    conn = None
    try:
        conn = get_db()
        cur = conn.cursor(cursor_factory=RealDictCursor)

        cur.execute("SELECT * FROM kelebek_plans WHERE id = %s", (plan_id,))
        plan = cur.fetchone()
        if not plan:
            return jsonify({"error": "Plan bulunamadı"}), 404

        for key in ['exam_date', 'created_at', 'updated_at']:
            if plan.get(key) and hasattr(plan[key], 'isoformat'):
                plan[key] = plan[key].isoformat()

        cur.execute("SELECT * FROM kelebek_rooms WHERE plan_id = %s ORDER BY room_name", (plan_id,))
        rooms = cur.fetchall()

        cur.execute("SELECT * FROM kelebek_participants WHERE plan_id = %s ORDER BY grade_level, class_name, student_name", (plan_id,))
        participants = cur.fetchall()

        cur.execute("""
            SELECT a.*, p.student_name, p.class_name, p.grade_level, p.student_no,
                   r.room_name, r.room_type
            FROM kelebek_assignments a
            JOIN kelebek_participants p ON a.participant_id = p.id
            JOIN kelebek_rooms r ON a.room_id = r.id
            WHERE a.plan_id = %s
            ORDER BY r.room_name, a.desk_number, a.seat_position
        """, (plan_id,))
        assignments = cur.fetchall()

        return jsonify({
            "success": True,
            "plan": plan,
            "rooms": rooms,
            "participants": participants,
            "assignments": assignments
        })
    except Exception as e:
        logger.error(f"Error getting plan: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        if conn:
            conn.close()


@kelebek_bp.route('/api/plan/<int:plan_id>', methods=['DELETE'])
@login_required
def delete_plan(plan_id):
    if current_user.role not in ['admin']:
        return jsonify({"error": "Yetkisiz erişim"}), 403

    conn = None
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("DELETE FROM kelebek_plans WHERE id = %s", (plan_id,))
        conn.commit()
        return jsonify({"success": True, "message": "Plan silindi"})
    except Exception as e:
        if conn:
            conn.rollback()
        logger.error(f"Error deleting plan: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        if conn:
            conn.close()


@kelebek_bp.route('/api/excel-template')
@login_required
def download_excel_template():
    if current_user.role not in ['admin']:
        return jsonify({"error": "Yetkisiz erişim"}), 403

    wb = Workbook()
    ws = wb.active
    ws.title = "Sınav Katılımcıları"

    header_fill = PatternFill(start_color="1E40AF", end_color="1E40AF", fill_type="solid")
    header_font = Font(bold=True, color="FFFFFF", size=12)
    header_alignment = Alignment(horizontal='center', vertical='center')
    thin_border = Border(
        left=Side(style='thin'), right=Side(style='thin'),
        top=Side(style='thin'), bottom=Side(style='thin')
    )

    headers = ['Sınıf', 'Okul Numarası', 'Ad Soyad']
    for col_idx, header in enumerate(headers, 1):
        cell = ws.cell(row=1, column=col_idx, value=header)
        cell.fill = header_fill
        cell.font = header_font
        cell.alignment = header_alignment
        cell.border = thin_border

    sample_data = [
        ('5A', '501', 'Ahmet YILMAZ'),
        ('5A', '502', 'Ayşe KAYA'),
        ('6B', '601', 'Mehmet DEMİR'),
        ('7A', '701', 'Fatma ÖZ'),
        ('8C', '801', 'Ali CAN'),
    ]

    sample_font = Font(color="999999", italic=True)
    for row_idx, (sinif, no, ad) in enumerate(sample_data, 2):
        for col_idx, value in enumerate([sinif, no, ad], 1):
            cell = ws.cell(row=row_idx, column=col_idx, value=value)
            cell.font = sample_font
            cell.border = thin_border
            cell.alignment = Alignment(horizontal='center' if col_idx < 3 else 'left', vertical='center')

    ws.column_dimensions['A'].width = 12
    ws.column_dimensions['B'].width = 18
    ws.column_dimensions['C'].width = 30

    ws.row_dimensions[1].height = 30

    output = BytesIO()
    wb.save(output)
    output.seek(0)

    return send_file(
        output,
        mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        as_attachment=True,
        download_name='kelebek_katilimci_sablonu.xlsx'
    )


@kelebek_bp.route('/api/upload-participants/<int:plan_id>', methods=['POST'])
@login_required
def upload_participants(plan_id):
    if current_user.role not in ['admin']:
        return jsonify({"error": "Yetkisiz erişim"}), 403

    if 'file' not in request.files:
        return jsonify({"error": "Dosya bulunamadı"}), 400

    file = request.files['file']
    if not file.filename or not file.filename.endswith(('.xlsx', '.xls')):
        return jsonify({"error": "Sadece Excel dosyaları kabul edilir (.xlsx)"}), 400

    conn = None
    try:
        conn = get_db()
        cur = conn.cursor(cursor_factory=RealDictCursor)

        cur.execute("SELECT * FROM kelebek_plans WHERE id = %s", (plan_id,))
        plan = cur.fetchone()
        if not plan:
            return jsonify({"error": "Plan bulunamadı"}), 404

        grade_levels = plan['grade_levels']
        if isinstance(grade_levels, str):
            grade_levels = json.loads(grade_levels)

        cur.execute("DELETE FROM kelebek_assignments WHERE plan_id = %s", (plan_id,))
        cur.execute("DELETE FROM kelebek_participants WHERE plan_id = %s", (plan_id,))
        cur.execute("DELETE FROM kelebek_rooms WHERE plan_id = %s", (plan_id,))

        wb = load_workbook(file)
        ws = wb.active

        exam_takers = []
        for row in ws.iter_rows(min_row=2, values_only=True):
            if not row or not row[0]:
                continue
            class_name = str(row[0]).strip()
            student_no = str(row[1]).strip() if row[1] else ''
            student_name = str(row[2]).strip() if len(row) > 2 and row[2] else ''

            if not student_name:
                continue

            grade_level = None
            for ch in class_name:
                if ch.isdigit():
                    grade_level = int(ch)
                    break

            if grade_level is None or grade_level not in grade_levels:
                continue

            exam_takers.append({
                'student_name': student_name,
                'student_no': student_no,
                'class_name': class_name,
                'grade_level': grade_level
            })

        exam_taker_keys = set()
        for et in exam_takers:
            key = (et['student_name'].upper(), et['class_name'].upper())
            exam_taker_keys.add(key)
            cur.execute("""
                INSERT INTO kelebek_participants (plan_id, student_name, student_no, class_name, grade_level, is_exam_taker)
                VALUES (%s, %s, %s, %s, %s, TRUE)
            """, (plan_id, et['student_name'], et['student_no'], et['class_name'], et['grade_level']))

        grade_placeholders = ','.join(['%s'] * len(grade_levels))
        cur.execute(f"""
            SELECT full_name, username, class_name
            FROM users
            WHERE role = 'student' AND class_name IS NOT NULL
            AND CAST(SUBSTRING(class_name FROM 1 FOR 1) AS INTEGER) IN ({grade_placeholders})
        """, grade_levels)
        all_students = cur.fetchall()

        non_exam_count = 0
        for student in all_students:
            key = (student['full_name'].upper(), student['class_name'].upper())
            if key not in exam_taker_keys:
                grade_level = None
                for ch in student['class_name']:
                    if ch.isdigit():
                        grade_level = int(ch)
                        break
                if grade_level is None:
                    continue
                cur.execute("""
                    INSERT INTO kelebek_participants (plan_id, student_name, student_no, class_name, grade_level, is_exam_taker)
                    VALUES (%s, %s, %s, %s, %s, FALSE)
                """, (plan_id, student['full_name'], student['username'], student['class_name'], grade_level))
                non_exam_count += 1

        cur.execute("UPDATE kelebek_plans SET status = 'draft', updated_at = (CURRENT_TIMESTAMP AT TIME ZONE 'Europe/Istanbul') WHERE id = %s", (plan_id,))
        conn.commit()

        return jsonify({
            "success": True,
            "message": f"{len(exam_takers)} sınava giren, {non_exam_count} ders çalışacak öğrenci yüklendi",
            "exam_takers": len(exam_takers),
            "non_exam_takers": non_exam_count,
            "total": len(exam_takers) + non_exam_count
        })
    except Exception as e:
        if conn:
            conn.rollback()
        logger.error(f"Error uploading participants: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        if conn:
            conn.close()


def _run_butterfly_algorithm(plan_id, conn):
    cur = conn.cursor(cursor_factory=RealDictCursor)

    cur.execute("SELECT * FROM kelebek_plans WHERE id = %s", (plan_id,))
    plan = cur.fetchone()
    grade_levels = plan['grade_levels']
    if isinstance(grade_levels, str):
        grade_levels = json.loads(grade_levels)

    cur.execute("SELECT * FROM kelebek_participants WHERE plan_id = %s", (plan_id,))
    participants = cur.fetchall()

    exam_students = [p for p in participants if p['is_exam_taker']]
    non_exam_students = [p for p in participants if not p['is_exam_taker']]

    exam_by_grade = {}
    for s in exam_students:
        exam_by_grade.setdefault(s['grade_level'], []).append(s)

    non_exam_by_grade = {}
    for s in non_exam_students:
        non_exam_by_grade.setdefault(s['grade_level'], []).append(s)

    exam_count_by_class = {}
    for s in exam_students:
        exam_count_by_class[s['class_name']] = exam_count_by_class.get(s['class_name'], 0) + 1

    cur.execute("DELETE FROM kelebek_assignments WHERE plan_id = %s", (plan_id,))
    cur.execute("DELETE FROM kelebek_rooms WHERE plan_id = %s", (plan_id,))

    relevant_rooms = {}
    for room_name, info in DEFAULT_ROOM_CAPACITIES.items():
        if room_name == 'Yedek Sınıf':
            relevant_rooms[room_name] = info
            continue
        room_grade = None
        for ch in room_name:
            if ch.isdigit():
                room_grade = int(ch)
                break
        if room_grade and room_grade in grade_levels:
            relevant_rooms[room_name] = info

    exam_rooms = []
    study_rooms = []
    used_rooms = set()

    if 'Yedek Sınıf' in relevant_rooms:
        exam_rooms.append('Yedek Sınıf')
        used_rooms.add('Yedek Sınıf')

    for room in PRIORITY_EXAM_ROOMS:
        if room in relevant_rooms and room not in used_rooms and room not in ALWAYS_STUDY_ROOMS:
            exam_rooms.append(room)
            used_rooms.add(room)

    for room in ALWAYS_STUDY_ROOMS:
        if room in relevant_rooms and room not in used_rooms:
            study_rooms.append(room)
            used_rooms.add(room)

    fifth_grade_rooms = [r for r in relevant_rooms if r.startswith('5') and r not in used_rooms]
    if fifth_grade_rooms:
        fifth_grade_rooms.sort(key=lambda r: exam_count_by_class.get(r, 0), reverse=True)
        if fifth_grade_rooms:
            exam_rooms.append(fifth_grade_rooms[0])
            used_rooms.add(fifth_grade_rooms[0])
            for r in fifth_grade_rooms[1:]:
                study_rooms.append(r)
                used_rooms.add(r)

    total_exam_capacity = sum(relevant_rooms[r]['capacity'] for r in exam_rooms)
    total_exam_students = len(exam_students)

    remaining_rooms = [r for r in relevant_rooms if r not in used_rooms]
    remaining_rooms.sort(key=lambda r: relevant_rooms[r]['capacity'], reverse=True)

    for room in remaining_rooms:
        if total_exam_capacity >= total_exam_students:
            break
        exam_rooms.append(room)
        used_rooms.add(room)
        total_exam_capacity += relevant_rooms[room]['capacity']

    for room in remaining_rooms:
        if room not in used_rooms:
            study_rooms.append(room)
            used_rooms.add(room)

    room_ids = {}
    for room_name in exam_rooms:
        info = relevant_rooms[room_name]
        cur.execute("""
            INSERT INTO kelebek_rooms (plan_id, room_name, desk_count, capacity, room_type, grade_for_study)
            VALUES (%s, %s, %s, %s, 'exam', NULL)
            RETURNING id
        """, (plan_id, room_name, info['desks'], info['capacity']))
        room_ids[room_name] = cur.fetchone()['id']

    for room_name in study_rooms:
        info = relevant_rooms[room_name]
        room_grade = None
        for ch in room_name:
            if ch.isdigit():
                room_grade = int(ch)
                break
        cur.execute("""
            INSERT INTO kelebek_rooms (plan_id, room_name, desk_count, capacity, room_type, grade_for_study)
            VALUES (%s, %s, %s, %s, 'study', %s)
            RETURNING id
        """, (plan_id, room_name, info['desks'], info['capacity'], room_grade))
        room_ids[room_name] = cur.fetchone()['id']

    study_room_by_grade = {}
    for room_name in study_rooms:
        room_grade = None
        for ch in room_name:
            if ch.isdigit():
                room_grade = int(ch)
                break
        if room_grade:
            study_room_by_grade.setdefault(room_grade, []).append(room_name)

    for grade, students in non_exam_by_grade.items():
        available_rooms = study_room_by_grade.get(grade, [])
        if not available_rooms:
            all_study = [r for r in study_rooms if r not in [sr for srs in study_room_by_grade.values() for sr in srs]]
            if all_study:
                available_rooms = all_study

        random.shuffle(students)
        student_idx = 0
        for room_name in available_rooms:
            if student_idx >= len(students):
                break
            room_info = relevant_rooms[room_name]
            room_capacity = room_info['capacity']
            desk_num = 1
            while student_idx < len(students) and desk_num <= room_info['desks']:
                for pos in ['left', 'right']:
                    if student_idx >= len(students):
                        break
                    s = students[student_idx]
                    cur.execute("""
                        INSERT INTO kelebek_assignments (plan_id, room_id, participant_id, desk_number, seat_position, row_number)
                        VALUES (%s, %s, %s, %s, %s, %s)
                    """, (plan_id, room_ids[room_name], s['id'], desk_num, pos, desk_num))
                    student_idx += 1
                desk_num += 1

    for grade in exam_by_grade:
        random.shuffle(exam_by_grade[grade])

    grade_queues = {}
    for grade, students in exam_by_grade.items():
        grade_queues[grade] = list(students)

    for room_name in exam_rooms:
        room_info = relevant_rooms[room_name]
        room_id = room_ids[room_name]
        num_desks = room_info['desks']

        total_remaining = sum(len(q) for q in grade_queues.values())
        if total_remaining == 0:
            break

        room_share = min(num_desks * 2, total_remaining)

        for desk_num in range(1, num_desks + 1):
            active_grades = sorted(grade_queues.keys(), key=lambda g: len(grade_queues[g]), reverse=True)
            active_grades = [g for g in active_grades if len(grade_queues[g]) > 0]

            if not active_grades:
                break

            left_grade = active_grades[0]
            left_student = grade_queues[left_grade].pop(0)

            cur.execute("""
                INSERT INTO kelebek_assignments (plan_id, room_id, participant_id, desk_number, seat_position, row_number)
                VALUES (%s, %s, %s, %s, 'left', %s)
            """, (plan_id, room_id, left_student['id'], desk_num, desk_num))

            right_grades = [g for g in active_grades if g != left_grade and len(grade_queues[g]) > 0]
            if right_grades:
                right_grades.sort(key=lambda g: len(grade_queues[g]), reverse=True)
                right_grade = right_grades[0]
                right_student = grade_queues[right_grade].pop(0)
                cur.execute("""
                    INSERT INTO kelebek_assignments (plan_id, room_id, participant_id, desk_number, seat_position, row_number)
                    VALUES (%s, %s, %s, %s, 'right', %s)
                """, (plan_id, room_id, right_student['id'], desk_num, desk_num))
            else:
                remaining_same = [g for g in active_grades if len(grade_queues.get(g, [])) > 0]
                if remaining_same:
                    pass

    cur.execute("UPDATE kelebek_plans SET status = 'generated', updated_at = (CURRENT_TIMESTAMP AT TIME ZONE 'Europe/Istanbul') WHERE id = %s", (plan_id,))
    conn.commit()


@kelebek_bp.route('/api/generate/<int:plan_id>', methods=['POST'])
@login_required
def generate_seating(plan_id):
    if current_user.role not in ['admin']:
        return jsonify({"error": "Yetkisiz erişim"}), 403

    conn = None
    try:
        conn = get_db()
        cur = conn.cursor(cursor_factory=RealDictCursor)

        cur.execute("SELECT COUNT(*) as cnt FROM kelebek_participants WHERE plan_id = %s", (plan_id,))
        count = cur.fetchone()['cnt']
        if count == 0:
            return jsonify({"error": "Önce katılımcıları yükleyin"}), 400

        _run_butterfly_algorithm(plan_id, conn)

        return jsonify({"success": True, "message": "Kelebek yerleşim planı oluşturuldu"})
    except Exception as e:
        if conn:
            conn.rollback()
        logger.error(f"Error generating seating: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        if conn:
            conn.close()


@kelebek_bp.route('/api/regenerate/<int:plan_id>', methods=['POST'])
@login_required
def regenerate_seating(plan_id):
    if current_user.role not in ['admin']:
        return jsonify({"error": "Yetkisiz erişim"}), 403

    conn = None
    try:
        conn = get_db()
        _run_butterfly_algorithm(plan_id, conn)
        return jsonify({"success": True, "message": "Yerleşim planı yeniden oluşturuldu (yeni karışım)"})
    except Exception as e:
        if conn:
            conn.rollback()
        logger.error(f"Error regenerating seating: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        if conn:
            conn.close()


@kelebek_bp.route('/api/summary/<int:plan_id>')
@login_required
def get_summary(plan_id):
    if current_user.role not in ['admin']:
        return jsonify({"error": "Yetkisiz erişim"}), 403

    conn = None
    try:
        conn = get_db()
        cur = conn.cursor(cursor_factory=RealDictCursor)

        cur.execute("SELECT * FROM kelebek_plans WHERE id = %s", (plan_id,))
        plan = cur.fetchone()
        if not plan:
            return jsonify({"error": "Plan bulunamadı"}), 404

        cur.execute("""
            SELECT grade_level, is_exam_taker, COUNT(*) as cnt
            FROM kelebek_participants WHERE plan_id = %s
            GROUP BY grade_level, is_exam_taker
            ORDER BY grade_level
        """, (plan_id,))
        grade_stats = cur.fetchall()

        per_grade = {}
        total_exam = 0
        total_non_exam = 0
        for row in grade_stats:
            grade = row['grade_level']
            if grade not in per_grade:
                per_grade[grade] = {'exam_takers': 0, 'non_exam_takers': 0, 'total': 0}
            if row['is_exam_taker']:
                per_grade[grade]['exam_takers'] = row['cnt']
                total_exam += row['cnt']
            else:
                per_grade[grade]['non_exam_takers'] = row['cnt']
                total_non_exam += row['cnt']
            per_grade[grade]['total'] = per_grade[grade]['exam_takers'] + per_grade[grade]['non_exam_takers']

        cur.execute("""
            SELECT r.id, r.room_name, r.room_type, r.capacity, r.desk_count, r.grade_for_study,
                   COUNT(a.id) as assigned_count
            FROM kelebek_rooms r
            LEFT JOIN kelebek_assignments a ON a.room_id = r.id
            WHERE r.plan_id = %s
            GROUP BY r.id, r.room_name, r.room_type, r.capacity, r.desk_count, r.grade_for_study
            ORDER BY r.room_name
        """, (plan_id,))
        rooms = cur.fetchall()

        assigned_ids = set()
        cur.execute("SELECT DISTINCT participant_id FROM kelebek_assignments WHERE plan_id = %s", (plan_id,))
        for row in cur.fetchall():
            assigned_ids.add(row['participant_id'])

        cur.execute("SELECT id, student_name, class_name FROM kelebek_participants WHERE plan_id = %s", (plan_id,))
        all_parts = cur.fetchall()
        unassigned = [p for p in all_parts if p['id'] not in assigned_ids]

        return jsonify({
            "success": True,
            "summary": {
                "total_students": total_exam + total_non_exam,
                "exam_takers": total_exam,
                "non_exam_takers": total_non_exam,
                "per_grade": per_grade,
                "rooms": rooms,
                "unassigned_count": len(unassigned),
                "unassigned_students": [{"name": u['student_name'], "class": u['class_name']} for u in unassigned[:50]]
            }
        })
    except Exception as e:
        logger.error(f"Error getting summary: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        if conn:
            conn.close()


@kelebek_bp.route('/api/room-list-pdf/<int:plan_id>')
@login_required
def download_room_list_pdf(plan_id):
    if current_user.role not in ['admin']:
        return jsonify({"error": "Yetkisiz erişim"}), 403

    conn = None
    try:
        conn = get_db()
        cur = conn.cursor(cursor_factory=RealDictCursor)

        cur.execute("SELECT * FROM kelebek_plans WHERE id = %s", (plan_id,))
        plan = cur.fetchone()
        if not plan:
            return jsonify({"error": "Plan bulunamadı"}), 404

        cur.execute("SELECT * FROM kelebek_rooms WHERE plan_id = %s ORDER BY room_type DESC, room_name", (plan_id,))
        rooms = cur.fetchall()

        cur.execute("""
            SELECT a.*, p.student_name, p.class_name, p.grade_level, p.student_no
            FROM kelebek_assignments a
            JOIN kelebek_participants p ON a.participant_id = p.id
            WHERE a.plan_id = %s
            ORDER BY a.room_id, a.desk_number, a.seat_position
        """, (plan_id,))
        all_assignments = cur.fetchall()

        assignments_by_room = {}
        for a in all_assignments:
            assignments_by_room.setdefault(a['room_id'], []).append(a)

        buffer = BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=A4, topMargin=1*cm, bottomMargin=1*cm, leftMargin=1.5*cm, rightMargin=1.5*cm)

        styles = getSampleStyleSheet()
        title_style = ParagraphStyle('KelebekTitle', parent=styles['Title'], fontName=PDF_FONT_BOLD, fontSize=16, alignment=TA_CENTER, spaceAfter=6)
        subtitle_style = ParagraphStyle('KelebekSubtitle', parent=styles['Normal'], fontName=PDF_FONT, fontSize=11, alignment=TA_CENTER, spaceAfter=4)
        room_title_style = ParagraphStyle('RoomTitle', parent=styles['Heading2'], fontName=PDF_FONT_BOLD, fontSize=14, alignment=TA_CENTER, spaceAfter=8)
        cell_style = ParagraphStyle('CellStyle', parent=styles['Normal'], fontName=PDF_FONT, fontSize=9, alignment=TA_CENTER)
        cell_style_left = ParagraphStyle('CellStyleLeft', parent=styles['Normal'], fontName=PDF_FONT, fontSize=9, alignment=TA_LEFT)
        header_cell_style = ParagraphStyle('HeaderCell', parent=styles['Normal'], fontName=PDF_FONT_BOLD, fontSize=10, alignment=TA_CENTER, textColor=colors.white)

        elements = []

        for room_idx, room in enumerate(rooms):
            room_id = room['id']
            room_assignments = assignments_by_room.get(room_id, [])
            room_type_label = 'SINAV SALONU' if room['room_type'] == 'exam' else 'DERS SALONU'

            elements.append(Paragraph(f"{room['room_name']} - {room_type_label}", room_title_style))

            exam_date_str = ''
            if plan.get('exam_date'):
                ed = plan['exam_date']
                if hasattr(ed, 'strftime'):
                    exam_date_str = ed.strftime('%d.%m.%Y')
                else:
                    exam_date_str = str(ed)

            info_text = f"{plan['plan_name']}"
            if exam_date_str:
                info_text += f" | Tarih: {exam_date_str}"
            info_text += f" | Kapasite: {room['capacity']} | Sıra: {room['desk_count']}"
            if room['room_type'] == 'study' and room.get('grade_for_study'):
                info_text += f" | {room['grade_for_study']}. Sınıf Ders Çalışma"
            elements.append(Paragraph(info_text, subtitle_style))
            elements.append(Spacer(1, 10))

            if room['room_type'] == 'exam':
                desks = {}
                for a in room_assignments:
                    desk_num = a['desk_number']
                    if desk_num not in desks:
                        desks[desk_num] = {'left': None, 'right': None}
                    desks[desk_num][a['seat_position']] = a

                table_data = [[
                    Paragraph('Sıra', header_cell_style),
                    Paragraph('Sol Öğrenci', header_cell_style),
                    Paragraph('Sınıf', header_cell_style),
                    Paragraph('Sağ Öğrenci', header_cell_style),
                    Paragraph('Sınıf', header_cell_style),
                ]]

                for desk_num in sorted(desks.keys()):
                    desk = desks[desk_num]
                    left = desk.get('left')
                    right = desk.get('right')
                    table_data.append([
                        Paragraph(str(desk_num), cell_style),
                        Paragraph(left['student_name'] if left else '-', cell_style_left),
                        Paragraph(left['class_name'] if left else '-', cell_style),
                        Paragraph(right['student_name'] if right else '-', cell_style_left),
                        Paragraph(right['class_name'] if right else '-', cell_style),
                    ])

                col_widths = [1.2*cm, 6.5*cm, 2*cm, 6.5*cm, 2*cm]
                t = Table(table_data, colWidths=col_widths, repeatRows=1)
                t.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1e3a5f')),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                    ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                    ('FONTNAME', (0, 0), (-1, 0), PDF_FONT_BOLD),
                    ('FONTSIZE', (0, 0), (-1, 0), 10),
                    ('FONTNAME', (0, 1), (-1, -1), PDF_FONT),
                    ('FONTSIZE', (0, 1), (-1, -1), 9),
                    ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                    ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f0f4f8')]),
                    ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                    ('TOPPADDING', (0, 0), (-1, -1), 4),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                ]))
                elements.append(t)

            else:
                table_data = [[
                    Paragraph('No', header_cell_style),
                    Paragraph('Ad Soyad', header_cell_style),
                    Paragraph('Sınıf', header_cell_style),
                ]]

                for idx, a in enumerate(room_assignments, 1):
                    table_data.append([
                        Paragraph(str(idx), cell_style),
                        Paragraph(a['student_name'], cell_style_left),
                        Paragraph(a['class_name'], cell_style),
                    ])

                if not room_assignments:
                    table_data.append([
                        Paragraph('-', cell_style),
                        Paragraph('Atanmış öğrenci yok', cell_style_left),
                        Paragraph('-', cell_style),
                    ])

                col_widths = [1.5*cm, 12*cm, 3*cm]
                t = Table(table_data, colWidths=col_widths, repeatRows=1)
                t.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2d6a4f')),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                    ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                    ('FONTNAME', (0, 0), (-1, 0), PDF_FONT_BOLD),
                    ('FONTSIZE', (0, 0), (-1, 0), 10),
                    ('FONTNAME', (0, 1), (-1, -1), PDF_FONT),
                    ('FONTSIZE', (0, 1), (-1, -1), 9),
                    ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                    ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f0fdf4')]),
                    ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                    ('TOPPADDING', (0, 0), (-1, -1), 4),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                ]))
                elements.append(t)

            if room_idx < len(rooms) - 1:
                elements.append(PageBreak())

        if not rooms:
            elements.append(Paragraph("Henüz oda ataması yapılmamış", subtitle_style))

        doc.build(elements)
        buffer.seek(0)

        plan_name_safe = plan['plan_name'].replace(' ', '_')
        return send_file(
            buffer,
            mimetype='application/pdf',
            as_attachment=True,
            download_name=f'kelebek_{plan_name_safe}.pdf'
        )
    except Exception as e:
        logger.error(f"Error generating PDF: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        if conn:
            conn.close()
