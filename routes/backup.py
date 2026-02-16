import os
import io
import json
import logging
import gzip
import base64
from datetime import datetime, date, time, timedelta
from decimal import Decimal
from uuid import UUID
from flask import Blueprint, request, jsonify, render_template, send_file, session as flask_session
from flask_login import login_required, current_user
import psycopg2
from psycopg2.extras import RealDictCursor

logger = logging.getLogger(__name__)

backup_bp = Blueprint('backup', __name__)

DATABASE_URL = os.environ.get('DATABASE_URL')

BACKUP_TABLES = [
    'users', 'classes', 'teacher_classes', 'teacher_students',
    'practice_exams', 'student_achievements', 'student_badges', 'student_points', 'student_goals',
    'exams', 'exam_results', 'exam_submissions', 'exam_questions', 'exam_samples', 'exam_calendar',
    'assignments', 'assignment_submissions',
    'book_entries', 'book_challenges', 'book_challenge_submissions',
    'announcements', 'announcement_reads', 'teacher_announcements', 'public_announcements',
    'notifications',
    'report_cards', 'report_card_exams', 'report_card_exam_pages', 'report_card_results',
    'report_card_students', 'report_card_subjects', 'report_card_answers',
    'report_card_question_regions',
    'kelebek_plans', 'kelebek_rooms', 'kelebek_room_config', 'kelebek_assignments', 'kelebek_participants',
    'lgs_results',
    'surveys', 'survey_questions', 'survey_responses',
    'daily_study_tracking', 'study_schedules', 'study_plan_pdf', 'teacher_study_plan',
    'lesson_schedules', 'learning_outcomes',
    'question_asks', 'student_questions', 'question_analysis',
    'dashboard_widget_preferences', 'user_sessions',
    'parent_children', 'parent_messages', 'teacher_parent_notes', 'teacher_student_notes',
    'topic_requests',
    'optical_exams', 'optical_student_results', 'fmt_answer_keys',
]


def get_db():
    conn = psycopg2.connect(DATABASE_URL)
    return conn


def serialize_value(value):
    if value is None:
        return None
    if isinstance(value, datetime):
        return {'__type': 'datetime', '__value': value.isoformat()}
    if isinstance(value, date):
        return {'__type': 'date', '__value': value.isoformat()}
    if isinstance(value, time):
        return {'__type': 'time', '__value': value.isoformat()}
    if isinstance(value, timedelta):
        return {'__type': 'timedelta', '__value': value.total_seconds()}
    if isinstance(value, Decimal):
        return {'__type': 'decimal', '__value': str(value)}
    if isinstance(value, UUID):
        return {'__type': 'uuid', '__value': str(value)}
    if isinstance(value, bytes):
        return {'__type': 'bytes', '__value': base64.b64encode(value).decode('utf-8')}
    if isinstance(value, (str, int, float, bool, list, dict)):
        return value
    return str(value)


def deserialize_value(value):
    if value is None:
        return None
    if isinstance(value, dict) and '__type' in value:
        vtype = value['__type']
        vval = value['__value']
        if vtype == 'datetime':
            return datetime.fromisoformat(vval)
        if vtype == 'date':
            return date.fromisoformat(vval)
        if vtype == 'time':
            return time.fromisoformat(vval)
        if vtype == 'timedelta':
            return timedelta(seconds=vval)
        if vtype == 'decimal':
            return Decimal(vval)
        if vtype == 'uuid':
            return vval
        if vtype == 'bytes':
            return base64.b64decode(vval)
    return value


def get_table_counts():
    conn = get_db()
    cur = conn.cursor()
    counts = {}
    for table in BACKUP_TABLES:
        try:
            cur.execute(f'SELECT COUNT(*) FROM "{table}";')
            counts[table] = cur.fetchone()[0]
        except:
            conn.rollback()
            counts[table] = -1
    cur.close()
    conn.close()
    return counts


def create_backup_data():
    conn = get_db()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    backup = {
        'meta': {
            'created_at': datetime.now().isoformat(),
            'version': '2.0',
            'source': 'AMEO LMS Backup System'
        },
        'tables': {}
    }

    for table in BACKUP_TABLES:
        try:
            cur.execute(f'SELECT COUNT(*) FROM "{table}";')
        except:
            conn.rollback()
            continue

        conn.rollback()
        try:
            cur.execute(f'SELECT * FROM "{table}" ORDER BY id;')
        except:
            conn.rollback()
            try:
                cur.execute(f'SELECT * FROM "{table}";')
            except:
                conn.rollback()
                continue

        rows = cur.fetchall()
        if rows:
            serialized_rows = []
            for row in rows:
                serialized_row = {}
                for key, value in row.items():
                    serialized_row[key] = serialize_value(value)
                serialized_rows.append(serialized_row)
            backup['tables'][table] = {
                'count': len(serialized_rows),
                'rows': serialized_rows
            }

    cur.close()
    conn.close()
    return backup


def restore_all_tables(tables_data, selected_tables=None):
    if selected_tables is None:
        selected_tables = list(tables_data.keys())

    restore_order = []
    for table in BACKUP_TABLES:
        if table in selected_tables and table in tables_data:
            restore_order.append(table)
    for table in selected_tables:
        if table not in restore_order and table in tables_data:
            restore_order.append(table)

    conn = get_db()
    cur = conn.cursor()
    results = []
    errors = []

    try:
        delete_order = list(reversed(restore_order))
        for table in delete_order:
            try:
                cur.execute(f'DELETE FROM "{table}";')
            except Exception as e:
                conn.rollback()
                logger.warning(f"Delete from {table} failed: {e}")
        conn.commit()

        for table in restore_order:
            try:
                rows = tables_data[table]['rows']
                if not rows:
                    continue

                columns = list(rows[0].keys())
                col_list = ', '.join([f'"{c}"' for c in columns])
                placeholders = ', '.join(['%s'] * len(columns))

                insert_sql = f'INSERT INTO "{table}" ({col_list}) VALUES ({placeholders})'
                for row in rows:
                    values = [deserialize_value(row.get(col)) for col in columns]
                    cur.execute(insert_sql, values)

                cur.execute(f"""
                    SELECT column_name FROM information_schema.columns
                    WHERE table_name='{table}' AND column_default LIKE 'nextval%%';
                """)
                seq_cols = cur.fetchall()
                for (seq_col,) in seq_cols:
                    cur.execute(f'SELECT MAX("{seq_col}") FROM "{table}";')
                    max_val = cur.fetchone()[0]
                    cur.execute(f"SELECT pg_get_serial_sequence('{table}', '{seq_col}');")
                    seq_name_result = cur.fetchone()
                    if seq_name_result and seq_name_result[0]:
                        seq_name = seq_name_result[0]
                        new_val = max_val if max_val else 1
                        cur.execute(f"SELECT setval('{seq_name}', {new_val});")

                conn.commit()
                results.append({'table': table, 'rows': len(rows)})
            except Exception as e:
                conn.rollback()
                logger.error(f"Restore error for {table}: {e}")
                errors.append({'table': table, 'error': str(e)})

    except Exception as e:
        conn.rollback()
        logger.error(f"Restore transaction error: {e}")
        raise
    finally:
        cur.close()
        conn.close()

    return results, errors


def save_backup_to_object_storage(backup_data):
    try:
        from app import object_storage
        if not object_storage.is_available():
            return None

        json_str = json.dumps(backup_data, ensure_ascii=False, default=str)
        compressed = gzip.compress(json_str.encode('utf-8'))

        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        path = f"backups/ameo_backup_{timestamp}.json.gz"

        object_storage.client.upload_from_bytes(path, compressed)
        logger.info(f"Backup saved to Object Storage: {path} ({len(compressed)} bytes)")
        return path
    except Exception as e:
        logger.error(f"Object Storage backup error: {e}")
        return None


def list_backups_from_object_storage():
    try:
        from app import object_storage
        if not object_storage.is_available():
            return []

        objects = object_storage.client.list("backups/")
        backups = []
        for obj in objects:
            name = obj.name if hasattr(obj, 'name') else str(obj)
            if name.startswith('backups/') and name.endswith('.json.gz'):
                parts = name.replace('backups/ameo_backup_', '').replace('.json.gz', '')
                try:
                    dt = datetime.strptime(parts, '%Y%m%d_%H%M%S')
                    backups.append({
                        'path': name,
                        'date': dt.strftime('%d.%m.%Y %H:%M:%S'),
                        'timestamp': dt.isoformat()
                    })
                except:
                    backups.append({
                        'path': name,
                        'date': parts,
                        'timestamp': ''
                    })
        backups.sort(key=lambda x: x['timestamp'], reverse=True)
        return backups
    except Exception as e:
        logger.error(f"List backups error: {e}")
        return []


def download_backup_from_object_storage(path):
    try:
        from app import object_storage
        if not object_storage.is_available():
            return None

        data, _ = object_storage.download_as_bytes(path)
        json_str = gzip.decompress(data).decode('utf-8')
        return json.loads(json_str)
    except Exception as e:
        logger.error(f"Download backup error: {e}")
        return None


@backup_bp.route('/admin/backup')
@login_required
def admin_backup():
    if current_user.role != 'admin':
        return "Yetkisiz", 403
    return render_template('admin_backup.html')


@backup_bp.route('/api/backup/status')
@login_required
def backup_status():
    if current_user.role != 'admin':
        return jsonify({'error': 'Yetkisiz'}), 403

    counts = get_table_counts()
    total_rows = sum(v for v in counts.values() if v > 0)
    tables_with_data = {k: v for k, v in counts.items() if v > 0}
    backups = list_backups_from_object_storage()

    return jsonify({
        'total_rows': total_rows,
        'tables_with_data': tables_with_data,
        'table_count': len(tables_with_data),
        'cloud_backups': backups
    })


@backup_bp.route('/api/backup/create', methods=['POST'])
@login_required
def create_backup():
    if current_user.role != 'admin':
        return jsonify({'error': 'Yetkisiz'}), 403

    try:
        backup_data = create_backup_data()
        total_rows = sum(t['count'] for t in backup_data['tables'].values())
        table_count = len(backup_data['tables'])

        cloud_path = save_backup_to_object_storage(backup_data)

        return jsonify({
            'success': True,
            'total_rows': total_rows,
            'table_count': table_count,
            'cloud_path': cloud_path,
            'message': f'{table_count} tablo, {total_rows} kayıt yedeklendi'
        })
    except Exception as e:
        logger.error(f"Create backup error: {e}")
        return jsonify({'error': str(e)}), 500


@backup_bp.route('/api/backup/download')
@login_required
def download_backup():
    if current_user.role != 'admin':
        return jsonify({'error': 'Yetkisiz'}), 403

    try:
        backup_data = create_backup_data()
        json_str = json.dumps(backup_data, ensure_ascii=False, indent=2, default=str)
        compressed = gzip.compress(json_str.encode('utf-8'))

        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"ameo_yedek_{timestamp}.json.gz"

        return send_file(
            io.BytesIO(compressed),
            mimetype='application/gzip',
            as_attachment=True,
            download_name=filename
        )
    except Exception as e:
        logger.error(f"Download backup error: {e}")
        return jsonify({'error': str(e)}), 500


@backup_bp.route('/api/backup/download-cloud/<path:backup_path>')
@login_required
def download_cloud_backup(backup_path):
    if current_user.role != 'admin':
        return jsonify({'error': 'Yetkisiz'}), 403

    try:
        from app import object_storage
        if not object_storage.is_available():
            return jsonify({'error': 'Object Storage kullanılamıyor'}), 500

        data, _ = object_storage.download_as_bytes(backup_path)

        filename = backup_path.split('/')[-1].replace('ameo_backup_', 'ameo_yedek_')
        return send_file(
            io.BytesIO(data),
            mimetype='application/gzip',
            as_attachment=True,
            download_name=filename
        )
    except Exception as e:
        logger.error(f"Download cloud backup error: {e}")
        return jsonify({'error': str(e)}), 500


@backup_bp.route('/api/backup/restore', methods=['POST'])
@login_required
def restore_backup():
    if current_user.role != 'admin':
        return jsonify({'error': 'Yetkisiz'}), 403

    source = request.form.get('source', 'upload')

    try:
        if source == 'cloud':
            cloud_path = request.form.get('cloud_path')
            if not cloud_path:
                return jsonify({'error': 'Yedek dosya seçilmedi'}), 400
            backup_data = download_backup_from_object_storage(cloud_path)
            if not backup_data:
                return jsonify({'error': 'Yedek dosya indirilemedi'}), 500
        else:
            file = request.files.get('backup_file')
            if not file:
                return jsonify({'error': 'Dosya seçilmedi'}), 400

            file_data = file.read()
            try:
                json_str = gzip.decompress(file_data).decode('utf-8')
            except:
                json_str = file_data.decode('utf-8')

            backup_data = json.loads(json_str)

        if 'tables' not in backup_data:
            return jsonify({'error': 'Geçersiz yedek dosya formatı'}), 400

        tables_data = backup_data['tables']
        selected_tables = request.form.getlist('tables')
        if not selected_tables:
            selected_tables = list(tables_data.keys())

        results, errors = restore_all_tables(tables_data, selected_tables)

        return jsonify({
            'success': True,
            'restored': results,
            'errors': errors,
            'message': f'{len(results)} tablo geri yüklendi'
        })
    except json.JSONDecodeError:
        return jsonify({'error': 'Geçersiz JSON formatı'}), 400
    except Exception as e:
        logger.error(f"Restore error: {e}")
        return jsonify({'error': str(e)}), 500


@backup_bp.route('/api/backup/delete-cloud', methods=['POST'])
@login_required
def delete_cloud_backup():
    if current_user.role != 'admin':
        return jsonify({'error': 'Yetkisiz'}), 403

    data = request.get_json()
    path = data.get('path')
    if not path:
        return jsonify({'error': 'Dosya yolu belirtilmedi'}), 400

    try:
        from app import object_storage
        if not object_storage.is_available():
            return jsonify({'error': 'Object Storage kullanılamıyor'}), 500

        object_storage.client.delete(path)
        return jsonify({'success': True})
    except Exception as e:
        logger.error(f"Delete backup error: {e}")
        return jsonify({'error': str(e)}), 500
