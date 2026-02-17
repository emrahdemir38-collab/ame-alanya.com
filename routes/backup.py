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
from psycopg2.extras import RealDictCursor, Json

logger = logging.getLogger(__name__)

backup_bp = Blueprint('backup', __name__)

DATABASE_URL = os.environ.get('DATABASE_URL')
PROD_DATABASE_URL = os.environ.get('PROD_DATABASE_URL')
RAILWAY_DB_URL = os.environ.get('RAILWAY_DB_URL')

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


def get_source_db(source_type):
    if source_type == 'prod':
        url = PROD_DATABASE_URL
    elif source_type == 'dev':
        url = DATABASE_URL
    else:
        url = DATABASE_URL
    if not url:
        raise Exception(f'{source_type} veritabanı URL bulunamadı')
    return psycopg2.connect(url)


def sync_to_railway(source_type='prod'):
    if not RAILWAY_DB_URL:
        raise Exception('RAILWAY_DB_URL tanımlanmamış')

    source_conn = get_source_db(source_type)
    source_cur = source_conn.cursor(cursor_factory=RealDictCursor)

    source_cur.execute("""SELECT table_name FROM information_schema.tables 
                         WHERE table_schema = 'public' AND table_type = 'BASE TABLE' ORDER BY table_name""")
    source_tables = [r['table_name'] for r in source_cur.fetchall()]

    railway_conn = psycopg2.connect(RAILWAY_DB_URL)
    railway_cur = railway_conn.cursor(cursor_factory=RealDictCursor)

    railway_cur.execute("""SELECT table_name FROM information_schema.tables 
                          WHERE table_schema = 'public' AND table_type = 'BASE TABLE' ORDER BY table_name""")
    railway_tables = [r['table_name'] for r in railway_cur.fetchall()]

    results = []
    errors = []
    skipped = []

    for table in source_tables:
        try:
            if table not in railway_tables:
                source_cur.execute(f"""SELECT column_name, data_type, is_nullable, column_default, 
                                      character_maximum_length, numeric_precision, numeric_scale
                                   FROM information_schema.columns 
                                   WHERE table_name = '{table}' AND table_schema = 'public'
                                   ORDER BY ordinal_position""")
                columns_info = source_cur.fetchall()

                if not columns_info:
                    skipped.append({'table': table, 'reason': 'Sütun bilgisi alınamadı'})
                    continue

                col_defs = []
                for col in columns_info:
                    col_name = col['column_name']
                    data_type = col['data_type']
                    nullable = col['is_nullable']
                    default = col['column_default']
                    max_len = col['character_maximum_length']

                    if default and 'nextval' in str(default):
                        col_def = f'"{col_name}" SERIAL'
                    else:
                        if data_type == 'character varying':
                            type_str = f'VARCHAR({max_len})' if max_len else 'VARCHAR(255)'
                        elif data_type == 'integer':
                            type_str = 'INTEGER'
                        elif data_type == 'bigint':
                            type_str = 'BIGINT'
                        elif data_type == 'boolean':
                            type_str = 'BOOLEAN'
                        elif data_type == 'text':
                            type_str = 'TEXT'
                        elif data_type == 'numeric':
                            p = col['numeric_precision']
                            s = col['numeric_scale']
                            type_str = f'NUMERIC({p},{s})' if p else 'NUMERIC'
                        elif data_type == 'timestamp without time zone':
                            type_str = 'TIMESTAMP'
                        elif data_type == 'timestamp with time zone':
                            type_str = 'TIMESTAMPTZ'
                        elif data_type == 'date':
                            type_str = 'DATE'
                        elif data_type == 'time without time zone':
                            type_str = 'TIME'
                        elif data_type == 'double precision':
                            type_str = 'DOUBLE PRECISION'
                        elif data_type == 'real':
                            type_str = 'REAL'
                        elif data_type == 'smallint':
                            type_str = 'SMALLINT'
                        elif data_type == 'json':
                            type_str = 'JSON'
                        elif data_type == 'jsonb':
                            type_str = 'JSONB'
                        elif data_type == 'bytea':
                            type_str = 'BYTEA'
                        elif data_type == 'uuid':
                            type_str = 'UUID'
                        elif data_type == 'ARRAY':
                            type_str = 'TEXT[]'
                        else:
                            type_str = 'TEXT'

                        col_def = f'"{col_name}" {type_str}'
                        if nullable == 'NO' and not (default and 'nextval' in str(default)):
                            col_def += ' NOT NULL'
                        if default and 'nextval' not in str(default):
                            col_def += f' DEFAULT {default}'

                    col_defs.append(col_def)

                source_cur.execute(f"""SELECT kcu.column_name
                    FROM information_schema.table_constraints tc
                    JOIN information_schema.key_column_usage kcu ON tc.constraint_name = kcu.constraint_name
                    WHERE tc.table_name = '{table}' AND tc.constraint_type = 'PRIMARY KEY'""")
                pk_cols = [r['column_name'] for r in source_cur.fetchall()]
                if pk_cols:
                    pk_str = ', '.join([f'"{c}"' for c in pk_cols])
                    col_defs.append(f'PRIMARY KEY ({pk_str})')

                create_sql = f'CREATE TABLE IF NOT EXISTS "{table}" ({", ".join(col_defs)})'
                try:
                    railway_cur.execute(create_sql)
                    railway_conn.commit()
                    logger.info(f"Railway: Created table {table}")
                except Exception as ce:
                    railway_conn.rollback()
                    errors.append({'table': table, 'error': f'Tablo oluşturulamadı: {ce}'})
                    continue

        except Exception as e:
            source_conn.rollback()
            errors.append({'table': table, 'error': f'Tablo yapısı hatası: {e}'})
            logger.error(f"Railway table create error for {table}: {e}")

    railway_cur.execute("""SELECT column_name, table_name, data_type 
                          FROM information_schema.columns 
                          WHERE table_schema = 'public' AND data_type IN ('json', 'jsonb')""")
    jsonb_cols_map = {}
    for r in railway_cur.fetchall():
        jsonb_cols_map.setdefault(r['table_name'], set()).add(r['column_name'])

    railway_cur.execute("SET session_replication_role = 'replica';")
    railway_conn.commit()

    try:
        for table in source_tables:
            try:
                railway_cur.execute("""SELECT table_name FROM information_schema.tables 
                                     WHERE table_schema = 'public' AND table_name = %s""", (table,))
                if not railway_cur.fetchone():
                    skipped.append({'table': table, 'reason': 'Tablo Railway\'da yok'})
                    continue

                source_cur.execute(f'SELECT COUNT(*) as cnt FROM "{table}"')
                source_count = source_cur.fetchone()['cnt']

                if source_count == 0:
                    skipped.append({'table': table, 'reason': 'Boş tablo'})
                    continue

                try:
                    railway_cur.execute(f'DELETE FROM "{table}"')
                    railway_conn.commit()
                except:
                    railway_conn.rollback()

                railway_cur.execute("""SELECT column_name FROM information_schema.columns 
                                     WHERE table_name = %s AND table_schema = 'public'""", (table,))
                railway_col_set = set(r['column_name'] for r in railway_cur.fetchall())
                jsonb_set = jsonb_cols_map.get(table, set())

                source_cur.execute(f'SELECT * FROM "{table}"')
                rows = source_cur.fetchall()
                if not rows:
                    continue

                source_columns = list(rows[0].keys())
                valid_columns = [c for c in source_columns if c in railway_col_set]
                if not valid_columns:
                    skipped.append({'table': table, 'reason': 'Eşleşen sütun yok'})
                    continue

                col_list = ', '.join([f'"{c}"' for c in valid_columns])
                placeholders = ', '.join(['%s'] * len(valid_columns))
                insert_sql = f'INSERT INTO "{table}" ({col_list}) VALUES ({placeholders})'

                inserted = 0
                row_errors = 0
                for row in rows:
                    values = []
                    for col in valid_columns:
                        v = row[col]
                        if col in jsonb_set and isinstance(v, (dict, list)):
                            values.append(Json(v))
                        else:
                            values.append(v)
                    try:
                        railway_cur.execute(insert_sql, values)
                        inserted += 1
                        if inserted % 200 == 0:
                            railway_conn.commit()
                    except Exception as ie:
                        railway_conn.rollback()
                        row_errors += 1
                        if row_errors >= 5:
                            errors.append({'table': table, 'error': f'{row_errors} satır hatası (son: {ie})'})
                            break

                if inserted > 0:
                    railway_conn.commit()

                    try:
                        railway_cur.execute("""SELECT column_name FROM information_schema.columns
                            WHERE table_name=%s AND column_default LIKE 'nextval%%' AND table_schema='public'""", (table,))
                        seq_cols = railway_cur.fetchall()
                        for seq_col_row in seq_cols:
                            seq_col = seq_col_row['column_name']
                            railway_cur.execute(f'SELECT MAX("{seq_col}") as max_val FROM "{table}"')
                            max_val = railway_cur.fetchone()['max_val']
                            if max_val:
                                railway_cur.execute("SELECT pg_get_serial_sequence(%s, %s)", (table, seq_col))
                                seq_result = railway_cur.fetchone()
                                if seq_result and seq_result.get('pg_get_serial_sequence'):
                                    railway_cur.execute("SELECT setval(%s, %s)", (seq_result['pg_get_serial_sequence'], max_val))
                        railway_conn.commit()
                    except Exception as se:
                        railway_conn.rollback()
                        logger.warning(f"Sequence fix for {table}: {se}")

                    results.append({'table': table, 'rows': inserted})
                    logger.info(f"Railway sync: {table} - {inserted}/{source_count} rows")

            except Exception as e:
                railway_conn.rollback()
                source_conn.rollback()
                errors.append({'table': table, 'error': str(e)})
                logger.error(f"Railway sync error for {table}: {e}")

    finally:
        try:
            railway_cur.execute("SET session_replication_role = 'origin';")
            railway_conn.commit()
        except:
            pass

    source_cur.close()
    source_conn.close()
    railway_cur.close()
    railway_conn.close()

    return results, errors, skipped


@backup_bp.route('/api/backup/sync-to-railway', methods=['POST'])
@login_required
def sync_to_railway_endpoint():
    if current_user.role != 'admin':
        return jsonify({'error': 'Yetkisiz'}), 403

    data = request.get_json() or {}
    source_type = data.get('source', 'prod')

    try:
        safety_backup = create_backup_data()
        safety_path = save_backup_to_object_storage(safety_backup)
        safety_rows = sum(t['count'] for t in safety_backup['tables'].values())
        logger.info(f"Safety backup saved before Railway sync: {safety_path} ({safety_rows} rows)")

        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        local_filename = f'ameo_railway_safety_{timestamp}.json.gz'
        json_str = json.dumps(safety_backup, ensure_ascii=False, default=str)
        compressed = gzip.compress(json_str.encode('utf-8'))
        local_path = os.path.join('/tmp', local_filename)
        with open(local_path, 'wb') as f:
            f.write(compressed)
        logger.info(f"Local safety backup: {local_path}")

        results, errors, skipped = sync_to_railway(source_type)

        total_synced = sum(r['rows'] for r in results)
        return jsonify({
            'success': True,
            'synced_tables': results,
            'errors': errors,
            'skipped': skipped,
            'total_synced_rows': total_synced,
            'safety_backup_path': safety_path,
            'message': f'{len(results)} tablo, {total_synced} kayıt Railway\'a aktarıldı'
        })
    except Exception as e:
        logger.error(f"Railway sync error: {e}")
        return jsonify({'error': str(e)}), 500


@backup_bp.route('/api/backup/railway-status')
@login_required
def railway_status():
    if current_user.role != 'admin':
        return jsonify({'error': 'Yetkisiz'}), 403

    if not RAILWAY_DB_URL:
        return jsonify({'error': 'RAILWAY_DB_URL tanımlanmamış', 'connected': False})

    try:
        conn = psycopg2.connect(RAILWAY_DB_URL)
        cur = conn.cursor()

        cur.execute("""SELECT table_name FROM information_schema.tables 
                      WHERE table_schema = 'public' AND table_type = 'BASE TABLE' ORDER BY table_name""")
        tables = [r[0] for r in cur.fetchall()]

        counts = {}
        total = 0
        for table in tables:
            try:
                cur.execute(f'SELECT COUNT(*) FROM "{table}"')
                cnt = cur.fetchone()[0]
                if cnt > 0:
                    counts[table] = cnt
                    total += cnt
            except:
                conn.rollback()

        cur.close()
        conn.close()

        return jsonify({
            'connected': True,
            'table_count': len(counts),
            'total_rows': total,
            'tables': counts
        })
    except Exception as e:
        logger.error(f"Railway status error: {e}")
        return jsonify({'error': str(e), 'connected': False})
