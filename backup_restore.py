import os
import json
import psycopg2
import psycopg2.extras
from datetime import datetime, date
from decimal import Decimal
from replit.object_storage import Client

DATABASE_URL = os.environ.get('DATABASE_URL')
PROD_DATABASE_URL = os.environ.get('PROD_DATABASE_URL')

storage_client = Client()

BACKUP_PREFIX = "db_backups/"

ALL_TABLES = [
    'users', 'classes', 'user_sessions',
    'announcements', 'announcement_reads', 'public_announcements',
    'teacher_announcements', 'teacher_classes', 'teacher_students',
    'teacher_parent_notes', 'teacher_student_notes', 'teacher_study_plan',
    'parent_children', 'parent_messages',
    'assignments', 'assignment_submissions',
    'exams', 'exam_results', 'exam_questions', 'exam_submissions', 'exam_samples', 'exam_calendar',
    'optical_exams', 'optical_student_results',
    'practice_exams', 'fmt_answer_keys', 'question_analysis',
    'report_cards', 'report_card_exams', 'report_card_exam_pages',
    'report_card_results', 'report_card_students', 'report_card_subjects',
    'report_card_answers', 'report_card_question_regions',
    'lgs_results', 'learning_outcomes',
    'book_entries', 'book_challenges', 'book_challenge_submissions',
    'student_achievements', 'student_badges', 'student_goals', 'student_points', 'student_questions',
    'daily_study_tracking', 'study_schedules', 'study_plan_pdf', 'lesson_schedules',
    'surveys', 'survey_questions', 'survey_responses',
    'notifications', 'topic_requests', 'question_asks',
    'dashboard_widget_preferences',
    'kelebek_plans', 'kelebek_rooms', 'kelebek_assignments',
    'kelebek_participants', 'kelebek_room_config',
]


class JSONEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, (datetime, date)):
            return obj.isoformat()
        if isinstance(obj, Decimal):
            return float(obj)
        if isinstance(obj, bytes):
            return obj.hex()
        return super().default(obj)


def get_connection(use_prod=False):
    url = PROD_DATABASE_URL if use_prod else DATABASE_URL
    if not url:
        raise Exception(f"{'PROD_' if use_prod else ''}DATABASE_URL tanımlı değil")
    return psycopg2.connect(url)


def backup_all(use_prod=False, label=None):
    source = "production" if use_prod else "development"
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    if label:
        backup_name = f"{label}_{timestamp}"
    else:
        backup_name = f"backup_{source}_{timestamp}"

    print(f"\n{'='*60}")
    print(f"YEDEKLEME BAŞLIYOR: {backup_name}")
    print(f"Kaynak: {source} veritabanı")
    print(f"{'='*60}\n")

    conn = get_connection(use_prod)
    cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

    manifest = {
        'backup_name': backup_name,
        'source': source,
        'timestamp': datetime.now().isoformat(),
        'tables': {}
    }

    total_rows = 0

    for table in ALL_TABLES:
        try:
            cursor.execute(f"SELECT COUNT(*) as cnt FROM {table}")
            count = cursor.fetchone()['cnt']

            if count == 0:
                manifest['tables'][table] = {'rows': 0, 'file': None}
                print(f"  ⏭️  {table}: 0 kayıt (atlandı)")
                continue

            cursor.execute(f"SELECT * FROM {table}")
            rows = cursor.fetchall()
            data = [dict(row) for row in rows]

            json_data = json.dumps(data, cls=JSONEncoder, ensure_ascii=False)
            storage_path = f"{BACKUP_PREFIX}{backup_name}/{table}.json"
            storage_client.upload_from_bytes(storage_path, json_data.encode('utf-8'))

            manifest['tables'][table] = {'rows': count, 'file': storage_path}
            total_rows += count
            print(f"  ✅ {table}: {count} kayıt yedeklendi")

        except Exception as e:
            print(f"  ❌ {table}: HATA - {e}")
            manifest['tables'][table] = {'rows': 0, 'file': None, 'error': str(e)}

    manifest_path = f"{BACKUP_PREFIX}{backup_name}/manifest.json"
    manifest_json = json.dumps(manifest, cls=JSONEncoder, ensure_ascii=False, indent=2)
    storage_client.upload_from_bytes(manifest_path, manifest_json.encode('utf-8'))

    cursor.close()
    conn.close()

    print(f"\n{'='*60}")
    print(f"YEDEKLEME TAMAMLANDI!")
    print(f"Toplam: {total_rows} kayıt yedeklendi")
    print(f"Konum: Object Storage / {BACKUP_PREFIX}{backup_name}/")
    print(f"{'='*60}\n")

    return backup_name


def list_backups():
    print("\n📦 Mevcut Yedekler:")
    print("-" * 50)

    try:
        files = list(storage_client.list())
        manifests = [f.name for f in files if f.name.startswith(BACKUP_PREFIX) and f.name.endswith('manifest.json')]

        if not manifests:
            print("  Henüz yedek yok.")
            return []

        backups = []
        for m_path in sorted(manifests):
            try:
                data = storage_client.download_as_bytes(m_path)
                manifest = json.loads(data.decode('utf-8'))
                total = sum(t.get('rows', 0) for t in manifest['tables'].values())
                tables_with_data = sum(1 for t in manifest['tables'].values() if t.get('rows', 0) > 0)
                print(f"  📁 {manifest['backup_name']}")
                print(f"     Tarih: {manifest['timestamp']}")
                print(f"     Kaynak: {manifest['source']}")
                print(f"     Toplam: {total} kayıt, {tables_with_data} tablo")
                print()
                backups.append(manifest)
            except Exception as e:
                print(f"  ⚠️  {m_path}: okunamadı - {e}")

        return backups
    except Exception as e:
        print(f"  ❌ Hata: {e}")
        return []


def restore_from_backup(backup_name, target_prod=False):
    target = "production" if target_prod else "development"

    manifest_path = f"{BACKUP_PREFIX}{backup_name}/manifest.json"
    try:
        data = storage_client.download_as_bytes(manifest_path)
        manifest = json.loads(data.decode('utf-8'))
    except Exception as e:
        print(f"❌ Yedek bulunamadı: {backup_name} - {e}")
        return False

    print(f"\n{'='*60}")
    print(f"GERİ YÜKLEME BAŞLIYOR: {backup_name}")
    print(f"Hedef: {target} veritabanı")
    print(f"{'='*60}\n")

    conn = get_connection(target_prod)
    cursor = conn.cursor()

    print("🔓 FK kısıtlamaları devre dışı bırakılıyor...")
    cursor.execute("SET session_replication_role = 'replica'")
    conn.commit()

    print("🗑️  Mevcut veriler temizleniyor...")
    for table in reversed(ALL_TABLES):
        try:
            cursor.execute(f"TRUNCATE TABLE {table} CASCADE")
            conn.commit()
        except Exception as e:
            conn.rollback()

    total_restored = 0

    for table in ALL_TABLES:
        table_info = manifest['tables'].get(table, {})
        if not table_info.get('file') or table_info.get('rows', 0) == 0:
            continue

        try:
            file_data = storage_client.download_as_bytes(table_info['file'])
            rows = json.loads(file_data.decode('utf-8'))

            if not rows:
                continue

            columns = list(rows[0].keys())
            placeholders = ', '.join(['%s'] * len(columns))
            col_names = ', '.join([f'"{c}"' for c in columns])
            insert_sql = f'INSERT INTO {table} ({col_names}) VALUES ({placeholders}) ON CONFLICT DO NOTHING'

            for row in rows:
                values = [row.get(c) for c in columns]
                try:
                    cursor.execute(insert_sql, values)
                except Exception as row_err:
                    conn.rollback()
            conn.commit()

            cursor.execute(f"SELECT COUNT(*) FROM {table}")
            actual = cursor.fetchone()[0]
            total_restored += actual
            print(f"  ✅ {table}: {actual} kayıt geri yüklendi")

        except Exception as e:
            conn.rollback()
            print(f"  ❌ {table}: HATA - {e}")

    print("🔑 Sequence değerleri sıfırlanıyor...")
    for table in ALL_TABLES:
        try:
            cursor.execute(f"""
                SELECT column_name FROM information_schema.columns 
                WHERE table_name = '{table}' AND column_default LIKE 'nextval%%'
            """)
            seq_cols = cursor.fetchall()
            for (col,) in seq_cols:
                cursor.execute(f"""
                    SELECT setval(pg_get_serial_sequence('{table}', '{col}'), 
                           COALESCE((SELECT MAX("{col}") FROM {table}), 0) + 1, false)
                """)
            conn.commit()
        except Exception:
            conn.rollback()

    print("🔒 FK kısıtlamaları tekrar etkinleştiriliyor...")
    cursor.execute("SET session_replication_role = 'DEFAULT'")
    conn.commit()

    cursor.close()
    conn.close()

    print(f"\n{'='*60}")
    print(f"GERİ YÜKLEME TAMAMLANDI!")
    print(f"Toplam: {total_restored} kayıt geri yüklendi")
    print(f"{'='*60}\n")

    return True


if __name__ == '__main__':
    import sys
    if len(sys.argv) < 2:
        print("Kullanım:")
        print("  python backup_restore.py backup [label]     - Geliştirme DB yedekle")
        print("  python backup_restore.py backup-prod [label] - Üretim DB yedekle")
        print("  python backup_restore.py list                - Yedekleri listele")
        print("  python backup_restore.py restore <name>      - Geliştirme DB'ye geri yükle")
        sys.exit(1)

    cmd = sys.argv[1]

    if cmd == 'backup':
        label = sys.argv[2] if len(sys.argv) > 2 else None
        backup_all(use_prod=False, label=label)
    elif cmd == 'backup-prod':
        label = sys.argv[2] if len(sys.argv) > 2 else None
        backup_all(use_prod=True, label=label)
    elif cmd == 'list':
        list_backups()
    elif cmd == 'restore':
        if len(sys.argv) < 3:
            print("Yedek adını belirtiniz!")
            sys.exit(1)
        restore_from_backup(sys.argv[2])
    else:
        print(f"Bilinmeyen komut: {cmd}")
