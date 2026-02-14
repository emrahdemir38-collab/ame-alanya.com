import os
import sys
import psycopg2
import psycopg2.extras
import json
from io import StringIO

PROD_DB_URL = os.environ.get('PROD_DATABASE_URL')
DEV_DB_URL = os.environ.get('DATABASE_URL')

TABLES_TO_SYNC = [
    'users',
    'classes',
    'teacher_classes',
    'report_card_exams',
    'report_card_exam_pages',
    'report_card_question_regions',
    'report_card_results',
    'book_entries',
]

TABLES_TO_TRUNCATE = [
    'book_entries',
    'report_card_results',
    'report_card_question_regions',
    'report_card_exam_pages',
    'report_card_exams',
    'teacher_classes',
    'classes',
    'user_sessions',
    'users',
]

def sync(skip_tables=None):
    if not PROD_DB_URL:
        print("HATA: PROD_DATABASE_URL ortam degiskeni ayarlanmamis!")
        sys.exit(1)
    if not DEV_DB_URL:
        print("HATA: DATABASE_URL ortam degiskeni bulunamadi!")
        sys.exit(1)

    skip_tables = skip_tables or set()

    print("Production DB'ye baglaniliyor...")
    prod_conn = psycopg2.connect(PROD_DB_URL, cursor_factory=psycopg2.extras.RealDictCursor)
    prod_cur = prod_conn.cursor()

    print("Development DB'ye baglaniliyor...")
    dev_conn = psycopg2.connect(DEV_DB_URL)
    dev_cur = dev_conn.cursor()

    tables_to_truncate = [t for t in TABLES_TO_TRUNCATE if t not in skip_tables]
    if tables_to_truncate:
        print("\n=== ADIM 1: Development tablolari temizleniyor ===")
        for table in tables_to_truncate:
            try:
                dev_cur.execute(f"TRUNCATE TABLE {table} CASCADE")
                print(f"  TRUNCATED: {table}")
            except Exception as e:
                dev_conn.rollback()
                print(f"  HATA ({table}): {e}")
        dev_conn.commit()

    print("\n=== ADIM 2: Production'dan veriler kopyalaniyor ===")
    for table in TABLES_TO_SYNC:
        if table in skip_tables:
            print(f"  {table}: Atlaniyor (zaten aktarildi)")
            continue
        try:
            prod_cur.execute(f"SELECT * FROM {table} ORDER BY id")
            rows = prod_cur.fetchall()

            if not rows:
                print(f"  {table}: Bos tablo, atlaniyor")
                continue

            columns = list(rows[0].keys())

            json_columns = set()
            prod_cur.execute("""
                SELECT column_name FROM information_schema.columns 
                WHERE table_name = %s AND data_type IN ('json', 'jsonb')
            """, (table,))
            for r in prod_cur.fetchall():
                json_columns.add(r['column_name'])

            placeholders = []
            for col in columns:
                if col in json_columns:
                    placeholders.append('%s::json')
                else:
                    placeholders.append('%s')

            insert_sql = f"INSERT INTO {table} ({','.join(columns)}) VALUES ({','.join(placeholders)}) ON CONFLICT (id) DO NOTHING"

            total = len(rows)
            values_list = []
            for row in rows:
                values = []
                for col in columns:
                    val = row[col]
                    if col in json_columns and val is not None:
                        if isinstance(val, (dict, list)):
                            values.append(json.dumps(val, ensure_ascii=False))
                        else:
                            values.append(val if isinstance(val, str) else json.dumps(val, ensure_ascii=False))
                    else:
                        values.append(val)
                values_list.append(tuple(values))

            psycopg2.extras.execute_batch(dev_cur, insert_sql, values_list, page_size=200)
            dev_conn.commit()

            try:
                dev_cur.execute(f"SELECT setval(pg_get_serial_sequence('{table}', 'id'), COALESCE((SELECT MAX(id) FROM {table}), 1))")
                dev_conn.commit()
            except:
                dev_conn.rollback()

            print(f"  {table}: {total} satir aktarildi")

        except Exception as e:
            dev_conn.rollback()
            print(f"  HATA ({table}): {e}")
            import traceback
            traceback.print_exc()

    print("\n=== ADIM 3: Dogrulama ===")
    for table in TABLES_TO_SYNC:
        prod_cur.execute(f"SELECT COUNT(*) as cnt FROM {table}")
        prod_count = prod_cur.fetchone()['cnt']
        dev_cur.execute(f"SELECT COUNT(*) as cnt FROM {table}")
        dev_row = dev_cur.fetchone()
        dev_count = dev_row[0] if isinstance(dev_row, tuple) else dev_row['cnt']
        status = "OK" if prod_count == dev_count else "FARKLI"
        print(f"  {table}: Prod={prod_count}, Dev={dev_count} [{status}]")

    prod_cur.close()
    prod_conn.close()
    dev_cur.close()
    dev_conn.close()

    print("\nSenkronizasyon tamamlandi!")

if __name__ == '__main__':
    skip = set()
    if '--skip-done' in sys.argv:
        skip = {'users', 'classes'}
    sync(skip_tables=skip)
