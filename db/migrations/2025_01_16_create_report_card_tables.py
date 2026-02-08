"""
Karne Yönetimi Tabloları - PDF Karne Okuma Sistemi
"""
import os
import psycopg2

def get_db():
    return psycopg2.connect(os.environ.get('DATABASE_URL'))

def run():
    conn = get_db()
    cur = conn.cursor()
    
    try:
        # Ana karne tablosu - yüklenen PDF karneler
        cur.execute("""
            CREATE TABLE IF NOT EXISTS report_cards (
                id SERIAL PRIMARY KEY,
                exam_name VARCHAR(255) NOT NULL,
                publisher VARCHAR(100),
                class_name VARCHAR(20) NOT NULL,
                grade_level INTEGER,
                student_count INTEGER DEFAULT 0,
                pdf_filename VARCHAR(255),
                upload_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                uploaded_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
                parsed_at TIMESTAMP,
                parse_status VARCHAR(20) DEFAULT 'pending' CHECK (parse_status IN ('pending', 'processing', 'completed', 'failed')),
                parse_error TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Öğrenci karne sonuçları
        cur.execute("""
            CREATE TABLE IF NOT EXISTS report_card_students (
                id SERIAL PRIMARY KEY,
                report_card_id INTEGER NOT NULL REFERENCES report_cards(id) ON DELETE CASCADE,
                user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
                student_name VARCHAR(200) NOT NULL,
                student_no VARCHAR(50),
                class_name VARCHAR(20),
                lgs_score DECIMAL(10,3),
                percentile DECIMAL(10,2),
                total_questions INTEGER,
                total_correct INTEGER,
                total_wrong INTEGER,
                total_blank INTEGER,
                total_net DECIMAL(10,2),
                success_rate DECIMAL(5,2),
                school_rank INTEGER,
                district_rank INTEGER,
                city_rank INTEGER,
                country_rank INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Ders bazlı sonuçlar
        cur.execute("""
            CREATE TABLE IF NOT EXISTS report_card_subjects (
                id SERIAL PRIMARY KEY,
                student_result_id INTEGER NOT NULL REFERENCES report_card_students(id) ON DELETE CASCADE,
                subject VARCHAR(50) NOT NULL,
                question_count INTEGER,
                correct_count INTEGER,
                wrong_count INTEGER,
                blank_count INTEGER,
                net_score DECIMAL(10,2),
                success_rate DECIMAL(5,2),
                correct_answers TEXT,
                student_answers TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Soru bazlı cevaplar ve kazanımlar
        cur.execute("""
            CREATE TABLE IF NOT EXISTS report_card_answers (
                id SERIAL PRIMARY KEY,
                student_result_id INTEGER NOT NULL REFERENCES report_card_students(id) ON DELETE CASCADE,
                subject VARCHAR(50) NOT NULL,
                question_number INTEGER NOT NULL,
                correct_answer CHAR(1),
                student_answer CHAR(1),
                is_correct BOOLEAN,
                is_blank BOOLEAN DEFAULT FALSE,
                outcome_code VARCHAR(50),
                outcome_text TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # İndeksler
        cur.execute("CREATE INDEX IF NOT EXISTS idx_report_cards_class ON report_cards(class_name)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_report_card_students_report ON report_card_students(report_card_id)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_report_card_students_user ON report_card_students(user_id)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_report_card_answers_student ON report_card_answers(student_result_id)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_report_card_answers_subject ON report_card_answers(subject)")
        
        conn.commit()
        print("Karne tabloları başarıyla oluşturuldu!")
        
    except Exception as e:
        conn.rollback()
        print(f"Hata: {e}")
        raise e
    finally:
        cur.close()
        conn.close()

if __name__ == "__main__":
    run()
