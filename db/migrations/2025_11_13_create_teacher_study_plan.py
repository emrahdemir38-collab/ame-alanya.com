"""
Öğretmen Ders Çalışma Planı - Migration
Tarih: 2025-11-13
Öğretmen tarafından öğrenciler için günlük ders çalışma planının oluşturulması
"""

from db.database import get_db

def create_teacher_study_plan_table():
    """Teacher study plan tablosunu oluşturur"""
    conn = get_db()
    cur = conn.cursor()
    
    try:
        cur.execute("""
            CREATE TABLE IF NOT EXISTS teacher_study_plan (
                id SERIAL PRIMARY KEY,
                student_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                teacher_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                plan_date DATE NOT NULL,
                subject VARCHAR(100) NOT NULL,
                question_count INTEGER NOT NULL CHECK (question_count > 0),
                note TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(student_id, plan_date, subject)
            );
        """)
        
        cur.execute("""
            CREATE INDEX IF NOT EXISTS idx_teacher_study_plan_student 
            ON teacher_study_plan(student_id, plan_date);
        """)
        
        cur.execute("""
            CREATE INDEX IF NOT EXISTS idx_teacher_study_plan_teacher 
            ON teacher_study_plan(teacher_id, plan_date);
        """)
        
        conn.commit()
        print("✅ teacher_study_plan tablosu oluşturuldu")
        
    except Exception as e:
        conn.rollback()
        print(f"❌ teacher_study_plan tablosu oluşturma hatası: {e}")
        raise
    finally:
        cur.close()
        conn.close()

if __name__ == "__main__":
    create_teacher_study_plan_table()
