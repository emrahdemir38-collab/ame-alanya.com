"""
Deneme Sınavı Takvimi - Migration
Tarih: 2025-11-13
Admin tarafından deneme sınavı tarihlerinin eklenmesi için
"""

from db.database import get_db

def create_exam_calendar_table():
    """Exam calendar tablosunu oluşturur"""
    conn = get_db()
    cur = conn.cursor()
    
    try:
        cur.execute("""
            CREATE TABLE IF NOT EXISTS exam_calendar (
                id SERIAL PRIMARY KEY,
                exam_date DATE NOT NULL,
                exam_title VARCHAR(255) NOT NULL,
                description TEXT,
                created_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(exam_date)
            );
        """)
        
        cur.execute("""
            CREATE INDEX IF NOT EXISTS idx_exam_calendar_date 
            ON exam_calendar(exam_date);
        """)
        
        conn.commit()
        print("✅ exam_calendar tablosu oluşturuldu")
        
    except Exception as e:
        conn.rollback()
        print(f"❌ exam_calendar tablosu oluşturma hatası: {e}")
        raise
    finally:
        cur.close()
        conn.close()

if __name__ == "__main__":
    create_exam_calendar_table()
