"""
Migration: Add question_asks table for student-teacher Q&A system
Date: 2025-11-13
"""
import os
import psycopg2
from psycopg2.extras import RealDictCursor
import logging

logger = logging.getLogger(__name__)

def get_db():
    return psycopg2.connect(os.environ.get('DATABASE_URL'))

def up():
    """Apply migration"""
    try:
        conn = get_db()
        cur = conn.cursor()
        
        # Create question_asks table
        cur.execute("""
            CREATE TABLE IF NOT EXISTS question_asks (
                id SERIAL PRIMARY KEY,
                student_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                teacher_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                practice_exam_id INTEGER NOT NULL REFERENCES practice_exams(id) ON DELETE CASCADE,
                subject VARCHAR(50) NOT NULL,
                question_number INTEGER NOT NULL,
                reason VARCHAR(100) NOT NULL,
                student_note TEXT,
                teacher_response TEXT,
                status VARCHAR(20) DEFAULT 'pending' CHECK (status IN ('pending', 'answered')),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                answered_at TIMESTAMP
            )
        """)
        
        # Create indexes for performance
        cur.execute("""
            CREATE INDEX IF NOT EXISTS idx_question_asks_student 
            ON question_asks(student_id, status)
        """)
        
        cur.execute("""
            CREATE INDEX IF NOT EXISTS idx_question_asks_teacher 
            ON question_asks(teacher_id, status)
        """)
        
        conn.commit()
        cur.close()
        conn.close()
        
        logger.info("✅ Migration applied: question_asks table created")
        print("✅ Migration applied successfully")
        return True
        
    except Exception as e:
        logger.error(f"❌ Migration failed: {e}")
        print(f"❌ Migration failed: {e}")
        return False

def down():
    """Rollback migration"""
    try:
        conn = get_db()
        cur = conn.cursor()
        
        cur.execute("DROP TABLE IF EXISTS question_asks CASCADE")
        
        conn.commit()
        cur.close()
        conn.close()
        
        logger.info("✅ Migration rolled back: question_asks table dropped")
        print("✅ Migration rolled back successfully")
        return True
        
    except Exception as e:
        logger.error(f"❌ Rollback failed: {e}")
        print(f"❌ Rollback failed: {e}")
        return False

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "down":
        down()
    else:
        up()
