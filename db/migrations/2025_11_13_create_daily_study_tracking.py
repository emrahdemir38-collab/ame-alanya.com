"""
Migration: Add daily_study_tracking table for student daily study logging
Date: 2025-11-13
Feature: Haftalık Soru Takibi - Students track daily study progress
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
        
        # Create daily_study_tracking table
        cur.execute("""
            CREATE TABLE IF NOT EXISTS daily_study_tracking (
                id SERIAL PRIMARY KEY,
                student_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                date DATE NOT NULL,
                day_of_week VARCHAR(20) NOT NULL CHECK (day_of_week IN (
                    'Pazartesi', 'Salı', 'Çarşamba', 'Perşembe', 'Cuma', 'Cumartesi', 'Pazar'
                )),
                subject VARCHAR(100) NOT NULL,
                note TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(student_id, date, subject)
            )
        """)
        
        # Create indexes for performance
        cur.execute("""
            CREATE INDEX IF NOT EXISTS idx_daily_tracking_student_date 
            ON daily_study_tracking(student_id, date DESC)
        """)
        
        cur.execute("""
            CREATE INDEX IF NOT EXISTS idx_daily_tracking_student_week 
            ON daily_study_tracking(student_id, date)
        """)
        
        # Create function for updated_at timestamp
        cur.execute("""
            CREATE OR REPLACE FUNCTION update_daily_tracking_timestamp()
            RETURNS TRIGGER AS $$
            BEGIN
                NEW.updated_at = CURRENT_TIMESTAMP;
                RETURN NEW;
            END;
            $$ LANGUAGE plpgsql
        """)
        
        # Create trigger
        cur.execute("""
            DROP TRIGGER IF EXISTS update_daily_tracking_timestamp_trigger 
            ON daily_study_tracking
        """)
        
        cur.execute("""
            CREATE TRIGGER update_daily_tracking_timestamp_trigger
            BEFORE UPDATE ON daily_study_tracking
            FOR EACH ROW
            EXECUTE FUNCTION update_daily_tracking_timestamp()
        """)
        
        conn.commit()
        cur.close()
        conn.close()
        
        logger.info("✅ Migration applied: daily_study_tracking table created")
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
        
        cur.execute("DROP TRIGGER IF EXISTS update_daily_tracking_timestamp_trigger ON daily_study_tracking")
        cur.execute("DROP FUNCTION IF EXISTS update_daily_tracking_timestamp()")
        cur.execute("DROP TABLE IF EXISTS daily_study_tracking CASCADE")
        
        conn.commit()
        cur.close()
        conn.close()
        
        logger.info("✅ Migration rolled back: daily_study_tracking table dropped")
        print("✅ Migration rolled back successfully")
        return True
        
    except Exception as e:
        logger.error(f"❌ Rollback failed: {e}")
        print(f"❌ Rollback failed: {e}")
        return False

if __name__ == "__main__":
    print("Running migration: Create daily_study_tracking table")
    success = up()
    if not success:
        print("Migration failed. Check logs for details.")
        exit(1)
