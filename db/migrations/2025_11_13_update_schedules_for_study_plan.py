"""
Migration: Update lesson_schedules for study plan (instruction field, nullable times)
Date: 2025-11-13
"""
import os
import psycopg2
import logging

logger = logging.getLogger(__name__)

def get_db():
    return psycopg2.connect(os.environ.get('DATABASE_URL'))

def up():
    """Apply migration"""
    try:
        conn = get_db()
        cur = conn.cursor()
        
        # Add instruction field for study plan
        cur.execute("""
            ALTER TABLE lesson_schedules 
            ADD COLUMN IF NOT EXISTS instruction TEXT
        """)
        
        # Make start_time and end_time nullable (for study plans)
        cur.execute("""
            ALTER TABLE lesson_schedules 
            ALTER COLUMN start_time DROP NOT NULL
        """)
        
        cur.execute("""
            ALTER TABLE lesson_schedules 
            ALTER COLUMN end_time DROP NOT NULL
        """)
        
        # Update unique constraint to exclude study plans from time-based uniqueness
        # Drop old constraint
        cur.execute("""
            ALTER TABLE lesson_schedules 
            DROP CONSTRAINT IF EXISTS lesson_schedules_student_id_day_of_week_start_time_key
        """)
        
        # Create new partial unique constraint (only for lesson type)
        cur.execute("""
            CREATE UNIQUE INDEX IF NOT EXISTS unique_lesson_schedule_time 
            ON lesson_schedules(student_id, day_of_week, start_time) 
            WHERE schedule_type = 'lesson' AND start_time IS NOT NULL
        """)
        
        conn.commit()
        cur.close()
        conn.close()
        
        logger.info("✅ Migration applied: lesson_schedules updated for study plan")
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
        
        # Remove instruction field
        cur.execute("""
            ALTER TABLE lesson_schedules 
            DROP COLUMN IF EXISTS instruction
        """)
        
        # Make times NOT NULL again
        cur.execute("""
            ALTER TABLE lesson_schedules 
            ALTER COLUMN start_time SET NOT NULL
        """)
        
        cur.execute("""
            ALTER TABLE lesson_schedules 
            ALTER COLUMN end_time SET NOT NULL
        """)
        
        # Restore old unique constraint
        cur.execute("""
            DROP INDEX IF EXISTS unique_lesson_schedule_time
        """)
        
        cur.execute("""
            ALTER TABLE lesson_schedules 
            ADD CONSTRAINT lesson_schedules_student_id_day_of_week_start_time_key 
            UNIQUE(student_id, day_of_week, start_time)
        """)
        
        conn.commit()
        cur.close()
        conn.close()
        
        logger.info("✅ Migration rolled back")
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
