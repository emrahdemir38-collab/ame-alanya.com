import os
import sys
import json
import subprocess

DEV_DB_URL = os.environ.get('DATABASE_URL')

def export_table_from_prod(table_name, offset=0, limit=200):
    """Production'dan veri çekmek için Replit SQL aracını kullanamayacağımız için
    doğrudan psycopg2 ile production replica'ya bağlanacağız"""
    pass

if __name__ == '__main__':
    print("Bu script doğrudan çalıştırılamaz.")
    print("Production verileri Replit SQL aracı üzerinden aktarılacak.")
