"""
Модуль для управления таблицей ручного маппинга групп доступа audit_mapping.

Эта таблица заполняется ВРУЧНУЮ администратором и содержит соответствие:
БД -> схема -> роли -> AD-группы

Автоматическое построение маппинга ОТКЛЮЧЕНО.
"""

import psycopg2
from config import AUDIT_DB, DB_LIST


def get_audit_connection():
    """Подключение к базе данных для хранения результатов аудита."""
    connection_params = {
        "user": AUDIT_DB["user"],
        "password": AUDIT_DB["password"],
        "host": AUDIT_DB["host"],
        "port": AUDIT_DB["port"],
        "database": AUDIT_DB["db"]
    }
    return psycopg2.connect(**connection_params)


def init_mapping_table():
    """Создание таблицы audit_mapping если она не существует."""
    
    conn = get_audit_connection()
    try:
        with conn.cursor() as cur:
            create_mapping_table = """
            CREATE TABLE IF NOT EXISTS audit_mapping (
                id SERIAL PRIMARY KEY,
                db_name VARCHAR(100) NOT NULL,
                schemaname VARCHAR(255) NOT NULL,
                owner_role VARCHAR(255),
                owner_ad VARCHAR(255),
                write_role VARCHAR(50),
                write_ad VARCHAR(255),
                read_role VARCHAR(50),
                read_ad VARCHAR(255),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_active BOOLEAN DEFAULT TRUE,
                UNIQUE (db_name, schemaname)
            );
            
            CREATE INDEX IF NOT EXISTS idx_mapping_db_schema ON audit_mapping(db_name, schemaname);
            CREATE INDEX IF NOT EXISTS idx_mapping_roles ON audit_mapping(owner_role, write_role, read_role);
            CREATE INDEX IF NOT EXISTS idx_mapping_ad_groups ON audit_mapping(owner_ad, write_ad, read_ad);
            """
            
            cur.execute(create_mapping_table)
            conn.commit()
        print("Таблица audit_mapping успешно создана/проверена.")
        print("ВАЖНО: Таблица должна быть заполнена ВРУЧНУЮ администратором.")
    finally:
        conn.close()


def get_mapping_for_db(db_name):
    """
    Получает маппинг для конкретной БД из таблицы audit_mapping.
    
    Returns:
        DataFrame с колонками: db_name, schemaname, owner_role, owner_ad, 
                               write_role, write_ad, read_role, read_ad
    """
    import pandas as pd
    
    conn = get_audit_connection()
    try:
        query = """
        SELECT 
            db_name,
            schemaname,
            owner_role,
            owner_ad,
            write_role,
            write_ad,
            read_role,
            read_ad
        FROM audit_mapping
        WHERE db_name = %s AND is_active = TRUE
        ORDER BY schemaname
        """
        
        df = pd.read_sql_query(query, conn, params=(db_name,))
        return df
    finally:
        conn.close()


def get_all_mapping():
    """
    Получает весь активный маппинг из таблицы audit_mapping.
    
    Returns:
        DataFrame со всеми записями маппинга
    """
    import pandas as pd
    
    conn = get_audit_connection()
    try:
        query = """
        SELECT 
            db_name,
            schemaname,
            owner_role,
            owner_ad,
            write_role,
            write_ad,
            read_role,
            read_ad
        FROM audit_mapping
        WHERE is_active = TRUE
        ORDER BY db_name, schemaname
        """
        
        df = pd.read_sql_query(query, conn)
        return df
    finally:
        conn.close()


if __name__ == "__main__":
    # Пример использования
    print("Инициализация таблицы ручного маппинга...")
    init_mapping_table()
    
    print("\nГотово! Теперь заполните таблицу audit_mapping вручную.")
    print("Пример SQL для заполнения:")
    print("""
    INSERT INTO audit_mapping (db_name, schemaname, owner_role, owner_ad, write_role, write_ad, read_role, read_ad)
    VALUES 
        ('ODS', 'ab', 'all_cc', 'ODS All CC', NULL, NULL, 'read_cc', 'ODS Read CC'),
        ('ODS', 'actuary', 'all_actuary', 'ODS All Actuary', NULL, NULL, 'read_actuary', 'ODS Read Actuary')
    ON CONFLICT (db_name, schemaname) DO UPDATE SET
        owner_role = EXCLUDED.owner_role,
        owner_ad = EXCLUDED.owner_ad,
        write_role = EXCLUDED.write_role,
        write_ad = EXCLUDED.write_ad,
        read_role = EXCLUDED.read_role,
        read_ad = EXCLUDED.read_ad,
        last_updated_at = CURRENT_TIMESTAMP;
    """)
