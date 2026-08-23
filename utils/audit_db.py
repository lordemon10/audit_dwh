import psycopg2
from psycopg2.extras import execute_batch
from config import AUDIT_DB

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

def init_audit_tables():
    """Создание таблиц для каждой проверки, если они не существуют."""
    
    # Таблица для check_nologin
    create_nologin_table = """
    CREATE TABLE IF NOT EXISTS audit_check_nologin (
        id SERIAL PRIMARY KEY,
        db_name VARCHAR(100) NOT NULL,
        rolname VARCHAR(255) NOT NULL,
        Name VARCHAR(255),
        Enabled BOOLEAN,
        rolcanlogin BOOLEAN,
        nologin_sql TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_checked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        is_active BOOLEAN DEFAULT TRUE,
        UNIQUE (db_name, rolname, nologin_sql)
    );
    """
    
    # Таблица для check_grant
    create_grant_table = """
    CREATE TABLE IF NOT EXISTS audit_check_grant (
        id SERIAL PRIMARY KEY,
        db_name VARCHAR(100) NOT NULL,
        rolname VARCHAR(255) NOT NULL,
        Name VARCHAR(255),
        table_name VARCHAR(255),
        privilege_type VARCHAR(50),
        revoke_sql TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_checked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        is_active BOOLEAN DEFAULT TRUE,
        UNIQUE (db_name, rolname, table_name, privilege_type, revoke_sql)
    );
    """
    
    # Таблица для check_redundant
    create_redundant_table = """
    CREATE TABLE IF NOT EXISTS audit_check_redundant (
        id SERIAL PRIMARY KEY,
        db_name VARCHAR(100) NOT NULL,
        rolname VARCHAR(255) NOT NULL,
        Name VARCHAR(255),
        table_schema VARCHAR(255),
        table_name VARCHAR(255),
        privilege_type VARCHAR(50),
        duplicate_ad_group VARCHAR(255),
        revoke_sql TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_checked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        is_active BOOLEAN DEFAULT TRUE,
        UNIQUE (db_name, rolname, table_schema, table_name, privilege_type, revoke_sql)
    );
    """
    
    # Таблица для check_idm_dups
    create_idm_dups_table = """
    CREATE TABLE IF NOT EXISTS audit_check_idm_dups (
        id SERIAL PRIMARY KEY,
        db_name VARCHAR(100),
        login VARCHAR(255) NOT NULL,
        Name VARCHAR(255),
        group_name VARCHAR(255),
        source VARCHAR(100),
        business_role VARCHAR(255),
        comment TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_checked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        is_active BOOLEAN DEFAULT TRUE,
        UNIQUE (login, group_name, source, business_role)
    );
    """
    
    # Таблица для check_direct_ad
    create_direct_ad_table = """
    CREATE TABLE IF NOT EXISTS audit_check_direct_ad (
        id SERIAL PRIMARY KEY,
        db_name VARCHAR(100),
        login VARCHAR(255) NOT NULL,
        Name VARCHAR(255),
        group_name VARCHAR(255),
        source VARCHAR(100),
        business_role VARCHAR(255),
        comment TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_checked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        is_active BOOLEAN DEFAULT TRUE,
        UNIQUE (login, group_name, source, business_role)
    );
    """
    
    conn = get_audit_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(create_nologin_table)
            cur.execute(create_grant_table)
            cur.execute(create_redundant_table)
            cur.execute(create_idm_dups_table)
            cur.execute(create_direct_ad_table)
            conn.commit()
        print("Таблицы аудита успешно созданы/проверены.")
    finally:
        conn.close()

def bulk_upsert_violations(table_name, unique_columns, data_columns, values_list):
    """
    Массовая вставка или обновление записей о нарушениях.
    Использует временную таблицу для эффективной обработки больших объемов данных.
    
    Args:
        table_name: имя таблицы
        unique_columns: список колонок для UNIQUE constraints
        data_columns: список колонок с данными (без служебных полей)
        values_list: список кортежей значений для вставки
    """
    if not values_list:
        return
    
    conn = get_audit_connection()
    try:
        with conn.cursor() as cur:
            # Создаем временную таблицу для загрузки данных
            temp_table = f"temp_{table_name}"
            
            # Определяем типы данных для временной таблицы (упрощенно - все TEXT кроме BOOLEAN)
            # Для простоты используем ту же структуру, что и основная таблица
            columns_str = ", ".join(data_columns)
            
            # Формируем условия для UNIQUE conflict
            unique_str = ", ".join(unique_columns)
            
            # Сначала обновляем существующие записи
            update_query = f"""
            UPDATE {table_name} t
            SET last_checked_at = CURRENT_TIMESTAMP,
                is_active = TRUE
            FROM (VALUES {",".join(["(%s)"] * len(values_list))}) AS v({unique_str})
            WHERE {f" AND ".join([f"t.{col} = v.{col}" for col in unique_columns])}
              AND t.is_active = TRUE
            """
            
            # Для больших объемов данных используем более простой подход:
            # 1. Помечаем все активные записи как неактивные
            # 2. Вставляем новые данные с ON CONFLICT
            
            # Шаг 1: Деактивируем все текущие активные записи
            deactivate_query = f"""
            UPDATE {table_name}
            SET is_active = FALSE,
                last_checked_at = CURRENT_TIMESTAMP
            WHERE is_active = TRUE
            """
            cur.execute(deactivate_query)
            
            # Шаг 2: Вставляем новые записи (или обновляем существующие)
            placeholders = ", ".join(["%s"] * len(data_columns))
            update_set = ", ".join([f"{col} = EXCLUDED.{col}" for col in data_columns if col not in unique_columns])
            
            insert_query = f"""
            INSERT INTO {table_name} ({columns_str}, created_at, last_checked_at, is_active)
            VALUES ({placeholders}, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, TRUE)
            ON CONFLICT ({unique_str}) 
            DO UPDATE SET 
                last_checked_at = CURRENT_TIMESTAMP,
                is_active = TRUE
                {", " + update_set if update_set else ""}
            """
            
            # Выполняем пакетную вставку
            execute_batch(cur, insert_query, values_list, page_size=10000)
            
            conn.commit()
    finally:
        conn.close()

def save_nologin_violations(db_name, violations_df):
    """Сохранение результатов проверки check_nologin в БД."""
    table_name = "audit_check_nologin"
    data_columns = ["db_name", "rolname", "Name", "Enabled", "rolcanlogin", "nologin_sql"]
    unique_columns = ["db_name", "rolname", "nologin_sql"]
    
    values_list = []
    for _, row in violations_df.iterrows():
        values = (
            db_name,
            row["rolname"],
            row.get("Name", None),
            row.get("Enabled", None),
            row.get("rolcanlogin", None),
            row.get("nologin_sql", None)
        )
        values_list.append(values)
    
    bulk_upsert_violations(table_name, unique_columns, data_columns, values_list)
    print(f"Сохранено {len(violations_df)} нарушений в таблицу {table_name}")

def save_grant_violations(db_name, violations_df):
    """Сохранение результатов проверки check_grant в БД."""
    table_name = "audit_check_grant"
    data_columns = ["db_name", "rolname", "Name", "table_name", "privilege_type", "revoke_sql"]
    unique_columns = ["db_name", "rolname", "table_name", "privilege_type", "revoke_sql"]
    
    values_list = []
    for _, row in violations_df.iterrows():
        values = (
            db_name,
            row["rolname"],
            row.get("Name", None),
            row.get("table_name", None),
            row.get("privilege_type", None),
            row.get("revoke_sql", None)
        )
        values_list.append(values)
    
    bulk_upsert_violations(table_name, unique_columns, data_columns, values_list)
    print(f"Сохранено {len(violations_df)} нарушений в таблицу {table_name}")

def save_redundant_violations(db_name, violations_df):
    """Сохранение результатов проверки check_redundant в БД."""
    table_name = "audit_check_redundant"
    data_columns = ["db_name", "rolname", "Name", "table_schema", "table_name", "privilege_type", "duplicate_ad_group", "revoke_sql"]
    unique_columns = ["db_name", "rolname", "table_schema", "table_name", "privilege_type", "revoke_sql"]
    
    values_list = []
    for _, row in violations_df.iterrows():
        values = (
            db_name,
            row["rolname"],
            row.get("Name", None),
            row.get("table_schema", None),
            row.get("table_name", None),
            row.get("privilege_type", None),
            row.get("duplicate_ad_group", None),
            row.get("revoke_sql", None)
        )
        values_list.append(values)
    
    bulk_upsert_violations(table_name, unique_columns, data_columns, values_list)
    print(f"Сохранено {len(violations_df)} нарушений в таблицу {table_name}")

def save_idm_dups_violations(db_name, violations_df):
    """Сохранение результатов проверки check_idm_dups в БД."""
    table_name = "audit_check_idm_dups"
    data_columns = ["db_name", "login", "Name", "group_name", "source", "business_role", "comment"]
    unique_columns = ["login", "group_name", "source", "business_role"]
    
    values_list = []
    for _, row in violations_df.iterrows():
        values = (
            db_name,
            row.get("login", None),
            row.get("Name", None),
            row.get("group", None),
            row.get("source", None),
            row.get("business_role", None),
            row.get("comment", None)
        )
        values_list.append(values)
    
    bulk_upsert_violations(table_name, unique_columns, data_columns, values_list)
    print(f"Сохранено {len(violations_df)} нарушений в таблицу {table_name}")

def save_direct_ad_violations(db_name, violations_df):
    """Сохранение результатов проверки check_direct_ad в БД."""
    table_name = "audit_check_direct_ad"
    data_columns = ["db_name", "login", "Name", "group_name", "source", "business_role", "comment"]
    unique_columns = ["login", "group_name", "source", "business_role"]
    
    values_list = []
    for _, row in violations_df.iterrows():
        values = (
            db_name,
            row.get("login", None),
            row.get("Name", None),
            row.get("group", None),
            row.get("source", None),
            row.get("business_role", None),
            row.get("comment", None)
        )
        values_list.append(values)
    
    bulk_upsert_violations(table_name, unique_columns, data_columns, values_list)
    print(f"Сохранено {len(violations_df)} нарушений в таблицу {table_name}")
