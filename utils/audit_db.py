import psycopg2
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
        rolname VARCHAR(255) NOT NULL,
        Name VARCHAR(255),
        Enabled BOOLEAN,
        rolcanlogin BOOLEAN,
        nologin_sql TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_checked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        is_active BOOLEAN DEFAULT TRUE,
        UNIQUE (rolname, nologin_sql)
    );
    """
    
    # Таблица для check_grant
    create_grant_table = """
    CREATE TABLE IF NOT EXISTS audit_check_grant (
        id SERIAL PRIMARY KEY,
        rolname VARCHAR(255) NOT NULL,
        Name VARCHAR(255),
        table_name VARCHAR(255),
        privilege_type VARCHAR(50),
        revoke_sql TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_checked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        is_active BOOLEAN DEFAULT TRUE,
        UNIQUE (rolname, table_name, privilege_type, revoke_sql)
    );
    """
    
    # Таблица для check_redundant
    create_redundant_table = """
    CREATE TABLE IF NOT EXISTS audit_check_redundant (
        id SERIAL PRIMARY KEY,
        db_name VARCHAR(100),
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

def upsert_violation(table_name, unique_columns, data_columns, values):
    """
    Вставка или обновление записи о нарушении.
    
    Args:
        table_name: имя таблицы
        unique_columns: список колонок для UNIQUE constraints
        data_columns: список колонок с данными (без служебных полей)
        values: кортеж значений для вставки
    """
    conn = get_audit_connection()
    try:
        with conn.cursor() as cur:
            # Формируем строки колонок
            columns_str = ", ".join(data_columns)
            placeholders = ", ".join(["%s"] * len(values))
            
            # Формируем условия для UNIQUE conflict
            unique_str = ", ".join(unique_columns)
            
            # Формируем обновления для существующих записей
            update_columns = [col for col in data_columns if col not in unique_columns]
            update_set = ", ".join([f"{col} = EXCLUDED.{col}" for col in update_columns])
            
            insert_query = f"""
            INSERT INTO {table_name} ({columns_str}, created_at, last_checked_at, is_active)
            VALUES ({placeholders}, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, TRUE)
            ON CONFLICT ({unique_str}) 
            DO UPDATE SET 
                last_checked_at = CURRENT_TIMESTAMP,
                is_active = TRUE,
                {update_set if update_set else "is_active = TRUE"}
            """
            
            cur.execute(insert_query, values)
            conn.commit()
    finally:
        conn.close()

def deactivate_old_violations(table_name, current_violations_keys, key_columns):
    """
    Помечает как неактивные нарушения, которые не были найдены при текущей проверке.
    
    Args:
        table_name: имя таблицы
        current_violations_keys: список кортежей с ключами текущих нарушений
        key_columns: список колонок, составляющих уникальный ключ
    """
    conn = get_audit_connection()
    try:
        with conn.cursor() as cur:
            if current_violations_keys:
                # Создаем условия для фильтрации текущих записей
                conditions = []
                all_values = []
                for key_tuple in current_violations_keys:
                    cond = " AND ".join([f"{col} = %s" for col in key_columns])
                    conditions.append(f"({cond})")
                    all_values.extend(key_tuple)
                
                # Деактивируем все записи, которых нет в текущем списке
                deactivate_query = f"""
                UPDATE {table_name}
                SET is_active = FALSE,
                    last_checked_at = CURRENT_TIMESTAMP
                WHERE is_active = TRUE
                  AND NOT ({" OR ".join(conditions)})
                """
                cur.execute(deactivate_query, all_values)
            else:
                # Если текущих нарушений нет, деактивируем все активные
                deactivate_query = f"""
                UPDATE {table_name}
                SET is_active = FALSE,
                    last_checked_at = CURRENT_TIMESTAMP
                WHERE is_active = TRUE
                """
                cur.execute(deactivate_query)
            
            conn.commit()
    finally:
        conn.close()

def save_nologin_violations(db_name, violations_df):
    """Сохранение результатов проверки check_nologin в БД."""
    table_name = "audit_check_nologin"
    data_columns = ["rolname", "Name", "Enabled", "rolcanlogin", "nologin_sql"]
    unique_columns = ["rolname", "nologin_sql"]
    
    current_keys = []
    
    for _, row in violations_df.iterrows():
        values = (
            row["rolname"],
            row.get("Name", None),
            row.get("Enabled", None),
            row.get("rolcanlogin", None),
            row.get("nologin_sql", None)
        )
        upsert_violation(table_name, unique_columns, data_columns, values)
        current_keys.append((row["rolname"], row.get("nologin_sql", None)))
    
    deactivate_old_violations(table_name, current_keys, unique_columns)
    print(f"Сохранено {len(violations_df)} нарушений в таблицу {table_name}")

def save_grant_violations(db_name, violations_df):
    """Сохранение результатов проверки check_grant в БД."""
    table_name = "audit_check_grant"
    data_columns = ["rolname", "Name", "table_name", "privilege_type", "revoke_sql"]
    unique_columns = ["rolname", "table_name", "privilege_type", "revoke_sql"]
    
    current_keys = []
    
    for _, row in violations_df.iterrows():
        values = (
            row["rolname"],
            row.get("Name", None),
            row.get("table_name", None),
            row.get("privilege_type", None),
            row.get("revoke_sql", None)
        )
        upsert_violation(table_name, unique_columns, data_columns, values)
        current_keys.append((row["rolname"], row.get("table_name", None), row.get("privilege_type", None), row.get("revoke_sql", None)))
    
    deactivate_old_violations(table_name, current_keys, unique_columns)
    print(f"Сохранено {len(violations_df)} нарушений в таблицу {table_name}")

def save_redundant_violations(db_name, violations_df):
    """Сохранение результатов проверки check_redundant в БД."""
    table_name = "audit_check_redundant"
    data_columns = ["db_name", "rolname", "Name", "table_schema", "table_name", "privilege_type", "duplicate_ad_group", "revoke_sql"]
    unique_columns = ["db_name", "rolname", "table_schema", "table_name", "privilege_type", "revoke_sql"]
    
    current_keys = []
    
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
        upsert_violation(table_name, unique_columns, data_columns, values)
        current_keys.append((db_name, row["rolname"], row.get("table_schema", None), row.get("table_name", None), row.get("privilege_type", None), row.get("revoke_sql", None)))
    
    deactivate_old_violations(table_name, current_keys, unique_columns)
    print(f"Сохранено {len(violations_df)} нарушений в таблицу {table_name}")

def save_idm_dups_violations(violations_df):
    """Сохранение результатов проверки check_idm_dups в БД."""
    table_name = "audit_check_idm_dups"
    data_columns = ["login", "Name", "group_name", "source", "business_role", "comment"]
    unique_columns = ["login", "group_name", "source", "business_role"]
    
    current_keys = []
    
    for _, row in violations_df.iterrows():
        values = (
            row.get("login", None),
            row.get("Name", None),
            row.get("group", None),
            row.get("source", None),
            row.get("business_role", None),
            row.get("comment", None)
        )
        upsert_violation(table_name, unique_columns, data_columns, values)
        current_keys.append((row.get("login", None), row.get("group", None), row.get("source", None), row.get("business_role", None)))
    
    deactivate_old_violations(table_name, current_keys, unique_columns)
    print(f"Сохранено {len(violations_df)} нарушений в таблицу {table_name}")

def save_direct_ad_violations(violations_df):
    """Сохранение результатов проверки check_direct_ad в БД."""
    table_name = "audit_check_direct_ad"
    data_columns = ["login", "Name", "group_name", "source", "business_role", "comment"]
    unique_columns = ["login", "group_name", "source", "business_role"]
    
    current_keys = []
    
    for _, row in violations_df.iterrows():
        values = (
            row.get("login", None),
            row.get("Name", None),
            row.get("group", None),
            row.get("source", None),
            row.get("business_role", None),
            row.get("comment", None)
        )
        upsert_violation(table_name, unique_columns, data_columns, values)
        current_keys.append((row.get("login", None), row.get("group", None), row.get("source", None), row.get("business_role", None)))
    
    deactivate_old_violations(table_name, current_keys, unique_columns)
    print(f"Сохранено {len(violations_df)} нарушений в таблицу {table_name}")
