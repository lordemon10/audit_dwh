import psycopg2
from psycopg2.extras import execute_values, execute_batch
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
    """Создание таблиц для каждой проверки, если они не существуют, и добавление колонки db_name если её нет."""
    
    conn = get_audit_connection()
    try:
        with conn.cursor() as cur:
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
                table_schema VARCHAR(255),
                table_name VARCHAR(255),
                privilege_type VARCHAR(50),
                revoke_sql TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_checked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_active BOOLEAN DEFAULT TRUE,
                UNIQUE (db_name, rolname, table_schema, table_name, privilege_type, revoke_sql)
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
            
            # Таблица для check_orphan_grants (сиротские гранты)
            create_orphan_grants_table = """
            CREATE TABLE IF NOT EXISTS audit_check_orphan_grants (
                id SERIAL PRIMARY KEY,
                db_name VARCHAR(100) NOT NULL,
                user_name VARCHAR(255) NOT NULL,
                schema_name VARCHAR(255) NOT NULL,
                table_name VARCHAR(255),
                privilege_type VARCHAR(50),
                object_type VARCHAR(50),
                reason TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_checked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_active BOOLEAN DEFAULT TRUE,
                UNIQUE (db_name, user_name, schema_name, table_name, privilege_type, object_type)
            );
            """
            
            cur.execute(create_nologin_table)
            cur.execute(create_grant_table)
            cur.execute(create_redundant_table)
            cur.execute(create_idm_dups_table)
            cur.execute(create_direct_ad_table)
            cur.execute(create_orphan_grants_table)
            
            # Добавляем колонку db_name если её нет (для обратной совместимости)
            tables_to_check = [
                ('audit_check_nologin', 'rolname'),
                ('audit_check_grant', 'rolname'),
                ('audit_check_redundant', 'rolname'),
                ('audit_check_idm_dups', 'login'),
                ('audit_check_direct_ad', 'login')
            ]
            
            for table_name, key_column in tables_to_check:
                check_column_query = f"""
                SELECT COUNT(*) 
                FROM information_schema.columns 
                WHERE table_name = '{table_name}' AND column_name = 'db_name'
                """
                cur.execute(check_column_query)
                if cur.fetchone()[0] == 0:
                    print(f"Добавляем колонку db_name в таблицу {table_name}...")
                    add_column_query = f"""
                    ALTER TABLE {table_name} 
                    ADD COLUMN db_name VARCHAR(100) DEFAULT 'unknown'
                    """
                    cur.execute(add_column_query)
                    
                    # Обновляем UNIQUE constraint если нужно
                    # Для простоты оставляем как есть, новые записи будут с правильным db_name
            
            conn.commit()
        print("Таблицы аудита успешно созданы/проверены.")
    finally:
        conn.close()

def bulk_upsert_violations(table_name, unique_columns, data_columns, values_list):
    """
    Массовая вставка или обновление записей о нарушениях.
    Оптимизировано для больших объемов данных с использованием execute_values.
    
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
            # Шаг 1: Деактивируем все текущие активные записи
            deactivate_query = f"""
            UPDATE {table_name}
            SET is_active = FALSE,
                last_checked_at = CURRENT_TIMESTAMP
            WHERE is_active = TRUE
            """
            cur.execute(deactivate_query)
            
            # Шаг 2: Вставляем новые записи (или обновляем существующие)
            # Сначала удаляем дубликаты внутри самого пакета данных по unique_columns
            seen = set()
            unique_values_list = []
            for v in values_list:
                # Создаем ключ из значений уникальных колонок
                key = tuple(v[i] for i in range(len(unique_columns)))
                if key not in seen:
                    seen.add(key)
                    unique_values_list.append(v)
            
            if len(unique_values_list) < len(values_list):
                print(f"Удалено {len(values_list) - len(unique_values_list)} дубликатов из пакета данных для {table_name}")
            
            values_list = unique_values_list
            
            columns_str = ", ".join(data_columns)
            unique_str = ", ".join(unique_columns)
            
            # Формируем динамический UPDATE для ON CONFLICT
            update_set_parts = []
            for col in data_columns:
                if col not in unique_columns:
                    update_set_parts.append(f"{col} = EXCLUDED.{col}")
            
            update_clause = ""
            if update_set_parts:
                update_clause = ", " + ", ".join(update_set_parts)
            
            insert_query = f"""
            INSERT INTO {table_name} ({columns_str}, created_at, last_checked_at, is_active)
            VALUES %s
            ON CONFLICT ({unique_str}) 
            DO UPDATE SET 
                last_checked_at = CURRENT_TIMESTAMP,
                is_active = TRUE
                {update_clause}
            """
            
            # Подготавливаем данные с добавлением временных меток
            values_with_timestamps = [
                tuple(list(v) + [psycopg2.extensions.AsIs('CURRENT_TIMESTAMP'), 
                                psycopg2.extensions.AsIs('CURRENT_TIMESTAMP'), 
                                True])
                for v in values_list
            ]
            
            # Выполняем пакетную вставку с использованием execute_values (гораздо быстрее)
            execute_values(cur, insert_query, values_with_timestamps, page_size=50000)
            
            conn.commit()
            print(f"Обработано {len(values_list)} записей в таблице {table_name}")
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
    data_columns = ["db_name", "rolname", "Name", "table_schema", "table_name", "privilege_type", "revoke_sql"]
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

def save_orphan_grant_violations(db_name, violations_df):
    """Сохранение результатов проверки check_orphan_grants в БД."""
    table_name = "audit_check_orphan_grants"
    data_columns = ["db_name", "user_name", "schema_name", "table_name", "privilege_type", "object_type", "reason"]
    unique_columns = ["db_name", "user_name", "schema_name", "table_name", "privilege_type", "object_type"]
    
    values_list = []
    for _, row in violations_df.iterrows():
        values = (
            db_name,
            row.get("user_name", None),
            row.get("schema_name", None),
            row.get("table_name", None),
            row.get("privilege_type", None),
            row.get("object_type", None),
            row.get("reason", None)
        )
        values_list.append(values)
    
    bulk_upsert_violations(table_name, unique_columns, data_columns, values_list)
    print(f"Сохранено {len(violations_df)} нарушений в таблицу {table_name}")
