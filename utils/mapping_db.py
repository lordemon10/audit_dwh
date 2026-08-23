"""
Модуль для управления таблицей маппинга групп доступа audit_mapping_group.

Таблица содержит информацию о соответствии схем БД, ролей и AD-групп.
Используется для проверок orphan_grants и redundant.
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
    """Создание таблицы audit_mapping_group если она не существует."""
    
    conn = get_audit_connection()
    try:
        with conn.cursor() as cur:
            create_mapping_table = """
            CREATE TABLE IF NOT EXISTS audit_mapping_group (
                id SERIAL PRIMARY KEY,
                db_name VARCHAR(100) NOT NULL,
                is_prod BOOLEAN NOT NULL DEFAULT FALSE,
                ad_layer VARCHAR(50) NOT NULL,
                schema_name VARCHAR(255) NOT NULL,
                schema_owner_role VARCHAR(255),
                role_prefix_all VARCHAR(50),
                ad_group_all VARCHAR(255),
                role_prefix_owner VARCHAR(50),
                ad_group_owner VARCHAR(255),
                role_prefix_write VARCHAR(50),
                ad_group_write VARCHAR(255),
                role_prefix_read VARCHAR(50),
                ad_group_read VARCHAR(255),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_active BOOLEAN DEFAULT TRUE,
                UNIQUE (db_name, schema_name)
            );
            
            CREATE INDEX IF NOT EXISTS idx_mapping_schema ON audit_mapping_group(db_name, schema_name);
            CREATE INDEX IF NOT EXISTS idx_mapping_layer ON audit_mapping_group(ad_layer);
            CREATE INDEX IF NOT EXISTS idx_mapping_roles ON audit_mapping_group(role_prefix_read, role_prefix_owner, role_prefix_write);
            """
            
            cur.execute(create_mapping_table)
            conn.commit()
        print("Таблица audit_mapping_group успешно создана/проверена.")
    finally:
        conn.close()


def build_mapping_from_db():
    """
    Построение таблицы маппинга на основе данных из всех БД.
    
    Логика:
    1. Для каждой БД из DB_LIST подключаемся и получаем список схем с их владельцами
    2. Определяем префикс роли владельца (например, all_bcapp -> bcapp)
    3. Ищем соответствующие роли с префиксами read_<prefix>, write_<prefix>, owner_<prefix>
    4. Проверяем существование AD-групп для этих ролей
    5. Сохраняем маппинг в таблицу
    """
    
    conn = get_audit_connection()
    
    # Словарь для сбора всех уникальных префиксов ролей по БД
    role_mappings = {}
    
    for db_info in DB_LIST:
        db_name = db_info["name"]
        is_prod = db_info.get("is_prod", False)
        ad_layer = db_info.get("ad_layer", "")
        
        print(f"Сбор данных о схемах для БД: {db_name} (слой: {ad_layer})")
        
        try:
            db_conn_params = {
                "user": AUDIT_DB["user"],
                "password": AUDIT_DB["password"],
                "host": db_info["host"],
                "port": db_info["port"],
                "database": db_info["db"]
            }
            
            with psycopg2.connect(**db_conn_params) as db_conn:
                with db_conn.cursor() as db_cur:
                    # Получаем все схемы и их владельцев
                    get_schemas_query = """
                    SELECT 
                        n.nspname as schema_name,
                        r.rolname as owner_role
                    FROM pg_catalog.pg_namespace n
                    JOIN pg_catalog.pg_roles r ON r.oid = n.nspowner
                    WHERE n.nspname !~ '^pg_' AND n.nspname != 'information_schema'
                    ORDER BY n.nspname;
                    """
                    
                    db_cur.execute(get_schemas_query)
                    schemas = db_cur.fetchall()
                    
                    for schema_name, owner_role in schemas:
                        # Извлекаем префикс из имени роли владельца
                        # Например: all_bcapp -> bcapp, read_core -> core
                        prefix = extract_role_prefix(owner_role)
                        
                        if not prefix:
                            continue
                        
                        # Определяем ключ для уникальности записи
                        mapping_key = (db_name, schema_name.lower())
                        
                        if mapping_key not in role_mappings:
                            role_mappings[mapping_key] = {
                                "db_name": db_name,
                                "is_prod": is_prod,
                                "ad_layer": ad_layer,
                                "schema_name": schema_name.lower(),
                                "schema_owner_role": owner_role,
                                "role_prefix_all": f"all_{prefix}" if ad_layer in ['EDW', 'ODS', 'CBD', 'DWHT EDW', 'DWHT ODS'] else None,
                                "ad_group_all": None,
                                "role_prefix_owner": f"owner_{prefix}" if ad_layer == 'ADB' else f"all_{prefix}",
                                "ad_group_owner": None,
                                "role_prefix_write": f"write_{prefix}" if ad_layer == 'ADB' else None,
                                "ad_group_write": None,
                                "role_prefix_read": f"read_{prefix}",
                                "ad_group_read": None,
                            }
                            
        except Exception as e:
            print(f"Ошибка подключения к БД {db_name}: {e}")
            continue
    
    # Теперь проверяем existence ролей в каждой БД и обновляем маппинг
    print("\nПроверка существования ролей в БД...")
    
    for db_info in DB_LIST:
        db_name = db_info["name"]
        
        try:
            db_conn_params = {
                "user": AUDIT_DB["user"],
                "password": AUDIT_DB["password"],
                "host": db_info["host"],
                "port": db_info["port"],
                "database": db_info["db"]
            }
            
            with psycopg2.connect(**db_conn_params) as db_conn:
                with db_conn.cursor() as db_cur:
                    # Для каждой схемы в этой БД проверяем роли
                    for mapping_key, mapping in role_mappings.items():
                        if mapping_key[0] != db_name:
                            continue
                        
                        schema_name = mapping["schema_name"]
                        
                        # Проверяем существование ролей
                        roles_to_check = []
                        if mapping["role_prefix_all"]:
                            roles_to_check.append(("all", mapping["role_prefix_all"]))
                        if mapping["role_prefix_owner"]:
                            roles_to_check.append(("owner", mapping["role_prefix_owner"]))
                        if mapping["role_prefix_write"]:
                            roles_to_check.append(("write", mapping["role_prefix_write"]))
                        if mapping["role_prefix_read"]:
                            roles_to_check.append(("read", mapping["role_prefix_read"]))
                        
                        for priv_type, role_name in roles_to_check:
                            if not role_name:
                                continue
                            
                            db_cur.execute("""
                                SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = %s
                            """, (role_name,))
                            
                            if db_cur.fetchone():
                                # Роль существует, обновляем маппинг
                                if priv_type == "all":
                                    mapping["role_prefix_all"] = role_name
                                elif priv_type == "owner":
                                    mapping["role_prefix_owner"] = role_name
                                elif priv_type == "write":
                                    mapping["role_prefix_write"] = role_name
                                elif priv_type == "read":
                                    mapping["role_prefix_read"] = role_name
                        
        except Exception as e:
            print(f"Ошибка проверки ролей в БД {db_name}: {e}")
            continue
    
    # Сохраняем маппинг в таблицу
    print("\nСохранение маппинга в таблицу audit_mapping_group...")
    
    try:
        with conn.cursor() as cur:
            # Сначала деактивируем все текущие записи
            cur.execute("UPDATE audit_mapping_group SET is_active = FALSE, last_updated_at = CURRENT_TIMESTAMP WHERE is_active = TRUE")
            
            # Вставляем новые записи
            for mapping_key, mapping in role_mappings.items():
                insert_query = """
                INSERT INTO audit_mapping_group (
                    db_name, is_prod, ad_layer, schema_name, schema_owner_role,
                    role_prefix_all, ad_group_all,
                    role_prefix_owner, ad_group_owner,
                    role_prefix_write, ad_group_write,
                    role_prefix_read, ad_group_read,
                    created_at, last_updated_at, is_active
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, TRUE)
                ON CONFLICT (db_name, schema_name) DO UPDATE SET
                    is_prod = EXCLUDED.is_prod,
                    ad_layer = EXCLUDED.ad_layer,
                    schema_owner_role = EXCLUDED.schema_owner_role,
                    role_prefix_all = EXCLUDED.role_prefix_all,
                    ad_group_all = EXCLUDED.ad_group_all,
                    role_prefix_owner = EXCLUDED.role_prefix_owner,
                    ad_group_owner = EXCLUDED.ad_group_owner,
                    role_prefix_write = EXCLUDED.role_prefix_write,
                    ad_group_write = EXCLUDED.ad_group_write,
                    role_prefix_read = EXCLUDED.role_prefix_read,
                    ad_group_read = EXCLUDED.ad_group_read,
                    last_updated_at = CURRENT_TIMESTAMP,
                    is_active = TRUE
                """
                
                cur.execute(insert_query, (
                    mapping["db_name"],
                    mapping["is_prod"],
                    mapping["ad_layer"],
                    mapping["schema_name"],
                    mapping["schema_owner_role"],
                    mapping["role_prefix_all"],
                    mapping["ad_group_all"],
                    mapping["role_prefix_owner"],
                    mapping["ad_group_owner"],
                    mapping["role_prefix_write"],
                    mapping["ad_group_write"],
                    mapping["role_prefix_read"],
                    mapping["ad_group_read"]
                ))
            
            conn.commit()
        print(f"Успешно сохранено {len(role_mappings)} записей маппинга.")
    finally:
        conn.close()


def extract_role_prefix(role_name):
    """
    Извлекает префикс из имени роли.
    
    Примеры:
    - all_bcapp -> bcapp
    - read_core -> core
    - owner_analysis -> analysis
    - write_data -> data
    
    Возвращает None если роль не соответствует ожидаемому формату.
    """
    if not role_name:
        return None
    
    role_lower = role_name.lower()
    
    # Список возможных префиксов
    prefixes = ["all_", "read_", "write_", "owner_", "unspec_"]
    
    for prefix in prefixes:
        if role_lower.startswith(prefix):
            extracted = role_lower[len(prefix):]
            # Проверка что после префикса что-то есть
            if extracted:
                return extracted
    
    # Если роль не начинается с известного префикса, возможно это имя схемы
    # Возвращаем как есть если не содержит специальных символов
    if not any(c in role_lower for c in ["_", "-", "."]):
        return role_lower
    
    return None


def update_ad_groups_from_cache(ad_groups_set):
    """
    Обновляет поля ad_group_* в таблице маппинга на основе выгруженных AD-групп.
    
    Args:
        ad_groups_set: множество имен AD-групп (в нижнем регистре)
    """
    conn = get_audit_connection()
    
    try:
        with conn.cursor() as cur:
            # Получаем все активные записи маппинга
            cur.execute("""
                SELECT id, db_name, ad_layer, schema_name,
                       role_prefix_all, role_prefix_owner, role_prefix_write, role_prefix_read
                FROM audit_mapping_group
                WHERE is_active = TRUE
            """)
            
            mappings = cur.fetchall()
            
            updates_count = 0
            
            for mapping in mappings:
                mapping_id = mapping[0]
                db_name = mapping[1]
                ad_layer = mapping[2]
                schema_name = mapping[3]
                role_all = mapping[4]
                role_owner = mapping[5]
                role_write = mapping[6]
                role_read = mapping[7]
                
                # Формируем возможные имена AD-групп на основе ролей
                # Логика аналогична той что в bash-скрипте
                
                # Определяем базовый слой
                base_layer = ad_layer.rstrip('T')
                
                # Для тестовых сред EDW/ODS/CBD используем префикс DWHT
                group_prefix = base_layer
                if not ad_layer.endswith('T') and base_layer in ['EDW', 'ODS', 'CBD']:
                    # Прод группа
                    pass
                elif ad_layer.endswith('T') or base_layer in ['EDW', 'ODS', 'CBD']:
                    # Тестовая группа
                    if base_layer in ['EDW', 'ODS', 'CBD']:
                        group_prefix = 'DWHT ' + base_layer
                    else:
                        group_prefix = ad_layer
                
                # Проверяем и обновляем AD-группы
                updates = {}
                
                if role_all:
                    # Формируем имя группы: "<LAYER> All <schema>"
                    ad_group_name = f"{group_prefix} All {schema_name}".lower()
                    if ad_group_name in ad_groups_set:
                        updates['ad_group_all'] = ad_group_name
                
                if role_owner:
                    if base_layer == 'ADB':
                        ad_group_name = f"{ad_layer} Owner {schema_name}".lower()
                    else:
                        ad_group_name = f"{group_prefix} All {schema_name}".lower()
                    if ad_group_name in ad_groups_set:
                        updates['ad_group_owner'] = ad_group_name
                
                if role_write and base_layer == 'ADB':
                    ad_group_name = f"{ad_layer} Write {schema_name}".lower()
                    if ad_group_name in ad_groups_set:
                        updates['ad_group_write'] = ad_group_name
                
                if role_read:
                    if base_layer == 'ADB':
                        ad_group_name = f"{ad_layer} Read {schema_name}".lower()
                    else:
                        ad_group_name = f"{group_prefix} Read {schema_name}".lower()
                    if ad_group_name in ad_groups_set:
                        updates['ad_group_read'] = ad_group_name
                
                # Выполняем обновление если есть совпадения
                if updates:
                    set_clause = ", ".join([f"{k} = %s" for k in updates.keys()])
                    update_query = f"""
                        UPDATE audit_mapping_group
                        SET {set_clause}, last_updated_at = CURRENT_TIMESTAMP
                        WHERE id = %s
                    """
                    
                    values = list(updates.values()) + [mapping_id]
                    cur.execute(update_query, values)
                    updates_count += len(updates)
            
            conn.commit()
            print(f"Обновлено {updates_count} AD-групп в таблице маппинга.")
    
    finally:
        conn.close()


def get_mapping_for_db(db_name):
    """
    Получает маппинг для конкретной БД.
    
    Returns:
        DataFrame с колонками: schema_name, role_prefix_all, ad_group_all, 
                               role_prefix_owner, ad_group_owner,
                               role_prefix_write, ad_group_write,
                               role_prefix_read, ad_group_read
    """
    import pandas as pd
    
    conn = get_audit_connection()
    try:
        query = """
        SELECT 
            schema_name,
            role_prefix_all,
            ad_group_all,
            role_prefix_owner,
            ad_group_owner,
            role_prefix_write,
            ad_group_write,
            role_prefix_read,
            ad_group_read,
            ad_layer,
            is_prod
        FROM audit_mapping_group
        WHERE db_name = %s AND is_active = TRUE
        ORDER BY schema_name
        """
        
        df = pd.read_sql_query(query, conn, params=(db_name,))
        return df
    finally:
        conn.close()


if __name__ == "__main__":
    # Пример использования
    print("Инициализация таблицы маппинга...")
    init_mapping_table()
    
    print("\nПостроение маппинга из данных БД...")
    build_mapping_from_db()
    
    print("\nГотово!")
