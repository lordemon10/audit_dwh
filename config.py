# Путь к файлу IDM.csv
IDM_FILE_PATH = "./data/IDM.csv"

# Путь куда сохранять результаты
OUTPUT_DIR = "audit_results"

# Учетные данные для БД
DB_AUTH = {
    "user": "login",
    "password": "password"
}


# Список баз данных 
DB_LIST = [
    {"name": "edw_prod", "host": "server", "db": "db_edw", "port": 5434, "is_prod": True, "ad_layer": "EDW"}

]

# Настройка AD
AD_CONFIG = {
    "server": "server",
    "user": "RGSMAIN\\login",
    "password": "password",
    "domain": "DC=rgs,DC=ru",
}

# Настройка БД для аудита (используем одну из существующих БД)
AUDIT_DB = {
    "name": "edw_prod",
    "host": "server",
    "db": "db_edw",
    "port": 5434,
    "user": DB_AUTH["user"],
    "password": DB_AUTH["password"]
}

# SQL Запросы
SQL_QUERY = {
    "rolcanlogin": """
        select rolname, rolcanlogin 
        from pg_catalog.pg_roles
        where rolname !~ '^pg_|^rld_|^posgres$|^all_|^read_|^unspec|^write_';
    """,
    "direct_grants": """
        select 
            r.rolname,
            n.nspname as table_schema,
            c.relname as table_name,
            case 
                when a.privilege_type = 'SELECT' then 'SELECT'
                when a.privilege_type = 'INSERT' then 'INSERT'
                when a.privilege_type = 'UPDATE' then 'UPDATE'
                when a.privilege_type = 'DELETE' then 'DELETE'
                else a.privilege_type
            end as privilege_type
        from pg_catalog.pg_class c
        join pg_catalog.pg_namespace n on n.oid = c.relnamespace
        join pg_catalog.pg_roles r on true
        cross join lateral aclexplode(coalesce(c.relacl, acldefault('r', c.relowner))) a
        where a.grantee = r.oid
          and c.relkind = 'r' -- только обычные таблицы
          and n.nspname !~ '^pg_' and n.nspname != 'information_schema'
          and r.rolname !~ '^pg_|^rld_|^postgres$|^all_|^read_|^unspec|^write_';
    """,
    "schema_grants": """
        select 
            r.rolname,
            n.nspname as table_schema,
            c.relname as table_name,
            case 
                when a.privilege_type = 'SELECT' then 'SELECT'
                when a.privilege_type = 'INSERT' then 'INSERT'
                when a.privilege_type = 'UPDATE' then 'UPDATE'
                when a.privilege_type = 'DELETE' then 'DELETE'
                else a.privilege_type
            end as privilege_type
        from pg_catalog.pg_class c
        join pg_catalog.pg_namespace n on n.oid = c.relnamespace
        join pg_catalog.pg_roles r on true
        cross join lateral aclexplode(coalesce(c.relacl, acldefault('r', c.relowner))) a
        where a.grantee = r.oid
          and c.relkind = 'r'
          and n.nspname !~ '^pg_' and n.nspname != 'information_schema'
          and r.rolname !~ '^pg_|^rld_|^postgres$|^all_|^read_|^unspec|^write_';
    """
}