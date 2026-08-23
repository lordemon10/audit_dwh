import pandas as pd
import psycopg2
from config import DB_AUTH

def get_db_users(db_info, query):
    """Подключается к БД и забираем результат запроса."""
    connection_params = {
        "user":DB_AUTH["user"],
        "password": DB_AUTH["password"],
        "host": db_info["host"],
        "port": db_info["port"],
        "database": db_info["db"]
    }

    try:
        with psycopg2.connect(**connection_params) as conn:
            df = pd.read_sql_query(query, conn)
            # Очищаем логин в новую колонку rolname_clean
            df["rolname_clean"] = df["rolname"].astype(str).str.strip().str.lower()
            return df
    except Exception as e:
        print(f"Ошибка подключения к БД {db_info['name']} {db_info['host']}:{db_info['port']}: {e}")
        return None