"""
Проверка на наличие 'сиротских' прямых грантов.
Выявляет пользователей, у которых есть прямой доступ (GRANT),
но они НЕ состоят в соответствующей AD-группе, которая должна управлять этим доступом.
"""

import pandas as pd
from utils.audit_db import save_orphan_grant_violations

def get_cluster_name(db_name: str) -> str:
    """Извлекает имя кластера (ADB, EDW, ODS, CBD) из имени БД."""
    db_name_upper = db_name.upper()
    if db_name_upper.startswith('ADB'):
        return 'ADB'
    elif db_name_upper.startswith('EDW'):
        return 'EDW'
    elif db_name_upper.startswith('ODS'):
        return 'ODS'
    elif db_name_upper.startswith('CBD'):
        return 'CBD'
    return 'UNKNOWN'

def map_privilege_to_group_keyword(privilege: str) -> str:
    """Сопоставляет привилегию PostgreSQL с ключевым словом в имени группы."""
    priv = privilege.upper()
    if priv in ['SELECT', 'USAGE']:
        return 'READ'
    elif priv in ['INSERT', 'UPDATE', 'DELETE', 'TRUNCATE']:
        return 'WRITE'
    elif priv == 'ALL PRIVILEGES':
        return 'OWNER'
    return 'READ'

def run_check(db_df, ad_df, db_info, output_dir):
    """
    Проверка на сиротские гранты.
    Логика: если у пользователя есть прямой грант, но нет членства в AD-группе,
    которая должна предоставлять такой доступ -> нарушение.
    """
    db_name = db_info["name"]
    is_prod_db = db_info.get("is_prod", False)
    target_layer = db_info.get("ad_layer", get_cluster_name(db_name))
    
    print(f"Запуск проверки на сиротские гранты для БД: {db_name} (Кластер: {target_layer})")

    # Фильтруем только активные записи AD
    active_ad = ad_df[ad_df["Enabled"] == True]
    
    # Мерджим данные о грантах с данными AD по очищенному имени роли
    merged = pd.merge(
        db_df, active_ad, left_on="rolname_clean", right_on="sam_clean", how="inner"
    )

    if merged.empty:
        print("Нет данных для анализа после объединения с AD.")
        return

    violations = []
    
    for idx, row in merged.iterrows():
        user = row.get("rolname", "")
        db_schema = str(row.get("table_schema", "")).lower()
        db_table = row.get("table_name", None)
        db_privilege = str(row.get("privilege_type", "")).lower()
        user_groups = row.get("accesses", [])
        
        # Определяем ключевое слово привилегии для поиска группы
        priv_keyword = map_privilege_to_group_keyword(db_privilege)
        
        # Ищем хотя бы одну группу, которая подтверждает этот грант
        has_valid_group = False
        
        for group in user_groups:
            g_layer = group.get("group_layer", "")  # "EDW", "EDWT", "CBD"...
            g_schema = group.get("group_schema", "")  # "core", "cdm_analysis"...
            g_privilege = group.get("group_privilege", "")  # "read", "write"...
            
            # Фильтр по кластеру/слою (аналогично check_redundant)
            if target_layer not in g_layer:
                continue
            
            # Фильтр прод/тест
            if is_prod_db and g_layer.endswith("T"):
                continue
            
            # Проверка совпадения схемы и привилегии
            if g_schema.lower() == db_schema and g_privilege.lower() == db_privilege:
                has_valid_group = True
                break
        
        # Если грант есть, но подтверждающей группы нет -> нарушение
        if not has_valid_group:
            violations.append({
                'user_name': user,
                'schema_name': row.get("table_schema", ""),
                'table_name': db_table,
                'privilege_type': db_privilege,
                'object_type': 'TABLE',
                'reason': f"No matching AD group for {priv_keyword} on {db_schema}"
            })

    if violations:
        report_df = pd.DataFrame(violations)
        print(f"Найдено нарушений (сиротские гранты): {len(report_df)}")
        save_orphan_grant_violations(db_name, report_df)
    else:
        print("Нарушений не найдено. Все прямые гранты подтверждены членством в группах.")
