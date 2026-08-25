"""
Проверка на избыточные (дублирующие) прямые гранты.
Выявляет пользователей, у которых есть прямой доступ (GRANT) к таблице,
и при этом они состоят в AD-группе, которая уже предоставляет этот доступ.

Использует РУЧНОЙ маппинг из таблицы audit_mapping.
Если в маппинге для схемы не заполнены роли и AD-группы - схема пропускается.
"""

import pandas as pd
from utils.audit_db import save_redundant_violations
from utils.mapping_db import get_mapping_for_db


def run_check(db_df, ad_df, db_info, output_dir):
    """
    Проверка на дублирующие гранты.
    Логика: если у пользователя есть прямой грант И он состоит в AD-группе,
    которая предоставляет такой же доступ -> нарушение (избыточный грант).
    
    Используется ТОЛЬКО ручной маппинг из таблицы audit_mapping.
    Если для схемы не заполнены read_ad/write_ad/owner_ad - проверка эту схему пропускает.
    """
    db_name = db_info["name"]
    
    print(f"Запуск проверки на дублирующие гранты для БД: {db_name}")

    # Загружаем маппинг для этой БД
    mapping_df = get_mapping_for_db(db_name)
    if mapping_df.empty:
        print(f"Предупреждение: таблица маппинга пуста для БД {db_name}. Проверка невозможна.")
        return
    
    # Преобразуем маппинг в словарь для быстрого доступа
    # Ключ: schema_name, Значение: dict с AD-группами
    schema_mapping = {}
    for _, row in mapping_df.iterrows():
        schema = row['schemaname'].lower()
        
        # Проверяем что хотя бы одна AD-группа заполнена
        ad_groups = {
            'read_ad': row.get('read_ad'),
            'write_ad': row.get('write_ad'),
            'owner_ad': row.get('owner_ad')
        }
        
        # Если все AD-группы пустые - пропускаем эту схему
        if not any(pd.notna(v) and v for v in ad_groups.values()):
            continue
        
        schema_mapping[schema] = ad_groups
    
    if not schema_mapping:
        print(f"В маппинге нет схем с заполненными AD-группами для БД {db_name}. Проверка невозможна.")
        return
    
    # Фильтруем только активные записи AD
    active_ad = ad_df[ad_df["Enabled"] == True]
    
    # Мерджим данные о грантах с данными AD по очищенному имени роли
    merged = pd.merge(
        db_df, active_ad, left_on="rolname_clean", right_on="sam_clean", how="inner"
    )

    if merged.empty:
        print("Нет данных для анализа после объединения с AD.")
        return

    redundant_rows = []
    
    for idx, row in merged.iterrows():
        db_schema = str(row["table_schema"]).lower()
        db_privilege = str(row["privilege_type"]).lower()
        user_groups = row["accesses"]
        
        # Получаем маппинг для этой схемы
        mapping_entry = schema_mapping.get(db_schema)
        
        # Если схемы нет в маппинге или все AD-группы пустые - пропускаем
        if not mapping_entry:
            continue
        
        # Определяем какую AD-группу искать в зависимости от привилегии
        # Также проверяем группу уровня "All" которая покрывает все привилегии
        expected_ad_groups = []
        
        # Добавляем группу All если она указана (покрывает все привилегии)
        if mapping_entry.get('owner_ad'):
            expected_ad_groups.append(mapping_entry.get('owner_ad'))
        
        if db_privilege == "select":
            if mapping_entry.get('read_ad'):
                expected_ad_groups.append(mapping_entry.get('read_ad'))
        elif db_privilege in ["insert", "update", "delete"]:
            # Для write привилегий проверяем write_ad, read_ad или owner_ad
            if mapping_entry.get('write_ad'):
                expected_ad_groups.append(mapping_entry.get('write_ad'))
            if mapping_entry.get('read_ad'):
                expected_ad_groups.append(mapping_entry.get('read_ad'))
        elif db_privilege == "all privileges":
            # Для all privileges проверяем owner_ad или read_ad
            if mapping_entry.get('owner_ad'):
                expected_ad_groups.append(mapping_entry.get('owner_ad'))
            if mapping_entry.get('read_ad'):
                expected_ad_groups.append(mapping_entry.get('read_ad'))
        
        # Если ожидаемые AD-группы не указаны в маппинге - пропускаем
        if not expected_ad_groups or not any(pd.notna(g) and g for g in expected_ad_groups):
            continue
        
        # Проверяем состоит ли пользователь хотя бы в одной из ожидаемых групп
        has_duplicate_group = False
        covering_group_name = None
        expected_ad_groups_lower = [str(g).lower() for g in expected_ad_groups if pd.notna(g)]
        
        for group in user_groups:
            g_original_name = group.get("original_name", "")
            if g_original_name and g_original_name.lower() in expected_ad_groups_lower:
                has_duplicate_group = True
                covering_group_name = g_original_name
                break
        
        if has_duplicate_group:
            revoke_sql = f"REVOKE {row['privilege_type']} ON {row['table_schema']}.{row['table_name']} FROM {row['rolname']};"
            
            redundant_rows.append({
                "rolname": row["rolname"],
                "Name": row["Name"],
                "table_schema": row["table_schema"],
                "table_name": row["table_name"],
                "privilege_type": row["privilege_type"],
                "duplicate_ad_group": covering_group_name,
                "revoke_sql": revoke_sql,
            })

    if not redundant_rows:
        print("Нарушений не найдено")
    else:
        report_df = pd.DataFrame(redundant_rows)
        print(f"Найдено нарушений: {len(report_df)}")
        
        # Сохраняем в БД
        save_redundant_violations(db_name, report_df)
