"""
Проверка на наличие 'сиротских' прямых грантов.
Выявляет пользователей, у которых есть прямой доступ (GRANT),
но они НЕ состоят в соответствующей AD-группе, которая должна управлять этим доступом.

Использует РУЧНОЙ маппинг из таблицы audit_mapping.
Если в маппинге для схемы не заполнены роли и AD-группы - схема пропускается.
"""

import pandas as pd
from utils.audit_db import save_orphan_grant_violations
from utils.mapping_db import get_mapping_for_db


def run_check(db_df, ad_df, db_info, output_dir):
    """
    Проверка на сиротские гранты.
    Логика: если у пользователя есть прямой грант, но нет членства в AD-группе,
    которая должна предоставлять такой доступ -> нарушение.
    
    Используется ТОЛЬКО ручной маппинг из таблицы audit_mapping.
    Если для схемы не заполнены read_ad/write_ad/owner_ad - проверка эту схему пропускает.
    """
    db_name = db_info["name"]
    
    print(f"Запуск проверки на сиротские гранты для БД: {db_name}")

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

    violations = []
    
    for idx, row in merged.iterrows():
        user = row.get("rolname", "")
        db_schema = str(row.get("table_schema", "")).lower()
        db_table = row.get("table_name", None)
        db_privilege = str(row.get("privilege_type", "")).lower()
        user_groups = row.get("accesses", [])
        
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
        has_valid_group = False
        expected_ad_groups_lower = [str(g).lower() for g in expected_ad_groups if pd.notna(g)]
        
        for group in user_groups:
            g_original_name = group.get("original_name", "")
            if g_original_name and g_original_name.lower() in expected_ad_groups_lower:
                has_valid_group = True
                break
        
        # Если грант есть, но подтверждающей группы нет -> нарушение
        if not has_valid_group:
            # Формируем понятное сообщение с перечислением ожидаемых групп
            expected_groups_str = ", ".join([g for g in expected_ad_groups if pd.notna(g)])
            violations.append({
                'user_name': user,
                'schema_name': row.get("table_schema", ""),
                'table_name': db_table,
                'privilege_type': db_privilege,
                'object_type': 'TABLE',
                'reason': f"No matching AD group ({expected_groups_str}) for {db_privilege} on {db_schema}"
            })

    if violations:
        report_df = pd.DataFrame(violations)
        print(f"Найдено нарушений (сиротские гранты): {len(report_df)}")
        save_orphan_grant_violations(db_name, report_df)
    else:
        print("Нарушений не найдено. Все прямые гранты подтверждены членством в группах.")
