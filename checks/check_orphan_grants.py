"""
Проверка на наличие 'сиротских' прямых грантов.
Выявляет пользователей, у которых есть прямой доступ (GRANT),
но они НЕ состоят в соответствующей AD-группе, которая должна управлять этим доступом.
"""

import pandas as pd
from utils.audit_db import save_orphan_grant_violations
from utils.mapping_db import get_mapping_for_db, init_mapping_table


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
    
    # Определяем базовый слой (без суффикса T)
    base_target_layer = target_layer.rstrip('T')
    
    print(f"Запуск проверки на сиротские гранты для БД: {db_name} (Кластер: {target_layer})")

    # Загружаем маппинг для этой БД
    mapping_df = get_mapping_for_db(db_name)
    if mapping_df.empty:
        print(f"Предупреждение: таблица маппинга пуста для БД {db_name}. Используем старую логику.")
        # Fallback на старую логику если маппинг пуст
        return _run_check_legacy(db_df, ad_df, db_info, output_dir)
    
    # Преобразуем маппинг в словарь для быстрого доступа
    # Ключ: schema_name, Значение: dict с ролями и AD-группами
    schema_mapping = {}
    for _, row in mapping_df.iterrows():
        schema = row['schema_name'].lower()
        schema_mapping[schema] = {
            'role_prefix_all': row.get('role_prefix_all'),
            'ad_group_all': row.get('ad_group_all'),
            'role_prefix_owner': row.get('role_prefix_owner'),
            'ad_group_owner': row.get('ad_group_owner'),
            'role_prefix_write': row.get('role_prefix_write'),
            'ad_group_write': row.get('ad_group_write'),
            'role_prefix_read': row.get('role_prefix_read'),
            'ad_group_read': row.get('ad_group_read'),
            'ad_layer': row.get('ad_layer'),
            'is_prod': row.get('is_prod', False)
        }
    
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
        
        # Фильтр привилегий в зависимости от слоя
        # Для EDW, ODS, CBD учитываем только Read, All, Owner
        # Для ADB учитываем Read, Owner, Write
        allowed_privileges = ['read', 'all', 'owner']
        if base_target_layer == 'ADB':
            allowed_privileges.append('write')
        
        # Если привилегия не входит в разрешенные для этого слоя - пропускаем
        if priv_keyword.lower() not in [p.lower() for p in allowed_privileges]:
            continue
        
        # Получаем маппинг для этой схемы
        mapping_entry = schema_mapping.get(db_schema)
        
        # Ищем хотя бы одну группу, которая подтверждает этот грант
        has_valid_group = False
        
        # Проверяем через таблицу маппинга
        if mapping_entry:
            # Определяем какую AD-группу искать в зависимости от привилегии
            expected_ad_group = None
            
            if priv_keyword == 'READ':
                expected_ad_group = mapping_entry.get('ad_group_read')
            elif priv_keyword == 'WRITE':
                expected_ad_group = mapping_entry.get('ad_group_write')
            elif priv_keyword == 'OWNER':
                expected_ad_group = mapping_entry.get('ad_group_owner') or mapping_entry.get('ad_group_all')
            elif priv_keyword == 'ALL':
                expected_ad_group = mapping_entry.get('ad_group_all') or mapping_entry.get('ad_group_owner')
            
            # Если ожидаемая AD-группа найдена в маппинге, проверяем состоит ли в ней пользователь
            if expected_ad_group and pd.notna(expected_ad_group):
                expected_ad_group_lower = str(expected_ad_group).lower()
                for group in user_groups:
                    g_original_name = group.get("original_name", "")
                    if g_original_name and g_original_name.lower() == expected_ad_group_lower:
                        has_valid_group = True
                        break
        
        # Если через маппинг не нашли, пробуем старую логику как fallback
        if not has_valid_group:
            for group in user_groups:
                g_layer = group.get("group_layer", "")  # "EDW", "EDWT", "CBD"...
                g_schema = group.get("group_schema", "")  # "core", "cdm_analysis"...
                g_privilege = group.get("group_privilege", "")  # "read", "write"...
                g_original_name = group.get("original_name", "")
                
                # Определяем базовый слой группы
                base_g_layer = g_layer.rstrip('T')
                
                # Фильтр по кластеру/слою
                if base_target_layer != base_g_layer:
                    continue
                
                # Фильтр прод/тест
                if is_prod_db:
                    # Для прод-базы подходят только прод-группы (без 'T' в конце)
                    if g_layer.endswith("T"):
                        continue
                else:
                    # Для тестовой базы подходят:
                    # 1. Тестовые группы (с 'T') того же кластера
                    # 2. Универсальные группы dwht (для EDW/ODS/CBD тестов)
                    if not g_layer.endswith("T"):
                        # Для ADB тестовых сред нужны группы ADBT
                        if base_target_layer == 'ADB':
                            continue
                        # Для EDW/ODS/CBD тестовых сред допускаются группы с префиксом DWHT
                        if base_target_layer in ['EDW', 'ODS', 'CBD']:
                            if not g_original_name.upper().startswith('DWHT'):
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


def _run_check_legacy(db_df, ad_df, db_info, output_dir):
    """Старая логика проверки (fallback если маппинг пуст)."""
    # Импортируем локально чтобы избежать циклического импорта
    db_name = db_info["name"]
    is_prod_db = db_info.get("is_prod", False)
    target_layer = db_info.get("ad_layer", get_cluster_name(db_name))
    base_target_layer = target_layer.rstrip('T')
    
    active_ad = ad_df[ad_df["Enabled"] == True]
    merged = pd.merge(
        db_df, active_ad, left_on="rolname_clean", right_on="sam_clean", how="inner"
    )

    if merged.empty:
        return

    violations = []
    
    for idx, row in merged.iterrows():
        user = row.get("rolname", "")
        db_schema = str(row.get("table_schema", "")).lower()
        db_table = row.get("table_name", None)
        db_privilege = str(row.get("privilege_type", "")).lower()
        user_groups = row.get("accesses", [])
        
        priv_keyword = map_privilege_to_group_keyword(db_privilege)
        allowed_privileges = ['read', 'all', 'owner']
        if base_target_layer == 'ADB':
            allowed_privileges.append('write')
        
        if priv_keyword.lower() not in [p.lower() for p in allowed_privileges]:
            continue
        
        has_valid_group = False
        
        for group in user_groups:
            g_layer = group.get("group_layer", "")
            g_schema = group.get("group_schema", "")
            g_privilege = group.get("group_privilege", "")
            g_original_name = group.get("original_name", "")
            
            base_g_layer = g_layer.rstrip('T')
            
            if base_target_layer != base_g_layer:
                continue
            
            if is_prod_db:
                if g_layer.endswith("T"):
                    continue
            else:
                if not g_layer.endswith("T"):
                    if base_target_layer == 'ADB':
                        continue
                    if base_target_layer in ['EDW', 'ODS', 'CBD']:
                        if not g_original_name.upper().startswith('DWHT'):
                            continue
            
            if g_schema.lower() == db_schema and g_privilege.lower() == db_privilege:
                has_valid_group = True
                break
        
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
