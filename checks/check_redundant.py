import os
import pandas as pd
from utils import save_redundant_violations
from utils.mapping_db import get_mapping_for_db


def run_check(db_df, ad_df, db_info, output_dir):
    """Проверка №3 (redundant_grants): Ищет избыточные прямые гранты."""
    db_name = db_info["name"]
    is_prod_db = db_info["is_prod"]
    target_layer = db_info["ad_layer"]  # Например, 'EDW' или 'CBD'
    
    print(f"Запуск проверки на дублирующие grant - ", end="")

    check_dir = os.path.join(output_dir, "check_redunant")
    os.makedirs(check_dir, exist_ok=True)

    # Загружаем маппинг для этой БД
    mapping_df = get_mapping_for_db(db_name)
    use_mapping = not mapping_df.empty
    
    if use_mapping:
        # Преобразуем маппинг в словарь для быстрого доступа
        schema_mapping = {}
        for _, row in mapping_df.iterrows():
            schema = row['schema_name'].lower()
            schema_mapping[schema] = {
                'ad_group_all': row.get('ad_group_all'),
                'ad_group_owner': row.get('ad_group_owner'),
                'ad_group_write': row.get('ad_group_write'),
                'ad_group_read': row.get('ad_group_read'),
            }
        print("используется таблица маппинга.")
    else:
        print("таблица маппинга пуста, используется старая логика.")
    
    active_ad = ad_df[ad_df["Enabled"] == True]
    merged = pd.merge(
        db_df, active_ad, left_on="rolname_clean", right_on="sam_clean", how="inner"
    )

    redundant_rows = []

    for idx, row in merged.iterrows():
        db_schema = str(row["table_schema"]).lower()
        db_privilege = str(row["privilege_type"]).lower()
        user_groups = row["accesses"]

        has_duplicate_group = False
        covering_group_name = ""

        # Если есть маппинг, сначала пробуем найти через него
        if use_mapping:
            mapping_entry = schema_mapping.get(db_schema)
            if mapping_entry:
                # Определяем какую AD-группу искать в зависимости от привилегии
                expected_ad_group = None
                
                if db_privilege == "select":
                    expected_ad_group = mapping_entry.get('ad_group_read')
                elif db_privilege in ["insert", "update", "delete"]:
                    expected_ad_group = mapping_entry.get('ad_group_write') or mapping_entry.get('ad_group_read')
                elif db_privilege == "all privileges":
                    expected_ad_group = mapping_entry.get('ad_group_all') or mapping_entry.get('ad_group_owner')
                
                # Проверяем состоит ли пользователь в ожидаемой группе
                if expected_ad_group:
                    for group in user_groups:
                        g_original_name = group.get("original_name", "").lower()
                        if g_original_name == expected_ad_group.lower():
                            has_duplicate_group = True
                            covering_group_name = group.get("original_name", "")
                            break
        
        # Если через маппинг не нашли или маппинга нет, используем старую логику
        if not has_duplicate_group:
            for group in user_groups:
                g_layer = group["group_layer"]  # "EDW", "EDWT", "CBD"...
                g_schema = group["group_schema"]  # "cdm_analysis"
                g_privilege = group["group_privilege"]  # "read"
                g_original_name = group.get("original_name", "")

                # ------------------------------------------------------------------
                # 🔥 КРИТИЧЕСКИЙ ФИЛЬТР КОНТУРА БАЗЫ ДАННЫХ
                # ------------------------------------------------------------------
                # Определяем базовый слой (без суффикса T)
                base_target_layer = target_layer.rstrip('T')
                base_g_layer = g_layer.rstrip('T')
                
                # Группа должна подходить к нашей базе по базовому имени
                if base_target_layer != base_g_layer:
                    continue  # Пропускаем! Группа CBD не может давать доступ в базу EDW

                # ------------------------------------------------------------------
                # Проверка прод / тест среды
                # ------------------------------------------------------------------
                if is_prod_db:
                    # Для прод-базы подходят только прод-группы (без 'T' в конце)
                    if g_layer.endswith("T"):
                        continue
                else:
                    # Для тестовой базы подходят:
                    # 1. Тестовые группы (с 'T') того же кластера
                    # 2. Универсальные группы dwht (для EDW/ODS/CBD тестов)
                    # Проверяем: если база тестовая, а группа продовая (без T) и не dwht - пропускаем
                    if not g_layer.endswith("T"):
                        # Для ADB тестовых сред нужны группы ADBT
                        if base_target_layer == 'ADB':
                            continue
                        # Для EDW/ODS/CBD тестовых сред допускаются группы с префиксом DWHT
                        if base_target_layer in ['EDW', 'ODS', 'CBD']:
                            if not g_original_name.upper().startswith('DWHT'):
                                continue

                # ------------------------------------------------------------------
                # Проверка совпадения схемы и силы прав
                # ------------------------------------------------------------------
                if db_schema == g_schema:
                    # Фильтр привилегий в зависимости от слоя
                    # Для EDW, ODS, CBD учитываем только Read, All, Owner
                    # Для ADB учитываем Read, Owner, Write
                    allowed_privileges = ['read', 'all', 'owner']
                    if base_target_layer == 'ADB':
                        allowed_privileges.append('write')
                    
                    if g_privilege not in allowed_privileges:
                        continue
                    
                    if g_privilege in ["all", "owner"]:
                        has_duplicate_group = True
                    elif g_privilege == "read" and db_privilege == "select":
                        has_duplicate_group = True
                    elif g_privilege == "write" and db_privilege in [
                        "insert",
                        "update",
                        "delete",
                        "select",
                    ]:
                        has_duplicate_group = True

                    if has_duplicate_group:
                        # Берем сохраненное оригинальное красивое имя группы из AD
                        covering_group_name = g_original_name
                        break

        if has_duplicate_group:
            revoke_sql = f"REVOKE {row['privilege_type']} ON {row['table_schema']}.{row['table_name']} FROM {row['rolname']};"

            redundant_rows.append(
                {
                    "rolname": row["rolname"],
                    "Name": row["Name"],
                    "table_schema": row["table_schema"],
                    "table_name": row["table_name"],
                    "privilege_type": row["privilege_type"],
                    "duplicate_ad_group": covering_group_name,  # Выведется реальное имя группы AD
                    "revoke_sql": revoke_sql,
                }
            )

    file_name = f"{db_name}_check_redundant.csv"
    full_path = os.path.join(check_dir, file_name)

    if not redundant_rows:
        print(f"Нарушений не найдено")
    else:
        report_df = pd.DataFrame(redundant_rows)
        print(f"Найдено нарушений: {len(report_df)} ")

        # Сохраняем в БД
        save_redundant_violations(db_name, report_df)
