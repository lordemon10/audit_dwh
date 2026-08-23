import os
import pandas as pd


def run_check(db_df, ad_df, db_info, output_dir):
    """Проверка №3 (redundant_grants): Ищет избыточные прямые гранты."""
    db_name = db_info["name"]
    is_prod_db = db_info["is_prod"]
    target_layer = db_info["ad_layer"]  # Например, 'EDW' или 'CBD'

    print(f"Запуск проверки на дублирующие grant - ", end="")

    check_dir = os.path.join(output_dir, "check_redunant")
    os.makedirs(check_dir, exist_ok=True)

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

        for group in user_groups:
            g_layer = group["group_layer"]  # "EDW", "EDWT", "CBD"...
            g_schema = group["group_schema"]  # "cdm_analysis"
            g_privilege = group["group_privilege"]  # "read"

            # ------------------------------------------------------------------
            # 🔥 КРИТИЧЕСКИЙ ФИЛЬТР КОНТУРА БАЗЫ ДАННЫХ
            # ------------------------------------------------------------------
            # Группа должна подходить к нашей базе по базовому имени (например, EDW == EDW или EDWT содержит EDW)
            if target_layer not in g_layer:
                continue  # Пропускаем! Группа CBD не может давать доступ в базу EDW

            # Проверка прод / тест среды
            if is_prod_db and g_layer.endswith("T"):
                continue  # Пропускаем! Тестовая группа (с 'T') не работает на проде

            # ------------------------------------------------------------------
            # Проверка совпадения схемы и силы прав
            # ------------------------------------------------------------------
            if db_schema == g_schema:
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
                    covering_group_name = group["original_name"]
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

        report_df.to_csv(full_path, index=False, encoding="utf-8-sig", sep=";")
