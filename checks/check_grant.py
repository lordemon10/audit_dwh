import os
import pandas as pd
from utils import save_grant_violations


def run_check(db_df, ad_df, db_name, output_dir):
    """Проверка №2 (direct_grants): Поиск уволенных сотрудников, у которых остались прямые гранты."""
    print(f"Запуск проверки прямых grant у уволенных сотрудников для БД: {db_name} - ", end="")

    check_dir = os.path.join(output_dir, "check_grant")
    os.makedirs(check_dir, exist_ok=True)

    # 1. Сверяем по очищенным логинам
    merged = pd.merge(
        db_df, ad_df, left_on="rolname_clean", right_on="sam_clean", how="inner"
    )

    # 2. Фильтруем: сотрудник заблокирован в AD (Enabled == False)
    violations = merged[merged["Enabled"] == False].copy()

    file_name = f"{db_name}_check_grant.csv"
    full_path = os.path.join(check_dir, file_name)

    if violations.empty:
        print(f"Нарушений не обнаружено" )

    else:
        print(f"Найдено нарушений: {len(violations)}")

        # 3. ГЕНЕРИРУЕМ SQL-ЗАПРОС НА ОТЗЫВ ПРАВ
        # Шаблон в PostgreSQL: REVOKE [тип_права] ON [имя_таблицы] FROM [имя_роли];
        violations["revoke_sql"] = (
            "REVOKE " + violations["privilege_type"].astype(str) + 
            " ON " + violations["table_schema"].astype(str) + "." + violations["table_name"].astype(str) + 
            " FROM " + violations["rolname"].astype(str) + ";"
        )



        # 4. Выбираем важные колонки
        report_columns = [
            "rolname",
            "Name",
            "table_name",
            "privilege_type",
            "revoke_sql",
        ]
        report_df = violations[report_columns]

        # 5. Сохраняем в БД
        save_grant_violations(db_name, report_df)
