import os
import pandas as pd


def run_check(db_df, ad_df, db_name, output_dir):
    """Проверка №1 (nologin): Если сотрудник заблокирован в AD, он должен быть заблокирован в БД."""
    print(f"Запуск проверки на nologin - ", end="")

    check_dir = os.path.join(output_dir, "check_nologin")
    os.makedirs(check_dir, exist_ok=True)

    # 1. Объединяем таблицы по очищенным логинам
    merged = pd.merge(
        db_df, ad_df, left_on="rolname_clean", right_on="sam_clean", how="inner"
    )

    # 2. Приводим статус rolcanlogin к строгому логическому типу (True/False)
    merged["rolcanlogin"] = merged["rolcanlogin"].isin(
        [True, "t", "true", "True"]
    )

    # 3. Фильтруем нарушения: уволен в AD (Enabled == False), но может входить в БД (rolcanlogin == True)
    violations = merged[
        (merged["Enabled"] == False) & (merged["rolcanlogin"] == True)
    ].copy()

    # Формируем путь к файлу отчета
    file_name = f"{db_name}_check_nologin.csv"
    full_path = os.path.join(check_dir, file_name)

    if violations.empty:
        print(f"Нарушений не найдено.")
    else:
        print(f"Найдено нарушений: {len(violations)}")

        # 4. ГЕНЕРИРУЕМ SQL-ЗАПРОС НА БЛОКИРОВКУ ВХОДА
        # Шаблон в PostgreSQL: ALTER ROLE имя_роли NOLOGIN;
        violations["nologin_sql"] = (
            "ALTER ROLE " + violations["rolname"].astype(str) + " NOLOGIN;"
        )

        # 5. Выбираем колонки для финального отчета ИБ
        report_columns = [
            "rolname",
            "Name",
            "Enabled",
            "rolcanlogin",
            "nologin_sql",
        ]
        report_df = violations[report_columns]

        # 6. Сохраняем индивидуальный CSV-файл
        report_df.to_csv(full_path, index=False, encoding="utf-8-sig", sep=";")
