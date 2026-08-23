import os
import pandas as pd
from utils import save_direct_ad_violations


def run_check(idm_file_path, ad_df, output_dir, db_name):
    """Проверка №5: Поиск строк, где в 3-й колонке Synchronization, а в 4-й

    колонке роль НЕ пустая.
    """
    print("\n Запуск проверки на Synchronization и НЕ пустую роль - ", end="")

    check_dir = os.path.join(output_dir, "check_direct_ad")
    os.makedirs(check_dir, exist_ok=True)

    if not os.path.exists(idm_file_path):
        print(f"Ошибка: Файл {idm_file_path} не найден в папке проекта.")
        return

    try:
        # Читаем исходный файл IDM.csv (он с табами)
        df = pd.read_csv(idm_file_path, sep="\t", engine="python")
        if len(df.columns) == 1:
            df = pd.read_csv(idm_file_path, sep=None, engine="python")

        if len(df.columns) < 4:
            print(f"Ошибка: В файле IDM.csv слишком мало колонок.")
            return

        df = df.iloc[:, :4]
        df.columns = ["login", "group", "source", "business_role"]

        for col in df.columns:
            df[col] = df[col].astype(str).str.strip().str.replace('"', "")

        df["source"] = df["source"].str.rstrip(",")
        df["login"] = df["login"].str.lower()

        # 🔥 ЖЕСТКАЯ ОЧИСТКА: убираем слово "nan" и точку, превращая их в пустую строку
        df["business_role"] = df["business_role"].replace(
            ["nan", "None", "NaN", "unspecified", "null", "."], ""
        )
        df["business_role"] = df["business_role"].apply(
            lambda x: "" if not x or str(x).isspace() or str(x).lower() == "nan" or str(x) == "." else x
        )

        # Выбираем все строки со статусом Synchronization
        sync_only_df = df[df["source"].str.lower() == "synchronization"].copy()

        # 🔥 СТРОГИЙ ФИЛЬТР: Источник равен Synchronization И Роль НЕ ПУСТАЯ
        violations_df = sync_only_df[sync_only_df["business_role"] != ""].copy()

        file_name = "idm_check_direct_ad_grants.csv"
        full_path = os.path.join(check_dir, file_name)

        if violations_df.empty:
            print(f"Нарушений не обнаружено.")
        else:
            report_df = pd.merge(
                violations_df,
                ad_df[["sam_clean", "Name"]],
                left_on="login",
                right_on="sam_clean",
                how="left",
            )
            report_df["Name"] = report_df["Name"].fillna("Не найден в кэше AD")
            report_df["comment"] = "Synchronization + заполненная бизнес-роль"

            final_columns = ["login", "Name", "group", "source", "business_role", "comment"]
            report_df = report_df[final_columns].drop_duplicates()

            print(f"Найдено нарушений: {len(report_df)}")
            
            # Сохраняем в БД
            save_direct_ad_violations(db_name, report_df)

    except Exception as e:
        print(f"  Ошибка в Проверке 5: {e}")
