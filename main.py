import os
from config import AD_CONFIG, DB_LIST, SQL_QUERY, OUTPUT_DIR, IDM_FILE_PATH, AUDIT_DB
from utils import get_ad_users, get_db_users, init_audit_tables
from utils.mapping_db import init_mapping_table, build_mapping_from_db, update_ad_groups_from_cache
from checks.check_nologin import run_check as run_nologin_check
from checks.check_grant import run_check as run_grant_check
from checks.check_redundant import run_check as run_redundant_check
from checks.check_idm_dups import run_check as run_idm_check
from checks.check_direct_ad import run_check as run_direct_ad_check
from checks.check_orphan_grants import run_check as run_orphan_grant_check
import warnings
warnings.filterwarnings("ignore", category=UserWarning)


def main():

    # Инициализация таблиц аудита в БД
    init_audit_tables()
    
    # Инициализация таблицы маппинга групп
    print("=" * 60)
    print("Инициализация таблицы маппинга групп доступа...")
    init_mapping_table()
    print("=" * 60)

    os.makedirs(OUTPUT_DIR, exist_ok=True)

    # --- БЛОК 1: ПРОВЕРКИ БАЗ ДАННЫХ И AD ---
    ad_df = get_ad_users()
    
    if ad_df is not None and not ad_df.empty:
        # Сначала строим маппинг схем и ролей из БД с передачей AD DataFrame
        # Функция сама вызовет update_ad_groups_from_cache внутри
        print("\nПостроение маппинга схем и ролей из БД с обновлением AD-групп...")
        build_mapping_from_db(ad_df)
        
        for db_info in DB_LIST:
            print(
                f"\nПроверка БД: {db_info['name']}"
            )

            # Проверка №1: nologin
            db_df_nologin = get_db_users(
                db_info, query=SQL_QUERY["rolcanlogin"]
            )
            if db_df_nologin is not None:
                run_nologin_check(
                    db_df_nologin, ad_df, db_info["name"], OUTPUT_DIR
                )

            # Проверка №2: Уволенные и их гранты
            db_df_grants = get_db_users(
                db_info, query=SQL_QUERY["direct_grants"]
            )
            if db_df_grants is not None:
                run_grant_check(
                    db_df_grants, ad_df, db_info["name"], OUTPUT_DIR
                )

            # Проверка №3: Избыточные гранты
            db_df_schemas = get_db_users(
                db_info, query=SQL_QUERY["schema_grants"]
            )
            if db_df_schemas is not None:
                run_redundant_check(db_df_schemas, ad_df, db_info, OUTPUT_DIR)

            # Проверка №4: Сиротские гранты (прямые гранты без AD группы)
            db_df_orphan = get_db_users(
                db_info, query=SQL_QUERY["schema_grants"]
            )
            if db_df_orphan is not None:
                run_orphan_grant_check(db_df_orphan, ad_df, db_info, OUTPUT_DIR)

            print("-" * 60)
    else:
        print(
            "Проверки БД пропущены, так как не удалось собрать кэш AD.\n"
        )

    # --- БЛОК 2: АВТОНОМНАЯ ПРОВЕРКА IDM ---

    # Запускаем проверку №4
    run_idm_check(idm_file_path=IDM_FILE_PATH, ad_df=ad_df, output_dir=OUTPUT_DIR, db_name=AUDIT_DB["name"])
    run_direct_ad_check(idm_file_path=IDM_FILE_PATH, ad_df=ad_df, output_dir=OUTPUT_DIR, db_name=AUDIT_DB["name"])


    print(
        f"\nИнвентаризация выполнена"
    )


if __name__ == "__main__":
    main()
