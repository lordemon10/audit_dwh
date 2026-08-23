import os
import pandas as pd
from config import AD_CONFIG
from ldap3 import ALL, Connection, Server


def get_ad_users():
    """Выгружает ВСЕХ пользователей из Active Directory и собирает их доступы.

    Гарантирует сохранение заблокированных учетных записей без групп для корректной работы nologin.
    """
    server = Server(AD_CONFIG["server"], get_info=ALL)
    # Добавлен префикс 'dwht ' для универсальных групп тестовых сред EDW/ODS/CBD
    target_prefixes = ("adb ", "cbd ", "dwht ", "adbt ", "edw ", "ods ")

    try:
        with Connection(
            server, user=AD_CONFIG["user"], password=AD_CONFIG["password"]
        ) as conn:
            if not conn.bind():
                print("Не удалось авторизоваться в Active Directory.")
                return None

            search_filter = "(&(objectCategory=person)(objectClass=user))"
            attributes = [
                "sAMAccountName",
                "displayName",
                "userAccountControl",
                "memberOf",
            ]

            print("Выгружаем данные из Active Directory...")
            paged_results = conn.extend.standard.paged_search(
                search_base=AD_CONFIG["domain"],
                search_filter=search_filter,
                attributes=attributes,
                paged_size=1000,
                generator=False,
            )

            ad_data = []

            for entry in paged_results:
                if entry.get("type") != "searchResEntry":
                    continue

                attrs = entry.get("attributes", {})
                sam = attrs.get("sAMAccountName")
                display_name = attrs.get("displayName")
                uac = attrs.get("userAccountControl")
                member_of = attrs.get("memberOf", [])

                if not sam:
                    continue

                is_enabled = True if uac is None else not bool(uac & 0x02)

                if isinstance(member_of, str):
                    member_of = [member_of]

                user_accesses = []

                for group_dn in member_of:
                    parts_dn = group_dn.split(",")
                    if not parts_dn:
                        continue

                    raw_cn = parts_dn[0]
                    if not raw_cn.lower().startswith("cn="):
                        continue
                    original_group_name = raw_cn[3:]

                    group_name_lower = original_group_name.lower().strip()

                    if group_name_lower.startswith(target_prefixes):
                        parts = group_name_lower.split()
                        if len(parts) < 3:
                            continue

                        layer = parts[0].upper()
                        privilege = parts[1].lower()
                        schema_target = "_".join(parts[2:])

                        user_accesses.append(
                            {
                                "original_name": original_group_name,
                                "group_layer": layer,
                                "group_privilege": privilege,
                                "group_schema": schema_target,
                            }
                        )

                # 🔥 ИСПРАВЛЕНИЕ: Мы БОЛЬШЕ НЕ пропускаем пользователей без ИТ-групп!
                # Мы сохраняем ВСЕХ (особенно заблокированных для проверки nologin)
                ad_data.append(
                    {
                        "sam_clean": str(sam).strip().lower(),
                        "Name": str(display_name) if display_name else "Нет имени",
                        "Enabled": is_enabled,
                        "accesses": user_accesses,  # Для пользователей без групп тут будет просто пустой список []
                    }
                )

            df = pd.DataFrame(ad_data)
            if not df.empty:
                df = df.drop_duplicates(subset=["sam_clean"])
                print(f"Успешно загружено пользователей из AD: {len(df)}")

            return df

    except Exception as e:
        print(f"Ошибка при работе с Active Directory (ldap3): {e}")
        return None
