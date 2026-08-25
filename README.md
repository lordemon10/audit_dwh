# Инвентаризация доступов в DWH выданных через БД & IDM & AD

Скрипт помогает провести инвентаризацию доступов DWH автоматически. Скрипт оркеструет запросы к СУБД PostgreSQL и контроллерам домена Active Directory (LDAP), сопоставляет матрицы доступов и проверяет чистоту интеграции с системой IDM.

**Важное изменение:** Результаты проверок теперь сохраняются в таблицу базы данных PostgreSQL вместо CSV-файлов. Для каждой проверки создана отдельная таблица с тремя служебными полями: `created_at` (дата создания записи), `last_checked_at` (дата последней проверки) и `is_active` (актуальна ли ошибка).

**Критическое изменение:** Таблица маппинга `audit_mapping` теперь заполняется ВРУЧНУЮ администратором. Автоматическое построение маппинга ОТКЛЮЧЕНО.

---

## 📊 Таблица ручного маппинга групп доступа

При запуске скрипт создает таблицу `audit_mapping`, которую необходимо заполнить ВРУЧНУЮ. Эта таблица связывает схемы баз данных с ролями PostgreSQL и AD-группами. Проверки `check_orphan_grants` и `check_redundant` используют эту таблицу для определения корректности выдачи доступов.

### Структура таблицы `audit_mapping`:

| Колонка | Описание |
|---------|----------|
| `db_name` | Имя базы данных (например, `ods_prod`, `edw_test2`) |
| `schemaname` | Имя схемы в БД (например, `ab`, `core`, `actuary`) |
| `owner_role` | Роль-владелец схемы (например, `all_cc`) - опционально |
| `owner_ad` | AD-группа Owner/All (например, `ODS All CC`) - опционально |
| `write_role` | Роль Write (для ADB) - опционально |
| `write_ad` | AD-группа Write (например, `ADB Write Schema`) - опционально |
| `read_role` | Роль Read (например, `read_cc`) - опционально |
| `read_ad` | AD-группа Read (например, `ODS Read CC`) - опционально |
| `created_at` | Дата создания записи |
| `last_updated_at` | Дата последнего обновления |
| `is_active` | Флаг актуальности записи |

### Как заполнить таблицу маппинга:

1. **Подключитесь к базе данных аудита** (указана в `config.py` как `AUDIT_DB`)

2. **Заполните таблицу примером SQL:**

```sql
INSERT INTO audit_mapping (db_name, schemaname, owner_role, owner_ad, write_role, write_ad, read_role, read_ad)
VALUES 
    -- ODS Prod
    ('ods_prod', 'ab', 'all_cc', 'ODS All CC', NULL, NULL, 'read_cc', 'ODS Read CC'),
    ('ods_prod', 'actuary', 'all_actuary', 'ODS All Actuary', NULL, NULL, 'read_actuary', 'ODS Read Actuary'),
    ('ods_prod', 'arctrl', 'all_arctrl', 'ODS All ARCtrl', NULL, NULL, 'read_arctrl', 'ODS Read ARCtrl'),
    ('ods_prod', 'audatex', 'all_audatex', 'ODS All Audatex', NULL, NULL, 'read_audatex', 'ODS Read Audatex'),
    ('ods_prod', 'auto', 'all_auto', 'ODS All Auto', NULL, NULL, 'read_auto', 'ODS Read Auto'),
    
    -- EDW Prod
    ('edw_prod', 'core', 'all_core', 'EDW All Core', NULL, NULL, 'read_core', 'EDW Read Core'),
    ('edw_prod', 'cdm_analysis', 'all_cdm_analysis', 'EDW All CDM Analysis', NULL, NULL, 'read_cdm_analysis', 'EDW Read CDM Analysis'),
    
    -- DWHT EDW Test (тестовые среды)
    ('edw_preprod', 'core', NULL, 'DWHT EDW Read Core', NULL, NULL, 'read_core', 'DWHT EDW Read Core'),
    ('eds_preprod', 'ab', NULL, 'DWHT ODS Read AB', NULL, NULL, 'read_ab', 'DWHT ODS Read AB'),
    
    -- ADB Prod
    ('adb_prod', 'schema1', 'all_schema1', 'ADB All Schema1', 'write_schema1', 'ADB Write Schema1', 'read_schema1', 'ADB Read Schema1')
ON CONFLICT (db_name, schemaname) DO UPDATE SET
    owner_role = EXCLUDED.owner_role,
    owner_ad = EXCLUDED.owner_ad,
    write_role = EXCLUDED.write_role,
    write_ad = EXCLUDED.write_ad,
    read_role = EXCLUDED.read_role,
    read_ad = EXCLUDED.read_ad,
    last_updated_at = CURRENT_TIMESTAMP;
```

3. **Важные правила заполнения:**
   - Если для схемы не заполнены AD-группы (`read_ad`, `write_ad`, `owner_ad`) - эта схема будет пропущена при проверках
   - Заполняйте только те группы, которые реально существуют в AD
   - Для тестовых сред (DWHT) указывайте полные имена групп например `DWHT EDW Read Core`
   - Для продуктовых сред указывайте например `EDW Read Core`, `ODS Read CC`

4. **Проверьте заполненность таблицы:**

```sql
SELECT db_name, schemaname, owner_ad, read_ad, write_ad 
FROM audit_mapping 
WHERE is_active = TRUE 
ORDER BY db_name, schemaname;
```

### Примеры имен AD-групп:

- **EDW/ODS/CBD Prod:** `EDW Read <schema>`, `EDW All <schema>`, `ODS Read <schema>`, `ODS All <schema>`
- **EDW/ODS/CBD Test (DWHT):** `DWHT EDW Read <schema>`, `DWHT ODS Read <schema>`
- **ADB Prod:** `ADB Read <schema>`, `ADB Write <schema>`, `ADB Owner <schema>`
- **ADBT Test:** `ADBT Read <schema>`, `ADBT Write <schema>`, `ADBT Owner <schema>`

---

## 🔍 Описание проверок и структура отчетов

Все результаты работы сохраняются в базу данных PostgreSQL (настраивается в `config.py` параметр `AUDIT_DB`). Под каждую проверку создана отдельная таблица:

### 1. `check_nologin`
* **Суть:** Проверяет уволенных сотрудников. Если учетная запись пользователя заблокирована в Active Directory (`Enabled = False`), скрипт проверяет, чтобы у соответствующей роли в PostgreSQL было отключено право входа (`rolcanlogin = False`).
* **Таблица:** `audit_check_nologin`
* **Колонки:** `id`, `rolname`, `Name`, `Enabled`, `rolcanlogin`, `nologin_sql`, `created_at`, `last_checked_at`, `is_active`
* **SQL для блокировки:** `ALTER ROLE имя_роли NOLOGIN;`

### 2. `check_grant`
* **Суть:** Проверяет grant уволенных сотрудников. Скрипт проверяет остались ли grant'ы в PostgreSQL у заблокированных пользователей.
* **Таблица:** `audit_check_grant`
* **Колонки:** `id`, `rolname`, `Name`, `table_name`, `privilege_type`, `revoke_sql`, `created_at`, `last_checked_at`, `is_active`
* **SQL для очистки:** `REVOKE [право] ON [схема].[таблица] FROM [роль];`

### 3. `check_redundant`
* **Суть:** Находит пользователей, которым выдали прямой персональный грант на таблицу в базе данных, хотя они **уже имеют доступ** к этой схеме через ролевую модель AD.
* **Таблица:** `audit_check_redundant`
* **Колонки:** `id`, `db_name`, `rolname`, `Name`, `table_schema`, `table_name`, `privilege_type`, `duplicate_ad_group`, `revoke_sql`, `created_at`, `last_checked_at`, `is_active`
* **SQL для удаления:** `REVOKE [право] ON [схема].[таблица] FROM [роль];`

### 4. `check_idm_dups`
* **Суть:** Ищем сотрудников, у которых доступ к группе AD был выдан напрямую (`source == "Synchronization"`), но позже на этого же человека была назначена официальная бизнес-роль (`BR.*`), содержащая эту же группу. Выявляет логические задвоения.
* **Таблица:** `audit_check_idm_dups`
* **Колонки:** `id`, `login`, `Name`, `group_name`, `source`, `business_role`, `comment`, `created_at`, `last_checked_at`, `is_active`

### 5. `check_direct_ad`
* **Суть:** Поиск AD групп выданных в обход IDM. Выгружает список сотрудников, у которых группа AD привязана напрямую ручными действиями администраторов домена (`source == "Synchronization"`), но при этом в IDM у пользователя отсутствует бизнес-роль, дублирующая группу.
* **Таблица:** `audit_check_direct_ad`
* **Колонки:** `id`, `login`, `Name`, `group_name`, `source`, `business_role`, `comment`, `created_at`, `last_checked_at`, `is_active`

---

## 📂 Что необходимо положить для работы скрипта

Для полноценного запуска утилиты в корневой папке /data/ должен обязательно находиться один внешний файл:

1. **`IDM.csv`** — актуальная выгрузка из базы данных IDM. Выгрузку необходимо запросить у администраторов IDM.

---

## 🛠️ Быстрый старт

1. Склонируйте репозиторий на рабочую машину.
2. Убедитесь, что активировано виртуальное окружение:
   ```bash
   .\venv\Scripts\activate
   ```
3. Установите все необходимые зависимости из зафиксированного списка:
   ```bash
   pip install -r requirements.txt
   ```
4. Настройте актуальные учетные данные доступов к вашим 4-м базам и контроллеру домена в файле `config.py`. Также настройте параметр `AUDIT_DB` для подключения к базе данных, где будут храниться результаты аудита.
5. Положите актуальный файл `IDM.csv` в корень.
6. Запустите комплексное сканирование:
   ```bash
   python main.py
   ```

При первом запуске скрипт автоматически создаст таблицы для хранения результатов проверок в базе данных `AUDIT_DB`.

---

## 📊 Логика работы с нарушениями

Для каждой проверки реализована следующая логика:

- **Новое нарушение:** Создается запись с `created_at = CURRENT_TIMESTAMP`, `last_checked_at = CURRENT_TIMESTAMP`, `is_active = TRUE`.
- **Нарушение подтвердилось:** Обновляется `last_checked_at = CURRENT_TIMESTAMP`, `is_active = TRUE`.
- **Нарушение устранено:** Обновляется `last_checked_at = CURRENT_TIMESTAMP`, `is_active = FALSE`.

Таким образом, в таблицах всегда сохраняется полная история нарушений, а поле `is_active` позволяет отфильтровать только актуальные проблемы.

---

## 🔍 Примеры SQL-запросов для анализа результатов

### Получить все активные нарушения по проверке nologin:
```sql
SELECT * FROM audit_check_nologin WHERE is_active = TRUE;
```

### Получить историю нарушений для конкретного пользователя:
```sql
SELECT * FROM audit_check_grant 
WHERE rolname = 'username' 
ORDER BY created_at DESC;
```

### Получить статистику по всем проверкам:
```sql
SELECT 
    'check_nologin' as check_type,
    COUNT(*) as total_violations,
    SUM(CASE WHEN is_active THEN 1 ELSE 0 END) as active_violations
FROM audit_check_nologin
UNION ALL
SELECT 
    'check_grant' as check_type,
    COUNT(*) as total_violations,
    SUM(CASE WHEN is_active THEN 1 ELSE 0 END) as active_violations
FROM audit_check_grant
UNION ALL
SELECT 
    'check_redundant' as check_type,
    COUNT(*) as total_violations,
    SUM(CASE WHEN is_active THEN 1 ELSE 0 END) as active_violations
FROM audit_check_redundant
UNION ALL
SELECT 
    'check_idm_dups' as check_type,
    COUNT(*) as total_violations,
    SUM(CASE WHEN is_active THEN 1 ELSE 0 END) as active_violations
FROM audit_check_idm_dups
UNION ALL
SELECT 
    'check_direct_ad' as check_type,
    COUNT(*) as total_violations,
    SUM(CASE WHEN is_active THEN 1 ELSE 0 END) as active_violations
FROM audit_check_direct_ad;
```