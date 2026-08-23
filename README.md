# Инвентаризация доступов в DWH выданных через БД & IDM & AD

Скрипт помогает провести инвентаризацию доступов DWH автоматически. Скрипт оркеструет запросы к СУБД PostgreSQL и контроллерам домена Active Directory (LDAP), сопоставляет матрицы доступов и проверяет чистоту интеграции с системой IDM.

**Важное изменение:** Результаты проверок теперь сохраняются в таблицу базы данных PostgreSQL вместо CSV-файлов. Для каждой проверки создана отдельная таблица с тремя служебными полями: `created_at` (дата создания записи), `last_checked_at` (дата последней проверки) и `is_active` (актуальна ли ошибка).

---

## 📊 Таблица маппинга групп доступа

При запуске скрипт автоматически строит таблицу `audit_mapping_group`, которая связывает схемы баз данных с ролями PostgreSQL и AD-группами. Эта таблица используется проверками `check_orphan_grants` и `check_redundant` для определения корректности выдачи доступов.

### Структура таблицы `audit_mapping_group`:

| Колонка | Описание |
|---------|----------|
| `db_name` | Имя базы данных |
| `is_prod` | Признак продуктового контура (TRUE/FALSE) |
| `ad_layer` | Слой AD (EDW, ODS, CBD, ADB, DWHT EDW, DWHT ODS, ADBT) |
| `schema_name` | Имя схемы в БД |
| `schema_owner_role` | Роль-владелец схемы (например, `all_bcapp`) |
| `role_prefix_all` | Роль с полным доступом (например, `all_bcapp`) |
| `ad_group_all` | Соответствующая AD-группа All (если существует) |
| `role_prefix_owner` | Роль Owner (для ADB) |
| `ad_group_owner` | Соответствующая AD-группа Owner (если существует) |
| `role_prefix_write` | Роль Write (для ADB) |
| `ad_group_write` | Соответствующая AD-группа Write (если существует) |
| `role_prefix_read` | Роль Read (например, `read_bcapp`) |
| `ad_group_read` | Соответствующая AD-группа Read (если существует) |
| `created_at` | Дата создания записи |
| `last_updated_at` | Дата последнего обновления |
| `is_active` | Флаг актуальности записи |

### Логика построения маппинга:

1. **Извлечение префикса из владельца схемы:** Если владелец схемы `all_bcapp`, префикс = `bcapp`
2. **Поиск соответствующих ролей:** Для префикса `bcapp` ищем роли `read_bcapp`, `write_bcapp` (для ADB), `owner_bcapp` (для ADB), `all_bcapp`
3. **Проверка существования ролей в БД:** Подключаемся к каждой БД и проверяем наличие ролей
4. **Сопоставление с AD-группами:** На основе имен ролей формируем ожидаемые имена AD-групп и проверяем их существование

### Примеры имен AD-групп:

- **EDW/ODS/CBD Prod:** `EDW Read <schema>`, `EDW All <schema>`, `ODW Read <schema>`
- **EDW/ODS/CBD Test:** `DWHT EDW Read <schema>`, `DWHT ODS Read <schema>`
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