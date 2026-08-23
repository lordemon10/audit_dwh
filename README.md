# Инвентаризация доступов в DWH выданных через БД & IDM & AD

Скрипт помогает провести инвентаризацию доступов DWH автоматически. Скрипт оркеструет запросы к СУБД PostgreSQL и контроллерам домена Active Directory (LDAP), сопоставляет матрицы доступов и проверяет чистоту интеграции с системой IDM.
---

## 🔍 Описание проверок и структура отчетов
Все результаты работы сохраняются в корневую папку `audit_results/`. Подпапка для конкретного правила создается **только в том случае, если в ней обнаружены нарушения**. Если нарушений нет — папка остается чистой.

### 1. `check_nologin`
* **Суть:** Проверяет уволенных сотрудников. Если учетная запись пользователя заблокирована в Active Directory (`Enabled = False`), скрипт проверяет, чтобы у соответствующей роли в PostgreSQL было отключено право входа (`rolcanlogin = False`).
* **Результат:** Папка `audit_results/check_nologin/`. Генерация готовых команд блокировки вида: `ALTER ROLE имя_роли NOLOGIN;`.

### 2. `check_grant`
* **Суть:** Проворяет grant уволенных сотрудников. Скрипт проверяет остались ли grant'ы в PostgreSQL у заблокированных пользователей.
* **Результат:** Папка `audit_results/check_grant/`. Генерация готовых SQL-скриптов для очистки: `REVOKE [право] ON [схема].[таблица] FROM [роль];`.

### 3. `check_redundant`
* **Суть:** Находит пользователей, которым выдали прямой персональный грант на таблицу в базе данных, хотя они **уже имеют доступ** к этой схеме через ролевую модель AD.
* **Результат:** Папка `audit_results/3_redundant_grants/`. Генерация SQL-команд `REVOKE` для удаления дублирующих прав.

### 4. `check_idm_dups`
* **Суть:** Ищем сотрудников, у которых доступ к группе AD был выдан напрямую (`source == "Synchronization"`), но позже на этого же человека была назначена официальная бизнес-роль (`BR.*`), содержащая эту же группу. Выявляет логические задвоения.
* **Результат:** Папка `audit_results/check_idm_dups/`. CSV-отчет с подтянутыми из домена ФИО сотрудников для удобства анализа.

### 5. `check_direct_ad`
* **Суть:** Поиск AD групп выданных в обход IDM. Выгружает список сотрудников, у которых группа AD привязана напрямую ручными действиями администраторов домена (`source == "Synchronization"`), но при этом в IDM у пользователя  отсутствует бизнес-роль, дублирующая группу.
* **Результат:** Папка `audit_results/check_direct_ad/`. CSV-отчет с ФИО нарушителей и комментарием для проведения расследования.

---

## 📂 Что необходимо положить для работы скрипта

Для полноценного запуска утилиты в корневой папке /data/ должен обязательно находиться один внешний файл:

1. **`IDM.csv`** — актуальная выгрузка из базы данных IDM. Выгрузку необходимо запросить у администраторов IDM. Скрипт:

```sql
WITH user_role_group AS (
SELECT 
	a.SAMAccountName AS "user"
	, o.Ident_Org AS "role"
	, g.SAMAccountName AS "group"
FROM dbo.Person p
JOIN dbo.ADSAccount a
	ON a.UID_Person = p.UID_Person
	AND a.UID_ADSDomain = 'e7eab9fe-1479-4e94-9a4d-e0e0509de1b8'
JOIN dbo.PersonInOrg pio
	ON pio.UID_Person = p.UID_Person
JOIN dbo.Org o
	ON o.UID_Org = pio.UID_Org
JOIN dbo.OrgHasADSGroup oha
	ON oha.UID_Org = o.UID_Org
JOIN dbo.ADSGroup g
	ON g.UID_ADSGroup = oha.UID_ADSGroup
	AND g.UID_ADSDomain = 'e7eab9fe-1479-4e94-9a4d-e0e0509de1b8'
WHERE 1=1
	AND (

		 g.SAMAccountName LIKE 'EDW %'
		OR g.SAMAccountName LIKE 'ODS %'
		OR g.SAMAccountName LIKE 'DWHT %'
		OR g.SAMAccountName LIKE 'ADB %'
		OR g.SAMAccountName LIKE 'ADBT %'
		OR g.SAMAccountName LIKE 'CBD %'
		OR g.SAMAccountName LIKE 'ART %'
	)
), user_group AS (
SELECT 
	a.SAMAccountName AS "user"
	, g.SAMAccountName AS "group"
	, ag.XUserUpdated
FROM dbo.ADSGroup g
JOIN dbo.ADSAccountInADSGroup ag
	ON ag.UID_ADSGroup = g.UID_ADSGroup
JOIN dbo.ADSAccount a
	ON a.UID_ADSAccount = ag.UID_ADSAccount
	AND a.UID_ADSDomain = 'e7eab9fe-1479-4e94-9a4d-e0e0509de1b8'
WHERE 1=1
	AND g.UID_ADSDomain = 'e7eab9fe-1479-4e94-9a4d-e0e0509de1b8'
	AND (
         g.SAMAccountName LIKE 'EDW %'
		OR g.SAMAccountName LIKE 'ODS %'
		OR g.SAMAccountName LIKE 'DWHT %'
		OR g.SAMAccountName LIKE 'ADB %'
		OR g.SAMAccountName LIKE 'ADBT %'
		OR g.SAMAccountName LIKE 'CBD %'
		OR g.SAMAccountName LIKE 'ART %'
	)
)
SELECT 
	ug.[user]
	, ug.[group]
	, ug.XUserUpdated
	, string_agg(CASE 
		WHEN urg.[role] IS NULL THEN NULL ELSE urg.[role]
	END, ',')
FROM user_group ug
LEFT JOIN user_role_group urg
	ON urg."user" = ug."user"
	AND urg."group" = ug."group"
WHERE 1=1
	AND ug.[user] = 'YVVorobev'
GROUP BY ug.[user]
	, ug.[group]
	, ug.XUserUpdated
ORDER BY 1, 2
;
```

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
4. Настройте актуальные учетные данные доступов к вашим 4-м базам и контроллеру домена в файле `config.py` (пароли рекомендуется держать в безопасности).
5. Положите актуальный файл `IDM.csv` в корень.
6. Запустите комплексное сканирование:
   ```bash
   python main.py
   ```