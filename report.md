## 1. Asset Inventory

| Актив                          | Тип            | Ценность    | Описание                                               |
 |--------------------------------|----------------|-------------|--------------------------------------------------------|
| Данные пользователей           | Данные         | Высокая     | Возможна утечка персональных данных и эксплуатация XSS |
| Данные пользовательских сессий | Данные         | Высокая     | Раскрывают поведенческие паттерны пользователей        |
| Файловая система сервера       | Инфраструктура | Критическая | Подвержена атаке Path Traversal                        |
| Внутренние сетевые ресурсы     | Инфраструктура | Критическая | Могут быть скомпрометированы через SSRF                |
| REST API                       | Приложение     | Высокая     | Основная точка взаимодействия с системой               |
| Логи приложения                | Данные         | Средняя     | Могут содержать чувствительную информацию              |

---

## 2. Threat Modeling (STRIDE)

| Категория              | Применимость | Поверхность атаки                          | Потенциальный ущерб             |
|------------------------|--------------|--------------------------------------------|---------------------------------|
| Spoofing               | Да           | Все эндпоинты                              | Подмена пользователей           |
| Tampering              | Да           | `/register`, `/recordSession`              | Изменение аналитических данных  |
| Repudiation            | Да           | Отсутствие логирования                     | Невозможность доказать действия |
| Information Disclosure | Да           | `/userProfile`, `/exportReport`, `/notify` | Утечка конфиденциальных данных  |
| Denial of Service      | Да           | Все эндпоинты                              | Перегрузка сервера              |
| Elevation of Privilege | Да           | `/notify`, `/exportReport`                 | Доступ к внутренним ресурсам    |

---

## 3. Найденные уязвимости

### Finding 1: Stored Cross-Site Scripting (XSS)

| Параметр    | Значение                                         |
|-------------|--------------------------------------------------|
| Компонент   | `/userProfile`                                   |
| CWE         | CWE-79                                           |
| CVSS        | 6.1 MEDIUM (AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N) |
| Критичность | Medium                                           |
| Статус      | Confirmed                                        |

**Описание:**

Имя пользователя (`userName`) сохраняется в системе и затем отображается в HTML-ответе эндпоинта `/userProfile` без
экранирования. Это позволяет злоумышленнику внедрить вредоносный JavaScript-код, который будет выполняться в браузере
других пользователей. Проблема возникает из-за отсутствия HTML-экранирования пользовательского ввода.

**Шаги воспроизведения:**

1. Зарегистрировать пользователя с вредоносным именем:
   ```
   curl -X POST "http://localhost:7000/register?userId=xss&userName=<script>alert(1)</script>"
   ```
2. Открыть профиль пользователя:
   ```
   curl "http://localhost:7000/userProfile?userId=xss"
   ```
3. Ожидаемый результат: HTML-теги экранированы, скрипт не выполняется.
   Фактический результат: в ответе присутствует тег `<script>`, который выполняется в браузере.

**Влияние:**

Атакующий может:

* Выполнять JavaScript-код в браузере жертвы.
* Похищать cookies и токены сессий.
* Выполнять действия от имени пользователя.
* Проводить фишинговые атаки.

**Рекомендации по исправлению:**

Экранировать пользовательский ввод перед выводом в HTML.

**Security Test Case:**

```java

@Test
@DisplayName("[SECURITY] Stored XSS should be sanitized")
void storedXssShouldBeSanitized() {
    String malicious = "<script>alert(1)</script>";

    Unirest.post("http://localhost:7000/register")
            .queryString("userId", "xss")
            .queryString("userName", malicious)
            .asString();

    HttpResponse<String> response = Unirest.get("http://localhost:7000/userProfile")
            .queryString("userId", "xss")
            .asString();

    assertEquals(200, response.getStatus());
    assertFalse(response.getBody().contains("<script>"));
}
```

### Finding 2: Path Traversal

| Параметр    | Значение                                           |
|-------------|----------------------------------------------------|
| Компонент   | `/exportReport`                                    |
| CWE         | CWE-22                                             |
| CVSS        | 9.1 CRITICAL (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N) |
| Критичность | High                                               |
| Статус      | Confirmed                                          |

**Описание:**

Эндпоинт /exportReport использует параметр `filename` для создания файла без проверки пути. Злоумышленник может
использовать последовательности ../ для выхода за пределы разрешённой директории и записи или перезаписи произвольных
файлов на сервере.

**Шаги воспроизведения:**

1. Отправить запрос с вредоносным именем файла:
   ```
   curl "http://localhost:7000/exportReport?userId=test&filename=../../../../tmp/pwned.txt"
   ```
2. Проверить наличие созданного файла вне директории reports.
3. Ожидаемый результат: запрос отклонён с ошибкой 400.
   Фактический результат: файл создаётся за пределами разрешённой директории.

**Влияние:**

Атакующий может:

* Записывать или перезаписывать системные файлы.
* Размещать вредоносные скрипты.
* Получать доступ к конфиденциальной информации.
* Потенциально добиться удалённого выполнения кода.

**Рекомендации по исправлению:**

Нормализовать путь и проверить его принадлежность базовой директории.

**Security Test Case:**

```java

@Test
@DisplayName("[SECURITY] Path traversal should be prevented")
void pathTraversalShouldBePrevented() {
    String maliciousFilename = "../../etc/passwd";

    HttpResponse<String> response = Unirest.get("http://localhost:7000/exportReport")
            .queryString("userId", "test")
            .queryString("filename", maliciousFilename)
            .asString();

    assertEquals(400, response.getStatus());
}
```

### Finding 3: Server-Side Request Forgery (SSRF)

| Параметр    | Значение                                           |
|-------------|----------------------------------------------------|
| Компонент   | `/notify`                                          |
| CWE         | CWE-918                                            |
| CVSS        | 9.1 CRITICAL (AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N) |
| Критичность | Critical                                           |
| Статус      | Confirmed                                          |

**Описание:**

Эндпоинт `/notify` принимает параметр `callbackUrl` и выполняет HTTP-запрос к указанному адресу без проверки. Это
позволяет злоумышленнику инициировать запросы к внутренним сервисам или метаданным облачной инфраструктуры.

**Шаги воспроизведения:**

1. Отправить запрос к внутреннему ресурсу:
   ```
   curl -X POST "http://localhost:7000/notify?userId=test&callbackUrl=http://169.254.169.254/latest/meta-data/"
   ```
2. Проанализировать ответ сервера.
3. Ожидаемый результат: Запрос отклонён с ошибкой 400.
   Фактический результат: Сервер выполняет запрос к внутреннему ресурсу.

**Влияние:**

Атакующий может:

* Получать доступ к внутренним сервисам.
* Извлекать метаданные облачной инфраструктуры.
* Обходить сетевые ограничения.
* Использовать сервер для сканирования внутренней сети.

**Рекомендации по исправлению:**

Разрешить только HTTPS-запросы и использовать белый список доменов.

**Security Test Case:**

```java

@Test
@DisplayName("[SECURITY] SSRF should be blocked")
void ssrfShouldBeBlocked() {
    String maliciousUrl = "http://127.0.0.1:8080";

    HttpResponse<String> response = Unirest.post("http://localhost:7000/notify")
            .queryString("userId", "test")
            .queryString("callbackUrl", maliciousUrl)
            .asString();

    assertEquals(400, response.getStatus());
}
```

### Finding 4: Missing Authentication and Authorization

| Параметр    | Значение                                           |
|-------------|----------------------------------------------------|
| Компонент   | Все эндпоинты                                      |
| CWE         | CWE-306                                            |
| CVSS        | 9.1 CRITICAL (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N) |
| Критичность | High                                               |
| Статус      | Confirmed                                          |

**Описание:**

Все эндпоинты API доступны без аутентификации и авторизации. Любой пользователь может выполнять операции от имени
другого, передавая произвольный `userId`. Это приводит к нарушению конфиденциальности и целостности данных.

**Шаги воспроизведения:**

1. Зарегистрировать пользователя:
   ```
   curl -X POST "http://localhost:7000/register?userId=user1&userName=User1"
   ```
2. Получить данные другого пользователя без аутентификации:
   ```
   curl "http://localhost:7000/userProfile?userId=user1"
   ```
3. Ожидаемый результат: Доступ запрещён (401/403) без аутентификации.
   Фактический результат: Данные пользователя возвращаются без каких-либо проверок.

**Влияние:**

Атакующий может:

* Получать доступ к данным других пользователей.
* Изменять или удалять данные.
* Выполнять действия от имени жертвы.
* Компрометировать всю систему.

**Рекомендации по исправлению:**

Внедрить аутентификацию.

**Security Test Case:**

```java

@Test
@DisplayName("[SECURITY] Access should require authentication")
void accessShouldRequireAuthentication() {
    HttpResponse<String> response = Unirest.get("http://localhost:7000/userProfile")
            .queryString("userId", "user1")
            .asString();

    assertEquals(401, response.getStatus());
}
```

### Finding 5: Insecure Direct Object Reference (IDOR)

| Параметр    | Значение                                       |
|-------------|------------------------------------------------|
| Компонент   | Все эндпоинты                                  |
| CWE         | CWE-639                                        |
| CVSS        | 8.1 HIGH (AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N) |
| Критичность | High                                           |
| Статус      | Confirmed                                      |

**Описание:**

Даже при наличии аутентификации, отсутствие проверки соответствия `userId` аутентифицированному пользователю позволяет
получать доступ к данным других пользователей. Это классическая уязвимость IDOR.

**Шаги воспроизведения:**

1. Получить JWT-токен для пользователя `user1`.
2. Выполнить запрос к данным пользователя `user2`:
   ```
   curl -H "Authorization: Bearer <token_user1>" \
     "http://localhost:7000/userProfile?userId=user2"
   ```
3. Ожидаемый результат: Ответ 403 Forbidden.
   Фактический результат: Возвращаются данные пользователя `user2`.

**Влияние:**

Атакующий может:

* Получать конфиденциальные данные других пользователей.
* Нарушать целостность и конфиденциальность системы.
* Выполнять действия от имени других пользователей.

**Рекомендации по исправлению:**

Проверять, что `userId` из токена совпадает с `userId` в запросе:

**Security Test Case:**

```java
@Test
@DisplayName("[SECURITY] IDOR should be prevented")
void idorShouldBePrevented() {
    String tokenUser1 = "validTokenForUser1";

    HttpResponse<String> response = Unirest.get("http://localhost:7000/userProfile")
            .header("Authorization", "Bearer " + tokenUser1)
            .queryString("userId", "user2")
            .asString();

    assertEquals(403, response.getStatus());
}
```
