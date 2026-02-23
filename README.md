Selenium Security Testing Framework

A comprehensive Java-based security testing framework using Selenium WebDriver to automate OWASP Top 10 vulnerability testing.

##Features

- **SQL Injection Testing** - Tests login forms and input fields for SQL injection vulnerabilities
- **XSS Testing** - Cross-Site Scripting vulnerability detection
- **Authentication Testing** - Tests for authentication bypass and broken access control
- **Session Management Testing** - Session fixation, timeout, and cookie security tests
- **Sensitive Data Exposure Testing** - HTTPS enforcement, password masking, etc.
- **CSRF Testing** - Cross-Site Request Forgery token validation
- **OWASP ZAP Integration** - Optional integration with OWASP ZAP proxy for deeper scanning

##Project Structure
~~~
SecurityTestFramework/
│── pom.xml
│── README.md
│── src/
│   ├── main/java/com/security/
│   │   ├── config/
│   │   │   └── ConfigReader.java
│   │   ├── pages/
│   │   │   ├── BasePage.java
│   │   │   └── LoginPage.java
│   │   ├── utils/
│   │   │   ├── DriverFactory.java
│   │   │   ├── SecurityPayloads.java
│   │   │   ├── ReportManager.java
│   │   │   └── ZapIntegration.java
│   ├── test/java/com/security/tests/
│   │   ├── BaseTest.java
│   │   ├── SqlInjectionTest.java
│   │   ├── XssTest.java
│   │   ├── AuthenticationTest.java
│   │   ├── SessionManagementTest.java
│   │   ├── SensitiveDataExposureTest.java
│   │   └── CsrfTest.java
│   ├── src/test/resources/
│   │   ├── config.properties
│   │   ├── log4j2.xml
│   │   ├── payloads/
│   │   │   ├── sql_injection_payloads.txt
│   │   │   └── xss_payloads.txt
│── testng.xml



