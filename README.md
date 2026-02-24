# Selenium Security Testing Framework

A comprehensive **Java-based security testing framework** using
**Selenium WebDriver** to automate **OWASP Top 10** vulnerability
testing.

------------------------------------------------------------------------

## 🚀 Features

-   **SQL Injection Testing** -- Tests login forms and input fields for
    SQL injection vulnerabilities.
-   **XSS Testing** -- Cross-Site Scripting vulnerability detection.
-   **Authentication Testing** -- Tests for authentication bypass and
    broken access control.
-   **Session Management Testing** -- Session fixation, timeout, and
    cookie security tests.
-   **Sensitive Data Exposure Testing** -- HTTPS enforcement, password
    masking, etc.
-   **CSRF Testing** -- Cross-Site Request Forgery token validation.
-   **OWASP ZAP Integration** -- Optional integration with OWASP ZAP
    proxy for deeper scanning

------------------------------------------------------------------------

## 📁 Project Structure

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
    │   └── test/resources/
    │       ├── config.properties
    │       ├── log4j2.xml
    │       └── payloads/
    │           ├── sql_injection_payloads.txt
    │           └── xss_payloads.txt
    │── testng.xml

------------------------------------------------------------------------

## 📋 Prerequisites

-   Java 17 or higher
-   Maven 3.6+
-   Chrome or Firefox browser
-   (Optional) OWASP ZAP for proxy-based testing

------------------------------------------------------------------------

## ⚙️ Setup

### 1️⃣ Clone or Copy the Project

``` bash
git clone <repository-url>
```

### 2️⃣ Configure Target Application

Edit:

    src/test/resources/config.properties

``` properties
base.url=https://your-target-app.com
browser=chrome
headless=false
```

### 3️⃣ Install Dependencies

``` bash
mvn clean install -DskipTests
```

------------------------------------------------------------------------

## ▶️ Running Tests

### Run All Security Tests

``` bash
mvn test
```

### Run Specific Test Class

``` bash
mvn test -Dtest=SqlInjectionTest
mvn test -Dtest=XssTest
mvn test -Dtest=AuthenticationTest
```

### Run with Specific Browser

``` bash
mvn test -Dbrowser=firefox
```

### Run in Headless Mode

``` bash
mvn test -Dheadless=true
```

------------------------------------------------------------------------

## 🧪 Test Categories

### 1️⃣ SQL Injection Tests

-   Login form injection
-   Search field injection
-   URL parameter injection
-   Error-based injection detection

### 2️⃣ XSS Tests

-   Reflected XSS
-   Stored XSS
-   DOM-based XSS
-   Input sanitization verification

### 3️⃣ Authentication Tests

-   Direct URL access without login
-   Session token validation
-   Password policy enforcement
-   Account lockout testing

### 4️⃣ Session Management Tests

-   Session ID regeneration after login
-   Session timeout verification
-   Cookie security flags (HttpOnly, Secure)
-   Concurrent session handling

### 5️⃣ Sensitive Data Exposure Tests

-   HTTPS enforcement
-   Password field masking
-   Sensitive data in URL parameters
-   Autocomplete disabled for sensitive fields

### 6️⃣ CSRF Tests

-   CSRF token presence
-   Token validation on form submission

------------------------------------------------------------------------

## 🔐 OWASP ZAP Integration

### 1️⃣ Start OWASP ZAP in Daemon Mode

``` bash
zap.sh -daemon -port 8080
```

### 2️⃣ Enable ZAP in `config.properties`

``` properties
zap.enabled=true
zap.host=localhost
zap.port=8080
```

### 3️⃣ Run Tests

Traffic will be proxied through ZAP for additional scanning.

------------------------------------------------------------------------

## 📊 Reports

Test reports are generated in:

-   **ExtentReports**:\
    `test-output/SecurityTestReport.html`

-   **TestNG Reports**:\
    `target/surefire-reports/`

------------------------------------------------------------------------

## 🔧 Customization

### ➕ Adding Custom Payloads

Add payloads to:

    src/test/resources/payloads/

-   `sql_injection_payloads.txt`\
-   `xss_payloads.txt`

### ➕ Adding New Tests

1.  Create a new test class extending `BaseTest`\
2.  Use the `@Test` annotation with appropriate groups\
3.  Add it to `testng.xml` if required

------------------------------------------------------------------------

## ⚠️ Security Considerations

-   Only test applications you have permission to test\
-   Use in controlled environments (dev/staging)\
-   Never test production systems without explicit authorization\
-   Review and comply with your organization's security testing policies

------------------------------------------------------------------------

🚀 Built for DevSecOps & Security Automation Excellence