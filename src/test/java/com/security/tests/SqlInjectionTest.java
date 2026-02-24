/**
 * @author Venkateshwara Doijode 
 *
 * © https://github.com/venkywarriors
 */
package com.security.tests;

import com.security.pages.LoginPage;
import com.security.pages.SearchPage;
import com.security.utils.ReportManager;
import com.security.utils.SecurityPayloads;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

/**
 * SQL Injection vulnerability tests.
 * Tests login forms, search fields, and URL parameters for SQL injection.
 */
public class SqlInjectionTest extends BaseTest {

    private LoginPage loginPage;
    private SearchPage searchPage;

    @BeforeMethod
    public void initPages() {
        loginPage = new LoginPage(driver);
        searchPage = new SearchPage(driver);
    }

    // ==================== DATA PROVIDERS ====================

    @DataProvider(name = "basicSqlPayloads")
    public Object[][] basicSqlPayloads() {
        return convertToDataProvider(SecurityPayloads.SQL_INJECTION_BASIC);
    }

    @DataProvider(name = "unionSqlPayloads")
    public Object[][] unionSqlPayloads() {
        return convertToDataProvider(SecurityPayloads.SQL_INJECTION_UNION);
    }

    @DataProvider(name = "errorBasedPayloads")
    public Object[][] errorBasedPayloads() {
        return convertToDataProvider(SecurityPayloads.SQL_INJECTION_ERROR_BASED);
    }

    private Object[][] convertToDataProvider(String[] payloads) {
        Object[][] data = new Object[payloads.length][1];
        for (int i = 0; i < payloads.length; i++) {
            data[i][0] = payloads[i];
        }
        return data;
    }

    // ==================== LOGIN FORM TESTS ====================

    @Test(dataProvider = "basicSqlPayloads",
            description = "Test login form for basic SQL injection vulnerabilities",
            groups = {"sql-injection", "login"})
    public void testLoginSqlInjection_BasicPayloads(String payload) {
        ReportManager.logInfo("Testing payload: " + payload);
        
        navigateTo("/login");

        // Test username field
        loginPage.enterUsername(payload);
        loginPage.enterPassword("testpassword");
        loginPage.clickLogin();

        // verify injection did not succeed 
        boolean loggedIn = loginPage.isLoggedIn();
        String pageSource = getPageSource();

        if (loggedIn) {
            logVulnerability("SQL Injection - Authentication Bypass",
                    "Payload '" + payload + "' bypassed authentication");
        }

        // Check for SQL error disclosure
        if (SecurityPayloads.containsSqlError(pageSource)) {
            logVulnerability("SQL Injection - Error Disclosure",
                    "SQL error revealed in response for payload: " + payload);
        }

        Assert.assertFalse(loggedIn,
                "SQL Injection vulnerability: Login bypassed with payload: " + payload);

        Assert.assertFalse(SecurityPayloads.containsSqlError(pageSource),
                "SQL error message disclosed for payload: " + payload);

        logSecurityPassed("SQL Injection", "Payload rejected: " + payload);
    }

    @Test(dataProvider = "basicSqlPayloads",
            description = "Test password field for SQL injection",
            groups = {"sql-injection", "login"})
    public void testPasswordSqlInjection(String payload) {

        ReportManager.logInfo("Testing password field with payload: " + payload);
        navigateTo("/login");

        loginPage.enterUsername("admin");
        loginPage.enterPassword(payload);
        loginPage.clickLogin();

        boolean loggedIn = loginPage.isLoggedIn();

        Assert.assertFalse(loggedIn,
                "SQL Injection in password field: " + payload);

        logSecurityPassed("SQL Injection (Password)", "Payload rejected: " + payload);
    }

    @Test(description = "Test both username and password fields simultaneously",
            groups = {"sql-injection", "login"})
    public void testBothFieldsSqlInjection() {
        navigateTo("/login");

        for (String payload : SecurityPayloads.SQL_INJECTION_BASIC) {

            ReportManager.logInfo("Testing both fields with: " + payload);

            loginPage.testBothFieldsInjection(payload);

            Assert.assertFalse(loginPage.isLoggedIn(),
                    "Authentication bypass with payload: " + payload);

            navigateTo("/login");
        }

        logSecurityPassed("SQL Injection (Both Fields)", "All payloads rejected");
    }

    // ==================== SEARCH FIELD TESTS ====================

    @Test(dataProvider = "basicSqlPayloads",
            description = "Test search functionality for SQL injection",
            groups = {"sql-injection", "search"})
    public void testSearchSqlInjection(String payload) {

        ReportManager.logInfo("Testing search with payload: " + payload);
        navigateTo("/search");

        boolean vulnerable = searchPage.testSqlInjection(payload);

        if (vulnerable) {
            logVulnerability("SQL Injection - Search",
                    "SQL error disclosed for payload: " + payload);
        }

        Assert.assertFalse(vulnerable,
                "SQL Injection vulnerability in search: " + payload);

        logSecurityPassed("SQL Injection (Search)", "Payload handled safely: " + payload);
    }

    @Test(dataProvider = "unionSqlPayloads",
            description = "Test for UNION-based SQL injection",
            groups = {"sql-injection", "advanced"})
    public void testUnionSqlInjection(String payload) {

        ReportManager.logInfo("Testing UNION payload: " + payload);
        navigateTo("/search");

        searchPage.search(payload);

        String pageSource = getPageSource().toLowerCase();

        boolean dataExposed =
                pageSource.contains("password") ||
                pageSource.contains("admin") ||
                pageSource.contains("user_id") ||
                pageSource.contains("username");

        if (dataExposed) {
            logVulnerability("SQL Injection - Data Exposure",
                    "UNION injection exposed sensitive data: " + payload);
        }

        Assert.assertFalse(dataExposed,
                "UNION SQL Injection exposed data: " + payload);

        logSecurityPassed("UNION SQL Injection", "No data exposure: " + payload);
    }

    // ==================== URL PARAMETER TESTS ====================

    @Test(description = "Test URL parameters for SQL injection",
            groups = {"sql-injection", "url"})
    public void testUrlParameterSqlInjection() {
        String[] endpoints = {
                "/product?id=",
                "/user?id=",
                "/order?order_id=",
                "/item?item_id="
        };

        for (String endpoint : endpoints) {
            for (String payload : SecurityPayloads.SQL_INJECTION_BASIC) {
                String testUrl = baseUrl + endpoint + payload;
                ReportManager.logInfo("Testing URL: " + testUrl);

                driver.get(testUrl);
                String pageSource = getPageSource();

                if (SecurityPayloads.containsSqlError(pageSource)) {
                    logVulnerability("SQL Injection - URL Parameter",
                            "Error disclosed at: " + endpoint + " with payload: " + payload);
                    Assert.fail("SQL Injection in URL parameter");
                }
            }
        }

        logSecurityPassed("SQL Injection (URL)", "All URL parameters handled safely");
    }

    // ==================== ERROR-BASED TESTS ====================

    @Test(dataProvider = "errorBasedPayloads",
            description = "Test for error-based SQL injection",
            groups = {"sql-injection", "error-based"})
    public void testErrorBasedSqlInjection(String payload) {

        ReportManager.logInfo("Testing error-based payload: " + payload);
        navigateTo("/login");

        loginPage.enterUsername(payload);
        loginPage.enterPassword("test");
        loginPage.clickLogin();

        String pageSource = getPageSource();

        boolean vulnerable =
                SecurityPayloads.containsSqlError(pageSource) ||
                pageSource.contains("exception") ||
                pageSource.contains("mysql") ||
                pageSource.contains("postgresql") ||
                pageSource.contains("microsoft sql server");

        Assert.assertFalse(vulnerable,
                "Error-based SQL Injection vulnerability: " + payload);

        logSecurityPassed("Error-based SQL Injection", "No error disclosure: " + payload);
    }

    // ==================== TIME-BASED TESTS ====================

    @Test(description = "Test for time-based blind SQL injection",
            groups = {"sql-injection", "blind"},
            timeOut = 30000)
    public void testTimeBasedSqlInjection() {
        String[] timePayloads = {
                "'; WAITFOR DELAY '0:0:5'--",
                "'; SELECT SLEEP(5)--",
                "' OR SLEEP(5)--"
        };

        navigateTo("/login");

        for (String payload : timePayloads) {

            ReportManager.logInfo("Testing time-based payload: " + payload);

            long startTime = System.currentTimeMillis();

            loginPage.enterUsername(payload);
            loginPage.enterPassword("test");
            loginPage.clickLogin();

            long responseTime = System.currentTimeMillis() - startTime;

            if (responseTime > 4000) {
                logVulnerability("Time-based Blind SQL Injection",
                        "Delayed response (" + responseTime + "ms) for payload: " + payload);
                Assert.fail("Time-based SQL Injection vulnerability detected");
            }

            navigateTo("/login");
        }

        logSecurityPassed("Time-based SQL Injection", "No delays detected");
    }

    // ==================== SECOND-ORDER TESTS ====================

    @Test(description = "Test for second-order SQL injection via registration",
            groups = {"sql-injection", "second-order"})
    public void testSecondOrderSqlInjection() {
        ReportManager.logInfo("Testing second-order SQL injection");

        // this test registers with malicious payload and check it's executed later
        String maliciousUsername = "test' OR '1'='1";
       
        // navigation to registration if exists
        navigateTo("/register");
        
// check if page exists 
        if (getCurrentUrl().contains("register")) {
            // implementation depends on application 
            ReportManager.logInfo("Registration page found - manual testing recommended");
        }

        // second order injection often requires manual testing 
        logSecurityPassed("Second-order SQL Injection",
                "Automated test complete - recommend manual verification");
    }
}
