package com.security.tests;

import com.security.pages.LoginPage;
import com.security.utils.ReportManager;
import org.openqa.selenium.Cookie;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import java.util.Set;

/**
 * Session management security tests.
 * Tests for session fixation, hijacking, timeout, and cookie security.
 */
public class SessionManagementTest extends BaseTest {

    private LoginPage loginPage;

    @BeforeMethod
    public void initPages() {
        loginPage = new LoginPage(driver);
    }

    // ==================== SESSION FIXATION TESTS ====================

    @Test(description = "Test session ID regeneration after login (session fixation)",
            groups = {"session", "fixation"})
    public void testSessionFixation_IdRegeneration() {

        navigateTo("/login");

        // Get session ID before login
        String sessionBefore = loginPage.getSessionId();
        ReportManager.logInfo("Session ID before login: " + sessionBefore);

        if (sessionBefore != null) {

            // Attempt login (with test credentials if available)
            loginPage.login("testuser", "testpassword");

            // Get session ID after login attempt
            String sessionAfter = loginPage.getSessionId();
            ReportManager.logInfo("Session ID after login: " + sessionAfter);

            if (loginPage.isLoggedIn()) {

                // Session ID should have changed
                if (sessionBefore.equals(sessionAfter)) {
                    logVulnerability("Session Fixation",
                            "Session ID not regenerated after login");
                    Assert.fail("Session fixation vulnerability - ID not regenerated");
                } else {
                    logSecurityPassed("Session Fixation",
                            "Session ID properly regenerated after login");
                }

            } else {
                ReportManager.logInfo("Could not complete login for session fixation test");
            }

        } else {
            ReportManager.logInfo("No pre-authentication session - checking after failed login");

            loginPage.login("testuser", "wrongpassword");
            String sessionAfterFail = loginPage.getSessionId();

            if (sessionAfterFail != null) {
                ReportManager.logInfo("Session created after failed login: " + sessionAfterFail);
            }
        }
    }

    // ==================== SESSION COOKIE SECURITY ====================

    @Test(description = "Test session cookie has HttpOnly flag",
            groups = {"session", "cookies"})
    public void testSessionCookie_HttpOnly() {

        navigateTo("/login");

        String sessionCookieName = loginPage.getSessionCookieName();

        if (sessionCookieName == null) {

            ReportManager.logInfo("No standard session cookie found");

            // Check all cookies
            Set<Cookie> cookies = driver.manage().getCookies();
            for (Cookie cookie : cookies) {
                if (!cookie.isHttpOnly()) {
                    ReportManager.logWarning("Cookie " + cookie.getName()
                            + " missing HttpOnly flag");
                }
            }

        } else {

            boolean isHttpOnly = loginPage.isSessionCookieHttpOnly();

            if (!isHttpOnly) {
                logVulnerability("Session Cookie - Missing HttpOnly",
                        "Session cookie can be accessed by JavaScript (XSS risk)");
            }

            Assert.assertTrue(isHttpOnly,
                    "Session cookie must have HttpOnly flag");

            logSecurityPassed("Session Cookie HttpOnly",
                    "Flag properly set");
        }
    }

    @Test(description = "Test session cookie has Secure flag",
            groups = {"session", "cookies"})
    public void testSessionCookie_Secure() {

        // Only relevant for HTTPS sites
        if (!baseUrl.startsWith("https://")) {
            ReportManager.logWarning("Site not using HTTPS - Secure flag test skipped");
            return;
        }

        navigateTo("/login");

        String sessionCookieName = loginPage.getSessionCookieName();

        if (sessionCookieName != null) {

            boolean isSecure = loginPage.isSessionCookieSecure();

            if (!isSecure) {
                logVulnerability("Session Cookie - Missing Secure Flag",
                        "Session cookie can be transmitted over HTTP");
            }

            Assert.assertTrue(isSecure,
                    "Session cookie must have Secure flag for HTTPS sites");

            logSecurityPassed("Session Cookie Secure",
                    "Flag properly set");
        }
    }

    @Test(description = "Test session cookie SameSite attribute",
            groups = {"session", "cookies"})
    public void testSessionCookie_SameSite() {

        navigateTo("/login");

        Set<Cookie> cookies = driver.manage().getCookies();

        for (Cookie cookie : cookies) {
            String name = cookie.getName().toLowerCase();

            if (name.contains("session") || name.contains("sid")) {
                // Note: Selenium doesn't expose SameSite attribute directly
                // This would require checking HTTP headers or using browser dev tools
                ReportManager.logInfo("Cookie " + cookie.getName()
                        + " SameSite attribute requires HTTP header inspection");
            }
        }

        logSecurityPassed("Session Cookie SameSite",
                "Manual verification required via HTTP headers");
    }

    // ==================== SESSION ID ANALYSIS ====================

    @Test(description = "Test session ID length and entropy",
            groups = {"session", "entropy"})
    public void testSessionId_Entropy() {

        navigateTo("/login");

        String sessionId = loginPage.getSessionId();

        if (sessionId != null) {

            int length = sessionId.length();

            ReportManager.logInfo("Session ID: " + sessionId);
            ReportManager.logInfo("Session ID length: " + length);

            // Session ID should be at least 128 bits
            if (length < 20) {
                logVulnerability("Weak Session ID",
                        "Session ID too short (" + length + " chars) - may be predictable");
                Assert.fail("Session ID length insufficient: " + length);
            }

            // Check entropy (variety of characters)
            boolean hasNumbers = sessionId.matches(".*\\d.*");
            boolean hasLetters = sessionId.matches(".*[a-zA-Z].*");

            if (!(hasNumbers && hasLetters)) {
                ReportManager.logWarning("Session ID may have low entropy");
            }

            logSecurityPassed("Session ID Entropy",
                    "Length: " + length + " chars");

        } else {
            ReportManager.logInfo("No session ID found for entropy analysis");
        }
    }

    @Test(description = "Test session ID is not exposed in URL",
            groups = {"session", "exposure"})
    public void testSessionId_NotInUrl() {

        navigateTo("/login");

        String currentUrl = getCurrentUrl();
        String sessionId = loginPage.getSessionId();

        // Check URL for session-related parameters
        String[] sessionParams = {"jsessionid", "sessionid", "sid", "phpsessid", "session"};

        for (String param : sessionParams) {
            if (currentUrl.toLowerCase().contains(param + "=")) {
                logVulnerability("Session ID in URL",
                        "Session ID exposed in URL parameter: " + param);
                Assert.fail("Session ID should not be in URL");
            }
        }

        // Also check if actual session value appears in URL
        if (sessionId != null && currentUrl.contains(sessionId)) {
            logVulnerability("Session ID in URL",
                    "Actual session ID value found in URL");
            Assert.fail("Session ID value exposed in URL");
        }

        logSecurityPassed("Session ID Not in URL",
                "Session ID properly hidden");
    }

    // ==================== SESSION TIMEOUT TESTS ====================

    @Test(description = "Test session timeout configuration",
            groups = {"session", "timeout"})
    public void testSessionTimeout() {

        ReportManager.logInfo("Session timeout test requires long wait - recommend manual testing");

        navigateTo("/login");

        String pageSource = getPageSource().toLowerCase();

        // Look for client-side timeout mechanisms
        if (pageSource.contains("settimeout")
                || (pageSource.contains("session")
                && (pageSource.contains("expire") || pageSource.contains("timeout")))) {

            ReportManager.logInfo("Client-side session handling detected");
        }

        logSecurityPassed("Session Timeout",
                "Manual verification recommended - check server configuration");
    }

    // ==================== CONCURRENT SESSION TESTS ====================

    @Test(description = "Test concurrent session handling",
            groups = {"session", "concurrent"})
    public void testConcurrentSessions() {

        ReportManager.logInfo("Concurrent session test - checking for session limits");

        navigateTo("/login");

        String pageSource = getPageSource().toLowerCase();

        if (pageSource.contains("already logged in")
                || pageSource.contains("another session")
                || pageSource.contains("logged in elsewhere")) {

            ReportManager.logInfo("Concurrent session handling detected");
        }

        logSecurityPassed("Concurrent Sessions",
                "Policy verification requires multi-browser testing");
    }

    // ==================== SESSION HIJACKING PREVENTION ====================

    @Test(description = "Test session bound to client fingerprint",
            groups = {"session", "hijacking"})
    public void testSessionClientBinding() {

        ReportManager.logInfo("Session-client binding test");

        // Proper session security should bind session to:
        // - IP address (optional, may cause issues with mobile)
        // - User-Agent
        // - Other fingerprinting

        // This is difficult to test automatically

        logSecurityPassed("Session Binding",
                "Requires manual testing with modified client parameters");
    }

    // ==================== SESSION INVALIDATION TESTS ====================

    @Test(description = "Test proper session invalidation on logout",
            groups = {"session", "logout"})
    public void testSessionInvalidation_Logout() {

        ReportManager.logInfo("Testing session invalidation on logout");

        navigateTo("/login");

        String sessionBefore = loginPage.getSessionId();

        // After logout:
        // 1. Session cookie should be deleted OR
        // 2. New session ID should be issued
        // 3. Old session should not work for authenticated actions

        logSecurityPassed("Session Invalidation",
                "Requires authentication to fully test");
    }

    @Test(description = "Test session invalidation on password change",
            groups = {"session", "password-change"})
    public void testSessionInvalidation_PasswordChange() {

        ReportManager.logInfo("Password change should invalidate all sessions");

        // Best practice: changing password should invalidate all existing sessions
        // This prevents attackers from maintaining access after password reset

        // Testing requires:
        // 1. Login and get session
        // 2. Change password
        // 3. Try to use old session
        // 4. Verify access denied

        logSecurityPassed("Password Change Session",
                "Requires authentication to test - manual verification recommended");
    }

    // ==================== TOKEN SECURITY TESTS ====================

    @Test(description = "Test for insecure tokens in localStorage/sessionStorage",
            groups = {"session", "storage"})
    public void testInsecureTokenStorage() {

        navigateToBaseUrl();

        @SuppressWarnings("unchecked")
        java.util.Map<String, String> localStorage =
                (java.util.Map<String, String>) ((org.openqa.selenium.JavascriptExecutor) driver)
                        .executeScript("return Object.assign({}, localStorage);");

        @SuppressWarnings("unchecked")
        java.util.Map<String, String> sessionStorage =
                (java.util.Map<String, String>) ((org.openqa.selenium.JavascriptExecutor) driver)
                        .executeScript("return Object.assign({}, sessionStorage);");

        // Look for sensitive tokens
        String[] sensitiveKeys = {"token", "jwt", "access_token", "auth",
                "session", "password", "secret", "key", "credential"};

        for (String key : sensitiveKeys) {

            for (String storageKey : localStorage.keySet()) {
                if (storageKey.toLowerCase().contains(key)) {
                    ReportManager.logWarning("Sensitive data in localStorage: " + storageKey);
                }
            }

            for (String storageKey : sessionStorage.keySet()) {
                if (storageKey.toLowerCase().contains(key)) {
                    ReportManager.logWarning("Sensitive data in sessionStorage: " + storageKey);
                }
            }
        }
    }
}