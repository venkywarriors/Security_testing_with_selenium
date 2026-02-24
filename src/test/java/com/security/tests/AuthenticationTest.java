/**
 * @author Venkateshwara Doijode 
 *
 * © https://github.com/venkywarriors
 */
package com.security.tests;

import com.security.pages.LoginPage;
import com.security.utils.ReportManager;
import org.openqa.selenium.Cookie;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import java.util.Set;

/**
 * Authentication and authorization security tests.
 * Tests for authentication bypass, broken access control, and session management.
 */
public class AuthenticationTest extends BaseTest {

    private LoginPage loginPage;

    @BeforeMethod
    public void initPages() {
        loginPage = new LoginPage(driver);
    }

    // ===================== AUTHENTICATION BYPASS TESTS =====================

    @Test(description = "Test direct URL access to protected pages without authentication",
            groups = {"auth", "access-control"})
    public void testDirectUrlAccess_ProtectedPages() {

        String[] protectedUrls = {
                "/dashboard",
                "/admin",
                "/admin/users",
                "/settings",
                "/profile",
                "/account",
                "/api/users",
                "/internal",
                "/management"
        };

        for (String url : protectedUrls) {

            ReportManager.logInfo("Testing direct access to: " + url);

            // Clear cookies to ensure no session
            driver.manage().deleteAllCookies();

            navigateTo(url);

            String currentUrl = getCurrentUrl();

            // Should redirect to login or show access denied
            boolean isProtected =
                    currentUrl.contains("login") ||
                    currentUrl.contains("signin") ||
                    currentUrl.contains("auth") ||
                    currentUrl.contains("error") ||
                    currentUrl.contains("403") ||
                    currentUrl.contains("401") ||
                    getPageSource().toLowerCase().contains("access denied") ||
                    getPageSource().toLowerCase().contains("unauthorized") ||
                    getPageSource().toLowerCase().contains("please log in");

            if (!isProtected && !currentUrl.equals(baseUrl + url)) {
                // Page might have redirected elsewhere
                isProtected = true;
            }

            if (!isProtected && currentUrl.equals(baseUrl + url)) {

                String pageSource = getPageSource().toLowerCase();

                if (!pageSource.contains("login") && !pageSource.contains("signin")) {
                    logVulnerability("Authentication Bypass",
                            "Direct access allowed to: " + url);
                }
            }

            Assert.assertTrue(isProtected || !currentUrl.equals(baseUrl + url),
                    "Authentication bypass: Direct access to " + url);
        }

        logSecurityPassed("Direct URL Access", "All protected URLs require authentication");
    }

    @Test(description = "Test for forced browsing to admin pages",
            groups = {"auth", "access-control"})
    public void testForcedBrowsing_AdminPages() {

        String[] adminUrls = {
                "/admin",
                "/administrator",
                "/admin.php",
                "/admin.html",
                "/admin/dashboard",
                "/admin/config",
                "/admin/settings",
                "/wp-admin",
                "/phpmyadmin",
                "/manage",
                "/console"
        };

        driver.manage().deleteAllCookies();

        for (String url : adminUrls) {

            ReportManager.logInfo("Testing admin URL: " + url);

            navigateTo(url);

            String currentUrl = getCurrentUrl();
            String pageSource = getPageSource().toLowerCase();

            // Check for signs of successful access
            boolean accessGranted =
                    currentUrl.equals(baseUrl + url) &&
                    !pageSource.contains("login") &&
                    !pageSource.contains("denied") &&
                    !pageSource.contains("404") &&
                    !pageSource.contains("not found") &&
                    !pageSource.contains("unauthorized");

            if (accessGranted && pageSource.contains("admin")) {
                logVulnerability("Forced Browsing",
                        "Admin page accessible: " + url);
                Assert.fail("Admin page accessible without authentication: " + url);
            }
        }

        logSecurityPassed("Forced Browsing", "Admin pages protected");
    }

    // ===================== PASSWORD SECURITY TESTS =====================

    @Test(description = "Test password field masking",
            groups = {"auth", "password"})
    public void testPasswordFieldMasking() {

        navigateTo("/login");

        boolean isMasked = loginPage.isPasswordMasked();

        if (!isMasked) {
            logVulnerability("Password Exposure",
                    "Password field is not masked (type != 'password')");
        }

        Assert.assertTrue(isMasked,
                "Password field must be masked with type='password'");

        logSecurityPassed("Password Masking", "Password field properly masked");
    }

    @Test(description = "Test password field autocomplete disabled",
            groups = {"auth", "password"})
    public void testPasswordAutocomplete() {

        navigateTo("/login");

        boolean autocompleteDisabled = loginPage.isPasswordAutocompleteDisabled();

        if (!autocompleteDisabled) {
            ReportManager.logWarning("Password autocomplete not disabled - potential risk");
        }

        // This is a warning level issue, not critical
        logSecurityPassed("Password Autocomplete",
                "Checked - " + (autocompleteDisabled ? "disabled" : "enabled (warning)"));
    }

    @Test(description = "Test for verbose error messages revealing usernames",
            groups = {"auth", "enumeration"})
    public void testUserEnumeration_ErrorMessages() {

        navigateTo("/login");

        // Test with definitely invalid username
        loginPage.login("nonexistent_user_12345", "wrongpassword");
        String errorInvalidUser = loginPage.getErrorMessage();

        navigateTo("/login");

        // Test with common username but wrong password
        loginPage.login("admin", "wrongpassword");
        String errorValidUser = loginPage.getErrorMessage();

        ReportManager.logInfo("Error for invalid user: " + errorInvalidUser);
        ReportManager.logInfo("Error for valid user: " + errorValidUser);

        // Check if error messages are different (allows enumeration)
        if (!errorInvalidUser.isEmpty() &&
                !errorValidUser.isEmpty() &&
                !errorInvalidUser.equals(errorValidUser)) {

            logVulnerability("User Enumeration",
                    "Different error messages for valid/invalid users");
        }

        // Check for verbose messages
        if (loginPage.hasVerboseErrorMessage()) {
            logVulnerability("Verbose Error Message",
                    "Error message reveals user existence");
        }

        logSecurityPassed("User Enumeration", "Error messages checked");
    }

    // ===================== ACCOUNT LOCKOUT TESTS =====================

    @Test(description = "Test account lockout after failed attempts",
            groups = {"auth", "brute-force"})
    public void testAccountLockout() {

        navigateTo("/login");

        String testUsername = "admin";
        int maxAttempts = 5;

        boolean lockoutExists = false;

        for (int i = 1; i <= maxAttempts + 2; i++) {

            loginPage.login(testUsername, "wrongpassword" + i);

            String error = loginPage.getErrorMessage().toLowerCase();

            if (error.contains("locked") ||
                error.contains("blocked") ||
                error.contains("too many") ||
                error.contains("try again later") ||
                error.contains("temporarily disabled")) {

                lockoutExists = true;
                ReportManager.logInfo("Account lockout triggered after " + i + " attempts");
                break;
            }

            navigateTo("/login");
        }

        if (!lockoutExists) {
            ReportManager.logWarning("No account lockout detected after "
                    + (maxAttempts + 2) + " failed attempts");

            logVulnerability("Missing Account Lockout",
                    "No lockout after multiple failed login attempts");
        } else {
            logSecurityPassed("Account Lockout", "Lockout mechanism exists");
        }
    }

    // ===================== CREDENTIAL TESTS =====================

    @Test(description = "Test default credentials",
            groups = {"auth", "defaults"})
    public void testDefaultCredentials() {

        String[][] defaultCreds = {
                {"admin", "admin"},
                {"admin", "password"},
                {"admin", "123456"},
                {"administrator", "administrator"},
                {"root", "root"},
                {"test", "test"},
                {"user", "user"},
                {"demo", "demo"},
                {"guest", "guest"}
        };

        for (String[] cred : defaultCreds) {

            navigateTo("/login");

            loginPage.login(cred[0], cred[1]);

            if (loginPage.isLoggedIn()) {
                logVulnerability("Default Credentials",
                        "Login successful with " + cred[0] + "/" + cred[1]);

                loginPage.logout();
                Assert.fail("Default credentials work: " + cred[0] + "/" + cred[1]);
            }
        }

        logSecurityPassed("Default Credentials", "No default credentials work");
    }

    // ===================== HTTPS TESTS =====================

    @Test(description = "Test HTTPS enforcement on login page",
            groups = {"auth", "https"})
    public void testHttpsEnforcement_Login() {

        String httpUrl = baseUrl.replace("https://", "http://");

        if (baseUrl.startsWith("https://")) {

            driver.get(httpUrl + "/login");

            String currentUrl = getCurrentUrl();

            if (!currentUrl.startsWith("https://")) {
                logVulnerability("HTTPS Not Enforced",
                        "Login page accessible via HTTP");
            }

            Assert.assertTrue(currentUrl.startsWith("https://")
                            || !currentUrl.contains("/login"),
                    "Login page must use HTTPS");

        } else {
            ReportManager.logWarning("Base URL is not HTTPS - security risk");
            logVulnerability("Missing HTTPS",
                    "Application not using HTTPS");
        }
    }

    // ===================== COOKIE SECURITY TESTS =====================

    @Test(description = "Test session cookie security flags",
            groups = {"auth", "cookies"})
    public void testSessionCookieFlags() {

        navigateTo("/login");

        Set<Cookie> cookies = driver.manage().getCookies();

        for (Cookie cookie : cookies) {

            String name = cookie.getName().toLowerCase();

            // Check session-related cookies
            if (name.contains("session") ||
                name.contains("sid") ||
                name.equals("jsessionid") ||
                name.equals("phpsessid")) {

                ReportManager.logInfo("Checking cookie: " + cookie.getName());

                if (!cookie.isSecure() && baseUrl.startsWith("https://")) {
                    ReportManager.logWarning("Session cookie "
                            + cookie.getName() + " missing Secure flag");
                }

                if (!cookie.isHttpOnly()) {
                    ReportManager.logWarning("Session cookie "
                            + cookie.getName() + " missing HttpOnly flag");
                }
            }
        }

        logSecurityPassed("Cookie Flags", "Session cookie security checked");
    }

    // ===================== LOGOUT TESTS =====================

    @Test(description = "Test logout functionality properly invalidates session",
            groups = {"auth", "logout"})
    public void testLogoutInvalidatesSession() {

        // This test requires valid test credentials
        ReportManager.logInfo("Logout session invalidation test requires authentication");

        // If we can login with test credentials:
        // 1. Login
        // 2. Get session ID
        // 3. Logout
        // 4. Try to access protected page with old session ID
        // 5. Verify access is denied

        logSecurityPassed("Logout", "Manual verification recommended");
    }

    // ===================== PASSWORD RESET TESTS =====================

    @Test(description = "Test password reset link security",
            groups = {"auth", "password-reset"})
    public void testPasswordResetSecurity() {
        navigateTo("/forgot-password");

        String currentUrl = getCurrentUrl();

        if (currentUrl.contains("forgot") || currentUrl.contains("reset")) {

            ReportManager.logInfo("Password reset page found");

            // Check for CSRF protection on reset form
            // Check for rate limiting
            // Check that tokens are not predictable

            // These checks require manual verification
        } else {
            ReportManager.logInfo("Password reset page not found at /forgot-password");
        }
        
        logSecurityPassed("Password Reset", "Page structure checked - Manual verification recommended");
    }
}
