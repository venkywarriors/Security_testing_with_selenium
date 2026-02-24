package com.security.tests;

import com.security.pages.LoginPage;
import com.security.utils.ReportManager;
import org.openqa.selenium.By;
import org.openqa.selenium.WebElement;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Sensitive Data Exposure vulnerability tests.
 * Tests for unprotected sensitive data, information disclosure, and data leakage.
 */
public class SensitiveDataExposureTest extends BaseTest {

    private LoginPage loginPage;

    // Patterns for sensitive data detection
    private static final Pattern EMAIL_PATTERN =
            Pattern.compile("[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}");

    private static final Pattern SSN_PATTERN =
            Pattern.compile("\\b\\d{3}-\\d{2}-\\d{4}\\b");

    private static final Pattern CREDIT_CARD_PATTERN =
            Pattern.compile("\\b(?:\\d[ -]*?){13,16}\\b");

    private static final Pattern API_KEY_PATTERN =
            Pattern.compile("(?i)(api[_-]?key|apikey|api_key|secret)[\"'\\s:=]+[a-zA-Z0-9]{20,}");

    private static final Pattern PASSWORD_PATTERN =
            Pattern.compile("(?i)(password|passwd|pwd)[\"'\\s:=]+[^\"'\\s]{4,}");

    private static final Pattern PRIVATE_KEY_PATTERN =
            Pattern.compile("-----BEGIN (RSA|EC|DSA)? PRIVATE KEY-----");

    @BeforeMethod
    public void initPages() {
        loginPage = new LoginPage(driver);
    }

    // ================= SOURCE CODE EXPOSURE TESTS =================

    @Test(description = "Test for exposed sensitive data in HTML comments",
            groups = {"sensitive-data", "source-code"})
    public void testHtmlComments_SensitiveData() {

        String[] pagesToCheck = {"/", "/login", "/register", "/dashboard", "/profile"};

        for (String page : pagesToCheck) {

            ReportManager.logInfo("Checking HTML comments on: " + page);
            navigateTo(page);

            String pageSource = getPageSource();

            // Extract HTML comments
            Pattern commentPattern = Pattern.compile("<!--([\\s\\S]*?)-->");
            Matcher matcher = commentPattern.matcher(pageSource);

            while (matcher.find()) {

                String comment = matcher.group().toLowerCase();

                // Check for sensitive info in comments
                if (comment.contains("password") ||
                        comment.contains("api_key") ||
                        comment.contains("secret") ||
                        comment.contains("todo") ||
                        comment.contains("fixme") ||
                        comment.contains("bug") ||
                        comment.contains("hack") ||
                        comment.contains("sql") ||
                        (comment.contains("admin") && comment.contains("credentials"))) {

                    logVulnerability("Information Disclosure in HTML Comments",
                            "Sensitive comment found on " + page + ": " +
                                    matcher.group().substring(0,
                                            Math.min(100, matcher.group().length())) + "...");
                }
            }
        }

        logSecurityPassed("HTML Comments", "Checked for sensitive data in comments");
    }

    // ================= HEADER INFORMATION DISCLOSURE TESTS =================

    @Test(description = "Test for server information disclosure in error pages",
            groups = {"sensitive-data", "information-disclosure"})
    public void testErrorPageInformationDisclosure() {

        String[] errorUrls = {
                "/nonexistent_page_12345",
                "/error",
                "/test.php",
                "/admin/../../../../etc/passwd"
        };

        for (String url : errorUrls) {

            ReportManager.logInfo("Testing error page: " + url);

            navigateTo(url);
            String pageSource = getPageSource().toLowerCase();

            // Check for server/framework disclosure
            boolean serverDisclosed =
                    pageSource.contains("apache") ||
                            pageSource.contains("nginx") ||
                            pageSource.contains("iis") ||
                            pageSource.contains("tomcat") ||
                            pageSource.contains("jetty");

            boolean frameworkDisclosed =
                    pageSource.contains("spring") ||
                            pageSource.contains("struts") ||
                            pageSource.contains("django") ||
                            pageSource.contains("laravel") ||
                            pageSource.contains("ruby on rails") ||
                            pageSource.contains("express");

            boolean stackTraceDisclosed =
                    pageSource.contains("stack trace") ||
                            pageSource.contains("exception") ||
                            pageSource.contains("error in") ||
                            pageSource.contains("at line") ||
                            pageSource.contains("traceback");

            if (serverDisclosed) {
                ReportManager.logWarning("Server version disclosed in error page: " + url);
            }

            if (frameworkDisclosed) {
                ReportManager.logWarning("Framework information disclosed: " + url);
            }

            if (stackTraceDisclosed) {
                logVulnerability("Stack Trace Disclosure",
                        "Stack trace exposed on error page: " + url);
            }
        }

        logSecurityPassed("Error Pages", "Information disclosure checked");
    }

    // ================= DIRECTORY LISTING TESTS =================

    @Test(description = "Test for directory listing vulnerability",
            groups = {"sensitive-data", "directory"})
    public void testDirectoryListing() {

        String[] directories = {
                "/images/",
                "/uploads/",
                "/files/",
                "/assets/",
                "/static/",
                "/media/",
                "/backup/",
                "/temp/"
        };

        for (String dir : directories) {

            ReportManager.logInfo("Testing directory: " + dir);
            navigateTo(dir);

            String pageSource = getPageSource().toLowerCase();

            // Check for directory listing indicators
            if (pageSource.contains("index of") ||
                    pageSource.contains("directory listing") ||
                    pageSource.contains("parent directory") ||
                    (pageSource.contains("<a href=") && pageSource.contains("../"))) {

                logVulnerability("Directory Listing Enabled",
                        "Directory listing at: " + dir);
            }
        }

        logSecurityPassed("Directory Listing", "Directory listing checked");
    }
}