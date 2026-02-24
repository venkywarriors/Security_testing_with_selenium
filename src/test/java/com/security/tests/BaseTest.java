/**
 * @author Venkateshwara Doijode 
 *
 * © https://github.com/venkywarriors
 */
package com.security.tests;

import com.security.config.ConfigReader;
import com.security.utils.DriverFactory;
import com.security.utils.ReportManager;
import org.openqa.selenium.WebDriver;
import org.testng.ITestResult;
import org.testng.annotations.*;

/**
 * Base test class for all security tests.
 * Handles WebDriver setup/teardown and reporting.
 */
public abstract class BaseTest {

    protected WebDriver driver;
    protected String baseUrl;

    @BeforeSuite
    public void beforeSuite() {
        // Initialize reporting
        ReportManager.getExtentReports();
        System.out.println("==============================================");
        System.out.println("  Selenium Security Testing Framework");
        System.out.println("==============================================");
        System.out.println("Base URL: " + ConfigReader.getBaseUrl());
        System.out.println("Browser: " + ConfigReader.getBrowser());
        System.out.println("Headless: " + ConfigReader.isHeadless());
        System.out.println("ZAP Enabled: " + ConfigReader.isZapEnabled());
        System.out.println("==============================================");
    }

    @BeforeClass
    public void beforeClass() {
        baseUrl = ConfigReader.getBaseUrl();
    }

    @BeforeMethod
    public void setUp(ITestResult result) {
        driver = DriverFactory.getDriver();

        // Create test in report
        String testName = result.getMethod().getMethodName();
        String description = result.getMethod().getDescription();

        if (description != null && !description.isEmpty()) {
            ReportManager.createTest(testName, description);
        } else {
            ReportManager.createTest(testName);
        }

        ReportManager.logInfo("Starting test: " + testName);
        ReportManager.logInfo("Browser: " + ConfigReader.getBrowser());
    }

    @AfterMethod
    public void tearDown(ITestResult result) {

        // Log test result
        if (result.getStatus() == ITestResult.FAILURE) {
            ReportManager.logFail("Test FAILED: " + result.getThrowable().getMessage());

            // Capture screenshot on failure
            if (driver != null) {
                ReportManager.captureScreenshot(driver, result.getName());
            }

        } else if (result.getStatus() == ITestResult.SUCCESS) {
            ReportManager.logPass("Test PASSED");

        } else if (result.getStatus() == ITestResult.SKIP) {
            ReportManager.logSkip("Test SKIPPED: " + result.getThrowable().getMessage());
        }

        // Quit driver
        DriverFactory.quitDriver();
    }

    @AfterSuite
    public void afterSuite() {
        // Flush reports
        ReportManager.flushReports();
        System.out.println("==============================================");
        System.out.println("  Test Execution Complete");
        System.out.println("  Report: test-output/SecurityTestReport.html");
        System.out.println("==============================================");
    }

    /**
     * Navigate to base URL.
     */
    protected void navigateToBaseUrl() {
        driver.get(baseUrl);
    }

    /**
     * Navigate to specific path.
     */
    protected void navigateTo(String path) {
        String url = path.startsWith("http") ? path : baseUrl + path;
        driver.get(url);
    }

    /**
     * Get current URL.
     */
    protected String getCurrentUrl() {
        return driver.getCurrentUrl();
    }

    /**
     * Get page source.
     */
    protected String getPageSource() {
        return driver.getPageSource();
    }

    /**
     * Log security finding.
     */
    protected void logVulnerability(String type, String details) {
        ReportManager.logVulnerability(type, details);
        System.err.println("[VULNERABILITY] " + type + ": " + details);
    }

    /**
     * Log security check passed.
     */
    protected void logSecurityPassed(String type, String details) {
        ReportManager.logSecurityPassed(type, details);
        System.out.println("[SECURE] " + type + ": " + details);
    }
}