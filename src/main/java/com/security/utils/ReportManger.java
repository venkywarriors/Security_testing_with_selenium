package com.security.utils;

import com.aventstack.extentreports.ExtentReports;
import com.aventstack.extentreports.ExtentTest;
import com.aventstack.extentreports.Status;
import com.aventstack.extentreports.reporter.ExtentSparkReporter;
import com.aventstack.extentreports.reporter.configuration.Theme;
import org.openqa.selenium.OutputType;
import org.openqa.selenium.TakesScreenshot;
import org.openqa.selenium.WebDriver;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.text.SimpleDateFormat;
import java.util.Date;

/**
 * Report manager for generating ExtentReports test reports.
 */
public class Create {

    private static ExtentReports extentReports;
    private static final ThreadLocal<ExtentTest> extentTestThreadLocal = new ThreadLocal<>();
    private static final String REPORT_DIR = "test-output";
    private static final String SCREENSHOTS_DIR = REPORT_DIR + "/screenshots";

    /**
     * Initialize ExtentReports.
     */
    public static synchronized ExtentReports getExtentReports() {
        if (extentReports == null) {
            createReportDirectory();

            String timestamp = new SimpleDateFormat("yyyyMMdd_HHmmss").format(new Date());
            String reportPath = REPORT_DIR + "/SecurityTestReport_" + timestamp + ".html";

            ExtentSparkReporter sparkReporter = new ExtentSparkReporter(reportPath);
            sparkReporter.config().setTheme(Theme.DARK);
            sparkReporter.config().setDocumentTitle("Security Test Report");
            sparkReporter.config().setReportName("Selenium Security Testing Results");
            sparkReporter.config().setTimeStampFormat("yyyy-MM-dd HH:mm:ss");

            extentReports = new ExtentReports();
            extentReports.attachReporter(sparkReporter);
            extentReports.setSystemInfo("OS", System.getProperty("os.name"));
            extentReports.setSystemInfo("Java Version", System.getProperty("java.version"));
            extentReports.setSystemInfo("Browser", "Chrome");
        }
        return extentReports;
    }

    /**
     * Create test in report.
     */
    public static ExtentTest createTest(String testName) {
        ExtentTest test = getExtentReports().createTest(testName);
        extentTestThreadLocal.set(test);
        return test;
    }

    /**
     * Create test with description.
     */
    public static ExtentTest createTest(String testName, String description) {
        ExtentTest test = getExtentReports().createTest(testName, description);
        extentTestThreadLocal.set(test);
        return test;
    }

    /**
     * Get current test.
     */
    public static ExtentTest getTest() {
        return extentTestThreadLocal.get();
    }

    /**
     * Log info message.
     */
    public static void logInfo(String message) {
        ExtentTest test = getTest();
        if (test != null) {
            test.log(Status.INFO, message);
        }
    }

    /**
     * Log pass message.
     */
    public static void logPass(String message) {
        ExtentTest test = getTest();
        if (test != null) {
            test.log(Status.PASS, message);
        }
    }

    /**
     * Log fail message.
     */
    public static void logFail(String message) {
        ExtentTest test = getTest();
        if (test != null) {
            test.log(Status.FAIL, message);
        }
    }

    /**
     * Log warning message.
     */
    public static void logWarning(String message) {
        ExtentTest test = getTest();
        if (test != null) {
            test.log(Status.WARNING, message);
        }
    }

    /**
     * Log skip message.
     */
    public static void logSkip(String message) {
        ExtentTest test = getTest();
        if (test != null) {
            test.log(Status.SKIP, message);
        }
    }

    /**
     * Log vulnerability found.
     */
    public static void logVulnerability(String vulnerabilityType, String details) {
        ExtentTest test = getTest();
        if (test != null) {
            test.log(Status.FAIL,
                    "<b style='color:red'>VULNERABILITY FOUND: "
                            + vulnerabilityType + "</b><br>" + details);
        }
    }

    /**
     * Log security check passed.
     */
    public static void logSecurityPassed(String checkType, String details) {
        ExtentTest test = getTest();
        if (test != null) {
            test.log(Status.PASS,
                    "<b style='color:green'>SECURE: "
                            + checkType + "</b><br>" + details);
        }
    }

    /**
     * Take and attach screenshot.
     */
    public static String captureScreenshot(WebDriver driver, String screenshotName) {
        try {
            createScreenshotDirectory();

            String timestamp = new SimpleDateFormat("yyyyMMdd_HHmmss").format(new Date());
            String fileName = screenshotName + "_" + timestamp + ".png";
            String filePath = SCREENSHOTS_DIR + "/" + fileName;

            File srcFile = ((TakesScreenshot) driver).getScreenshotAs(OutputType.FILE);
            Files.copy(srcFile.toPath(), Paths.get(filePath));

            ExtentTest test = getTest();
            if (test != null) {
                test.addScreenCaptureFromPath(filePath);
            }

            return filePath;
        } catch (IOException e) {
            System.err.println("Failed to capture screenshot: " + e.getMessage());
            return null;
        }
    }

    /**
     * Flush and close reports.
     */
    public static synchronized void flushReports() {
        if (extentReports != null) {
            extentReports.flush();
        }
    }

    /**
     * Create report directory.
     */
    private static void createReportDirectory() {
        Path path = Paths.get(REPORT_DIR);
        if (!Files.exists(path)) {
            try {
                Files.createDirectories(path);
            } catch (IOException e) {
                System.err.println("Failed to create report directory: " + e.getMessage());
            }
        }
    }

    /**
     * Create screenshot directory.
     */
    private static void createScreenshotDirectory() {
        Path path = Paths.get(SCREENSHOTS_DIR);
        if (!Files.exists(path)) {
            try {
                Files.createDirectories(path);
            } catch (IOException e) {
                System.err.println("Failed to create screenshots directory: " + e.getMessage());
            }
        }
    }
}