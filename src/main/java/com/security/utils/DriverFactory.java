package com.security.utils;

import com.security.config.ConfigReader;
import io.github.bonigarcia.wdm.WebDriverManager;
import org.openqa.selenium.Proxy;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.chrome.ChromeDriver;
import org.openqa.selenium.chrome.ChromeOptions;
import org.openqa.selenium.edge.EdgeDriver;
import org.openqa.selenium.edge.EdgeOptions;
import org.openqa.selenium.firefox.FirefoxDriver;
import org.openqa.selenium.firefox.FirefoxOptions;

import java.time.Duration;

/**
 * WebDriver factory for creating and managing browser instances.
 * Supports Chrome, Firefox, and Edge with optional ZAP proxy integration.
 */
public class DriverFactory {

    private static final ThreadLocal<WebDriver> driverThreadLocal = new ThreadLocal<>();

    /**
     * Get or create WebDriver instance for current thread.
     */
    public static WebDriver getDriver() {
        if (driverThreadLocal.get() == null) {
            driverThreadLocal.set(createDriver());
        }
        return driverThreadLocal.get();
    }

    /**
     * Create new WebDriver based on configuration.
     */
    private static WebDriver createDriver() {

        String browser = ConfigReader.getBrowser().toLowerCase();
        boolean headless = ConfigReader.isHeadless();
        WebDriver driver;

        Proxy proxy = null;
        if (ConfigReader.isZapEnabled()) {
            proxy = createZapProxy();
        }

        switch (browser) {

            case "firefox":
                driver = createFirefoxDriver(headless, proxy);
                break;

            case "edge":
                driver = createEdgeDriver(headless, proxy);
                break;

            case "chrome":
            default:
                driver = createChromeDriver(headless, proxy);
                break;
        }

        configureDriver(driver);
        return driver;
    }

    /**
     * Create Chrome WebDriver.
     */
    private static WebDriver createChromeDriver(boolean headless, Proxy proxy) {

        WebDriverManager.chromedriver().setup();

        ChromeOptions options = new ChromeOptions();

        if (headless) {
            options.addArguments("--headless=new");
        }

        // Security testing specific options
        options.addArguments("--disable-web-security");
        options.addArguments("--allow-running-insecure-content");
        options.addArguments("--ignore-certificate-errors");
        options.addArguments("--disable-popup-blocking");
        options.addArguments("--disable-notifications");
        options.addArguments("--no-sandbox");
        options.addArguments("--disable-dev-shm-usage");

        if (proxy != null) {
            options.setProxy(proxy);
            options.setAcceptInsecureCerts(true);
        }

        return new ChromeDriver(options);
    }

    /**
     * Create Firefox WebDriver.
     */
    private static WebDriver createFirefoxDriver(boolean headless, Proxy proxy) {

        WebDriverManager.firefoxdriver().setup();

        FirefoxOptions options = new FirefoxOptions();

        if (headless) {
            options.addArguments("--headless");
        }

        // Security testing specific preferences
        options.addPreference("security.insecure_field_warning.contextual.enabled", false);
        options.addPreference("security.insecure_password.ui.enabled", false);
        options.setAcceptInsecureCerts(true);

        if (proxy != null) {
            options.setProxy(proxy);
        }

        return new FirefoxDriver(options);
    }

    /**
     * Create Edge WebDriver.
     */
    private static WebDriver createEdgeDriver(boolean headless, Proxy proxy) {

        WebDriverManager.edgedriver().setup();

        EdgeOptions options = new EdgeOptions();

        if (headless) {
            options.addArguments("--headless=new");
        }

        options.addArguments("--disable-web-security");
        options.addArguments("--ignore-certificate-errors");

        if (proxy != null) {
            options.setProxy(proxy);
            options.setAcceptInsecureCerts(true);
        }

        return new EdgeDriver(options);
    }

    /**
     * Create ZAP proxy configuration.
     */
    private static Proxy createZapProxy() {

        String zapAddress = ConfigReader.getZapHost() + ":" + ConfigReader.getZapPort();

        Proxy proxy = new Proxy();
        proxy.setHttpProxy(zapAddress);
        proxy.setSslProxy(zapAddress);

        return proxy;
    }

    /**
     * Configure driver timeouts and settings.
     */
    private static void configureDriver(WebDriver driver) {

        driver.manage().timeouts().implicitlyWait(
                Duration.ofSeconds(ConfigReader.getImplicitWait())
        );

        driver.manage().timeouts().pageLoadTimeout(
                Duration.ofSeconds(ConfigReader.getPageLoadTimeout())
        );

        driver.manage().window().maximize();
    }

    /**
     * Quit WebDriver and remove from thread local.
     */
    public static void quitDriver() {

        WebDriver driver = driverThreadLocal.get();

        if (driver != null) {
            driver.quit();
            driverThreadLocal.remove();
        }
    }

    /**
     * Get new driver instance without caching (for parallel tests).
     */
    public static WebDriver createNewDriver() {
        return createDriver();
    }
}