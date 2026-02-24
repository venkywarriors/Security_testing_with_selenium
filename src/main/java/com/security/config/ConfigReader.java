/**
 * @author Venkateshwara Doijode 
 *
 * © https://github.com/venkywarriors
 */
package com.security.config;

import java.io.FileInputStream;
import java.io.IOException;
import java.util.Properties;

/**
 * Configuration reader for test properties.
 * Reads from config.properties and supports system property overrides.
 */
public class ConfigReader {

    private static Properties properties;
    private static final String CONFIG_PATH = "src/test/resources/config.properties";

    static {
        loadProperties();
    }

    private static void loadProperties() {
        properties = new Properties();
        try (FileInputStream fis = new FileInputStream(CONFIG_PATH)) {
            properties.load(fis);
        } catch (IOException e) {
            System.err.println("Warning: Could not load config.properties. Using defaults.");
        }
    }

    /**
     * Get property value with system property override support.
     */
    public static String getProperty(String key) {
        String systemProp = System.getProperty(key);
        if (systemProp != null) {
            return systemProp;
        }
        return properties.getProperty(key);
    }

    /**
     * Get property with default value.
     */
    public static String getProperty(String key, String defaultValue) {
        String value = getProperty(key);
        return value != null ? value : defaultValue;
    }

    /**
     * Get boolean property.
     */
    public static boolean getBooleanProperty(String key, boolean defaultValue) {
        String value = getProperty(key);
        return value != null ? Boolean.parseBoolean(value) : defaultValue;
    }

    /**
     * Get integer property.
     */
    public static int getIntProperty(String key, int defaultValue) {
        String value = getProperty(key);
        try {
            return value != null ? Integer.parseInt(value) : defaultValue;
        } catch (NumberFormatException e) {
            return defaultValue;
        }
    }

    // Convenience methods for common properties

    public static String getBaseUrl() {
        return getProperty("base.url", "http://localhost:8080");
    }

    public static String getBrowser() {
        return getProperty("browser", "chrome");
    }

    public static boolean isHeadless() {
        return getBooleanProperty("headless", false);
    }

    public static int getImplicitWait() {
        return getIntProperty("implicit.wait", 10);
    }

    public static int getExplicitWait() {
        return getIntProperty("explicit.wait", 15);
    }

    public static int getPageLoadTimeout() {
        return getIntProperty("page.load.timeout", 30);
    }

    public static boolean isZapEnabled() {
        return getBooleanProperty("zap.enabled", false);
    }

    public static String getZapHost() {
        return getProperty("zap.host", "localhost");
    }

    public static int getZapPort() {
        return getIntProperty("zap.port", 8080);
    }

    public static String getZapApiKey() {
        return getProperty("zap.api.key", "");
    }
}