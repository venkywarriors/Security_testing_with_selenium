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
 * Cross-Site Scripting (XSS) vulnerability tests.
 * Tests for Reflected, Stored, and DOM-based XSS vulnerabilities.
 */
public class XssTest extends BaseTest {

    private SearchPage searchPage;
    private LoginPage loginPage;

    @BeforeMethod
    public void initPages() {
        searchPage = new SearchPage(driver);
        loginPage = new LoginPage(driver);
    }

    // ==================== DATA PROVIDERS ====================

    @DataProvider(name = "basicXssPayloads")
    public Object[][] basicXssPayloads() {
        return convertToDataProvider(SecurityPayloads.XSS_BASIC);
    }

    @DataProvider(name = "eventHandlerPayloads")
    public Object[][] eventHandlerPayloads() {
        return convertToDataProvider(SecurityPayloads.XSS_EVENT_HANDLERS);
    }

    @DataProvider(name = "encodedXssPayloads")
    public Object[][] encodedXssPayloads() {
        return convertToDataProvider(SecurityPayloads.XSS_ENCODED);
    }

    @DataProvider(name = "allXssPayloads")
    public Object[][] allXssPayloads() {
        java.util.List<String> all = SecurityPayloads.getAllXssPayloads();
        Object[][] data = new Object[all.size()][1];
        for (int i = 0; i < all.size(); i++) {
            data[i][0] = all.get(i);
        }
        return data;
    }

    private Object[][] convertToDataProvider(String[] payloads) {
        Object[][] data = new Object[payloads.length][1];
        for (int i = 0; i < payloads.length; i++) {
            data[i][0] = payloads[i];
        }
        return data;
    }

    // ==================== REFLECTED XSS TESTS ====================

    @Test(dataProvider = "basicXssPayloads",
            description = "Test search field for reflected XSS with basic payloads",
            groups = {"xss", "reflected"})
    public void testReflectedXss_BasicPayloads(String payload) {
        ReportManager.logInfo("Testing reflected XSS: " + payload);

        navigateTo("/search");

        boolean vulnerable = searchPage.testXssPayload(payload);

        if (vulnerable) {
            logVulnerability("Reflected XSS",
                    "Payload reflected without encoding: " + payload);
        }

        Assert.assertFalse(vulnerable,
                "Reflected XSS vulnerability: " + payload);

        logSecurityPassed("Reflected XSS", "Payload properly handled: " + payload);
    }

    @Test(dataProvider = "eventHandlerPayloads",
            description = "Test for XSS using event handlers",
            groups = {"xss", "reflected"})
    public void testReflectedXss_EventHandlers(String payload) {
        ReportManager.logInfo("Testing event handler XSS: " + payload);

        navigateTo("/search");

        searchPage.search(payload);

        // Check if alert was triggered
        if (searchPage.isAlertPresent()) {
            String alertText = searchPage.getAlertText();
            searchPage.acceptAlert();

            logVulnerability("Reflected XSS - Event Handler",
                    "XSS executed via event handler. Alert text: " + alertText);
            Assert.fail("XSS vulnerability: " + payload);
        }

        // Check if payload is reflected
        String pageSource = getPageSource();
        if (SecurityPayloads.isXssReflected(pageSource, payload)) {
            logVulnerability("Reflected XSS",
                    "Event handler payload reflected: " + payload);
            Assert.fail("XSS payload reflected without encoding: " + payload);
        }

        logSecurityPassed("Event Handler XSS", "Payload sanitized: " + payload);
    }

    @Test(dataProvider = "encodedXssPayloads",
            description = "Test for XSS bypass using encoded payloads",
            groups = {"xss", "bypass"})
    public void testReflectedXss_EncodedPayloads(String payload) {
        ReportManager.logInfo("Testing encoded XSS bypass: " + payload);

        navigateTo("/search");

        searchPage.search(payload);

        // Check for alert
        if (searchPage.isAlertPresent()) {
            searchPage.acceptAlert();
            logVulnerability("Reflected XSS - Encoding Bypass",
                    "Encoded payload executed: " + payload);
            Assert.fail("XSS encoding bypass: " + payload);
        }

        logSecurityPassed("Encoded XSS", "Payload blocked: " + payload);
    }

    // ==================== DOM-BASED XSS TESTS ====================

    @Test(description = "Test for DOM-based XSS in URL hash",
            groups = {"xss", "dom"})
    public void testDomXss_UrlHash() {

        String[] domPayloads = {
                "#<script>alert('XSS')</script>",
                "#<img src=x onerror=alert('XSS')>",
                "#javascript:alert('XSS')"
        };

        for (String payload : domPayloads) {
            ReportManager.logInfo("Testing DOM XSS in hash: " + payload);

            driver.get(baseUrl + "/search" + payload);

            // Wait briefly for DOM processing
            try { Thread.sleep(500); } catch (InterruptedException e) {}

            if (searchPage.isAlertPresent()) {
                searchPage.acceptAlert();
                logVulnerability("DOM-based XSS",
                        "XSS via URL hash: " + payload);
                Assert.fail("DOM XSS vulnerability in URL hash");
            }
        }

        logSecurityPassed("DOM XSS (Hash)", "All hash payloads blocked");
    }

    @Test(description = "Test for DOM-based XSS in URL parameters",
            groups = {"xss", "dom"})
    public void testDomXss_UrlParameters() {

        String[] params = {"q", "search", "query", "keyword", "s"};

        for (String param : params) {
            for (String payload : SecurityPayloads.XSS_BASIC) {

                String testUrl = baseUrl + "/search?" + param + "=" +
                        java.net.URLEncoder.encode(payload,
                                java.nio.charset.StandardCharsets.UTF_8);

                ReportManager.logInfo("Testing: " + testUrl);
                driver.get(testUrl);

                try { Thread.sleep(300); } catch (InterruptedException e) {}

                if (searchPage.isAlertPresent()) {
                    searchPage.acceptAlert();
                    logVulnerability("DOM-based XSS",
                            "XSS via URL parameter: " + param);
                    Assert.fail("DOM XSS vulnerability in URL parameter");
                }
            }
        }

        logSecurityPassed("DOM XSS (Params)", "All parameter payloads blocked");
    }
}