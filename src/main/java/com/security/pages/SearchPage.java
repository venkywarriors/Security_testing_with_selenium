package com.security.pages;

import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;

import java.util.List;

/**
 * Search page object for XSS and injection testing.
 * Customize selectors based on your target application.
 */
public class SearchPage extends BasePage {

    // ================= LOCATORS =================

    // Update these selectors to match your target application
    private static final By SEARCH_INPUT = By.id("search");
    private static final By SEARCH_BUTTON = By.id("searchBtn");
    private static final By RESULTS = By.id("results");
    private static final By RESULT_ITEMS = By.className("result-item");
    private static final By NO_RESULTS_MESSAGE = By.className("no-results");

    // Alternative selectors
    private static final By SEARCH_BY_NAME = By.name("q");
    private static final By SEARCH_BY_TYPE = By.cssSelector("input[type='search']");

    public SearchPage(WebDriver driver) {
        super(driver);
    }

    // ================= PAGE ACTIONS =================

    /**
     * Enter search query.
     */
    public SearchPage enterSearchQuery(String query) {
        type(SEARCH_INPUT, query);
        return this;
    }

    /**
     * Click search button.
     */
    public SearchPage clickSearch() {
        click(SEARCH_BUTTON);
    }

    /**
     * Submit search 
     */
    public void submitSearch() {
        WebElement searchInput = driver.findElement(SEARCH_INPUT);
        searchInput.submit();
    }
    /**
     * Perform full search action.
     */
    public SearchPage search(String query) {
        enterSearchQuery(query);
        clickSearch();
        return this;
    }

/**
Get search results text..
*/
public String getResultsText() {
if (isElementPresent(SEARCH_RESULTS)) {
return getText(SEARCH_RESULTS);
}
return "";
}

    /**
     * Get result count.
     */
    public int getResultCount() {
        List<WebElement> results = driver.findElements(RESULT_ITEMS);
        return results.size();
    }

    /**
     * Check if no results message is shown.
     */
    public boolean isNoResultsDisplayed() {
        return isDisplayed(NO_RESULTS_MESSAGE);
    }

    // ================= XSS TESTING =================

    /**
     * Test XSS payload in search.
     */
    public boolean testXssPayload(String payload) {
        search(payload);

        // Check if payload is reflected without encoding
        String pageSource = getPageSource();

        if (pageSource.contains(payload)) {
            return true; // Potential reflected XSS
        }

        // Check if alert was triggered
        if (isAlertPresent()) {
            String alertText = getAlertText();
            acceptAlert();
            return true; // XSS executed
        }

        return false;
    }

    /**
     * Check if search query is reflected in page.
     */
    public boolean isQueryReflected(String query) {
        return getPageSource().contains(query);
    }

    /**
     * Check if query is properly encoded in page.
     */
    public boolean isQueryEncoded(String payload) {
        String pageSource = getPageSource();

        String encodedLt = "&lt;";
        String encodedGt = "&gt;";

        if (payload.contains("<") && pageSource.contains(encodedLt)) {
            return true; // Properly encoded
        }

        return !pageSource.contains(payload);
    }

    /**
     * Check for DOM-based XSS in URL.
     */
    public boolean testDomXss(String baseUrl, String payload) {
        String testUrl = baseUrl + "?search=" + payload;
        navigateTo(testUrl);

        if (isAlertPresent()) {
            acceptAlert();
            return true; // DOM XSS vulnerability
        }

        return false;
    }

    /**
     * Get reflected content from results.
     */
    public String getReflectedContent() {
        return getResultsText();
    }

    // ================= SQL INJECTION TESTING =================

    /**
     * Test SQL injection in search.
     */
    public boolean testSqlInjection(String payload) {
        search(payload);

        String pageSource = getPageSource().toLowerCase();

        String[] sqlErrors = {
                "sql syntax",
                "mysql_fetch",
                "ora-",
                "postgresql",
                "sqlite",
                "syntax error",
                "unclosed quotation",
                "microsoft sql"
        };

        for (String error : sqlErrors) {
            if (pageSource.contains(error)) {
                return true; // SQL error disclosed
            }
        }

        return false;
    }

    /**
     * Check if search returns unexpected data (SQL Injection success).
     */
    public boolean returnsUnexpectedData(String payload, int expectedResults) {
        search(payload);
        int actualResults = getResultCount();

        // If we get more results than expected, injection may have worked
        return actualResults > expectedResults;
    }
}
