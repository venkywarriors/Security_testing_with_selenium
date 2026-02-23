package com.security.pages;

import com.security.config.ConfigReader;
import org.openqa.selenium.*;
import org.openqa.selenium.support.PageFactory;
import org.openqa.selenium.support.ui.ExpectedConditions;
import org.openqa.selenium.support.ui.WebDriverWait;

import java.time.Duration;
import java.util.List;
import java.util.Set;

/**
 * Base page class with common web interaction methods.
 * All page objects should extend this class.
 */
public abstract class BasePage {

    protected WebDriver driver;
    protected WebDriverWait wait;

    public BasePage(WebDriver driver) {
        this.driver = driver;
        this.wait = new WebDriverWait(driver, Duration.ofSeconds(ConfigReader.getExplicitWait()));
        PageFactory.initElements(driver, this);
    }

    // ================= NAVIGATION =================

/**
 * Navigate to URL
 */
    public void navigateTo(String url) {
        driver.get(url);
    }

/**
 * Get Current URL
 */
    public String getCurrentUrl() {
        return driver.getCurrentUrl();
    }

/**
 * page Title 
 */
    public String getPageTitle() {
        return driver.getTitle();
    }

/**
 * page source 
 */
    public String getPageSource() {
        return driver.getPageSource();
    }

/**
 * page refresh 
 */
    public void refreshPage() {
        driver.navigate().refresh();
    }

/**
 * navigation back 
 */
    public void navigateBack() {
        driver.navigate().back();
    }

    // ================= ELEMENT INTERACTIONS =================

/**
 * wait for element
 */
    protected WebElement waitForElement(By locator) {
        return wait.until(ExpectedConditions.visibilityOfElementLocated(locator));
    }

/**
 * wait for element
 */
    protected WebElement waitForClickable(By locator) {
        return wait.until(ExpectedConditions.elementToBeClickable(locator));
    }

/**
 * wait for element
 */
    protected WebElement waitForPresence(By locator) {
        return wait.until(ExpectedConditions.presenceOfElementLocated(locator));
    }

/**
 * check if element exists 
 */
    protected boolean isElementPresent(By locator) {
        try {
            driver.findElement(locator);
            return true;
        } catch (NoSuchElementException e) {
            return false;
        }
    }

/**
 * check if element exists 
 */
    protected boolean isElementDisplayed(By locator) {
        try {
            return driver.findElement(locator).isDisplayed();
        } catch (NoSuchElementException | StaleElementReferenceException e) {
            return false;
        }
    }

/**
 * click element 
 */
    protected void click(By locator) {
        waitForClickable(locator).click();
    }

/**
 * Type text 
 */
    protected void type(By locator, String text) {
        WebElement element = waitForElement(locator);
        element.clear();
        element.sendKeys(text);
    }

/**
 * get Text 
 */
    protected String getText(By locator) {
        return waitForElement(locator).getText();
    }

/**
 * get attribute 
 */
    protected String getAttribute(By locator, String attribute) {
        return waitForElement(locator).getAttribute(attribute);
    }

/**
 * get all elements 
 */
    protected List<WebElement> getElements(By locator) {
        return driver.findElements(locator);
    }

    // ================= COOKIE MANAGEMENT =================

/**
 * get all cookies 
 */
    public Set<Cookie> getAllCookies() {
        return driver.manage().getCookies();
    }

/**
 * get cookies 
 */
    public Cookie getCookie(String name) {
        return driver.manage().getCookieNamed(name);
    }

/**
 * add cookies 
 */
    public void addCookie(Cookie cookie) {
        driver.manage().addCookie(cookie);
    }

/**
 * delete cookies 
 */
    public void deleteCookie(String name) {
        driver.manage().deleteCookieNamed(name);
    }

/**
 * delete cookies 
 */
    public void deleteAllCookies() {
        driver.manage().deleteAllCookies();
    }
