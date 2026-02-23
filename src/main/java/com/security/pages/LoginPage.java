package com.security.pages;

import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.support.FindBy;

public class LoginPage extends BasePage {

    // ================= LOCATORS =================

    private static final By USERNAME_INPUT = By.id("username");
    private static final By PASSWORD_INPUT = By.id("password");
    private static final By LOGIN_BUTTON = By.id("loginBtn");
    private static final By ERROR_MESSAGE = By.className("error-message");
    private static final By LOGOUT_LINK = By.id("logout");
    private static final By FORGOT_PASSWORD_LINK = By.linkText("Forgot Password");
    private static final By REMEMBER_ME_CHECKBOX = By.id("rememberMe");

    // ================= PAGE FACTORY =================

    @FindBy(id = "username")
    private WebElement usernameField;

    @FindBy(id = "password")
    private WebElement passwordField;

    @FindBy(id = "loginBtn")
    private WebElement loginButton;

    // ================= CONSTRUCTOR =================

    public LoginPage(WebDriver driver) {
        super(driver);
    }

    // ================= PAGE ACTIONS =================

    public LoginPage enterUsername(String username) {
        type(USERNAME_INPUT, username);
        return this;
    }

    public LoginPage enterPassword(String password) {
        type(PASSWORD_INPUT, password);
        return this;
    }

    public void clickLogin() {
        click(LOGIN_BUTTON);
    }

    public void login(String username, String password) {
        enterUsername(username);
        enterPassword(password);
        clickLogin();
    }

    public boolean isLoggedIn() {
        return isElementPresent(LOGOUT_LINK) ||
                !getCurrentUrl().contains("login");
    }

    public boolean isErrorDisplayed() {
        return isElementDisplayed(ERROR_MESSAGE);
    }

    public String getErrorMessage() {
        if (isErrorDisplayed()) {
            return getText(ERROR_MESSAGE);
        }
        return "";
    }

    public void logout() {
        if (isElementPresent(LOGOUT_LINK)) {
            click(LOGOUT_LINK);
        }
    }

    // ================= SECURITY CHECKS =================

    public boolean isPasswordMasked() {
        return isPasswordField(PASSWORD_INPUT);
    }

    public boolean isUsernameAutocompleteDisabled() {
        return isAutocompleteDisabled(USERNAME_INPUT);
    }

    public boolean isPasswordAutocompleteDisabled() {
        return isAutocompleteDisabled(PASSWORD_INPUT);
    }

    public boolean hasCsrfProtection() {
        WebElement form = driver.findElement(By.tagName("form"));
        return hasCsrfToken(form);
    }

    public String getSessionCookieName() {
        String[] commonNames = {"JSESSIONID", "PHPSESSID", "ASP.NET_SessionId", "session", "sessionid", "sid"};

        for (String name : commonNames) {
            if (getCookie(name) != null) {
                return name;
            }
        }
        return null;
    }

    public String getSessionId() {
        String cookieName = getSessionCookieName();
        if (cookieName != null) {
            return getCookie(cookieName).getValue();
        }
        return null;
    }

    public boolean isSessionCookieSecure() {
        String cookieName = getSessionCookieName();
        return cookieName != null && isCookieSecure(cookieName);
    }

    public boolean isSessionCookieHttpOnly() {
        String cookieName = getSessionCookieName();
        return cookieName != null && isCookieHttpOnly(cookieName);
    }

    public boolean hasVerboseErrorMessage() {
        String errorMsg = getErrorMessage().toLowerCase();

        return errorMsg.contains("user not found") ||
                errorMsg.contains("invalid username") ||
                errorMsg.contains("password incorrect") ||
                errorMsg.contains("no account") ||
                errorMsg.contains("doesn't exist");
    }

    public boolean hasAccountLockout(String username, int maxAttempts) {
        for (int i = 0; i < maxAttempts + 1; i++) {
            login(username, "wrongpassword" + i);

            String error = getErrorMessage().toLowerCase();
            if (error.contains("locked") ||
                    error.contains("blocked") ||
                    error.contains("too many attempts")) {
                return true;
            }
        }
        return false;
    }

    public String testUsernameInjection(String payload) {
        enterUsername(payload);
        enterPassword("test");
        clickLogin();
        return getPageSource();
    }

    public String testPasswordInjection(String payload) {
        enterUsername("test");
        enterPassword(payload);
        clickLogin();
        return getPageSource();
    }

    public String testBothFieldsInjection(String payload) {
        enterUsername(payload);
        enterPassword(payload);
        clickLogin();
        return getPageSource();
    }
}