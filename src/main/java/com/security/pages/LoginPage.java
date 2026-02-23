package com.security.pages;

import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.support.FindBy;

/**
* Login page object for security testing 
    * customize selectors based on your target application 
    */
public class LoginPage extends BasePage {

    // ================= LOCATORS =================
    // Update these selectors to match your target application 

    private static final By USERNAME_INPUT = By.id("username");
    private static final By PASSWORD_INPUT = By.id("password");
    private static final By LOGIN_BUTTON = By.id("loginBtn");
    private static final By ERROR_MESSAGE = By.className("error-message");
    private static final By LOGOUT_LINK = By.id("logout");
    private static final By FORGOT_PASSWORD_LINK = By.linkText("Forgot Password");
    private static final By REMEMBER_ME_CHECKBOX = By.id("rememberMe");

    //Alternative common selectors 
    private static final By USERNAME_BY_NAME = By.id("username");
    private static final By PASSWORD_BY_NAME = By.id("password");
    private static final By LOGIN_BY_TYPE = By.cssSelector("button[type='submit']");
    
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

/*
* Enter username.
 */
    public LoginPage enterUsername(String username) {
        type(USERNAME_INPUT, username);
        return this;
    }

/*
* Enter password.
 */
    public LoginPage enterPassword(String password) {
        type(PASSWORD_INPUT, password);
        return this;
    }

/*
* Click login button. 
*/
    public void clickLogin() {
        click(LOGIN_BUTTON);
    }

/*
* Perform complete login. 
*/
    public void login(String username, String password) {
        enterUsername(username);
        enterPassword(password);
        clickLogin();
    }

/*
* Check if login was successful (user is logged in).
 */
    public boolean isLoggedIn() {
        return isElementPresent(LOGOUT_LINK) ||
                !getCurrentUrl().contains("login");
    }

/*
* Check if error message is displayed. 
*/
    public boolean isErrorDisplayed() {
        return isElementDisplayed(ERROR_MESSAGE);
    }

/*
* Get error message text. 
*/
    public String getErrorMessage() {
        if (isErrorDisplayed()) {
            return getText(ERROR_MESSAGE);
        }
        return "";
    }

/*
* click logout. 
*/
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
