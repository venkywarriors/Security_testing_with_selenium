/**
 * @author Venkateshwara Doijode 
 *
 * © https://github.com/venkywarriors
 */
import org.zaproxy.clientapi.core.ClientApi;
import org.zaproxy.clientapi.core.ClientApiException;
import org.zaproxy.clientapi.core.ApiResponse;
import org.zaproxy.clientapi.core.ApiResponseElement;

import java.util.List;
import java.util.Map;

/**
 * OWASP ZAP integration for advanced security scanning.
 * Provides methods to control ZAP proxy and retrieve scan results.
 */
public class ZapIntegration {

    private ClientApi zapClient;
    private final String zapHost;
    private final int zapPort;
    private final String apiKey;

    public ZapIntegration() {
        this.zapHost = ConfigReader.getZapHost();
        this.zapPort = ConfigReader.getZapPort();
        this.apiKey = ConfigReader.getZapApiKey();

        if (ConfigReader.isZapEnabled()) {
            initializeClient();
        }
    }

    /**
     * Initialize ZAP client connection.
     */
    private void initializeClient() {
        try {
            zapClient = new ClientApi(zapHost, zapPort, apiKey);
            System.out.println("ZAP Client initialized: " + zapHost + ":" + zapPort);
        } catch (Exception e) {
            System.err.println("Failed to initialize ZAP client: " + e.getMessage());
        }
    }

    /**
     * Check if ZAP is available.
     */
    public boolean isZapAvailable() {
        if (zapClient == null) return false;
        try {
            zapClient.core.version();
            return true;
        } catch (ClientApiException e) {
            return false;
        }
    }

    /**
     * Get ZAP version.
     */
    public String getZapVersion() {
        if (zapClient == null) return "N/A";
        try {
            ApiResponse response = zapClient.core.version();
            return ((ApiResponseElement) response).getValue();
        } catch (ClientApiException e) {
            return "Error: " + e.getMessage();
        }
    }

    /**
     * Start active scan on target URL.
     */
    public String startActiveScan(String targetUrl) {
        if (zapClient == null) return null;
        try {
            ApiResponse response = zapClient.ascan.scan(targetUrl, "True", "False", null, null, null);
            return ((ApiResponseElement) response).getValue();
        } catch (ClientApiException e) {
            System.err.println("Failed to start active scan: " + e.getMessage());
            return null;
        }
    }

    /**
     * Get active scan progress.
     */
    public int getActiveScanProgress(String scanId) {
        if (zapClient == null) return -1;
        try {
            ApiResponse response = zapClient.ascan.status(scanId);
            return Integer.parseInt(((ApiResponseElement) response).getValue());
        } catch (ClientApiException e) {
            return -1;
        }
    }

    /**
     * Wait for active scan to complete.
     */
    public void waitForActiveScan(String scanId) throws InterruptedException {
        int progress = 0;
        while (progress < 100) {
            progress = getActiveScanProgress(scanId);
            System.out.println("Active scan progress: " + progress + "%");
            Thread.sleep(5000);
        }
    }

    /**
     * Start spider scan.
     */
    public String startSpider(String targetUrl) {
        if (zapClient == null) return null;
        try {
            ApiResponse response = zapClient.spider.scan(targetUrl, null, null, null, null);
            return ((ApiResponseElement) response).getValue();
        } catch (ClientApiException e) {
            System.err.println("Failed to start spider: " + e.getMessage());
            return null;
        }
    }

    /**
     * Get spider progress.
     */
    public int getSpiderProgress(String scanId) {
        if (zapClient == null) return -1;
        try {
            ApiResponse response = zapClient.spider.status(scanId);
            return Integer.parseInt(((ApiResponseElement) response).getValue());
        } catch (ClientApiException e) {
            return -1;
        }
    }

    /**
     * Wait for spider to complete.
     */
    public void waitForSpider(String scanId) throws InterruptedException {
        int progress = 0;
        while (progress < 100) {
            progress = getSpiderProgress(scanId);
            System.out.println("Spider progress: " + progress + "%");
            Thread.sleep(2000);
        }
    }

    /**
     * Get alerts/vulnerabilities found.
     */
    public ApiResponse getAlerts(String baseUrl) {
        if (zapClient == null) return null;
        try {
            return zapClient.core.alerts(baseUrl, null, null, null);
        } catch (ClientApiException e) {
            System.err.println("Failed to get alerts: " + e.getMessage());
            return null;
        }
    }

    /**
     * Get high risk alerts count.
     */
    public int getHighAlertCount(String baseUrl) {
        if (zapClient == null) return -1;
        try {
            ApiResponse response = zapClient.alert.alertCountsByRisk(baseUrl, "false");
            // Parse response to get high count
            return parseAlertCount(response, "High");
        } catch (ClientApiException e) {
            return -1;
        }
    }

    /**
     * Generate HTML report.
     */
    public byte[] generateHtmlReport() {
        if (zapClient == null) return null;
        try {
            return zapClient.core.htmlreport();
        } catch (ClientApiException e) {
            System.err.println("Failed to generate report: " + e.getMessage());
            return null;
        }
    }

    /**
     * Generate XML report.
     */
    public byte[] generateXmlReport() {
        if (zapClient == null) return null;
        try {
            return zapClient.core.xmlreport();
        } catch (ClientApiException e) {
            System.err.println("Failed to generate XML report: " + e.getMessage());
            return null;
        }
    }

    /**
     * Clear session/alerts.
     */
    public void clearSession() {
        if (zapClient == null) return;
        try {
            zapClient.core.newSession("", "true");
        } catch (ClientApiException e) {
            System.err.println("Failed to clear session: " + e.getMessage());
        }
    }

    /**
     * Set scan policy.
     */
    public void enableOnlySqlInjection() {
        if (zapClient == null) return;
        try {
            // Disable all scanners first
            zapClient.ascan.disableAllScanners(null);

            // Enable only SQL injection scanners (IDs: 40018, 40019, 40020, 40021, 40022)
            zapClient.ascan.enableScanners("40018,40019,40020,40021,40022", null);
        } catch (ClientApiException e) {
            System.err.println("Failed to set scan policy: " + e.getMessage());
        }
    }

    /**
     * Enable only XSS scanners.
     */
    public void enableOnlyXss() {
        if (zapClient == null) return;
        try {
            zapClient.ascan.disableAllScanners(null);

            // XSS scanner IDs: 40012, 40014, 40016, 40017
            zapClient.ascan.enableScanners("40012,40014,40016,40017", null);
        } catch (ClientApiException e) {
            System.err.println("Failed to set XSS scan policy: " + e.getMessage());
        }
    }

    /**
     * Parse alert count from response.
     */
    private int parseAlertCount(ApiResponse response, String riskLevel) {
        // Implementation depends on ZAP API response structure
        // This is a simplified version
        try {
            String responseStr = response.toString();
            // Parse the response to extract count for risk level
            return 0; // Placeholder
        } catch (Exception e) {
            return -1;
        }
    }

    /**
     * Shutdown ZAP.
     */
    public void shutdown() {
        if (zapClient == null) return;
        try {
            zapClient.core.shutdown();
        } catch (ClientApiException e) {
            System.err.println("Failed to shutdown ZAP: " + e.getMessage());
        }
    }
}