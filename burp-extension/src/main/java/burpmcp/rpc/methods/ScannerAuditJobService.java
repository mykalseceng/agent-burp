package burpmcp.rpc.methods;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.AuditConfiguration;
import burp.api.montoya.scanner.BuiltInAuditConfiguration;
import burp.api.montoya.scanner.Crawl;
import burp.api.montoya.scanner.CrawlConfiguration;
import burp.api.montoya.scanner.ScanTask;
import burp.api.montoya.scanner.audit.Audit;
import burp.api.montoya.sitemap.SiteMapFilter;
import burpmcp.jobs.JobContext;
import burpmcp.jobs.JobManager;
import burpmcp.rpc.RpcException;
import com.google.gson.JsonObject;

import java.net.URI;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ConcurrentHashMap;

class ScannerAuditJobService {
    private static final int DEFAULT_AUDIT_IDLE_LIMIT_SECONDS = 8;
    private static final int DEFAULT_CRAWL_IDLE_LIMIT_SECONDS = 30;
    private static final int DEFAULT_CRAWL_MAX_RUNTIME_SECONDS = 300;
    private static final int DEFAULT_MAX_AUDIT_ITEMS = 200;

    private static final Map<String, List<ScanTask>> tasksByJobId = new ConcurrentHashMap<>();

    private final MontoyaApi api;
    private final JobManager jobManager;

    ScannerAuditJobService(MontoyaApi api, JobManager jobManager) {
        this.api = api;
        this.jobManager = jobManager;
    }

    Map<String, Object> start(JsonObject params, StartOptions options) throws RpcException {
        try {
            api.scanner();
        } catch (UnsupportedOperationException e) {
            throw new RpcException(RpcException.PRO_REQUIRED, options.proRequiredMessage);
        }

        String url = params.has("url") ? params.get("url").getAsString() : null;
        if (url == null || url.isEmpty()) {
            throw new RpcException(RpcException.INVALID_PARAMS, "url parameter required");
        }

        boolean doCrawl = options.allowCrawl && params.has("crawl") && params.get("crawl").getAsBoolean();
        boolean fromSitemap = params.has("fromSitemap") && params.get("fromSitemap").getAsBoolean();
        String sitemapPrefix = params.has("sitemapPrefix")
            ? params.get("sitemapPrefix").getAsString()
            : sitemapOriginPrefix(url);
        int maxAuditItems = boundedInt(params, "maxAuditItems", DEFAULT_MAX_AUDIT_ITEMS, 1, 5000);
        int auditIdleLimitSeconds = boundedInt(params, "auditIdleLimitSeconds", DEFAULT_AUDIT_IDLE_LIMIT_SECONDS, 3, 3600);
        int crawlIdleLimitSeconds = boundedInt(params, "crawlIdleLimitSeconds", DEFAULT_CRAWL_IDLE_LIMIT_SECONDS, 3, 3600);
        int crawlMaxRuntimeSeconds = boundedInt(params, "crawlMaxRuntimeSeconds", DEFAULT_CRAWL_MAX_RUNTIME_SECONDS, 0, 86400);
        if (crawlMaxRuntimeSeconds > 0 && crawlMaxRuntimeSeconds < crawlIdleLimitSeconds) {
            crawlMaxRuntimeSeconds = crawlIdleLimitSeconds;
        }

        final boolean crawlEnabled = doCrawl;
        final boolean sitemapSourceEnabled = fromSitemap || doCrawl;
        final String finalSitemapPrefix = sitemapPrefix;
        final int finalMaxAuditItems = maxAuditItems;
        final int finalAuditIdleLimitSeconds = auditIdleLimitSeconds;
        final int finalCrawlIdleLimitSeconds = crawlIdleLimitSeconds;
        final int finalCrawlMaxRuntimeSeconds = crawlMaxRuntimeSeconds;

        String jobId = jobManager.submit(options.jobType, ctx -> {
            ctx.setStage("starting");
            ctx.setProgress(5);
            String currentJobId = String.valueOf(ctx.getDetail("jobId"));
            ctx.putDetail("targetUrl", url);
            ctx.putDetail("crawlEnabled", crawlEnabled);
            ctx.putDetail("fromSitemap", sitemapSourceEnabled);
            ctx.putDetail("sitemapPrefix", finalSitemapPrefix);
            ctx.putDetail("maxAuditItems", finalMaxAuditItems);
            ctx.putDetail("auditIdleLimitSeconds", finalAuditIdleLimitSeconds);

            Audit audit = null;

            try {
                if (crawlEnabled) {
                    startAndWaitForCrawl(ctx, currentJobId, url, finalCrawlIdleLimitSeconds, finalCrawlMaxRuntimeSeconds);
                }

                List<HttpRequestResponse> sitemapItems = sitemapSourceEnabled
                    ? collectSitemapItems(finalSitemapPrefix, finalMaxAuditItems)
                    : List.of();
                ctx.putDetail("sitemapRequestCount", sitemapItems.size());

                ctx.setStage("auditing");
                ctx.setProgress(crawlEnabled ? 55 : 20);

                AuditConfiguration auditConfig = AuditConfiguration.auditConfiguration(BuiltInAuditConfiguration.LEGACY_ACTIVE_AUDIT_CHECKS);
                audit = api.scanner().startAudit(auditConfig);
                trackTask(currentJobId, audit);

                int submittedRequests = addRequestsToAudit(audit, url, sitemapItems);
                ctx.putDetail("submittedAuditItemCount", submittedRequests);
                ctx.putDetail("requestSource", sitemapItems.isEmpty() ? "seed_url" : "sitemap");

                waitForAudit(ctx, audit, crawlEnabled ? 60 : 25, finalAuditIdleLimitSeconds);

                if (ctx.isCancelled()) {
                    deleteTrackedTasks(currentJobId);
                    throw new InterruptedException(options.displayName + " job cancelled");
                }

                int issueCount = audit.issues() == null ? 0 : audit.issues().size();
                ctx.putDetail("issueCount", issueCount);
                ctx.setProgress(100);

                Map<String, Object> out = new HashMap<>();
                out.put("targetUrl", url);
                out.put("crawlEnabled", crawlEnabled);
                out.put("fromSitemap", sitemapSourceEnabled);
                out.put("requestSource", sitemapItems.isEmpty() ? "seed_url" : "sitemap");
                out.put("submittedAuditItemCount", submittedRequests);
                out.put("issueCount", issueCount);
                out.put("message", options.displayName + " completed for: " + url);
                return out;
            } finally {
                deleteTrackedTasks(currentJobId);
                tasksByJobId.remove(currentJobId);
            }
        }, ScannerAuditJobService::cancelTask);

        Map<String, Object> result = new HashMap<>();
        result.put("jobId", jobId);
        result.put(options.idField, jobId);
        result.put("status", "queued");
        result.put("targetUrl", url);
        result.put("crawlEnabled", crawlEnabled);
        result.put("fromSitemap", sitemapSourceEnabled);
        result.put("message", options.displayName + " job queued for: " + url);
        return result;
    }

    private void startAndWaitForCrawl(
        JobContext ctx,
        String jobId,
        String url,
        int idleLimitSeconds,
        int maxRuntimeSeconds
    ) throws Exception {
        ctx.setStage("crawling");
        ctx.setProgress(10);
        ctx.putDetail("crawlIdleLimitSeconds", idleLimitSeconds);
        ctx.putDetail("crawlMaxRuntimeSeconds", maxRuntimeSeconds);

        Crawl crawl = api.scanner().startCrawl(CrawlConfiguration.crawlConfiguration(url));
        trackTask(jobId, crawl);

        int idle = 0;
        int lastCount = -1;
        int activeLoops = 0;
        while (!ctx.isCancelled()) {
            int count = crawl.requestCount();
            ctx.putDetail("crawlRequestCount", count);
            ctx.putDetail("crawlErrorCount", crawl.errorCount());

            if (count == lastCount) {
                idle++;
            } else {
                idle = 0;
            }
            lastCount = count;
            activeLoops++;

            if (maxRuntimeSeconds > 0 && activeLoops >= maxRuntimeSeconds) {
                break;
            }
            if (idle >= idleLimitSeconds) {
                break;
            }

            ctx.setProgress(Math.min(50, 10 + count));
            Thread.sleep(1000);
        }

        if (ctx.isCancelled()) {
            deleteQuietly(crawl);
            throw new InterruptedException("crawl cancelled");
        }

        deleteQuietly(crawl);
        ctx.putDetail("crawlRuntimeSeconds", activeLoops);
    }

    private void waitForAudit(JobContext ctx, Audit audit, int baseProgress, int idleLimitSeconds) throws Exception {
        int idleLoops = 0;
        int lastActivityCount = -1;
        while (!ctx.isCancelled()) {
            int auditRequests = audit.requestCount();
            ctx.putDetail("auditRequestCount", auditRequests);
            ctx.putDetail("auditErrorCount", audit.errorCount());
            ctx.putDetail("auditInsertionPointCount", audit.insertionPointCount());

            if (auditRequests == lastActivityCount) {
                idleLoops++;
            } else {
                idleLoops = 0;
            }
            lastActivityCount = auditRequests;

            if (idleLoops >= idleLimitSeconds) {
                break;
            }

            ctx.setProgress(Math.min(95, baseProgress + Math.max(1, auditRequests)));
            Thread.sleep(1000);
        }
    }

    private int addRequestsToAudit(Audit audit, String url, List<HttpRequestResponse> sitemapItems) {
        if (sitemapItems.isEmpty()) {
            audit.addRequest(HttpRequest.httpRequestFromUrl(url));
            return 1;
        }

        int count = 0;
        for (HttpRequestResponse item : sitemapItems) {
            if (item == null || item.request() == null) {
                continue;
            }
            if (item.hasResponse()) {
                audit.addRequestResponse(item);
            } else {
                audit.addRequest(item.request());
            }
            count++;
        }

        if (count == 0) {
            audit.addRequest(HttpRequest.httpRequestFromUrl(url));
            return 1;
        }
        return count;
    }

    private List<HttpRequestResponse> collectSitemapItems(String prefix, int maxItems) {
        Map<String, HttpRequestResponse> byKey = new LinkedHashMap<>();

        for (HttpRequestResponse item : api.siteMap().requestResponses(SiteMapFilter.prefixFilter(prefix))) {
            if (item == null || item.request() == null) {
                continue;
            }
            String key = item.request().method() + " " + item.request().url();
            byKey.putIfAbsent(key, item);
            if (byKey.size() >= maxItems) {
                break;
            }
        }

        return new ArrayList<>(byKey.values());
    }

    private String sitemapOriginPrefix(String rawUrl) {
        try {
            URI uri = URI.create(rawUrl);
            if (uri.getScheme() == null || uri.getHost() == null) {
                return rawUrl;
            }
            StringBuilder prefix = new StringBuilder();
            prefix.append(uri.getScheme()).append("://").append(uri.getHost());
            if (uri.getPort() != -1) {
                prefix.append(":").append(uri.getPort());
            }
            return prefix.toString();
        } catch (IllegalArgumentException e) {
            return rawUrl;
        }
    }

    private static int boundedInt(JsonObject params, String key, int defaultValue, int min, int max) {
        int value = params.has(key) ? params.get(key).getAsInt() : defaultValue;
        if (value < min) {
            return min;
        }
        return Math.min(value, max);
    }

    private static void cancelTask(String jobId) {
        deleteTrackedTasks(jobId);
        tasksByJobId.remove(jobId);
    }

    private static void trackTask(String jobId, ScanTask task) {
        if (task == null) {
            return;
        }
        tasksByJobId.computeIfAbsent(jobId, ignored -> new CopyOnWriteArrayList<>()).add(task);
    }

    private static void deleteTrackedTasks(String jobId) {
        List<ScanTask> tasks = tasksByJobId.get(jobId);
        if (tasks == null) {
            return;
        }
        for (ScanTask task : tasks) {
            deleteQuietly(task);
        }
        tasks.clear();
    }

    private static void deleteQuietly(ScanTask task) {
        if (task != null) {
            try { task.delete(); } catch (Exception ignored) {}
        }
    }

    static void clearAllTasks() {
        tasksByJobId.clear();
    }

    static class StartOptions {
        final String jobType;
        final String idField;
        final String displayName;
        final String proRequiredMessage;
        final boolean allowCrawl;

        StartOptions(String jobType, String idField, String displayName, String proRequiredMessage, boolean allowCrawl) {
            this.jobType = jobType;
            this.idField = idField;
            this.displayName = displayName;
            this.proRequiredMessage = proRequiredMessage;
            this.allowCrawl = allowCrawl;
        }
    }
}
