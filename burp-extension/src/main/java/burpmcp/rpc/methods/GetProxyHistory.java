package burpmcp.rpc.methods;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import burpmcp.rpc.*;
import com.google.gson.JsonObject;

import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

public class GetProxyHistory implements RpcMethod {
    private final MontoyaApi api;

    public GetProxyHistory(MontoyaApi api) {
        this.api = api;
    }

    @Override
    public String getName() {
        return "get_proxy_history";
    }

    @Override
    public Object execute(JsonObject params) throws RpcException {
        String domain = params.has("domain") ? params.get("domain").getAsString() : null;
        if (domain == null || domain.isEmpty()) {
            throw new RpcException(RpcException.INVALID_PARAMS, "domain parameter required");
        }

        int limit = params.has("limit") ? params.get("limit").getAsInt() : 50;
        String method = params.has("method") ? params.get("method").getAsString() : null;
        Integer statusCode = params.has("statusCode") ? params.get("statusCode").getAsInt() : null;
        String search = params.has("search") ? params.get("search").getAsString() : null;
        boolean includeMessages = params.has("includeMessages")
            ? params.get("includeMessages").getAsBoolean()
            : search != null && !search.isEmpty();

        List<ProxyHttpRequestResponse> matches = api.proxy().history(item ->
            matchesItem(item, domain, method, statusCode, search)
        );

        List<Map<String, Object>> requests = new ArrayList<>();
        for (ProxyHttpRequestResponse item : matches) {
            if (requests.size() >= limit) {
                break;
            }
            requests.add(toEntry(item, includeMessages));
        }

        Map<String, Object> result = new HashMap<>();
        result.put("requests", requests);
        result.put("total", matches.size());
        result.put("returned", requests.size());

        return result;
    }

    static Map<String, Object> toEntry(ProxyHttpRequestResponse item, boolean includeMessages) {
        HttpRequest request = item.finalRequest();
        HttpResponse response = item.response();

        Map<String, Object> entry = new HashMap<>();
        entry.put("source", "proxy_history");
        entry.put("id", item.id());
        entry.put("timestamp", timestampMillis(item.time()));
        entry.put("method", request.method());
        entry.put("url", request.url());
        entry.put("host", request.httpService().host());
        entry.put("port", request.httpService().port());
        entry.put("isHttps", request.httpService().secure());
        entry.put("requestHeaders", headersToMap(request.headers()));
        entry.put("requestBody", request.bodyToString());
        entry.put("statusCode", response != null ? response.statusCode() : 0);
        entry.put("responseHeaders", response != null ? headersToMap(response.headers()) : Map.of());
        entry.put("responseBody", response != null ? response.bodyToString() : "");
        entry.put("mimeType", response != null ? response.mimeType().toString() : item.mimeType().toString());
        entry.put("listenerPort", item.listenerPort());

        if (includeMessages) {
            entry.put("request", redactRawMessage(item.request().toString()));
            entry.put("response", response != null ? redactRawMessage(response.toString()) : "");
        }

        return entry;
    }

    private static boolean matchesDomain(HttpRequest request, String domain) {
        String needle = domain.toLowerCase();
        String url = request.url().toLowerCase();
        if (needle.startsWith("http://") || needle.startsWith("https://")) {
            return url.startsWith(needle);
        }

        String host = request.httpService().host().toLowerCase();
        return host.equals(needle) || host.endsWith("." + needle) || url.contains(needle);
    }

    private static boolean matchesItem(
        ProxyHttpRequestResponse item,
        String domain,
        String method,
        Integer statusCode,
        String search
    ) {
        try {
            HttpRequest request = item.finalRequest();
            return matchesDomain(request, domain)
                && (method == null || request.method().equalsIgnoreCase(method))
                && (statusCode == null || responseStatus(item) == statusCode)
                && (search == null || search.isEmpty() || item.contains(search, false));
        } catch (Exception e) {
            return false;
        }
    }

    private static int responseStatus(ProxyHttpRequestResponse item) {
        HttpResponse response = item.response();
        return response != null ? response.statusCode() : 0;
    }

    private static long timestampMillis(ZonedDateTime time) {
        return time != null ? time.toInstant().toEpochMilli() : 0;
    }

    static Map<String, String> headersToMap(List<HttpHeader> headers) {
        return headers.stream()
            .collect(Collectors.toMap(
                HttpHeader::name,
                header -> redactHeaderValue(header.name(), header.value()),
                (v1, v2) -> v1 + ", " + v2
            ));
    }

    static String redactRawMessage(String message) {
        if (message == null || message.isEmpty()) {
            return "";
        }

        StringBuilder out = new StringBuilder(message.length());
        String[] lines = message.split("\\r?\\n", -1);
        for (int i = 0; i < lines.length; i++) {
            String line = lines[i];
            int colon = line.indexOf(':');
            if (colon > 0) {
                String name = line.substring(0, colon);
                if (isSensitiveHeader(name)) {
                    line = name + ": <redacted>";
                }
            }
            if (i > 0) {
                out.append('\n');
            }
            out.append(line);
        }
        return out.toString();
    }

    private static String redactHeaderValue(String name, String value) {
        return isSensitiveHeader(name) ? "<redacted>" : value;
    }

    private static boolean isSensitiveHeader(String name) {
        String lower = name.toLowerCase();
        return lower.equals("authorization")
            || lower.equals("proxy-authorization")
            || lower.equals("cookie")
            || lower.equals("set-cookie");
    }
}
