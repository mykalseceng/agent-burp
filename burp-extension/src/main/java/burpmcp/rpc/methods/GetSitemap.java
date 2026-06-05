package burpmcp.rpc.methods;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.sitemap.SiteMapFilter;
import burp.api.montoya.http.message.HttpRequestResponse;
import burpmcp.rpc.*;
import com.google.gson.JsonObject;

import java.util.*;
import java.util.stream.Collectors;

public class GetSitemap implements RpcMethod {
    private final MontoyaApi api;

    public GetSitemap(MontoyaApi api) {
        this.api = api;
    }

    @Override
    public String getName() {
        return "get_sitemap";
    }

    @Override
    public Object execute(JsonObject params) throws RpcException {
        String domain = params.has("domain") ? params.get("domain").getAsString() : null;
        boolean includeParams = !params.has("includeParams") || params.get("includeParams").getAsBoolean();
        String search = params.has("search") ? params.get("search").getAsString() : null;
        boolean includeMessages = params.has("includeMessages")
            ? params.get("includeMessages").getAsBoolean()
            : search != null && !search.isEmpty();

        List<HttpRequestResponse> items;
        if (domain != null && !domain.isEmpty()) {
            items = new ArrayList<>();
            for (String prefix : sitemapPrefixes(domain)) {
                items.addAll(api.siteMap().requestResponses(SiteMapFilter.prefixFilter(prefix)));
            }
        } else {
            items = api.siteMap().requestResponses();
        }

        List<Map<String, Object>> entries = items.stream()
            .filter(item -> search == null || search.isEmpty() || item.contains(search, false))
            .map(item -> {
                Map<String, Object> entry = new HashMap<>();
                entry.put("source", "sitemap");
                entry.put("url", item.request().url());
                entry.put("method", item.request().method());
                entry.put("statusCode", item.response() != null ? item.response().statusCode() : 0);
                entry.put("mimeType", item.response() != null ? item.response().mimeType().toString() : "");
                entry.put("requestHeaders", GetProxyHistory.headersToMap(item.request().headers()));
                entry.put("requestBody", item.request().bodyToString());
                entry.put("responseHeaders", item.response() != null ? GetProxyHistory.headersToMap(item.response().headers()) : Map.of());
                entry.put("responseBody", item.response() != null ? item.response().bodyToString() : "");
                if (includeParams) {
                    entry.put("parameters", item.request().parameters().stream()
                        .map(p -> p.name())
                        .collect(Collectors.toList()));
                }
                if (includeMessages) {
                    entry.put("request", GetProxyHistory.redactRawMessage(item.request().toString()));
                    entry.put("response", item.response() != null ? GetProxyHistory.redactRawMessage(item.response().toString()) : "");
                }
                return entry;
            })
            .collect(Collectors.toList());

        Map<String, Object> result = new HashMap<>();
        result.put("entries", entries);
        result.put("count", entries.size());

        return result;
    }

    private List<String> sitemapPrefixes(String domain) {
        if (domain.startsWith("http://") || domain.startsWith("https://")) {
            return List.of(domain);
        }
        return List.of("https://" + domain, "http://" + domain);
    }
}
