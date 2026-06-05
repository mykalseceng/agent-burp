package burpmcp.rpc.methods;

import burp.api.montoya.collaborator.CollaboratorServer;
import burp.api.montoya.collaborator.Interaction;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;

import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

final class CollaboratorInteractionSerializer {
    private static final int MAX_HTTP_MESSAGE_LENGTH = 10000;

    private CollaboratorInteractionSerializer() {
    }

    static Map<String, Object> serializeInteraction(Interaction interaction) {
        Map<String, Object> out = new HashMap<>();
        out.put("id", interaction.id().toString());
        out.put("type", interaction.type().name());
        out.put("timestamp", interaction.timeStamp().toString());
        out.put("clientIp", interaction.clientIp() != null ? interaction.clientIp().getHostAddress() : null);
        out.put("clientPort", interaction.clientPort());
        interaction.customData().ifPresent(value -> out.put("customData", value));

        interaction.dnsDetails().ifPresent(details -> {
            Map<String, Object> dns = new HashMap<>();
            dns.put("queryType", details.queryType().name());
            dns.put("query", details.query().toString());
            dns.put("queryBase64", byteArrayToBase64(details.query()));
            out.put("dnsDetails", dns);
        });

        interaction.httpDetails().ifPresent(details -> {
            Map<String, Object> http = new HashMap<>();
            http.put("protocol", details.protocol().toString());
            http.put("requestResponse", serializeRequestResponse(details.requestResponse()));
            out.put("httpDetails", http);
        });

        interaction.smtpDetails().ifPresent(details -> {
            Map<String, Object> smtp = new HashMap<>();
            smtp.put("protocol", details.protocol().name());
            smtp.put("conversation", details.conversation());
            out.put("smtpDetails", smtp);
        });

        return out;
    }

    static Map<String, Object> serializeServer(CollaboratorServer server) {
        Map<String, Object> out = new HashMap<>();
        out.put("address", server.address());
        out.put("literalAddress", server.isLiteralAddress());
        return out;
    }

    private static Map<String, Object> serializeRequestResponse(HttpRequestResponse requestResponse) {
        Map<String, Object> out = new HashMap<>();
        if (requestResponse == null) {
            return out;
        }

        if (requestResponse.httpService() != null) {
            Map<String, Object> service = new HashMap<>();
            service.put("host", requestResponse.httpService().host());
            service.put("port", requestResponse.httpService().port());
            service.put("secure", requestResponse.httpService().secure());
            out.put("httpService", service);
        }

        if (requestResponse.request() != null) {
            Map<String, Object> request = new HashMap<>();
            request.put("method", requestResponse.request().method());
            request.put("url", requestResponse.request().url());
            request.put("headers", headersToList(requestResponse.request().headers()));
            request.put("body", truncate(requestResponse.request().bodyToString(), MAX_HTTP_MESSAGE_LENGTH));
            request.put("raw", truncate(requestResponse.request().toString(), MAX_HTTP_MESSAGE_LENGTH));
            out.put("request", request);
        }

        if (requestResponse.response() != null) {
            Map<String, Object> response = new HashMap<>();
            response.put("statusCode", requestResponse.response().statusCode());
            response.put("headers", headersToList(requestResponse.response().headers()));
            response.put("body", truncate(requestResponse.response().bodyToString(), MAX_HTTP_MESSAGE_LENGTH));
            response.put("raw", truncate(requestResponse.response().toString(), MAX_HTTP_MESSAGE_LENGTH));
            out.put("response", response);
        }

        return out;
    }

    private static List<Map<String, String>> headersToList(List<HttpHeader> headers) {
        List<Map<String, String>> out = new ArrayList<>();
        for (HttpHeader header : headers) {
            Map<String, String> item = new HashMap<>();
            item.put("name", header.name());
            item.put("value", header.value());
            out.add(item);
        }
        return out;
    }

    private static String byteArrayToBase64(ByteArray bytes) {
        return Base64.getEncoder().encodeToString(bytes.getBytes());
    }

    private static String truncate(String value, int maxLength) {
        if (value == null || value.length() <= maxLength) {
            return value;
        }
        return value.substring(0, maxLength) + "... (truncated)";
    }
}
