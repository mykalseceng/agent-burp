package burpmcp.rpc.methods;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import burpmcp.rpc.*;
import burpmcp.traffic.TrafficStore;
import burpmcp.traffic.StoredRequest;
import com.google.gson.JsonObject;

import java.util.List;

public class GetProxyHistoryItem implements RpcMethod {
    private final MontoyaApi api;
    private final TrafficStore store;

    public GetProxyHistoryItem(MontoyaApi api, TrafficStore store) {
        this.api = api;
        this.store = store;
    }

    @Override
    public String getName() {
        return "get_proxy_history_item";
    }

    @Override
    public Object execute(JsonObject params) throws RpcException {
        if (!params.has("id")) {
            throw new RpcException(RpcException.INVALID_PARAMS, "id parameter required");
        }

        long id = params.get("id").getAsLong();
        List<ProxyHttpRequestResponse> matches = api.proxy().history(item -> item.id() == id);
        if (!matches.isEmpty()) {
            return GetProxyHistory.toEntry(matches.get(0), true);
        }

        StoredRequest request = store.getById(id);
        if (request == null) {
            throw new RpcException(RpcException.INVALID_PARAMS, "No request found with id " + id);
        }

        return request;
    }
}
