package burpmcp.rpc.methods;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.collaborator.CollaboratorClient;
import burp.api.montoya.collaborator.Interaction;
import burp.api.montoya.collaborator.InteractionFilter;
import burp.api.montoya.collaborator.SecretKey;
import burpmcp.rpc.RpcException;
import burpmcp.rpc.RpcMethod;
import com.google.gson.JsonObject;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class CollaboratorGetInteractions implements RpcMethod {
    private final MontoyaApi api;

    public CollaboratorGetInteractions(MontoyaApi api) {
        this.api = api;
    }

    @Override
    public String getName() {
        return "collaborator_get_interactions";
    }

    @Override
    public Object execute(JsonObject params) throws RpcException {
        String secretKey = stringParam(params, "secretKey");
        if (secretKey == null) {
            throw new RpcException(RpcException.INVALID_PARAMS, "secretKey parameter required");
        }

        String interactionId = stringParam(params, "interactionId");
        String payload = stringParam(params, "payload");
        if (interactionId != null && payload != null) {
            throw new RpcException(RpcException.INVALID_PARAMS, "specify only one of interactionId or payload");
        }

        int limit = params.has("limit") ? params.get("limit").getAsInt() : 100;
        int offset = params.has("offset") ? params.get("offset").getAsInt() : 0;
        if (limit < 0 || offset < 0) {
            throw new RpcException(RpcException.INVALID_PARAMS, "limit and offset must be non-negative");
        }

        try {
            CollaboratorClient client = api.collaborator().restoreClient(SecretKey.secretKey(secretKey));
            List<Interaction> all = filteredInteractions(client, interactionId, payload);
            List<Map<String, Object>> interactions = new ArrayList<>();
            int total = all.size();
            int end = Math.min(offset + limit, total);
            for (int i = offset; i < end; i++) {
                interactions.add(CollaboratorInteractionSerializer.serializeInteraction(all.get(i)));
            }

            Map<String, Object> out = new HashMap<>();
            out.put("interactions", interactions);
            out.put("total", total);
            out.put("returned", interactions.size());
            out.put("offset", offset);
            out.put("secretKey", client.getSecretKey().toString());
            out.put("server", CollaboratorInteractionSerializer.serializeServer(client.server()));
            return out;
        } catch (IllegalArgumentException e) {
            throw new RpcException(RpcException.INVALID_PARAMS, e.getMessage());
        } catch (UnsupportedOperationException e) {
            throw new RpcException(RpcException.PRO_REQUIRED, collaboratorUnavailableMessage(e));
        } catch (RuntimeException e) {
            throw new RpcException(RpcException.INTERNAL_ERROR, "Collaborator interaction polling failed: " + e.getMessage());
        }
    }

    private List<Interaction> filteredInteractions(CollaboratorClient client, String interactionId, String payload) {
        if (interactionId != null) {
            return client.getInteractions(InteractionFilter.interactionIdFilter(interactionId));
        }
        if (payload != null) {
            return client.getInteractions(InteractionFilter.interactionPayloadFilter(payload));
        }
        return client.getAllInteractions();
    }

    private String stringParam(JsonObject params, String name) {
        if (!params.has(name) || params.get(name).isJsonNull()) {
            return null;
        }
        String value = params.get(name).getAsString();
        return value.isBlank() ? null : value;
    }

    private String collaboratorUnavailableMessage(RuntimeException e) {
        return e.getMessage() != null ? e.getMessage() : "Burp Collaborator is unavailable";
    }
}
