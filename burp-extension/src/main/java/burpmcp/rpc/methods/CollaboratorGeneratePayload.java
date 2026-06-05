package burpmcp.rpc.methods;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.collaborator.CollaboratorClient;
import burp.api.montoya.collaborator.CollaboratorPayload;
import burp.api.montoya.collaborator.PayloadOption;
import burp.api.montoya.collaborator.SecretKey;
import burpmcp.rpc.RpcException;
import burpmcp.rpc.RpcMethod;
import com.google.gson.JsonObject;

import java.util.HashMap;
import java.util.Map;

public class CollaboratorGeneratePayload implements RpcMethod {
    private final MontoyaApi api;

    public CollaboratorGeneratePayload(MontoyaApi api) {
        this.api = api;
    }

    @Override
    public String getName() {
        return "collaborator_generate_payload";
    }

    @Override
    public Object execute(JsonObject params) throws RpcException {
        String secretKey = stringParam(params, "secretKey");
        String customData = stringParam(params, "customData");
        boolean withoutServerLocation = params.has("withoutServerLocation")
            && params.get("withoutServerLocation").getAsBoolean();

        if (customData != null && !customData.matches("[A-Za-z0-9]{1,16}")) {
            throw new RpcException(
                RpcException.INVALID_PARAMS,
                "customData must be 1-16 alphanumeric characters"
            );
        }

        try {
            CollaboratorClient client = secretKey == null
                ? api.collaborator().createClient()
                : api.collaborator().restoreClient(SecretKey.secretKey(secretKey));
            PayloadOption[] options = withoutServerLocation
                ? new PayloadOption[]{PayloadOption.WITHOUT_SERVER_LOCATION}
                : new PayloadOption[0];
            CollaboratorPayload payload = customData == null
                ? client.generatePayload(options)
                : client.generatePayload(customData, options);

            Map<String, Object> out = new HashMap<>();
            out.put("payload", payload.toString());
            out.put("id", payload.id().toString());
            payload.customData().ifPresent(value -> out.put("customData", value));
            payload.server().ifPresent(server ->
                out.put("server", CollaboratorInteractionSerializer.serializeServer(server)));
            out.put("secretKey", client.getSecretKey().toString());
            out.put("restoredClient", secretKey != null);
            return out;
        } catch (IllegalArgumentException e) {
            throw new RpcException(RpcException.INVALID_PARAMS, e.getMessage());
        } catch (UnsupportedOperationException e) {
            throw new RpcException(RpcException.PRO_REQUIRED, collaboratorUnavailableMessage(e));
        } catch (RuntimeException e) {
            throw new RpcException(RpcException.INTERNAL_ERROR, "Collaborator payload generation failed: " + e.getMessage());
        }
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
