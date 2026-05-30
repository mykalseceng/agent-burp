package burpmcp.rpc.methods;

import burpmcp.jobs.JobManager;
import burpmcp.rpc.RpcException;
import burpmcp.rpc.RpcMethod;
import com.google.gson.JsonObject;

import java.util.HashMap;
import java.util.Map;

public class StopAudit implements RpcMethod {
    private final JobManager jobManager;

    public StopAudit(JobManager jobManager) {
        this.jobManager = jobManager;
    }

    @Override
    public String getName() {
        return "stop_audit";
    }

    @Override
    public Object execute(JsonObject params) throws RpcException {
        String jobId = null;
        if (params.has("jobId")) {
            jobId = params.get("jobId").getAsString();
        } else if (params.has("auditId")) {
            jobId = params.get("auditId").getAsString();
        }

        if (jobId == null || jobId.isEmpty()) {
            throw new RpcException(RpcException.INVALID_PARAMS, "jobId or auditId parameter required");
        }

        boolean cancelled = jobManager.cancel(jobId);
        if (!cancelled) {
            throw new RpcException(RpcException.INVALID_PARAMS, "No audit job found with ID: " + jobId);
        }

        Map<String, Object> result = new HashMap<>();
        result.put("jobId", jobId);
        result.put("auditId", jobId);
        result.put("stopped", true);
        result.put("message", "Audit job cancelled: " + jobId);
        return result;
    }
}
