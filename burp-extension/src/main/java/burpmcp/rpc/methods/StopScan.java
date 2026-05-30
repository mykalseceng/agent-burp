package burpmcp.rpc.methods;

import burpmcp.jobs.JobManager;
import burpmcp.rpc.RpcException;
import burpmcp.rpc.RpcMethod;
import com.google.gson.JsonObject;

import java.util.HashMap;
import java.util.Map;

public class StopScan implements RpcMethod {
    private final JobManager jobManager;

    public StopScan(JobManager jobManager) {
        this.jobManager = jobManager;
    }

    @Override
    public String getName() {
        return "stop_scan";
    }

    @Override
    public Object execute(JsonObject params) throws RpcException {
        String jobId = null;
        if (params.has("jobId")) {
            jobId = params.get("jobId").getAsString();
        } else if (params.has("scanId")) {
            jobId = params.get("scanId").getAsString();
        }

        if (jobId == null || jobId.isEmpty()) {
            throw new RpcException(RpcException.INVALID_PARAMS, "jobId or scanId parameter required");
        }

        boolean cancelled = jobManager.cancel(jobId);
        if (!cancelled) {
            throw new RpcException(RpcException.INVALID_PARAMS, "No scan job found with ID: " + jobId);
        }

        Map<String, Object> result = new HashMap<>();
        result.put("jobId", jobId);
        result.put("scanId", jobId);
        result.put("stopped", true);
        result.put("message", "Scan job cancelled: " + jobId);
        return result;
    }
}
