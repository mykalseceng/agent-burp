package burpmcp.rpc.methods;

import burp.api.montoya.MontoyaApi;
import burpmcp.jobs.JobManager;
import burpmcp.rpc.RpcException;
import burpmcp.rpc.RpcMethod;
import com.google.gson.JsonObject;

public class StartScan implements RpcMethod {
    private final ScannerAuditJobService service;

    public StartScan(MontoyaApi api, JobManager jobManager) {
        this.service = new ScannerAuditJobService(api, jobManager);
    }

    @Override
    public String getName() {
        return "start_scan";
    }

    @Override
    public Object execute(JsonObject params) throws RpcException {
        return service.start(params, new ScannerAuditJobService.StartOptions(
            "scan",
            "scanId",
            "Scan",
            "Active scanning requires Burp Suite Professional",
            true
        ));
    }

    public static void clearAllScanTasks() {
        ScannerAuditJobService.clearAllTasks();
    }
}
