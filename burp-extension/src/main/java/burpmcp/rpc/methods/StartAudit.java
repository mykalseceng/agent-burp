package burpmcp.rpc.methods;

import burp.api.montoya.MontoyaApi;
import burpmcp.jobs.JobManager;
import burpmcp.rpc.RpcException;
import burpmcp.rpc.RpcMethod;
import com.google.gson.JsonObject;

public class StartAudit implements RpcMethod {
    private final ScannerAuditJobService service;

    public StartAudit(MontoyaApi api, JobManager jobManager) {
        this.service = new ScannerAuditJobService(api, jobManager);
    }

    @Override
    public String getName() {
        return "start_audit";
    }

    @Override
    public Object execute(JsonObject params) throws RpcException {
        return service.start(params, new ScannerAuditJobService.StartOptions(
            "audit",
            "auditId",
            "Audit",
            "Audit requires Burp Suite Professional",
            false
        ));
    }
}
