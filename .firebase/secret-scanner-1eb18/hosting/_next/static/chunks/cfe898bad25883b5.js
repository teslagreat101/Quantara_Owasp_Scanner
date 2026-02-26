(globalThis.TURBOPACK||(globalThis.TURBOPACK=[])).push(["object"==typeof document?document.currentScript:void 0,9165,t=>{"use strict";let e=new class{baseUrl;authToken=null;constructor(t="http://localhost:8000"){this.baseUrl=t}setAuthToken(t){this.authToken=t}async request(t,e={}){let a={"Content-Type":"application/json",...e.headers||{}};this.authToken&&(a.Authorization=`Bearer ${this.authToken}`);let r=`${this.baseUrl}${t}`,s=null;for(let t=0;t<3;t++)try{let t=new AbortController,s=setTimeout(()=>t.abort(Error("Timeout")),3e4),i=await fetch(r,{...e,headers:a,signal:t.signal});if(clearTimeout(s),!i.ok){let t=await i.text();throw Error(`API error ${i.status}: ${t}`)}return await i.json()}catch(e){s=e,!(t<2)||e instanceof DOMException||await new Promise(e=>setTimeout(e,1e3*Math.pow(2,t)))}throw s}async getHealth(){return this.request("/api/v1/health")}async getModules(){return(await this.request("/api/v1/modules")).modules}async getProfiles(){return(await this.request("/api/v1/profiles")).profiles}async startScan(t){return this.request("/api/v1/scan/start",{method:"POST",body:JSON.stringify(t)})}async getScanStatus(t){return this.request(`/api/v1/scan/${t}/status`)}async cancelScan(t){return this.request(`/api/v1/scan/${t}/cancel`,{method:"POST"})}async deleteScan(t){return this.request(`/api/v1/scan/${t}`,{method:"DELETE"})}async getScanFindings(t,e={}){let a=new URLSearchParams;e.page&&a.set("page",String(e.page)),e.page_size&&a.set("page_size",String(e.page_size)),e.severity&&a.set("severity",e.severity),e.module&&a.set("module",e.module),e.search&&a.set("search",e.search),e.sort_by&&a.set("sort_by",e.sort_by),e.sort_order&&a.set("sort_order",e.sort_order);let r=a.toString();return this.request(`/api/v1/scan/${t}/findings${r?`?${r}`:""}`)}async getScanReport(t){return this.request(`/api/v1/scan/${t}/report`)}async getScanLogs(t){return this.request(`/api/v1/scan/${t}/logs`)}async getScanHistory(t=50,e=0,a){let r=new URLSearchParams({limit:String(t),offset:String(e)});return a&&r.set("status",a),this.request(`/api/v1/scans?${r.toString()}`)}async getDashboardStats(){return this.request("/api/v1/dashboard/stats")}streamScanEvents(t,e){let a=new EventSource(`${this.baseUrl}/api/v1/scan/${t}/stream`);return a.addEventListener("log",t=>{try{let a=JSON.parse(t.data);e.onLog?.(a)}catch{}}),a.addEventListener("finding",t=>{try{let a=JSON.parse(t.data);e.onFinding?.(a)}catch{}}),a.addEventListener("status",t=>{try{let a=JSON.parse(t.data);e.onStatus?.(a)}catch{}}),a.addEventListener("complete",t=>{try{let r=JSON.parse(t.data);e.onComplete?.(r),a.close()}catch{}}),a.onerror=()=>{e.onError?.(Error("SSE connection error")),a.close()},()=>a.close()}async downloadReport(t,e="json"){var a;let r,s=await this.getScanReport(t);return"json"===e?new Blob([JSON.stringify(s,null,2)],{type:"application/json"}):new Blob([(a=s,r={critical:"#ef4444",high:"#f97316",medium:"#eab308",low:"#22c55e",info:"#6b7280"},`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Scan Report — ${a.target}</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Inter', -apple-system, sans-serif; background: #0B0F0C; color: #A5B3AD; line-height: 1.6; }
        .container { max-width: 1200px; margin: 0 auto; padding: 40px 20px; }
        h1 { color: #00FF88; font-size: 2rem; margin-bottom: 8px; }
        h2 { color: #fff; font-size: 1.5rem; margin: 32px 0 16px; border-bottom: 1px solid rgba(0,255,136,0.15); padding-bottom: 8px; }
        .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin: 24px 0; }
        .stat { background: #111716; border: 1px solid rgba(0,255,136,0.1); border-radius: 12px; padding: 20px; }
        .stat-value { font-size: 2rem; font-weight: 700; color: #00FF88; }
        .stat-label { font-size: 0.875rem; color: #6B7F77; }
        table { width: 100%; border-collapse: collapse; margin: 16px 0; }
        th { background: rgba(0,255,136,0.06); color: #6B7F77; text-align: left; padding: 12px; font-size: 0.75rem; text-transform: uppercase; }
        td { padding: 12px; border-bottom: 1px solid rgba(0,255,136,0.06); font-size: 0.875rem; }
        .sev { display: inline-block; padding: 2px 10px; border-radius: 6px; font-size: 0.75rem; font-weight: 600; }
        .footer { text-align: center; margin-top: 40px; color: #3D4F48; font-size: 0.75rem; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔒 OWASP Security Scan Report</h1>
        <p>Target: <strong style="color:#fff">${a.target}</strong> | Duration: ${a.duration}s | Risk Score: ${a.risk_score}/100</p>

        <div class="summary">
            ${Object.entries(a.summary).map(([t,e])=>`
                <div class="stat">
                    <div class="stat-value" style="color:${r[t]||"#6b7280"}">${e}</div>
                    <div class="stat-label">${t.charAt(0).toUpperCase()+t.slice(1)} Findings</div>
                </div>
            `).join("")}
            <div class="stat">
                <div class="stat-value">${a.total_findings}</div>
                <div class="stat-label">Total Findings</div>
            </div>
        </div>

        <h2>Findings (${a.total_findings})</h2>
        <table>
            <thead><tr><th>Severity</th><th>Title</th><th>File</th><th>CWE</th><th>Module</th></tr></thead>
            <tbody>
                ${a.findings.map(t=>`
                    <tr>
                        <td><span class="sev" style="background:${r[(t.severity||"").toLowerCase()]||"#6b7280"}22;color:${r[(t.severity||"").toLowerCase()]||"#6b7280"}">${t.severity}</span></td>
                        <td style="color:#fff">${t.title}</td>
                        <td style="color:#00FF88;font-family:monospace;font-size:0.75rem">${t.file}:${t.line_number}</td>
                        <td>${t.cwe||"-"}</td>
                        <td>${t.module_name||t.module}</td>
                    </tr>
                `).join("")}
            </tbody>
        </table>

        <div class="footer">
            Generated by Quantum Protocol v5.0 OWASP Scanner — ${new Date().toISOString()}
        </div>
    </div>
</body>
</html>`)],{type:"text/html"})}async getBillingPlans(){return(await this.request("/api/v1/billing/plans")).plans}async getSubscription(){return(await this.request("/api/v1/billing/subscription")).subscription}async createCheckout(t,e,a){return this.request("/api/v1/billing/checkout",{method:"POST",body:JSON.stringify({plan_id:t,success_url:e||`${window.location.origin}/billing?success=true`,cancel_url:a||`${window.location.origin}/billing?canceled=true`})})}async getPaymentMethods(){return(await this.request("/api/v1/billing/payment-methods")).payment_methods}async getInvoices(){return(await this.request("/api/v1/billing/invoices")).invoices}async getUsage(){return this.request("/api/v1/billing/usage")}async cancelSubscription(){return this.request("/api/v1/billing/cancel",{method:"POST"})}async aiAnalyzeFinding(t,e){return this.request("/api/v1/ai/analyze",{method:"POST",body:JSON.stringify({finding_id:t,finding:e})})}async aiChat(t,e){return this.request("/api/v1/ai/chat",{method:"POST",body:JSON.stringify({question:t,context:e})})}async aiPrioritize(t){return this.request("/api/v1/ai/prioritize",{method:"POST",body:JSON.stringify(t)})}};t.s(["api",0,e,"default",0,e])}]);