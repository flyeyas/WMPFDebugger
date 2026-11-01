import { XwebUseClient } from "./client";

// XWeb.EvaluateJavaScript runs a script in the applet's appContext (the
// appservice). Context routing happens server-side: the runtime's
// AppContextResolver probes every execution context with an IIFE that returns
// "__wx_app_context__" when the appservice globals (wx / getCurrentPages /
// App) are present, caches the resolved contextId, and dispatches the script
// there via Runtime.evaluate. No routing fields are needed (or accepted) in
// the command params — see 逆向/evaljs-debuginfo/notes.md §3.
//
// Response shape (per static analysis of cdp_command_evaluate_javascript.cc):
//   {success:true,data:<JSON>,executionTime:<ms>}
//   {success:false,error:{code,message,stack}}
// error codes: JS_SYNTAX_ERROR / JS_RUNTIME_ERROR /
//              RESULT_SERIALIZATION_ERROR / TIMEOUT_ERROR

export type EvaluateResult = {
    success: boolean;
    data?: unknown;
    executionTime?: number;
    error?: { code?: string; message?: string; stack?: string };
};

export const evaluateInAppContext = async (
    client: XwebUseClient,
    script: string,
    timeoutMs = 15000,
): Promise<EvaluateResult> => {
    const raw = await client.call("XWeb.EvaluateJavaScript", {
        script,
        timeout_ms: timeoutMs,
    });

    // the reply envelope is not fully pinned by static analysis; unwrap the
    // known template if present, otherwise surface the raw reply
    const result = (raw ?? {}) as Record<string, unknown>;
    const payload =
        (result.data as Record<string, unknown> | undefined) ??
        (result.result as Record<string, unknown> | undefined) ??
        result;

    if (typeof payload.success === "boolean") {
        return payload as unknown as EvaluateResult;
    }

    return {
        success: false,
        error: { code: "UNKNOWN_ENVELOPE", message: JSON.stringify(raw).slice(0, 500) },
    };
};
