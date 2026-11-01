import { Logger } from "./logger";

// Response bodies never traverse the debug channel: the __networkDebug
// reporter only emits CDP metadata events (dataReceived carries lengths, not
// bytes) and the runtime cannot serve Network.getResponseBody for appservice
// requests. This hook closes the gap WITHOUT any new frida work:
//
//   1. the proxy sends its own Runtime.enable over the existing relay path;
//   2. every Runtime.executionContextCreated is probed with the same IIFE the
//      runtime's native AppContextResolver uses (typeof wx/getCurrentPages/
//      App -> '__wx_app_context__') to locate the appservice context;
//   3. a wx.request wrapper is injected INTO that context (contextId) and
//      captures are polled from a global buffer;
//   4. captures are logged and answer Network.getResponseBody so the DevTools
//      Response tab works.

export const SYNTH_EVAL_ID_BASE = 900000;

const GLOBAL_REF =
    "(typeof globalThis !== 'undefined' ? globalThis : (typeof global !== 'undefined' ? global : this))";

// context identification probe — identical semantics to the native
// AppContextResolver probe (see 逆向/evaljs-debuginfo/notes.md §3)
const PROBE_EXPR = `(function(){try{if(typeof wx==='object'&&typeof getCurrentPages==='function'&&typeof App==='function')return '__wx_app_context__';}catch(e){}return '';})()`;

// verification probe: distinguishes "alive + hook installed" from "alive but
// hook missing" — executionContextsCleared fires on webview navigations even
// though the appservice context survives
const VERIFY_EXPR = `(function(){try{var g=${GLOBAL_REF};if(typeof wx==='object'&&typeof getCurrentPages==='function'&&typeof App==='function'){return g.__wmpfBodyHook?'__wx_app_hooked__':'__wx_app_context__';}}catch(e){}return '';})()`;

const INJECT_EXPR = `(function(){try{var g=${GLOBAL_REF};if(typeof wx==='undefined'||!wx.request)return 'no-wx';if(g.__wmpfBodyHook)return 'already';g.__wmpfBodyHook=true;g.__wmpfBodies=[];var origRequest=wx.request;wx.request=function(opts){if(!opts||typeof opts.success!=='function'){return origRequest.call(this,opts);}var userSuccess=opts.success;opts.success=function(res){try{var data=res&&res.data;g.__wmpfBodies.push({url:String(opts.url||''),method:String(opts.method||'GET').toUpperCase(),status:res&&res.statusCode,body:typeof data==='string'?data:JSON.stringify(data),ts:Date.now()});if(g.__wmpfBodies.length>200){g.__wmpfBodies.splice(0,g.__wmpfBodies.length-200);}}catch(e){}return userSuccess.apply(this,arguments);};return origRequest.call(this,opts);};return 'ok';}catch(e){return 'err:'+(e&&e.message);}})()`;

const POLL_EXPR = `(function(){
  try {
    var g = ${GLOBAL_REF};
    if (!g.__wmpfBodies) return null;
    if (!g.__wmpfBodies.length) return null;
    return JSON.stringify(g.__wmpfBodies.splice(0, 20));
  } catch (e) { return null; }
})()`;

type BodyCapture = {
    url?: unknown;
    method?: unknown;
    status?: unknown;
    body?: unknown;
    ts?: unknown;
};

type PendingEval = {
    kind: "probe" | "verify" | "inject" | "poll";
    contextId?: number;
};

// after a lost appContext, sweep small context ids — the runtime allocates
// execution contexts as small integers (3, 4, 8, 9 observed); evaluate on a
// non-existent id returns an agent error (undefined value), which
// distinguishes it from a live non-app context ('' result)
const BLIND_SWEEP_MAX_ID = 64;
const BLIND_SWEEP_BATCH = 6;
const VERIFY_FAILS_BEFORE_RESET = 2;

const BODY_LOG_CAP = 4000;

export class BodyHook {
    private miniappConnected = false;
    private injected = false;
    private appContextId: number | null = null;
    private nextEvalId = SYNTH_EVAL_ID_BASE;
    private pending = new Map<number, PendingEval>();
    private probedContexts = new Set<number>();
    private lastInjectError = "";
    private nonAppProbeLogs = 0;
    private verifyFails = 0;
    private blindSweepNextId = 1;
    private blindSweepActive = false;
    private fifo = new Map<string, BodyCapture[]>();

    /** total captures pulled out of the appservice buffer */
    bodies = 0;

    constructor(
        private readonly logger: Logger,
        private readonly sendCommand: (command: Record<string, unknown>) => void,
    ) {
        const timer = setInterval(() => this.tick(), 2500);
        timer.unref();
    }

    setMiniappConnected(connected: boolean): void {
        this.miniappConnected = connected;
        if (connected) {
            // replay existing execution contexts: the agent answers enable
            // with executionContextCreated for every live context
            this.sendCommand({ method: "Runtime.enable" });
        } else {
            this.reset();
        }
    }

    private reset(): void {
        this.injected = false;
        this.appContextId = null;
        this.probedContexts.clear();
        this.pending.clear();
        this.verifyFails = 0;
        this.blindSweepActive = true;
        this.blindSweepNextId = 1;
    }

    private sendEval(expression: string, meta: PendingEval): void {
        const id = this.nextEvalId++;
        this.pending.set(id, meta);
        const params: Record<string, unknown> = {
            expression,
            returnByValue: true,
        };
        if (meta.contextId !== undefined) {
            params.contextId = meta.contextId;
        }
        this.sendCommand({ id, method: "Runtime.evaluate", params });
    }

    /** Called for every Runtime.executionContextCreated seen on the relay. */
    onExecutionContextCreated(contextId: number): void {
        if (!this.miniappConnected || this.probedContexts.has(contextId)) {
            return;
        }
        this.probedContexts.add(contextId);
        this.sendEval(PROBE_EXPR, { kind: "probe", contextId });
    }

    onExecutionContextsCleared(): void {
        if (!this.miniappConnected) {
            return;
        }
        // cleared usually fires on webview navigation while the appservice
        // context survives — verify before tearing down our state
        if (this.appContextId !== null) {
            this.sendEval(VERIFY_EXPR, {
                kind: "verify",
                contextId: this.appContextId,
            });
        } else {
            this.reset();
        }
        // discover any genuinely new contexts (webview frames re-created)
        this.sendCommand({ method: "Runtime.enable" });
    }

    private tick(): void {
        if (!this.miniappConnected) {
            return;
        }
        if (this.appContextId !== null) {
            if (!this.injected) {
                this.sendEval(INJECT_EXPR, { kind: "inject", contextId: this.appContextId });
            } else {
                this.sendEval(POLL_EXPR, { kind: "poll", contextId: this.appContextId });
            }
            return;
        }
        // blind sweep: re-locate the appservice context after a lost appContext
        if (this.blindSweepActive) {
            for (let i = 0; i < BLIND_SWEEP_BATCH && this.blindSweepNextId <= BLIND_SWEEP_MAX_ID; i++) {
                const candidate = this.blindSweepNextId++;
                if (candidate === 1) {
                    continue; // page context, always non-app
                }
                this.sendEval(VERIFY_EXPR, { kind: "probe", contextId: candidate });
            }
            if (this.blindSweepNextId > BLIND_SWEEP_MAX_ID) {
                this.logger.error(
                    "[body] blind sweep exhausted without finding the appContext; " +
                        "will retry on the next contextCreated event",
                );
                this.blindSweepActive = false;
            }
        }
    }

    /** Returns true when the response id belonged to the hook (consumed). */
    handleSyntheticResponse(id: number, payload: string): boolean {
        if (id < SYNTH_EVAL_ID_BASE) {
            return false;
        }
        const meta = this.pending.get(id);
        this.pending.delete(id);
        if (!meta) {
            return true;
        }
        let value: unknown;
        try {
            const parsed = JSON.parse(payload) as {
                result?: { result?: { value?: unknown } };
            };
            value = parsed?.result?.result?.value;
        } catch {
            return true;
        }

        if (meta.kind === "probe") {
            if (value === "__wx_app_context__" || value === "__wx_app_hooked__") {
                this.appContextId = meta.contextId ?? null;
                this.blindSweepActive = false;
                if (value === "__wx_app_hooked__") {
                    // surviving hook from before we lost track — resume polling
                    this.injected = true;
                    this.logger.info(
                        `[body] appContext found with live hook (contextId=${this.appContextId})`,
                    );
                } else {
                    this.injected = false;
                    this.logger.info(
                        `[body] appContext resolved (contextId=${this.appContextId}), injecting hook`,
                    );
                    // inject immediately — the context can die before the next tick
                    this.sendEval(INJECT_EXPR, {
                        kind: "inject",
                        contextId: this.appContextId ?? undefined,
                    });
                }
            } else if (this.nonAppProbeLogs < 5) {
                this.nonAppProbeLogs += 1;
                this.logger.info(
                    `[body] context ${meta.contextId} is not appservice (probe=${JSON.stringify(value)})`,
                );
            }
            return true;
        }

        if (meta.kind === "verify") {
            if (value === "__wx_app_hooked__") {
                this.verifyFails = 0;
                this.logger.info(
                    `[body] appContext survived cleared (contextId=${meta.contextId}), hook still installed`,
                );
            } else if (value === "__wx_app_context__") {
                // context alive but fresh (hook gone) — re-inject
                this.verifyFails = 0;
                this.injected = false;
                this.logger.info(
                    `[body] appContext alive without hook (contextId=${meta.contextId}), re-injecting`,
                );
                this.sendEval(INJECT_EXPR, {
                    kind: "inject",
                    contextId: meta.contextId,
                });
            } else {
                // '' or undefined — retry before declaring the context dead:
                // transient agent hiccups must not blind us (no enable replay
                // exists, so losing the contextId means losing the hook)
                this.verifyFails += 1;
                if (this.verifyFails < VERIFY_FAILS_BEFORE_RESET && meta.contextId) {
                    this.sendEval(VERIFY_EXPR, {
                        kind: "verify",
                        contextId: meta.contextId,
                    });
                } else {
                    this.logger.info(
                        `[body] appContext ${meta.contextId} unusable after ${this.verifyFails} verifies, sweeping`,
                    );
                    this.reset();
                }
            }
            return true;
        }

        if (meta.kind === "inject") {
            if (value === "ok" || value === "already") {
                this.injected = true;
                this.lastInjectError = "";
                this.logger.info(
                    `[body] wx.request hook injected into appservice (contextId=${meta.contextId})`,
                );
            } else {
                const msg =
                    typeof value === "string" ? value : JSON.stringify(value) ?? "no value";
                if (msg !== this.lastInjectError) {
                    this.lastInjectError = msg;
                    this.logger.error(
                        `[body] inject failed: ${msg.slice(0, 140)} (retrying)`,
                    );
                }
            }
            return true;
        }

        // poll
        let entries: BodyCapture[] | null = null;
        if (typeof value === "string" && value.length > 0) {
            try {
                entries = JSON.parse(value) as BodyCapture[];
            } catch {
                entries = null;
            }
        }
        if (Array.isArray(entries)) {
            for (const entry of entries) {
                this.record(entry);
            }
        }
        return true;
    }

    private record(entry: BodyCapture): void {
        if (!entry || typeof entry.url !== "string" || entry.url.length === 0) {
            return;
        }
        this.bodies += 1;
        const method = typeof entry.method === "string" ? entry.method : "GET";
        const body = typeof entry.body === "string" ? entry.body : "";
        const size = body.length;
        const shown =
            size > BODY_LOG_CAP
                ? body.slice(0, BODY_LOG_CAP) + `...(truncated ${size - BODY_LOG_CAP} chars)`
                : body;
        this.logger.info(
            `[body] ${method} ${entry.url} ${String(entry.status ?? "?")} (${size} chars)\n${shown}`,
        );

        const key = `${method} ${entry.url}`;
        const queue = this.fifo.get(key) ?? [];
        queue.push(entry as BodyCapture);
        if (queue.length > 20) {
            queue.shift();
        }
        this.fifo.set(key, queue);
        if (this.fifo.size > 500) {
            const keys = [...this.fifo.keys()].slice(0, 125);
            for (const k of keys) {
                this.fifo.delete(k);
            }
        }
    }

    /** Pop one captured body for a request url (FIFO per method+url). */
    takeBody(method: string, url: string): string | undefined {
        const queue = this.fifo.get(`${method} ${url}`);
        const entry = queue?.shift();
        if (queue && queue.length === 0) {
            this.fifo.delete(`${method} ${url}`);
        }
        return typeof entry?.body === "string" ? entry.body : undefined;
    }
}
