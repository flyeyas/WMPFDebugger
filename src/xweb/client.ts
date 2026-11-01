import { EventEmitter } from "node:events";
import { execFile } from "node:child_process";
import WebSocket from "ws";

import { Logger } from "../logger";

// The runtime (WeChatAppEx Framework) hosts a local automation WS server:
//   ws://127.0.0.1:<port>/xweb-use/v1
// carrying the `XWeb.*` command surface (see 逆向/evaljs-debuginfo/notes.md).
// Static analysis pinned the endpoint path, message validation rules and the
// command names, but NOT the exact reply envelope; the client below is
// deliberately tolerant (id match -> method match -> FIFO) and logs raw
// messages under --debug-main so the shapes can be tightened after the first
// live session.

const XWEB_USE_PATH = "/xweb-use/v1";
const LSOF_TIMEOUT_MS = 5000;
const PROBE_TIMEOUT_MS = 2000;

type PendingCall = {
    id: number;
    method: string;
    resolve: (value: unknown) => void;
    reject: (reason: Error) => void;
    timer: NodeJS.Timeout;
};

export type XwebUseClientOptions = {
    port: number;
    token?: string;
    connectTimeoutMs?: number;
    callTimeoutMs?: number;
};

export class XwebUseClient extends EventEmitter {
    private ws: WebSocket | null = null;
    private nextId = 1;
    private pending: PendingCall[] = [];

    constructor(
        private readonly options: XwebUseClientOptions,
        private readonly logger: Logger,
    ) {
        super();
    }

    get port(): number {
        return this.options.port;
    }

    async connect(): Promise<void> {
        const timeoutMs = this.options.connectTimeoutMs ?? PROBE_TIMEOUT_MS;
        const url =
            `ws://127.0.0.1:${this.options.port}${XWEB_USE_PATH}` +
            (this.options.token ? `?token=${encodeURIComponent(this.options.token)}` : "");

        await new Promise<void>((resolve, reject) => {
            const ws = new WebSocket(url, { handshakeTimeout: timeoutMs });
            this.ws = ws;

            const timer = setTimeout(() => {
                ws.terminate();
                reject(new Error(`[xweb] connect timeout: ${url}`));
            }, timeoutMs);

            ws.on("open", () => {
                clearTimeout(timer);
                this.logger.info(`[xweb] connected: ${url}`);
                resolve();
            });
            ws.on("message", (data) => this.onMessage(String(data)));
            ws.on("error", (err) => {
                clearTimeout(timer);
                reject(new Error(`[xweb] connect failed: ${err.message}`));
            });
            ws.on("close", (code) => {
                this.rejectAllPending(new Error(`[xweb] connection closed (${code})`));
                this.emit("close", code);
            });
        });
    }

    close(): void {
        this.rejectAllPending(new Error("[xweb] client closed"));
        this.ws?.close();
        this.ws = null;
    }

    // Send one `{method, params}` command and await its reply. The `id` field
    // is best-effort correlation: static analysis never pinned whether the
    // server echoes a caller id, so replies are matched by id, then by method
    // name, then FIFO.
    async call(method: string, params: Record<string, unknown> = {}): Promise<unknown> {
        if (!this.ws || this.ws.readyState !== WebSocket.OPEN) {
            throw new Error("[xweb] not connected");
        }

        const id = this.nextId++;
        const payload = JSON.stringify({ id, method, params });

        return new Promise((resolve, reject) => {
            const timer = setTimeout(() => {
                this.pending = this.pending.filter((p) => p.id !== id);
                reject(new Error(`[xweb] call timeout: ${method} (id=${id})`));
            }, this.options.callTimeoutMs ?? 15000);

            this.pending.push({ id, method, resolve, reject, timer });
            this.logger.main_debug(`[xweb] >> ${payload}`);
            this.ws!.send(payload, (err) => {
                if (err) {
                    clearTimeout(timer);
                    this.pending = this.pending.filter((p) => p.id !== id);
                    reject(new Error(`[xweb] send failed: ${err.message}`));
                }
            });
        });
    }

    private onMessage(raw: string): void {
        this.logger.main_debug(`[xweb] << ${raw}`);

        let msg: unknown;
        try {
            msg = JSON.parse(raw);
        } catch {
            this.logger.error(`[xweb] non-JSON message: ${raw.slice(0, 200)}`);
            return;
        }
        if (msg === null || typeof msg !== "object") {
            return;
        }
        const obj = msg as Record<string, unknown>;

        // server-pushed notifications look like {"event":"XWeb.inspect","data":{...}}
        if (typeof obj.event === "string") {
            this.emit("event", { event: obj.event, data: obj.data });
            return;
        }

        // reply routing: explicit id -> same-method -> FIFO
        const idx = this.pending.findIndex((p) => p.id === obj.id);
        const byMethod =
            idx === -1 ? this.pending.findIndex((p) => p.method === obj.method) : idx;
        const chosen = idx !== -1 ? idx : byMethod !== -1 ? byMethod : 0;
        const call = this.pending[chosen];
        if (!call) {
            this.logger.main_debug(`[xweb] unmatched message: ${raw.slice(0, 200)}`);
            return;
        }
        this.pending.splice(chosen, 1);
        clearTimeout(call.timer);
        call.resolve(obj);
    }

    private rejectAllPending(reason: Error): void {
        for (const call of this.pending) {
            clearTimeout(call.timer);
            call.reject(reason);
        }
        this.pending = [];
    }
}

// Loopback listeners owned by WeChatAppEx processes. The xweb-use server picks
// an ephemeral port at startup and (per static analysis) announces itself via
// an HTTP POST we could not fully pin down, so discovery falls back to
// scanning the process' listening sockets and probing each candidate.
export const listWeChatLoopbackListeners = (): Promise<number[]> => {
    return new Promise((resolve) => {
        execFile(
            "lsof",
            ["-nP", "-iTCP", "-sTCP:LISTEN"],
            { timeout: LSOF_TIMEOUT_MS },
            (err, stdout) => {
                if (err) {
                    resolve([]);
                    return;
                }
                const ports = new Set<number>();
                for (const line of stdout.split("\n")) {
                    if (!/(WeChatAppEx|WeChat)/.test(line)) {
                        continue;
                    }
                    const m = line.match(/127\.0\.0\.1:(\d+)/);
                    if (m) {
                        ports.add(Number(m[1]));
                    }
                }
                resolve([...ports].sort((a, b) => a - b));
            },
        );
    });
};

// Probe candidate ports by attempting the upgrade + a cheap XWeb.version call.
export const probeXwebUseEndpoint = (
    port: number,
    logger: Logger,
): Promise<boolean> => {
    return new Promise((resolve) => {
        const client = new XwebUseClient({ port, connectTimeoutMs: PROBE_TIMEOUT_MS }, logger);
        const done = (ok: boolean) => {
            client.removeAllListeners();
            client.close();
            resolve(ok);
        };
        client.on("close", () => done(false));
        client
            .connect()
            .then(() => client.call("XWeb.version"))
            .then(() => done(true))
            .catch(() => done(false));
    });
};

export type DiscoveredEndpoint = { port: number; alive: boolean };

// candidate sets are re-probed on every bridge tick; only log when the set
// actually changes to avoid spamming the log every few seconds
let lastCandidateKey = "";

export const discoverXwebUseEndpoints = async (
    logger: Logger,
): Promise<DiscoveredEndpoint[]> => {
    const candidates = await listWeChatLoopbackListeners();
    if (candidates.length === 0) {
        if (lastCandidateKey !== "") {
            lastCandidateKey = "";
            logger.info("[xweb] no WeChat loopback listeners anymore");
        }
        return [];
    }
    const key = candidates.join(",");
    if (key !== lastCandidateKey) {
        lastCandidateKey = key;
        logger.info(`[xweb] probing loopback listeners: ${candidates.join(", ")}`);
    }
    const results: DiscoveredEndpoint[] = [];
    for (const port of candidates) {
        const alive = await probeXwebUseEndpoint(port, logger);
        if (alive) {
            logger.info(`[xweb] xweb-use endpoint found on port ${port}`);
        }
        results.push({ port, alive });
    }
    // alive first, keep the rest for reference
    return results.sort((a, b) => Number(b.alive) - Number(a.alive));
};

// Convenience: discover + connect to the first live endpoint (or use the
// explicit --port override).
export const autoConnect = async (
    portOverride: number | undefined,
    token: string | undefined,
    logger: Logger,
): Promise<XwebUseClient> => {
    let port = portOverride;
    if (!port) {
        const endpoints = await discoverXwebUseEndpoints(logger);
        const alive = endpoints.find((e) => e.alive);
        if (!alive) {
            throw new Error(
                "[xweb] no live xweb-use endpoint found; is a miniapp running? " +
                    "(or pass --port)",
            );
        }
        port = alive.port;
    }

    const client = new XwebUseClient({ port, token }, logger);
    await client.connect();
    return client;
};
