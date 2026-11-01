import { promises } from "node:fs";
import path from "node:path";

import { XwebUseClient } from "./client";
import { Logger } from "../logger";

// XWeb.NetLog* drives Chromium's net-export logger inside the runtime. With
// capture mode "IncludeSocketBytes" the resulting netlog contains request AND
// response bodies — this is the official, injection-free answer to the
// "Network.getResponseBody does not exist" limitation of the debug channel
// (see 逆向/evaljs-debuginfo/notes.md §6).

// Chromium net-export capture modes; body bytes require IncludeSocketBytes.
export const NETLOG_CAPTURE_MODES = [
    "Default",
    "IncludeSensitive",
    "IncludeSocketBytes",
] as const;

export type NetLogCaptureMode = (typeof NETLOG_CAPTURE_MODES)[number];

export class NetLogController {
    constructor(
        private readonly client: XwebUseClient,
        private readonly logger: Logger,
    ) {}

    async start(mode: NetLogCaptureMode = "IncludeSocketBytes"): Promise<unknown> {
        // wire param name derived from the runtime log "Start NetLog,
        // netlog_capture_mode_: " — unconfirmed against a live server
        return this.client.call("XWeb.NetLogStart", { netlog_capture_mode: mode });
    }

    async stop(): Promise<unknown> {
        return this.client.call("XWeb.NetLogStop");
    }

    async status(): Promise<unknown> {
        return this.client.call("XWeb.NetLogStatus");
    }

    async paths(): Promise<string[]> {
        // PathAll lists every capture; Path covers the current one. The reply
        // envelope is not pinned by static analysis, so walk the result and
        // collect absolute-path-looking strings.
        let result: unknown;
        try {
            result = await this.client.call("XWeb.NetLogPathAll");
        } catch {
            result = await this.client.call("XWeb.NetLogPath");
        }
        this.logger.main_debug(`[netlog] raw paths result: ${JSON.stringify(result)}`);
        return collectPaths(result);
    }
}

const looksLikePath = (value: string): boolean =>
    value.startsWith("/") && value.length > 4 && !value.includes("\n");

export const collectPaths = (node: unknown, found: string[] = []): string[] => {
    if (typeof node === "string") {
        if (looksLikePath(node) && !found.includes(node)) {
            found.push(node);
        }
    } else if (Array.isArray(node)) {
        for (const item of node) {
            collectPaths(item, found);
        }
    } else if (node !== null && typeof node === "object") {
        for (const value of Object.values(node)) {
            collectPaths(value, found);
        }
    }
    return found;
};

// ---------------------------------------------------------------------------
// net-export parsing: reconstruct URL_REQUESTs with response bodies
// ---------------------------------------------------------------------------

type NetlogEvent = {
    source?: { id?: number | string; type?: number | string };
    type?: number | string;
    time?: string | number;
    phase?: number;
    params?: Record<string, unknown>;
};

type NetExportFile = {
    constants?: {
        logEventTypes?: Record<string, number>;
        logSourceType?: Record<string, number>;
        [key: string]: unknown;
    };
    events?: NetlogEvent[];
};

export type ReconstructedRequest = {
    sourceId: string;
    url: string;
    method?: string;
    statusLine?: string;
    requestHeaders?: string[];
    responseHeaders?: string[];
    // base64 of the filtered (post-decompression) body chunks, in order
    bodyBase64?: string;
    bodySize?: number;
    // raw (wire) body when it differs from the filtered one
    rawBodyBase64?: string;
    startedTime?: string | number;
    endedTime?: string | number;
};

// net-export files can be truncated if the runtime is killed before
// NetLogStop; salvage by cutting back to the last complete event.
export const parseNetExport = (text: string): NetExportFile => {
    try {
        return JSON.parse(text) as NetExportFile;
    } catch {
        // fall through to salvage
    }
    const lastComplete = text.lastIndexOf("},");
    if (lastComplete === -1) {
        throw new Error("[netlog] file is not valid JSON and no salvage point found");
    }
    const salvaged = `${text.slice(0, lastComplete + 1)}]}`;
    thisLoggerWarn(`[netlog] JSON truncated, salvaged ${lastComplete} bytes worth of events`);
    return JSON.parse(salvaged) as NetExportFile;
};

// small indirection so the salvage path can log without threading a Logger
// through parseNetExport
let thisLoggerWarn: (message: string) => void = (message) => console.warn(message);
export const setNetlogWarn = (warn: (message: string) => void): void => {
    thisLoggerWarn = warn;
};

export const reconstructRequests = (parsed: NetExportFile): ReconstructedRequest[] => {
    const events = parsed.events ?? [];
    const constants = parsed.constants ?? {};

    // netlog serializes names as numbers; constants give name -> id maps
    const eventNames = new Map<number, string>();
    for (const [name, id] of Object.entries(constants.logEventTypes ?? {})) {
        eventNames.set(id, name);
    }
    const sourceTypes = new Map<number, string>();
    for (const [name, id] of Object.entries(constants.logSourceType ?? {})) {
        sourceTypes.set(id, name);
    }

    const eventName = (evt: NetlogEvent): string => {
        if (typeof evt.type === "string") {
            return evt.type;
        }
        return eventNames.get(Number(evt.type)) ?? `unknown_${evt.type}`;
    };
    const sourceType = (evt: NetlogEvent): string => {
        if (typeof evt.source?.type === "string") {
            return evt.source.type;
        }
        return sourceTypes.get(Number(evt.source?.type)) ?? "";
    };

    const bySource = new Map<string, NetlogEvent[]>();
    for (const evt of events) {
        const sid = String(evt.source?.id ?? "");
        if (!sid) {
            continue;
        }
        const bucket = bySource.get(sid) ?? [];
        bucket.push(evt);
        bySource.set(sid, bucket);
    }

    const requests: ReconstructedRequest[] = [];
    for (const [sid, evts] of bySource) {
        if (evts.length === 0 || sourceType(evts[0]) !== "URL_REQUEST") {
            continue;
        }

        const req: ReconstructedRequest = { sourceId: sid, url: "" };

        for (const evt of evts) {
            const name = eventName(evt);
            const params = evt.params ?? {};

            if (name === "REQUEST_ALIVE") {
                req.startedTime = evt.time;
                if (typeof params.url === "string") {
                    req.url = params.url;
                }
            } else if (name === "URL_REQUEST_START_JOB") {
                if (!req.url && typeof params.original_url === "string") {
                    req.url = params.original_url;
                }
            } else if (name === "HTTP_TRANSACTION_SEND_REQUEST") {
                if (typeof params.line === "string") {
                    // e.g. "GET /api/v1/xxx HTTP/1.1"
                    req.method = params.line.split(" ")[0];
                    if (!req.url) {
                        req.url = params.line;
                    }
                }
                if (Array.isArray(params.headers)) {
                    req.requestHeaders = params.headers.map(String);
                }
            } else if (name === "HTTP_TRANSACTION_READ_RESPONSE") {
                if (Array.isArray(params.headers)) {
                    const headers = params.headers.map(String);
                    req.responseHeaders = headers;
                    req.statusLine = headers[0];
                }
            } else if (name.endsWith("BYTES_READ") && name.includes("URL_REQUEST_JOB")) {
                const bytes = params.bytes;
                if (typeof bytes !== "string") {
                    continue;
                }
                const filtered = name.includes("FILTERED");
                if (filtered) {
                    req.bodyBase64 = (req.bodyBase64 ?? "") + bytes;
                } else {
                    req.rawBodyBase64 = (req.rawBodyBase64 ?? "") + bytes;
                }
            }

            req.endedTime = evt.time;
        }

        if (!req.bodyBase64 && req.rawBodyBase64) {
            // only unfiltered bytes were captured; keep them as the body
            req.bodyBase64 = req.rawBodyBase64;
            req.rawBodyBase64 = undefined;
        }
        if (req.bodyBase64) {
            req.bodySize = Math.floor((req.bodyBase64.length * 3) / 4);
        }
        if (req.url) {
            requests.push(req);
        }
    }

    return requests;
};

export const writeNetlogReport = async (
    requests: ReconstructedRequest[],
    outDir: string,
    saveBodies: boolean,
): Promise<void> => {
    await promises.mkdir(outDir, { recursive: true });

    const summary = requests.map((req) => ({
        sourceId: req.sourceId,
        url: req.url,
        method: req.method,
        status: req.statusLine,
        bodySize: req.bodySize ?? 0,
        hasBody: Boolean(req.bodyBase64),
        startedTime: req.startedTime,
        endedTime: req.endedTime,
    }));
    await promises.writeFile(
        path.join(outDir, "requests.json"),
        JSON.stringify(summary, null, 4),
    );

    if (!saveBodies) {
        return;
    }
    const bodiesDir = path.join(outDir, "bodies");
    await promises.mkdir(bodiesDir, { recursive: true });

    let index = 0;
    for (const req of requests) {
        if (!req.bodyBase64) {
            continue;
        }
        index += 1;
        let name = "unknown";
        try {
            const parsedUrl = new URL(req.url);
            name = `${parsedUrl.hostname}${parsedUrl.pathname}`.replace(/[^a-zA-Z0-9._-]+/g, "_");
        } catch {
            // url may be a request line rather than an absolute URL
            name = req.url.replace(/[^a-zA-Z0-9._-]+/g, "_").slice(0, 80);
        }
        const file = path.join(bodiesDir, `${String(index).padStart(4, "0")}_${name}.body`);
        await promises.writeFile(file, Buffer.from(req.bodyBase64, "base64"));
    }
};

export const parseNetlogFile = async (
    filePath: string,
    outDir: string,
    saveBodies: boolean,
    logger: Logger,
): Promise<ReconstructedRequest[]> => {
    setNetlogWarn((message) => logger.error(message));
    const text = await promises.readFile(filePath, "utf8");
    const parsed = parseNetExport(text);
    const requests = reconstructRequests(parsed);
    await writeNetlogReport(requests, outDir, saveBodies);
    return requests;
};
