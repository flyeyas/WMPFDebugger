import { promises } from "node:fs";
import path from "node:path";

import { Logger } from "../logger";
import { discoverXwebUseEndpoints, XwebUseClient } from "./client";
import { NetLogCaptureMode, NetLogController, parseNetlogFile } from "./netlog";

// XwebBridge runs alongside the main debugger flow: it keeps looking for the
// runtime's local automation server (ws://127.0.0.1:<port>/xweb-use/v1) —
// which only exists while a miniapp session is active — connects to it once
// found, and auto-starts a Chromium net-export capture so response bodies are
// on disk when the session ends. No frida involvement: the bridge talks to
// the runtime's own automation protocol (see 逆向/evaljs-debuginfo/notes.md).

export type XwebBridgeOptions = {
    enabled: boolean;
    netlogMode: NetLogCaptureMode;
    netlogOutDir: string;
    pollIntervalMs?: number;
};

export type XwebBridge = {
    client: () => XwebUseClient | null;
    stop: () => Promise<void>;
};

const DEFAULT_POLL_INTERVAL_MS = 3000;

export const startXwebBridge = (
    options: XwebBridgeOptions,
    logger: Logger,
): XwebBridge => {
    if (!options.enabled) {
        return { client: () => null, stop: async () => {} };
    }

    let client: XwebUseClient | null = null;
    let netlogStarted = false;
    let netlogPaths: string[] = [];
    let stopped = false;
    let timer: NodeJS.Timeout | null = null;

    const schedule = (delayMs = options.pollIntervalMs ?? DEFAULT_POLL_INTERVAL_MS) => {
        if (stopped || timer || client) {
            return;
        }
        timer = setTimeout(async () => {
            timer = null;
            await attach().catch(() => {});
            schedule();
        }, delayMs);
        timer.unref();
    };

    const attach = async (): Promise<void> => {
        if (stopped || client) {
            return;
        }
        const endpoints = await discoverXwebUseEndpoints(logger);
        const alive = endpoints.find((e) => e.alive);
        if (!alive) {
            return;
        }

        const candidate = new XwebUseClient({ port: alive.port }, logger);
        await candidate.connect();

        candidate.on("event", ({ event, data }) => {
            logger.info(
                `[xweb] event ${event} ${JSON.stringify(data ?? {}).slice(0, 200)}`,
            );
        });
        candidate.on("close", () => {
            if (client === candidate) {
                client = null;
                netlogStarted = false;
                logger.info("[xweb] endpoint lost (runtime churn?), resuming discovery");
                schedule(1000);
            }
        });

        client = candidate;
        logger.info(`[xweb] bridge attached to automation server on port ${alive.port}`);

        // WeChatAppEx processes churn as miniapps open/close; losing the
        // endpoint mid-session is normal and discovery resumes above.
        try {
            const netlog = new NetLogController(candidate, logger);
            await netlog.start(options.netlogMode);
            netlogStarted = true;
            logger.info(
                `[xweb] netlog capture started (${options.netlogMode}) — response ` +
                    `bodies will be written to the netlog file`,
            );
        } catch (e) {
            logger.error(`[xweb] netlog start failed: ${e} (continuing without capture)`);
        }
    };

    const stop = async (): Promise<void> => {
        stopped = true;
        if (timer) {
            clearTimeout(timer);
            timer = null;
        }
        const current = client;
        if (!current) {
            return;
        }

        const netlog = new NetLogController(current, logger);
        try {
            if (netlogStarted) {
                await netlog.stop();
                logger.info("[xweb] netlog capture stopped");
            }
            netlogPaths = await netlog.paths();
        } catch (e) {
            logger.error(`[xweb] netlog teardown failed: ${e}`);
        }

        if (netlogPaths.length > 0) {
            await tryParseNewestCapture(netlogPaths, options.netlogOutDir, logger);
        }

        current.close();
        client = null;
    };

    // kick off the discovery loop — without this the bridge would only start
    // polling after a (never-firing) close event
    schedule(1500);

    return { client: () => client, stop };
};

// Parse the most recent capture so bodies are ready right after shutdown.
// The netlog files may live inside WeChat's container, which the terminal
// cannot read without Full Disk Access — surface a clear hint when so.
const tryParseNewestCapture = async (
    paths: string[],
    outDir: string,
    logger: Logger,
): Promise<void> => {
    const candidates: Array<{ file: string; mtime: Date }> = [];
    for (const file of paths) {
        try {
            const stat = await promises.stat(file);
            if (stat.isFile()) {
                candidates.push({ file, mtime: stat.mtime });
            }
        } catch {
            logger.error(
                `[xweb] cannot stat netlog file: ${file} ` +
                    `(WeChat container is TCC-protected? grant Full Disk Access and re-run)`,
            );
        }
    }
    if (candidates.length === 0) {
        return;
    }
    candidates.sort((a, b) => b.mtime.getTime() - a.mtime.getTime());
    const newest = candidates[0].file;

    try {
        const requests = await parseNetlogFile(newest, outDir, true, logger);
        const withBody = requests.filter((r) => r.bodyBase64).length;
        logger.info(
            `[xweb] netlog parsed: ${requests.length} request(s), ` +
                `${withBody} with body -> ${outDir}`,
        );
    } catch (e) {
        logger.error(
            `[xweb] parsing ${newest} failed: ${e} — re-run later with ` +
                `"npx tsx src/index.ts xweb netlog-parse ${newest} --save-bodies"`,
        );
    }
};
