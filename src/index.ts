import { promises } from "node:fs";
import { EventEmitter } from "node:events";
import path from "node:path";
import * as frida from "frida";
import WebSocket, { WebSocketServer } from "ws";

import { platform } from "./platform";
import { parse_cli_options, CliOptions } from "./cli";
import { create_logger, Logger } from "./logger";
import { xwebMain } from "./xweb/main";
import { startXwebBridge } from "./xweb/bridge";

const codex = require("./third-party/RemoteDebugCodex.js");
const messageProto = require("./third-party/WARemoteDebugProtobuf.js");

class DebugMessageEmitter extends EventEmitter {}

type StructOffsetConfig = {
    // omitted when RemoteDebugConfigChain is used instead
    LaunchConfigOffsets?: number[];
    RemoteDebugConfigOffsets?: number[];
    SceneOffset: number;
    WebSocketURLStringOffset: number;
    RemoteDebugModeOffset: number;
}

type HookConfig = {
    Version: number;
    LoadStartHookOffset: string;
    CDPFilterHookOffset: string;
    CastToJsonHookOffset?: string;
    SceneOffsets?: number[];
    MiniAppConfigStructOffsets?: StructOffsetConfig;
    // pointer chain from `this` to the remote debug config, for builds where it
    // is not reachable through the launch config (e.g. darwin 25800)
    RemoteDebugConfigChain?: number[];
    // injected before the script is loaded: the launch config must point the
    // miniapp back at the port our debug server is listening on
    DebugPort?: number;
};

const debugMessageEmitter = new DebugMessageEmitter();

// CDP relay diagnostics + late-attach replay. The DevTools Network panel
// intermittently misses requests; these counters localize where events die
// (miniapp not reporting / non-Network payload / DevTools attached late),
// and the ring buffer replays Network.* events to DevTools clients that
// connect after they were relayed (launch-time requests are otherwise lost).
const cdpRelay = {
    buffer: [] as Array<{ t: number; message: string }>,
    maxBuffer: 500,
    stats: {
        customMessage: 0,
        networkDebug: 0,
        networkRelayed: 0,
        devtoolsResultRelayed: 0,
        droppedNonNetwork: 0,
    },
    otherMethods: new Map<string, number>(),
    // per-Network-method counts + distinct requestIds: a small distinct-id
    // count vs many events means the runtime reuses requestIds and DevTools
    // folds new requests into old rows (panel "looks empty")
    networkMethods: new Map<string, number>(),
    requestIds: new Set<string>(),
    samples: new Set<string>(),
    // what the DevTools frontend itself sends (Network.enable present?)
    clientMethods: new Map<string, number>(),
};

const pushCdpBuffer = (message: string) => {
    cdpRelay.buffer.push({ t: Date.now(), message });
    if (cdpRelay.buffer.length > cdpRelay.maxBuffer) {
        cdpRelay.buffer.shift();
    }
};

const noteOtherMethod = (method: unknown) => {
    if (typeof method !== "string" || cdpRelay.otherMethods.size >= 20) {
        return;
    }
    cdpRelay.otherMethods.set(method, (cdpRelay.otherMethods.get(method) ?? 0) + 1);
};

const noteNetworkEvent = (logger: Logger, method: string, payload: string) => {
    cdpRelay.networkMethods.set(method, (cdpRelay.networkMethods.get(method) ?? 0) + 1);
    if (!cdpRelay.samples.has(method)) {
        cdpRelay.samples.add(method);
        logger.info(`[relay] sample ${method}: ${payload.slice(0, 300)}`);
    }
    try {
        const requestId = (JSON.parse(payload) as { params?: { requestId?: unknown } })?.params
            ?.requestId;
        if (typeof requestId === "string" && cdpRelay.requestIds.size < 5000) {
            cdpRelay.requestIds.add(requestId);
        }
    } catch {
        // already validated upstream
    }
};

const bufferToHexString = (buffer: ArrayBuffer) => {
    return Array.from(new Uint8Array(buffer))
        .map((byte) => byte.toString(16).padStart(2, "0"))
        .join("");
};

const debugServer = (options: CliOptions, logger: Logger): WebSocketServer  => {
    const wss = new WebSocketServer({ port: options.debugPort });
    logger.info(
        `[server] debug server running on ws://localhost:${options.debugPort}`,
    );
    logger.info(`[server] debug server waiting for miniapp to connect...`);

    let messageCounter = 0;

    const onMessage = (message: ArrayBuffer) => {
        logger.main_debug(
            `[miniapp] client received raw message (hex): ${bufferToHexString(message)}`,
        );
        let unwrappedData: any = null;
        try {
            const decodedData =
                messageProto.mmbizwxadevremote.WARemoteDebug_DebugMessage.decode(
                    message,
                );
            unwrappedData = codex.unwrapDebugMessageData(decodedData);
            logger.main_debug(`[miniapp] [DEBUG] decoded data:`);
            logger.main_debug(unwrappedData);
        } catch (e) {
            logger.error(`[miniapp] miniapp client err: ${e}`);
        }

        if (unwrappedData === null) {
            return;
        }

        if (unwrappedData.category === "customMessage") {
            // the runtime reports wx.request traffic as `__networkDebug` custom
            // messages whose payload is already a standard CDP Network.* event;
            // relay it verbatim so the DevTools Network panel renders it
            cdpRelay.stats.customMessage++;
            const cm = unwrappedData.data ?? {};
            if (cm.method === "__networkDebug") {
                cdpRelay.stats.networkDebug++;
                try {
                    const evt = JSON.parse(String(cm.payload));
                    if (
                        evt &&
                        typeof evt.method === "string" &&
                        evt.method.startsWith("Network.")
                    ) {
                        cdpRelay.stats.networkRelayed++;
                        noteNetworkEvent(logger, evt.method, String(cm.payload));
                        pushCdpBuffer(String(cm.payload));
                        debugMessageEmitter.emit("cdpmessage", {
                            message: String(cm.payload),
                            networkDebug: true,
                        });
                    } else {
                        cdpRelay.stats.droppedNonNetwork++;
                        noteOtherMethod(evt?.method);
                        logger.main_debug(
                            `[relay] non-Network __networkDebug payload: ${String(cm.payload).slice(0, 200)}`,
                        );
                    }
                } catch (e) {
                    logger.error(
                        `[proxy] malformed __networkDebug payload: ${e}`,
                    );
                }
            } else if (typeof cm.method === "string") {
                noteOtherMethod(cm.method);
                logger.main_debug(
                    `[relay] customMessage method=${cm.method} (not relayed)`,
                );
            }
        }

        if (unwrappedData.category === "chromeDevtoolsResult") {
            // need to proxy to CDP client
            cdpRelay.stats.devtoolsResultRelayed++;
            debugMessageEmitter.emit("cdpmessage", unwrappedData.data.payload);
        }
    };

    wss.on("connection", (ws: WebSocket) => {
        logger.info("[miniapp] miniapp client connected");
        ws.on("message", onMessage);
        ws.on("error", (err) => {
            logger.error("[miniapp] miniapp client err:", err);
        });
        ws.on("close", () => {
            logger.info("[miniapp] miniapp client disconnected");
        });
    });

    debugMessageEmitter.on("proxymessage", (message: string) => {
        wss &&
            wss.clients.forEach((client) => {
                if (client.readyState === WebSocket.OPEN) {
                    // encode CDP and send to miniapp
                    // wrapDebugMessageData(data, category, compressAlgo)
                    const rawPayload = {
                        jscontext_id: "",
                        op_id: Math.round(100 * Math.random()),
                        payload: message.toString(),
                    };
                    logger.main_debug(rawPayload);
                    const wrappedData = codex.wrapDebugMessageData(
                        rawPayload,
                        "chromeDevtools",
                        0,
                    );
                    const outData = {
                        seq: ++messageCounter,
                        category: "chromeDevtools",
                        data: wrappedData.buffer,
                        compressAlgo: 0,
                        originalSize: wrappedData.originalSize,
                    };
                    const encodedData =
                        messageProto.mmbizwxadevremote.WARemoteDebug_DebugMessage.encode(
                            outData,
                        ).finish();
                    client.send(encodedData, { binary: true });
                }
            });
    });
    return wss;
};

// The runtime's __networkDebug events use `<page>.<seq>` requestIds that
// restart per page, so DevTools folds new requests into existing rows ("the
// Network panel has no requests"). Rewrite every requestWillBeSent to a fresh
// unique id per client; redirect chains (same id + redirectResponse) and all
// follow-up events of one logical request keep a stable mapping.
type ClientRelayState = {
    idMap: Map<string, string>;
    idSeq: number;
    enableSeen: boolean;
};

const clientStates = new WeakMap<WebSocket, ClientRelayState>();

const rewriteNetworkEventForClient = (
    state: ClientRelayState,
    message: string,
): string => {
    if (!message.startsWith('{"method":"Network.')) {
        return message;
    }
    let evt: {
        method?: string;
        params?: { requestId?: unknown; redirectResponse?: unknown };
    };
    try {
        evt = JSON.parse(message);
    } catch {
        return message;
    }
    if (
        !evt ||
        typeof evt.method !== "string" ||
        !evt.params ||
        typeof evt.params.requestId !== "string"
    ) {
        return message;
    }
    if (state.idMap.size > 8000) {
        state.idMap.clear();
    }
    const orig = evt.params.requestId;
    const isRedirect =
        evt.method === "Network.requestWillBeSent" && evt.params.redirectResponse;
    let mapped = state.idMap.get(orig);
    if (!mapped || (evt.method === "Network.requestWillBeSent" && !isRedirect)) {
        mapped = `u${++state.idSeq}_${orig}`;
    }
    state.idMap.set(orig, mapped);
    evt.params.requestId = mapped;
    return JSON.stringify(evt);
};

const proxyServer = (options: CliOptions, logger: Logger): WebSocketServer => {
    const wss = new WebSocketServer({ port: options.cdpPort });
    logger.info(
        `[server] proxy server running on ws://localhost:${options.cdpPort}`,
    );
    logger.info(
        `[server] link: devtools://devtools/bundled/inspector.html?ws=127.0.0.1:${options.cdpPort}`,
    );

    wss.on("connection", (ws: WebSocket) => {
        logger.info("[cdp] CDP client connected");
        const state: ClientRelayState = {
            idMap: new Map(),
            idSeq: 0,
            enableSeen: false,
        };
        clientStates.set(ws, state);

        ws.on("message", (data) => {
            const message = String(data);
            // count which domains the DevTools frontend actually enables
            try {
                const evt = JSON.parse(message) as { method?: unknown };
                if (evt && typeof evt.method === "string") {
                    cdpRelay.clientMethods.set(
                        evt.method,
                        (cdpRelay.clientMethods.get(evt.method) ?? 0) + 1,
                    );
                    if (evt.method === "Network.enable" && !state.enableSeen) {
                        state.enableSeen = true;
                        // the frontend registers its Network dispatcher on
                        // Network.enable; events pushed before that (including
                        // launch-time ones) are swallowed, so replay the buffer
                        // shortly after the enable round-trip settles
                        setTimeout(() => {
                            if (
                                ws.readyState !== WebSocket.OPEN ||
                                cdpRelay.buffer.length === 0
                            ) {
                                return;
                            }
                            logger.info(
                                `[cdp] replaying ${cdpRelay.buffer.length} buffered Network event(s) after Network.enable`,
                            );
                            for (const { message: buffered } of cdpRelay.buffer) {
                                if (ws.readyState === WebSocket.OPEN) {
                                    ws.send(
                                        rewriteNetworkEventForClient(state, buffered),
                                    );
                                }
                            }
                        }, 150);
                    }
                }
            } catch {
                // non-JSON traffic from the client, ignore for stats
            }
            debugMessageEmitter.emit("proxymessage", message);
        });
        ws.on("error", (err) => {
            logger.error("[cdp] CDP client err:", err);
        });
        ws.on("close", () => {
            logger.info("[cdp] CDP client disconnected");
        });
    });

    debugMessageEmitter.on(
        "cdpmessage",
        (
            message: string | { message: string; networkDebug: boolean },
        ) => {
            wss &&
                wss.clients.forEach((client) => {
                    if (client.readyState !== WebSocket.OPEN) {
                        return;
                    }
                    if (typeof message === "string") {
                        // native CDP (responses + runtime events), pass through
                        client.send(message);
                        return;
                    }
                    // __networkDebug event: hold until this client enabled the
                    // Network domain (the frontend would swallow it anyway);
                    // the global buffer covers it via replay otherwise
                    const state = clientStates.get(client);
                    if (!state || !state.enableSeen) {
                        return;
                    }
                    client.send(
                        rewriteNetworkEventForClient(state, message.message),
                    );
                });
        },
    );
    return wss;
};

const autoDetectConfig = async (
    session: frida.Session,
    projectRoot: string,
    wmpfVersion: number,
): Promise<HookConfig> => {
    let detectorContent: string;
    try {
        detectorContent = (
            await promises.readFile(
                path.join(
                    projectRoot,
                    "frida/autodetect",
                    `${process.platform}.js`,
                ),
            )
        ).toString();
    } catch (e) {
        throw new Error("[frida] auto-detect script not found");
    }

    const detector = await session.createScript(detectorContent);
    const detectedConfig = new Promise<Omit<HookConfig, "Version">>(
        (resolve, reject) => {
            detector.message.connect((message: frida.Message) => {
                if (message.type === "error") {
                    reject(
                        new Error(
                            `[frida] auto-detect failed: ${message.description}`,
                        ),
                    );
                    return;
                }

                const payload = message.payload as {
                    type?: string;
                    config?: Omit<HookConfig, "Version">;
                    error?: string;
                };
                if (payload.type === "wmpf-offsets" && payload.config) {
                    resolve(payload.config);
                } else if (payload.type === "wmpf-offsets-error") {
                    reject(
                        new Error(
                            `[frida] auto-detect failed: ${payload.error ?? "unknown error"}`,
                        ),
                    );
                }
            });
        },
    );

    try {
        await detector.load();
        return { Version: wmpfVersion, ...(await detectedConfig) };
    } finally {
        await detector.unload();
    }
};

const fridaServer = async (options: CliOptions, logger: Logger): Promise<frida.Session> => {
    const localDevice = await frida.getLocalDevice();
    const { pid: wmpfPid, version: wmpfVersion } = await platform.findWmpfProcess()

    // attach to process
    const session = await localDevice.attach(wmpfPid);

    // find hook script
    const projectRoot = path.join(
        path.dirname(
            (require.main && require.main.filename) ||
                (process.mainModule && process.mainModule.filename) ||
                process.cwd(),
        ),
        "..",
    );
    let scriptContent: string | null = null;
    try {
        scriptContent = (
            await promises.readFile(path.join(projectRoot, "frida/hook.js"))
        ).toString();
    } catch (e) {
        throw new Error("[frida] hook script not found");
    }

    let hookConfig: HookConfig;
    if (options.autoDetect) {
        logger.info(`[frida] auto-detecting hook offsets...`);
        hookConfig = await autoDetectConfig(session, projectRoot, wmpfVersion);
        logger.info(`[frida] detected hook offsets: ${JSON.stringify(hookConfig)}`);
    } else {
        try {
            hookConfig = JSON.parse(
                (
                    await promises.readFile(
                        path.join(
                            projectRoot,
                            `frida/config/${process.platform}`,
                            `addresses.${wmpfVersion}.json`,
                        ),
                    )
                ).toString(),
            );
        } catch (e) {
            throw new Error(`[frida] version config not found: ${wmpfVersion}`);
        }
    }

    // the miniapp connects back to us, so the hook script has to rewrite the
    // launch config with the port our debug server is actually listening on
    hookConfig.DebugPort = options.debugPort;

    if (scriptContent === null) {
        throw new Error("[frida] unable to find hook script");
    }

    // load script
    const script = await session.createScript(
        scriptContent.replace("@@CONFIG@@", JSON.stringify(hookConfig)),
    );
    script.message.connect((message: frida.Message) => {
        if (message.type === "error") {
            logger.error("[frida client]", message);
            return;
        }

        logger.frida_debug("[frida client]", message.payload);
    });
    await script.load();
    logger.info(
        `[frida] script loaded, WMPF version: ${wmpfVersion}, pid: ${wmpfPid}`,
    );
    logger.info(`[frida] you can now open any miniapps`);
    return session;
};

const main = async () => {
    if (process.argv[2] === "xweb") {
        // sidecar mode: drive the runtime's local automation server
        // (ws://127.0.0.1:<port>/xweb-use/v1) directly — no frida injection,
        // no debug/proxy servers. See 逆向/evaljs-debuginfo/notes.md.
        await xwebMain(process.argv.slice(3));
        return;
    }

    const options = parse_cli_options();
    const logger = create_logger(options);
    const debugWss = debugServer(options, logger);
    const proxyWss = proxyServer(options, logger);
    const fridaSession = await fridaServer(options, logger);

    // the xweb bridge discovers the runtime's local automation server once a
    // miniapp session is up, and auto-starts a netlog capture there so that
    // response bodies (invisible to the debug channel) land on disk
    const xweb = startXwebBridge(
        {
            enabled: options.xwebBridge,
            netlogMode: options.xwebNetlogMode as never,
            netlogOutDir: "./xweb-netlog-out",
        },
        logger,
    );
    if (options.xwebBridge) {
        logger.info(`[xweb] bridge enabled, waiting for a miniapp session...`);
    }

    // periodic relay status: prints only when counters changed; use it to
    // diagnose "Network panel has no requests" sessions (are customMessages
    // arriving at all? are payloads Network.*? is DevTools attaching late?)
    let lastRelaySnapshot = "";
    const relayStatusTimer = setInterval(() => {
        const others =
            cdpRelay.otherMethods.size > 0
                ? ` otherMethods=${JSON.stringify([...cdpRelay.otherMethods.entries()])}`
                : "";
        const netMethods =
            cdpRelay.networkMethods.size > 0
                ? ` netMethods=${JSON.stringify([...cdpRelay.networkMethods.entries()])}`
                : "";
        const clientMethods =
            cdpRelay.clientMethods.size > 0
                ? ` clientMethods=${JSON.stringify([...cdpRelay.clientMethods.entries()].slice(0, 8))}`
                : "";
        const snapshot =
            `customMessage=${cdpRelay.stats.customMessage} ` +
            `networkDebug=${cdpRelay.stats.networkDebug} ` +
            `networkRelayed=${cdpRelay.stats.networkRelayed} ` +
            `netReqIds=${cdpRelay.requestIds.size} ` +
            `devtoolsResultRelayed=${cdpRelay.stats.devtoolsResultRelayed} ` +
            `droppedNonNetwork=${cdpRelay.stats.droppedNonNetwork}` +
            others +
            netMethods +
            clientMethods;
        if (snapshot !== lastRelaySnapshot) {
            lastRelaySnapshot = snapshot;
            logger.info(`[relay] ${snapshot}`);
        }
    }, 15000);
    relayStatusTimer.unref();

    process.on("SIGINT", async () => {
        logger.info("[server] shutting down...");
        await xweb.stop().catch(() => {});
        debugWss.close();
        proxyWss.close();
        await fridaSession.detach();
        process.exit(0);
    });
};

(async () => {
    await main();
})();
