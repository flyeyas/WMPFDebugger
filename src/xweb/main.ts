import { promises } from "node:fs";
import { parseArgs } from "node:util";

import { CliOptions } from "../cli";
import { create_logger, Logger } from "../logger";
import { autoConnect, discoverXwebUseEndpoints, XwebUseClient } from "./client";
import { evaluateInAppContext } from "./evaluate";
import {
    NETLOG_CAPTURE_MODES,
    NetLogCaptureMode,
    NetLogController,
    parseNetlogFile,
} from "./netlog";

// xweb sidecar: talk to the runtime's local automation server
// (ws://127.0.0.1:<port>/xweb-use/v1) directly, without frida injection.
// Run via:  npx tsx src/index.ts xweb <command> [args] [options]

const print_help = () => {
    console.log(`Usage: npx tsx src/index.ts xweb <command> [args] [options]

Commands:
  discover                       Probe WeChatAppEx loopback listeners for the
                                 xweb-use endpoint
  version                        XWeb.version (channel smoke test)
  targets                        XWeb.targets (list inspectable applets)
  netlog-start [mode]            Start Chromium net-export capture
                                 (mode: ${NETLOG_CAPTURE_MODES.join(" | ")};
                                 default IncludeSocketBytes = capture bodies)
  netlog-stop                    Stop the capture
  netlog-status                  Capture status
  netlog-paths                   Print captured netlog file paths
  netlog-parse <file>            Parse a net-export file, reconstruct requests
                                 with response bodies, write a report (--out)
  eval <scriptFile | ->          Evaluate a script in the appContext
                                 (appservice); "-" reads stdin

Options:
  --port <port>        Skip discovery, use this endpoint port
  --token <token>      Append ?token= to the upgrade URL (rarely needed)
  --out <dir>          Output dir for netlog-parse (default ./xweb-netlog-out)
  --save-bodies        netlog-parse: also write decoded bodies to <out>/bodies
  --timeout-ms <n>     eval timeout (default 15000)
  --debug-main         Verbose raw message logging
  -h, --help           Show this help message`);
};

type XwebArgs = {
    command: string;
    positionals: string[];
    port?: number;
    token?: string;
    out: string;
    saveBodies: boolean;
    timeoutMs: number;
};

const parse_xweb_args = (argv: string[]): XwebArgs => {
    const { values, positionals } = parseArgs({
        args: argv,
        options: {
            port: { type: "string" },
            token: { type: "string" },
            out: { type: "string" },
            "save-bodies": { type: "boolean" },
            "timeout-ms": { type: "string" },
            "debug-main": { type: "boolean" },
            help: { type: "boolean", short: "h" },
        },
        allowPositionals: true,
    });

    if (values.help) {
        print_help();
        process.exit(0);
    }

    const command = positionals[0] ?? "";
    if (!command) {
        print_help();
        process.exit(command === "" ? 0 : 1);
    }

    let port: number | undefined;
    if (values.port !== undefined) {
        port = Number(values.port);
        if (!Number.isInteger(port) || port < 1 || port > 65535) {
            throw new Error(`[xweb] invalid --port: ${values.port}`);
        }
    }

    let timeoutMs = 15000;
    if (values["timeout-ms"] !== undefined) {
        timeoutMs = Number(values["timeout-ms"]);
        if (!Number.isInteger(timeoutMs) || timeoutMs < 1) {
            throw new Error(`[xweb] invalid --timeout-ms: ${values["timeout-ms"]}`);
        }
    }

    return {
        command,
        positionals: positionals.slice(1),
        port,
        token: values.token,
        out: values.out ?? "./xweb-netlog-out",
        saveBodies: values["save-bodies"] ?? false,
        timeoutMs,
    };
};

const printResult = (label: string, result: unknown): void => {
    console.log(`[${label}]`);
    console.log(typeof result === "string" ? result : JSON.stringify(result, null, 4));
};

const runWithClient = async (
    args: XwebArgs,
    logger: Logger,
    fn: (client: XwebUseClient) => Promise<void>,
): Promise<void> => {
    const client = await autoConnect(args.port, args.token, logger);
    try {
        await fn(client);
    } finally {
        client.close();
    }
};

const readStdin = async (): Promise<string> => {
    process.stdin.setEncoding("utf8");
    let data = "";
    for await (const chunk of process.stdin) {
        data += String(chunk);
    }
    return data;
};

const parseMode = (raw: string | undefined): NetLogCaptureMode => {
    const mode = raw ?? "IncludeSocketBytes";
    if (!(NETLOG_CAPTURE_MODES as readonly string[]).includes(mode)) {
        throw new Error(
            `[xweb] invalid capture mode: ${mode} (expected ${NETLOG_CAPTURE_MODES.join(" | ")})`,
        );
    }
    return mode as NetLogCaptureMode;
};

export const xwebMain = async (argv: string[]): Promise<void> => {
    const args = parse_xweb_args(argv);
    // xweb mode never touches frida; the logger only consumes debugMain
    const cliOptions = {
        debugPort: 0,
        cdpPort: 0,
        debugMain: parse_xweb_debug_flag(argv),
        debugFrida: false,
        autoDetect: false,
        xwebBridge: false,
        xwebNetlogMode: "IncludeSocketBytes",
    } satisfies CliOptions;
    const logger = create_logger(cliOptions);

    switch (args.command) {
        case "discover": {
            const endpoints = await discoverXwebUseEndpoints(logger);
            for (const { port, alive } of endpoints) {
                console.log(`${port}\t${alive ? "xweb-use" : "-"}`);
            }
            return;
        }

        case "version":
            await runWithClient(args, logger, async (client) => {
                printResult("XWeb.version", await client.call("XWeb.version"));
            });
            return;

        case "targets":
            await runWithClient(args, logger, async (client) => {
                printResult("XWeb.targets", await client.call("XWeb.targets"));
            });
            return;

        case "netlog-start": {
            const mode = parseMode(args.positionals[0]);
            await runWithClient(args, logger, async (client) => {
                const netlog = new NetLogController(client, logger);
                printResult("XWeb.NetLogStart", await netlog.start(mode));
                logger.info(
                    `[xweb] netlog started (mode=${mode}); stop it with netlog-stop, ` +
                        `then fetch paths with netlog-paths`,
                );
            });
            return;
        }

        case "netlog-stop":
            await runWithClient(args, logger, async (client) => {
                printResult("XWeb.NetLogStop", await new NetLogController(client, logger).stop());
            });
            return;

        case "netlog-status":
            await runWithClient(args, logger, async (client) => {
                printResult(
                    "XWeb.NetLogStatus",
                    await new NetLogController(client, logger).status(),
                );
            });
            return;

        case "netlog-paths":
            await runWithClient(args, logger, async (client) => {
                const paths = await new NetLogController(client, logger).paths();
                if (paths.length === 0) {
                    logger.info("[xweb] no paths in reply (raw reply shown above if --debug-main)");
                }
                for (const p of paths) {
                    console.log(p);
                }
            });
            return;

        case "netlog-parse": {
            const file = args.positionals[0];
            if (!file) {
                throw new Error("[xweb] netlog-parse requires a net-export file path");
            }
            const requests = await parseNetlogFile(file, args.out, args.saveBodies, logger);
            logger.info(`[xweb] ${requests.length} URL_REQUEST(s) reconstructed -> ${args.out}`);
            const withBody = requests.filter((r) => r.bodyBase64).length;
            logger.info(`[xweb] ${withBody} request(s) carried body bytes`);
            return;
        }

        case "eval": {
            const target = args.positionals[0];
            if (!target) {
                throw new Error("[xweb] eval requires a script file path, or - for stdin");
            }
            const script =
                target === "-" ? await readStdin() : (await promises.readFile(target, "utf8")).toString();

            await runWithClient(args, logger, async (client) => {
                const result = await evaluateInAppContext(client, script, args.timeoutMs);
                printResult("XWeb.EvaluateJavaScript", result);
                if (!result.success) {
                    process.exitCode = 1;
                }
            });
            return;
        }

        default:
            throw new Error(`[xweb] unknown command: ${args.command} (see --help)`);
    }
};

// --debug-main is consumed twice (logger flag + parseArgs whitelist); peek it
// here so create_logger can be built before the strict parse of command args
const parse_xweb_debug_flag = (argv: string[]): boolean =>
    argv.includes("--debug-main");
