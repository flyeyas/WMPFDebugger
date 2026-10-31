const getPlatform = () => {
    // retval: "windows" | "linux" | "darwin"
    return Process.platform;
}

const getMainModule = (version) => {
    const osPlatform = getPlatform();
    if (osPlatform === 'windows') {
        if (version >= 13331) {
            return Process.findModuleByName("flue.dll");
        }
        return Process.findModuleByName("WeChatAppEx.exe");
    } else if (osPlatform === 'linux') {
        return Process.findModuleByName("WeChatAppEx");
    } else if (osPlatform === 'darwin') {
        return Process.findModuleByName("WeChatAppEx Framework");
    }
};

const patchCDPFilter = (base, config) => {
    // xref: SendToClientFilter OR devtools_message_filter_applet_webview.cc
    // xref: CastToJson
    if (config.CastToJsonHookOffset) {
        // credit: @Redbeanw44602, pr #262
        const osPlatform = getPlatform();
        if (osPlatform === "windows") {
            // darwin must not take this path: its SendToClientFilter returns
            // via a sret slot, so replacing it with this wrapper crashes WMPF
            const castToJsonFunc = new NativeFunction(
                base.add(config.CastToJsonHookOffset),
                "pointer",
                ["pointer", "pointer"]
            );
            const callback = new NativeCallback(function(thiz, jsonOut, cborInput) {
                castToJsonFunc(jsonOut, cborInput);
                return jsonOut;
            }, "pointer", ["pointer", "pointer", "pointer"]);
            Interceptor.replace(base.add(config.CDPFilterHookOffset), callback);
        }
        if (osPlatform === "linux") {
            const castToJsonFunc = new NativeFunction(
                base.add(config.CastToJsonHookOffset),
                "pointer",
                ["pointer", "pointer", "pointer"]
            );
            const callback = new NativeCallback(function (jsonOut, thiz, cborInput, cborLen) {
                castToJsonFunc(jsonOut, cborInput, cborLen)
                return jsonOut
            }, "pointer", ["pointer", "pointer", "pointer", "pointer"]);
            Interceptor.replace(base.add(config.CDPFilterHookOffset), callback);
        }
        return;
    }

    // legacy flue fallback
    const offset = config.CDPFilterHookOffset;
    Interceptor.attach(base.add(offset), {
        onLeave(retval_) {
            // see https://github.com/evi0s/WMPFDebugger/pull/262
            const retval = getPlatform() == 'windows'
                ? retval_.readPointer()
                : retval_;
            if (retval.isNull()) return;
            try {
                const val = retval.add(8).readU32();
                send(`[patch] CDP filter on leave, retval+8 = ${val}`);
                if (val === 6) {
                    retval.add(8).writeU32(0x0);
                    send("[patch] CDP filter patched");
                }
            } catch (e) {
                send(`[patch] CDP filter error: ${e}`);
            }
        }
    });
};

const handleOnLoadStart = (a1, config) => {
    let miniappLaunchConfigPtr;
    let remoteDebugConfigPtr;
    let miniappScenePtr;

    const structOffsets = config.MiniAppConfigStructOffsets
        ? config.MiniAppConfigStructOffsets
        : config.SceneOffsets;

    // darwin 25800: the remote debug config hangs off `this` directly
    // (this+56 -> +1520 -> +16), not through the launch config
    if (config.RemoteDebugConfigChain) {
        remoteDebugConfigPtr = a1
            .add(config.RemoteDebugConfigChain[0])
            .readPointer()
            .add(config.RemoteDebugConfigChain[1])
            .readPointer()
            .add(config.RemoteDebugConfigChain[2])
            .readPointer();
        miniappScenePtr = remoteDebugConfigPtr.add(structOffsets.SceneOffset);
    } else if (config.SceneOffsets) {
        // legacy scene config
        miniappLaunchConfigPtr = a1
            .add(structOffsets[0])
            .readPointer()
            .add(structOffsets[1])
            .readPointer()
            .add(structOffsets[2])
            .readPointer();
        remoteDebugConfigPtr = miniappLaunchConfigPtr
            .add(structOffsets[3])
            .readPointer()
            .add(structOffsets[4])
            .readPointer();

        miniappScenePtr = remoteDebugConfigPtr.add(structOffsets[5]);
    } else {
        // later wmpf builds (win32)
        const launchConfigOffsets = structOffsets.LaunchConfigOffsets;
        const remoteDebugConfigOffsets = structOffsets.RemoteDebugConfigOffsets;
        miniappLaunchConfigPtr = a1
            .add(launchConfigOffsets[0])
            .readPointer()
            .add(launchConfigOffsets[1])
            .readPointer()
            .add(launchConfigOffsets[2])
            .readPointer();
        remoteDebugConfigPtr = miniappLaunchConfigPtr
            .add(remoteDebugConfigOffsets[0])
            .readPointer()
            .add(remoteDebugConfigOffsets[1])
            .readPointer();

        miniappScenePtr = remoteDebugConfigPtr.add(structOffsets.SceneOffset);
    }

    // 1000: from issue #83 <-- will crash the process
    // 1007: from issue #80
    // 1008: from issue #53
    // 1011: scan QR code
    // 1012: recognize QR code from long-pressed image (issue #128)
    // 1027: from issue #78
    // 1035: from issue #78
    // 1037: opened from another mini program
    // 1053: from issue #25
    // 1074: from issue #32
    // 1145: from search
    // 1178: from phone (issue #117)
    // 1256: from recent
    // 1260: from frequently used
    // 1302: from services
    // 1308: minigame?
    const sceneNumberArray = [
        1005, 1007, 1008, 1011, 1012, 1027, 1035, 1037, 1053, 1074, 1145, 1178,
        1256, 1260, 1302, 1308,
    ];
    if (!sceneNumberArray.includes(miniappScenePtr.readInt())) {
        return;
    }

    send(`[hook] scene: ${miniappScenePtr.readInt()}`);
    send("[hook] hook scene condition -> 1101");
    miniappScenePtr.writeInt(1101);

    if (config.SceneOffsets) {
        // legacy path, we are done here
        return;
    }

    // setup the websocket back connection URL for new flue builds
    // it's now adjustable as well :)
    // on darwin the URL string lives in the remote debug config (rc-relative),
    // on win32/linux in the launch config
    const websocketUrl = "ws://localhost:9421";
    const websocketUrlBasePtr = getPlatform() === "darwin"
            ? remoteDebugConfigPtr
            : miniappLaunchConfigPtr;
    const websocketUrlStringPtr = websocketUrlBasePtr
            .add(structOffsets.WebSocketURLStringOffset);
    const stringMarker = websocketUrlStringPtr.add(23).readS8();
    if (stringMarker < 0) {
        // long representation: { data pointer, length, capacity | high bit }.
        websocketUrlStringPtr.readPointer().writeUtf8String(websocketUrl);
        websocketUrlStringPtr.add(8).writeU64(websocketUrl.length);
    } else {
        // short representation: 23 inline bytes followed by a one-byte length.
        websocketUrlStringPtr.writeUtf8String(websocketUrl);
        websocketUrlStringPtr.add(23).writeU8(websocketUrl.length);
    }
    send(`[hook] websocket url -> ${websocketUrl}`);

    const remoteDebugModePtr = remoteDebugConfigPtr
            .add(structOffsets.RemoteDebugModeOffset);
    send(`[hook] remote debug mode: ${remoteDebugModePtr.readInt()} -> 1`);
    const originalMode = remoteDebugModePtr.readInt();
    remoteDebugModePtr.writeInt(1);

    // the scene/debug-mode values live in a struct shared across containers:
    // keeping scene=1101 + mode=1 makes every later container re-enter the
    // single-shot debug lifecycle (fails with "LifeCycle.load fail" and
    // crashes some programs), so the caller clears the debug-mode flag
    // shortly after this call; the network reporter only checks scene==1101
    return {
        modePtr: remoteDebugModePtr,
        originalMode,
    };
};

const patchedContainers = new Set();

const patchOnLoadStart = (base, config) => {
    // xref: AppletIndexContainer::OnLoadStart
    Interceptor.attach(base.add(config.LoadStartHookOffset), {
        onEnter(args) {
            // patching the same container twice re-runs the (single-shot)
            // debug lifecycle, which fails with
            // "LifeCycle.load fail: Cannot set a non-pending waiting value"
            // and tears down the debug client, so every later OnLoadStart of
            // an already-patched container is left untouched
            const container = args[0].toString();
            if (patchedContainers.has(container)) {
                return;
            }
            if (patchedContainers.size > 64) {
                patchedContainers.clear();
            }
            patchedContainers.add(container);

            send(
                `[inteceptor] AppletIndexContainer::OnLoadStart onEnter, ` +
                `indexContainer.this: ${args[0]}`,
            );
            // write debug_flag to 0x1
            if (args[1].and(0xff).toInt32() !== 1) {
                args[1] = args[1].and(ptr("0xffffffffffffff00")).or(1);
            }
            // handle onLoadStart parameters
            try {
                this.patchInfo = handleOnLoadStart(args[0], config);
            } catch (e) {
                // a bogus pointer chain on one container must not take down
                // the interceptor for the whole process
                send(`[hook] handleOnLoadStart failed: ${e}`);
            }
        },
        onLeave(retval) {
            const info = this.patchInfo;
            if (!info) return;
            // keep scene=1101 (the per-request network reporter checks it)
            // but clear the debug-mode flag ~2s in, once the appservice has
            // dialed back: the container debug lifecycle is gated on BOTH
            // scene==1101 and mode==1, so this stops later containers from
            // re-entering it (the crash trigger)
            setTimeout(() => {
                try {
                    info.modePtr.writeInt(info.originalMode);
                    send(`[hook] debug mode restored to ${info.originalMode}`);
                } catch (e) {
                    send(`[hook] debug mode restore failed: ${e}`);
                }
            }, 2000);
        },
    });
};

const parseConfig = () => {
    const rawConfig = `@@CONFIG@@`;
    if (rawConfig.includes("@@")) {
        // test addresses
        return {
            Version: 18955,
            LoadStartHookOffset: "0x25B52C0",
            CDPFilterHookOffset: "0x30248B0",
            SceneOffsets: [1408, 1344, 488],
        };
    }
    return JSON.parse(rawConfig);
};

const main = () => {
    const config = parseConfig();
    const mainModule = getMainModule(config.Version);
    patchOnLoadStart(mainModule.base, config);
    patchCDPFilter(mainModule.base, config);
};

main();
