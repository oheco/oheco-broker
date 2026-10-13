#!/usr/bin/env python3
"""Run a native build with isolated signing compatibility for HarmonyOS SDKs.

Some SDK distributions sign their relocatable CRT objects. Their .codesign data
must not propagate into a new ELF. Go may also sign a completed executable before
an explicit packaging sign step. Discard input signature sections while linking,
then sign a fresh copy with the PATH-selected binary-sign-tool. Installed SDKs,
compilers, signing keys and source inputs are never modified.

Usage: python3 -B sdk/c/build/native-toolchain.py -- sh scripts/build.sh
The wrapper also works around a standalone extracted SDK build.
"""
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile


def main():
    command = sys.argv[1:]
    if command[:1] == ["--"]:
        command = command[1:]
    if not command:
        raise SystemExit("Supply a build/test command after --")
    if platform.system() not in ("HarmonyOS", "OHOS", "OpenHarmony"):
        raise SystemExit(subprocess.call(command))
    names = ("clang", "clang++", "llvm-objcopy", "binary-sign-tool")
    tools = {name: shutil.which(name) for name in names}
    if not all(tools.values()):
        raise SystemExit("Native LLVM tools and binary-sign-tool must be in PATH")
    parent = Path(os.environ["TMPDIR"]).resolve()
    with tempfile.TemporaryDirectory(prefix="broker-native-toolchain-", dir=parent) as directory:
        root = Path(directory)
        assert root.resolve().parent == parent and root.name.startswith("broker-native-toolchain-")
        discard = root / "discard-input-signatures.ld"
        discard.write_text("SECTIONS { /DISCARD/ : { *(.codesign) } }\nINSERT AFTER .text;\n")
        for name in ("clang", "clang++"):
            wrapper = root / name
            wrapper.write_text("#!" + sys.executable + "\n" +
                "import os,sys\n" +
                "args=sys.argv[1:]\n" +
                "compile_only=any(a in args for a in ['-c','-S','-E','-fsyntax-only','-M','-MM'])\n" +
                "if '-o' in args and not compile_only: args.insert(0," + repr("-Wl,-T," + str(discard)) + ")\n" +
                "os.execv(" + repr(tools[name]) + ",[" + repr(tools[name]) + "]+args)\n")
            wrapper.chmod(0o700)
        signer = root / "binary-sign-tool"
        signer.write_text("#!" + sys.executable + "\n" +
            "import os,sys,tempfile,subprocess,pathlib\n" +
            "args=sys.argv[1:]\n" +
            "tool=" + repr(tools["binary-sign-tool"]) + "\n" +
            "if args[:1]==['sign'] and '-inFile' in args:\n" +
            "    index=args.index('-inFile')+1\n" +
            "    with tempfile.TemporaryDirectory(prefix='sign-input-',dir=" + repr(str(root)) + ") as directory:\n" +
            "        work=pathlib.Path(directory)\n" +
            "        assert work.resolve().parent==pathlib.Path(" + repr(str(root)) + ").resolve()\n" +
            "        original=str(work/'unsigned')\n" +
            "        subprocess.run([" + repr(tools["llvm-objcopy"]) + ",'--remove-section=.codesign',args[index],original],check=True)\n" +
            "        args[index]=original\n" +
            "        raise SystemExit(subprocess.call([tool]+args))\n" +
            "os.execv(tool,[tool]+args)\n")
        signer.chmod(0o700)
        env = dict(os.environ, PATH=str(root) + os.pathsep + os.environ["PATH"])
        raise SystemExit(subprocess.call(command, env=env))


if __name__ == "__main__":
    main()
