#!/usr/bin/env python3
"""Runs commands on a FastIron CLI over SSH, one at a time, waiting for the prompt.

The switch drops anything typed before its prompt, so commands cannot simply be piped.
Login goes through sshpass (password in SSHPASS). Stops at the first command the switch
refuses. "enable" prompts are answered with empty lines unless --enable-with-login is
given, which answers them with the login user and password.

Usage: fastiron-cli.py [--enable-with-login] <user@host> <ssh option>... -- <command>...
Prints the transcript (password masked) and exits 0 when every command ran, 2 when the
switch refused one, 3 on timeout or lost connection.
"""
import os
import re
import select
import subprocess
import sys
import time

PROMPT = re.compile(r"[\w.@()-]+[>#] ?$")
ASK_USER = re.compile(r"User ?Name ?: ?$", re.I)
ASK_PASSWORD = re.compile(r"Password ?: ?$", re.I)
REFUSED = re.compile(r"invalid input|incomplete command|^error|error -|not allowed|failed", re.I | re.M)
TIMEOUT = 60


def main():
    args = sys.argv[1:]
    enable_with_login = "--enable-with-login" in args
    args = [a for a in args if a != "--enable-with-login"]
    split = args.index("--")
    target, ssh_options, commands = args[0], args[1:split], args[split + 1:]
    user = target.split("@", 1)[0]
    password = os.environ.get("SSHPASS", "")

    proc = subprocess.Popen(
        ["sshpass", "-e", "ssh", "-tt", *ssh_options, target],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    transcript = []
    state = {"prompt": ""}

    def show():
        text = "".join(transcript).replace("\r", "")
        return text.replace(password, "********") if password else text

    def read_until(patterns):
        """Read until the last line matches one of patterns; return (index, new output)."""
        buffer = ""
        deadline = time.time() + TIMEOUT
        while time.time() < deadline:
            ready, _, _ = select.select([proc.stdout], [], [], 1)
            if ready:
                chunk = os.read(proc.stdout.fileno(), 4096).decode("utf-8", "replace")
                if not chunk:
                    break
                buffer += chunk
                transcript.append(chunk)
                last = buffer.replace("\r", "").rsplit("\n", 1)[-1]
                for index, pattern in enumerate(patterns):
                    if pattern.search(last):
                        if pattern is PROMPT:
                            state["prompt"] = last.strip()
                        return index, buffer
            elif proc.poll() is not None:
                break
        return None, buffer

    def send(line):
        proc.stdin.write((line + "\r\n").encode())
        proc.stdin.flush()

    def finish(code, message=""):
        try:
            send("exit")
            send("exit")
        except OSError:
            pass
        time.sleep(1)
        proc.kill()
        print(show())
        print(f"\nfastiron-cli: last prompt {state['prompt']}")
        if message:
            print(f"fastiron-cli: {message}")
        sys.exit(code)

    index, _ = read_until([PROMPT])
    if index is None:
        finish(3, "no prompt after login")

    for command in commands:
        send(command)
        while True:
            index, output = read_until([PROMPT, ASK_USER, ASK_PASSWORD])
            if index is None:
                finish(3, f"no prompt after: {command}")
            if index == 1:
                send(user if enable_with_login else "")
            elif index == 2:
                send(password if enable_with_login else "")
            else:
                break
        # the echoed command is the first line: look for refusals after it
        reply = output.replace("\r", "").split("\n", 1)[-1]
        if REFUSED.search(reply):
            finish(2, f"refused: {command}")

    finish(0)


if __name__ == "__main__":
    main()
