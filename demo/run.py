"""Drive the end-to-end demos in docker compose (``demo/compose.yaml``).

    python demo/run.py one-to-one      # just demo
    python demo/run.py group           # just demo-group

Every step runs the commands a person would run on that host, with
``docker compose exec``, and prints them. The few things the CLI has no
command for (a message from the human, closing a group) use the local API
with the human token, through ``curl`` on the daemon's Unix socket. Each
step checks what it should have caused and stops with an error if it
didn't, so the integration suite (``integration/tests``) runs the same
code.

Standard library only: the host needs docker and Python, nothing else.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import secrets
import shlex
import subprocess
import sys
import time
from collections.abc import Callable, Generator, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[1]
COMPOSE = REPO / "demo" / "compose.yaml"
IMAGE = "agentconnect-demo:dev"
WAIT = 90.0  # seconds any one step may take
POLL = 0.5
# The agents' data directories inside their containers (demo/compose.yaml).
SOCKET = "$AC_DATA_DIR/agentconnectd.sock"
HUMAN_TOKEN = "$AC_DATA_DIR/human-token"  # noqa: S105 - a path, not a token


class DemoError(RuntimeError):
    """A step didn't do what it should have."""


def say(text: str) -> None:
    print(f"\n== {text}", flush=True)


def show(command: str, output: str = "") -> None:
    print(f"$ {command}", flush=True)
    for line in output.rstrip().splitlines():
        print(f"  {line}", flush=True)


def wait_for[T](what: str, check: Callable[[], T | None], within: float = WAIT) -> T:
    """Poll ``check`` until it returns something other than ``None``."""
    deadline = time.monotonic() + within
    while True:
        found = check()
        if found is not None:
            return found
        if time.monotonic() > deadline:
            msg = f"timed out waiting for {what}"
            raise DemoError(msg)
        time.sleep(POLL)


def build_image(real_models: bool = False) -> None:
    """Build the demo image (cached after the first build)."""
    say("Build the demo image (the relay, the daemon, the SDK and the sample agents)")
    args = ["docker", "build", "-f", str(REPO / "demo" / "Dockerfile"), "-t", IMAGE]
    if real_models:
        args += ["--build-arg", "REAL_MODELS=1"]
    subprocess.run([*args, str(REPO)], check=True)  # noqa: S603


@dataclass
class Deployment:
    """One compose project: the relay and the hosts, on their own networks."""

    project: str
    profiles: Sequence[str] = ()
    quiet: bool = False
    env: dict[str, str] = field(default_factory=dict)

    def _base(self) -> list[str]:
        args: list[str] = ["docker", "compose", "-f", str(COMPOSE), "-p", self.project]
        for p in self.profiles:
            args += ["--profile", p]
        return args

    def compose(
        self, *args: str, stdin: str | None = None, check: bool = True
    ) -> subprocess.CompletedProcess[str]:
        result = subprocess.run(  # noqa: S603
            [*self._base(), *args],
            input=stdin,
            capture_output=True,
            text=True,
            env={**os.environ, **self.env},
            check=False,
        )
        if check and result.returncode != 0:
            msg = f"docker compose {' '.join(args)} failed ({result.returncode}): {result.stderr}"
            raise DemoError(msg)
        return result

    def up(self) -> None:
        say(f"Start the relay and the hosts (compose project {self.project})")
        self.compose("up", "-d", "--wait")
        show(f"docker compose -p {self.project} ps", self.compose("ps").stdout)

    def down(self) -> None:
        self.compose("down", "-v", "--remove-orphans", check=False)

    def sh(self, service: str, script: str, stdin: str | None = None) -> str:
        """Run ``script`` with ``sh -c`` in ``service`` (its environment)."""
        return self.compose("exec", "-T", service, "sh", "-c", script, stdin=stdin).stdout

    def run(self, service: str, *args: str, stdin: str | None = None, echo: bool = True) -> str:
        """Run a command in ``service``; print it and its output."""
        out = self.compose("exec", "-T", service, *args, stdin=stdin).stdout
        if echo and not self.quiet:
            show(f"[{service}] {shlex.join(args)}", out)
        return out

    def cli(self, service: str, *args: str, echo: bool = True) -> Any:
        """``agentconnect <args> --json`` in ``service``, parsed."""
        out = self.compose("exec", "-T", service, "agentconnect", *args, "--json").stdout
        if echo and not self.quiet:
            show(f"[{service}] agentconnect {shlex.join(args)} --json", _brief(out))
        return json.loads(out)

    def events(self, service: str) -> list[dict[str, Any]]:
        out = self.compose("exec", "-T", service, "agentconnect", "events", "--json").stdout
        return [json.loads(line) for line in out.splitlines() if line.strip()]

    def audit(self, service: str) -> list[dict[str, Any]]:
        return list(self.cli(service, "audit", echo=False)["audit"])

    def human_api(
        self, service: str, path: str, body: dict[str, Any] | None = None, *, echo: bool = True
    ) -> Any:
        """The local API with the human token, as ``curl`` would call it: a
        POST of ``body``, or a GET without one."""
        data = "--data-binary @- " if body is not None else ""
        script = (
            f'curl -sS --fail-with-body --unix-socket "{SOCKET}" '
            f'-H "Authorization: Bearer $(cat "{HUMAN_TOKEN}")" '
            f'-H "Content-Type: application/json" {data}"http://agentconnectd{path}"'
        )
        out = self.sh(service, script, stdin=None if body is None else json.dumps(body))
        if not echo:
            return json.loads(out)
        if not self.quiet:
            show(
                f"[{service}] curl --unix-socket ... -H 'Authorization: Bearer <human token>' "
                f"-d '{json.dumps(body)}' http://agentconnectd{path}",
                out,
            )
        return json.loads(out)

    def logs(self, service: str) -> str:
        return self.compose("logs", "--no-color", "--no-log-prefix", service).stdout

    def tap(self, host: str, op: str, **args: Any) -> Any:
        """A control operation on ``host``'s relay tap (agentconnect_harness.tap)."""
        out = self.compose(
            "exec",
            "-T",
            host,
            "python",
            "-m",
            "agentconnect_harness.tap",
            "ctl",
            op,
            json.dumps(args),
        ).stdout
        return json.loads(out)

    def group(self, service: str, group_id: str) -> dict[str, Any]:
        return dict(self.cli(service, "groups", "show", group_id, echo=False))

    def lines(self, service: str, needle: str) -> list[str]:
        return [ln for ln in self.logs(service).splitlines() if needle in ln]

    def wait_log(self, service: str, needle: str, count: int = 1) -> list[str]:
        found = wait_for(
            f"{count} line(s) with {needle!r} in {service}'s output",
            lambda: ls if len(ls := self.lines(service, needle)) >= count else None,
        )
        if not self.quiet:
            for ln in found[-count:]:
                print(f"  {service}| {ln}", flush=True)
        return found

    def wait_event(self, service: str, kind: str, count: int = 1) -> list[dict[str, Any]]:
        return wait_for(
            f"{count} {kind} event(s) on {service}",
            lambda: (
                es
                if len(es := [e for e in self.events(service) if e["type"] == kind]) >= count
                else None
            ),
        )


def _brief(out: str) -> str:
    """The JSON a command printed, without the long lists."""
    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        return out
    if isinstance(data, dict):
        keep = ("status", "group_id", "url", "epoch", "sas", "outcome", "msg_id", "request_id")
        keep += ("labels",)
        brief = {k: v for k, v in data.items() if k in keep}
        if "sas" in brief and isinstance(brief["sas"], dict):
            brief["sas"] = f"{brief['sas']['emoji']}  {brief['sas']['decimal']}"
        return json.dumps(brief, ensure_ascii=False) if brief else out
    return out


# -- steps shared by both demos ------------------------------------------------------------------


def invite_and_join(
    dep: Deployment, joiner: str, url: str, owner: str = "daemon-a"
) -> dict[str, Any]:
    """``joiner`` accepts ``url``; the owner's human approves; ``accept``
    then prints the group's short code."""
    say(f"{joiner}: accept the invite (it waits for the inviter's approval)")
    command = [*dep._base(), "exec", "-T", joiner, "agentconnect", "accept", url, "--yes", "--json"]
    accepting = subprocess.Popen(  # noqa: S603
        command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
    )
    if not dep.quiet:
        show(f"[{joiner}] agentconnect accept '<url>' --yes --json")
    try:
        say(f"{owner}: the human lists the join request and approves it")
        pending = wait_for(
            "the join request",
            lambda: next(
                (
                    a
                    for a in dep.cli(owner, "approvals", "list", echo=False)["approvals"]
                    if a["kind"] == "join"
                ),
                None,
            ),
        )
        if not dep.quiet:
            show(
                f"[{owner}] agentconnect approvals list --json",
                f"{pending['display_name']} {pending['fingerprint']} wants to join "
                f"(request {pending['request_id']})",
            )
        dep.cli(owner, "approvals", "approve", pending["request_id"], "--yes")
        out, err = accepting.communicate(timeout=WAIT)
    finally:
        if accepting.poll() is None:
            accepting.kill()
    if accepting.returncode != 0:
        msg = f"accept failed ({accepting.returncode}): {err}"
        raise DemoError(msg)
    joined = json.loads(out)
    if joined["status"] != "joined":
        msg = f"accept ended {joined['status']}"
        raise DemoError(msg)
    if not dep.quiet:
        show(f"[{joiner}] (accept finished)", _brief(out))
    return dict(joined)


def converge(dep: Deployment, services: Sequence[str], group_id: str) -> dict[str, Any]:
    """Wait until every member is on one epoch with the same member count."""

    def same() -> dict[str, Any] | None:
        views = [dep.group(s, group_id) for s in services]
        if len({(v["epoch"], len(v["members"])) for v in views}) == 1:
            return views[0]
        return None

    view = wait_for("the members to agree on the group", same)
    if not dep.quiet:
        print(f"  {', '.join(services)}: epoch {view['epoch']}", flush=True)
    return view


def verify_pair(dep: Deployment, one: str, other: str, group_id: str) -> dict[str, Any]:
    """Both humans run ``agentconnect verify`` at the same time, each for the
    other (SPEC 11): their daemons run the commit-then-reveal exchange, both
    show the same code with mirrored instance labels, and each human answers
    ``y`` twice (the labels, then the code). Returns ``one``'s answer."""
    ids = {s: identity(dep, s) for s in (one, other)}
    procs = {}
    for me, peer in ((one, other), (other, one)):
        command = [
            *dep._base(),
            "exec",
            "-T",
            me,
            "agentconnect",
            "verify",
            group_id,
            ids[peer],
            "--json",
        ]
        procs[me] = subprocess.Popen(  # noqa: S603
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if not dep.quiet:
            show(f"[{me}] agentconnect verify {group_id} <{peer}> --json")
    outs = {}
    try:
        for me, proc in procs.items():
            out, err = proc.communicate("y\ny\n", timeout=WAIT)
            if proc.returncode != 0:
                msg = f"verify on {me} failed ({proc.returncode}): {out} {err}"
                raise DemoError(msg)
            outs[me] = json.loads(out.strip().splitlines()[-1])
    finally:
        for proc in procs.values():
            if proc.poll() is None:
                proc.kill()
    first, second = outs[one], outs[other]
    mirrored = {"self": second["labels"]["peer"], "peer": second["labels"]["self"]}
    if first["sas"] != second["sas"] or first["labels"] != mirrored:
        msg = f"{one} and {other} didn't read the same code: {first} {second}"
        raise DemoError(msg)
    if not dep.quiet:
        show(f"[{one}] (verify finished)", _brief(json.dumps(first, ensure_ascii=False)))
        show(f"[{other}] (verify finished)", _brief(json.dumps(second, ensure_ascii=False)))
    return dict(first)


def sas_runs(
    dep: Deployment, one: str, other: str, group_id: str, *, within: float = WAIT
) -> tuple[dict[str, Any], dict[str, Any]]:
    """A SAS run started on both sides through the human API, without
    answering it; returns both views once both ended (or after ``within``,
    as they stand: a run that never pairs keeps waiting)."""
    ids = {s: identity(dep, s) for s in (one, other)}
    runs = {
        me: dep.human_api(me, f"/v0/groups/{group_id}/members/{ids[peer]}/sas", {}, echo=False)
        for me, peer in ((one, other), (other, one))
    }

    def views() -> dict[str, dict[str, Any]]:
        return {
            me: dep.human_api(me, f"/v0/groups/{group_id}/sas/runs/{r['run']}", echo=False)
            for me, r in runs.items()
        }

    def all_ended() -> dict[str, dict[str, Any]] | None:
        seen = views()
        return seen if all(x["state"] in ("done", "aborted") for x in seen.values()) else None

    with contextlib.suppress(DemoError):
        wait_for("both SAS runs to end", all_ended, within=within)
    seen = views()
    return seen[one], seen[other]


def identity(dep: Deployment, service: str) -> str:
    return str(dep.cli(service, "status", echo=False)["identity"])


def human_send(dep: Deployment, service: str, group_id: str, text: str, to: Sequence[str]) -> str:
    """A message from the human (origin ``human``): the human token sends it."""
    sent = dep.human_api(service, f"/v0/groups/{group_id}/messages", {"text": text, "to": list(to)})
    return str(sent["msg_id"])


def audit_from(dep: Deployment, service: str, sender: str, group_id: str) -> list[dict[str, Any]]:
    return [
        r
        for r in dep.audit(service)
        if r["direction"] == "in" and r["sender"] == sender and r["group_id"] == group_id
    ]


# -- demo 1: one to one ---------------------------------------------------------------------------


@dataclass
class OneToOne:
    group_id: str
    markers: list[str]
    sas: str


def one_to_one(dep: Deployment, run_id: str) -> OneToOne:
    m = [f"m{i}-{run_id}" for i in range(1, 5)]

    say("Host A: the human creates an invite (a new group of two)")
    invite = dep.cli("daemon-a", "invite", "create", "--purpose", "Plan the v0.1 release")
    gid = invite["group_id"]
    invite_and_join(dep, "daemon-b", invite["url"])

    say("Both humans run verify at once and compare the code on a call (SPEC 11)")
    converge(dep, ["daemon-a", "daemon-b"], gid)
    shown = verify_pair(dep, "daemon-a", "daemon-b", gid)
    for s in ("daemon-a", "daemon-b"):
        if not all(mb["verified"] for mb in dep.group(s, gid)["members"] if not mb["self"]):
            msg = f"{s} doesn't show the other member verified"
            raise DemoError(msg)

    say("B's agent asks A's agent for the release notes: A streams a task")
    dep.wait_log("agent-b", "attached to the daemon")
    dep.run(
        "daemon-b",
        "agentconnect",
        "send",
        gid,
        f"Please stream the release notes for v0.1 ({m[0]}).",
    )
    dep.wait_log(
        "agent-a", f"streaming release notes for 'Please stream the release notes for v0.1 ({m[0]})"
    )
    dep.wait_log("agent-b", "artifact:", count=2)
    dep.wait_log("agent-b", "TASK_STATE_COMPLETED")

    say("B's agent asks for a deploy: A's task needs input, B's agent answers, A completes it")
    dep.run("daemon-b", "agentconnect", "send", gid, f"Please deploy v0.1 ({m[1]}).")
    dep.wait_log("agent-b", "TASK_STATE_INPUT_REQUIRED")
    dep.wait_log("agent-b", " input: ")
    dep.wait_log("agent-a", "continued:")
    dep.wait_log("agent-b", "TASK_STATE_COMPLETED: 'Deploying v0.1 to")

    say("Host B goes offline; A's agent sends; B comes back and the message arrives")
    dep.compose("stop", "agent-b", "daemon-b")
    if not dep.quiet:
        show("docker compose stop agent-b daemon-b")
    dep.run(
        "daemon-a",
        "agentconnect",
        "send",
        gid,
        f"While you were away v0.1 was tagged ({m[2]}). Can you confirm?",
    )
    dep.compose("start", "daemon-b", "agent-b")
    if not dep.quiet:
        show("docker compose start daemon-b agent-b")
    dep.wait_log(
        "agent-b", f"question from release-agent: 'While you were away v0.1 was tagged ({m[2]})"
    )
    dep.wait_log(
        "agent-a", f"Noted: answer-bot answers: While you were away v0.1 was tagged ({m[2]})"
    )

    say("A's human closes the group: B gets close_requested, and B's human leaves")
    dep.human_api(
        "daemon-a",
        f"/v0/groups/{gid}/messages",
        {"kind": "control.close", "body": {"reason": f"release planned ({m[3]})"}},
    )
    (close,) = dep.wait_event("daemon-b", "close_requested")
    if not dep.quiet:
        show("[daemon-b] agentconnect events --json", json.dumps(close))
    dep.cli("daemon-b", "leave", gid)
    dep.wait_event("daemon-b", "left")
    dep.wait_event("daemon-a", "member_left")
    if not dep.quiet:
        show("[daemon-a] agentconnect events --json", "member_left: answer-bot left the group")
    return OneToOne(gid, m, shown["sas"]["decimal"])


# -- demo 2: a group of three --------------------------------------------------------------------


@dataclass
class GroupRun:
    group_id: str
    markers: list[str]
    ids: dict[str, str]


HOSTS = {"a": "daemon-a", "b": "daemon-b", "c": "agent-c"}


def form_group(dep: Deployment, max_agent_turns: int = 4) -> tuple[str, dict[str, str]]:
    """Three hosts in one group from one invite with two uses."""
    say("Host A: the human creates a group and one invite for two agents")
    invite = dep.cli(
        "daemon-a", "invite", "create", "--purpose", "Plan the v0.1 release", "--max-uses", "2"
    )
    gid = str(invite["group_id"])
    for joiner in ("daemon-b", "agent-c"):
        invite_and_join(dep, joiner, invite["url"])
    say("A's human sets the loop guard: at most this many agent turns in a row")
    dep.cli("daemon-a", "group", "policy", gid, "--max-agent-turns", str(max_agent_turns))
    say("The humans compare short codes, a pair at a time, and verify (SPEC 11)")
    view = converge(dep, list(HOSTS.values()), gid)
    if view["floor"]["mode"] != "mention":
        msg = f"the floor is {view['floor']['mode']}, not mention"
        raise DemoError(msg)
    if not dep.quiet:
        print(f"  floor: {view['floor']['mode']} (three members)", flush=True)
    hosts = list(HOSTS.values())
    for i, one in enumerate(hosts):
        for other in hosts[i + 1 :]:
            verify_pair(dep, one, other, gid)
    return gid, {k: identity(dep, s) for k, s in HOSTS.items()}


def group_demo(dep: Deployment, run_id: str) -> GroupRun:
    m = [f"g{i}-{run_id}" for i in range(1, 5)]
    gid, ids = form_group(dep)

    say("Mention mode: the human asks the LangGraph agent only; only it answers")
    sent = human_send(
        dep, "daemon-a", gid, f"What is the riskiest part of v0.1 ({m[0]})?", [ids["c"]]
    )
    dep.wait_log(
        "agent-c", f"question from release-agent: 'What is the riskiest part of v0.1 ({m[0]})?'"
    )
    wait_for(
        "the LangGraph agent's answer", lambda: audit_from(dep, "daemon-a", ids["c"], gid) or None
    )
    dep.wait_log(
        "agent-b", f"context from release-agent: 'What is the riskiest part of v0.1 ({m[0]})?'"
    )
    decisions = {r["msg_id"]: r["decision"] for r in dep.audit("daemon-b")}
    if decisions.get(sent) != "deliver_as_context" or audit_from(dep, "daemon-a", ids["b"], gid):
        msg = "the Agent SDK agent was triggered by a message that didn't name it"
        raise DemoError(msg)
    if not dep.quiet:
        print(
            "  daemon-b audit: the question was context for answer-bot; it didn't answer",
            flush=True,
        )

    say("The human names both SDK agents: both answer")
    human_send(dep, "daemon-a", gid, f"Who reviews the v0.1 notes ({m[1]})?", [ids["b"], ids["c"]])
    dep.wait_log("agent-b", f"question from release-agent: 'Who reviews the v0.1 notes ({m[1]})?'")
    dep.wait_log("agent-c", f"question from release-agent: 'Who reviews the v0.1 notes ({m[1]})?'")
    wait_for("both answers", lambda: audit_from(dep, "daemon-a", ids["b"], gid) or None)

    say("The owner's human removes the LangGraph agent: it can't read the next epoch")
    before = converge(dep, ["daemon-a", "daemon-b"], gid)
    dep.cli("daemon-a", "remove", gid, ids["c"], "--yes")
    dep.wait_event("agent-c", "removed")
    after = wait_for(
        "a new epoch on A and B",
        lambda: (
            v
            if (v := converge(dep, ["daemon-a", "daemon-b"], gid))["epoch"] > before["epoch"]
            and len(v["members"]) == 2  # noqa: PLR2004 - A and B
            else None
        ),
    )
    if not dep.quiet:
        print(f"  epoch before: {before['epoch']}, after: {after['epoch']}", flush=True)
    sent = human_send(
        dep, "daemon-a", gid, f"C is gone; B, can you still read this ({m[2]})?", [ids["b"]]
    )
    dep.wait_log("agent-b", f"C is gone; B, can you still read this ({m[2]})")
    (left,) = [g for g in dep.cli("agent-c", "groups", "list")["groups"] if g["group_id"] == gid]
    if left["status"] != "removed" or left["epoch"] >= after["epoch"]:
        msg = f"the removed agent is {left['status']} at epoch {left['epoch']}"
        raise DemoError(msg)
    if any(r["msg_id"] == sent for r in dep.audit("agent-c")) or dep.lines("agent-c", m[2]):
        msg = "the removed agent read a message from after its removal"
        raise DemoError(msg)
    if not dep.quiet:
        print(
            f"  agent-c: {left['status']} at epoch {left['epoch']}, the others are at "
            f"{after['epoch']}; nothing from the new epoch reached it",
            flush=True,
        )
    say("A and B compare a new short code, of the group without C")
    verify_pair(dep, "daemon-a", "daemon-b", gid)

    say("Loop guard: the Agent SDK agent and the release agent debate until the guard pauses them")
    human_send(
        dep,
        "daemon-a",
        gid,
        f"Is Friday a good day to ship v0.1? Keep debating it with the release agent ({m[3]})?",
        [ids["b"]],
    )
    for s in ("daemon-a", "daemon-b"):
        (guard,) = dep.wait_event(s, "loop_guard")
        if not dep.quiet:
            show(
                f"[{s}] agentconnect events --json",
                json.dumps({"type": "loop_guard", **guard["data"]}),
            )
    return GroupRun(gid, m, ids)


# -- entry point ---------------------------------------------------------------------------------


@contextlib.contextmanager
def deployment(
    project: str, profiles: Sequence[str] = (), keep: bool = False, quiet: bool = False
) -> Generator[Deployment]:
    dep = Deployment(project, profiles, quiet=quiet)
    dep.down()
    try:
        dep.up()
        yield dep
    except BaseException:
        for s in dep.compose("ps", "--services", check=False).stdout.split():
            print(f"\n--- {s} ---\n{dep.logs(s)[-4000:]}", file=sys.stderr)
        raise
    finally:
        if not keep:
            dep.down()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run an AgentConnect demo in docker compose.")
    parser.add_argument("demo", choices=["one-to-one", "group"])
    parser.add_argument("--keep", action="store_true", help="leave the containers running")
    parser.add_argument("--no-build", action="store_true", help="use the image as it is")
    ns = parser.parse_args(argv)
    real = os.environ.get("AC_EXAMPLE_MODEL", "stub") == "real"
    if real and not os.environ.get("ANTHROPIC_API_KEY", ""):
        print("AC_EXAMPLE_MODEL=real needs ANTHROPIC_API_KEY", file=sys.stderr)
        return 2
    if not ns.no_build:
        build_image(real_models=real)
    run_id = secrets.token_hex(4)
    try:
        if ns.demo == "one-to-one":
            with deployment("agentconnect-demo", keep=ns.keep) as dep:
                one_to_one(dep, run_id)
        else:
            with deployment("agentconnect-demo-group", ("group",), keep=ns.keep) as dep:
                group_demo(dep, run_id)
    except DemoError as e:
        print(f"\ndemo failed: {e}", file=sys.stderr)
        return 1
    say("Done")
    return 0


if __name__ == "__main__":
    sys.exit(main())
