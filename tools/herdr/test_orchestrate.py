import argparse
import json
import subprocess
import sys
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from pathlib import Path
from threading import Barrier
from unittest.mock import Mock, patch

from orchestrate import (
    Herdr,
    Stop,
    abandon,
    advance,
    agent_binding,
    collect,
    connect,
    evidence_digest,
    get_task,
    has_receipt,
    native_executable,
    reserve,
    send,
    sender_lock,
    transaction,
    update_run,
    verify_workspace,
)


class TaskTests(unittest.TestCase):
    def setUp(self):
        directory = self.enterContext(tempfile.TemporaryDirectory())
        self.root = Path(directory)
        self.db = self.enterContext(closing(connect(self.root / "tasks.sqlite")))
        self.brief = self.root / "brief.txt"
        self.brief.write_text("Tool-free synthetic test.", encoding="utf-8")

    def add(self, name, owner="copilot", reviewer="deepseek", mode="tool-free"):
        with transaction(self.db):
            self.db.execute(
                "INSERT INTO tasks(id,owner,reviewer,mode) VALUES(?,?,?,?)", (name, owner, reviewer, mode)
            )

    def test_status_cli_filters_by_task(self):
        command = [
            sys.executable,
            "-B",
            str(Path(__file__).with_name("orchestrate.py")),
            "--db",
            str(self.root / "cli-tasks.sqlite"),
        ]

        def run_cli(*args):
            return subprocess.run([*command, *args], capture_output=True, text=True, timeout=15)

        for task, owner in (("second", "qwen"), ("first", "copilot")):
            created = run_cli("create", task, owner, "deepseek", "--mode", "tool-free")
            self.assertEqual(created.returncode, 0, created.stderr)

        unfiltered = run_cli("status")
        self.assertEqual(unfiltered.returncode, 0, unfiltered.stderr)
        self.assertEqual(unfiltered.stderr, "")
        lines = unfiltered.stdout.splitlines()
        records = [json.loads(line) for line in lines]
        self.assertEqual([record["id"] for record in records], ["first", "second"])
        for record in records:
            self.assertEqual(list(record), ["id", "owner", "reviewer", "mode", "phase", "state", "revision"])

        filtered = run_cli("status", "--task", "second")
        self.assertEqual(filtered.returncode, 0, filtered.stderr)
        self.assertEqual(filtered.stderr, "")
        self.assertEqual(filtered.stdout, lines[1] + "\n")

        for task in ("missing", "", "missing'task"):
            with self.subTest(task=task):
                unknown = run_cli("status", f"--task={task}")
                self.assertNotEqual(unknown.returncode, 0)
                self.assertEqual(unknown.stdout, "")
                self.assertEqual(unknown.stderr.strip(), "Unknown task.")

    def test_concurrency_count_and_heavy_limits_across_connections(self):
        self.add("one", "minimax")
        self.add("two", "nemotron")
        self.add("three")
        self.add("four", "qwen")
        self.add("five", "particle")
        reserve(self.db, "one", "minimax")
        with closing(connect(self.root / "tasks.sqlite")) as other:
            with self.assertRaisesRegex(Stop, "concurrency"):
                reserve(other, "two", "nemotron")
            reserve(other, "three", "copilot")
            reserve(other, "four", "qwen")
        with self.assertRaisesRegex(Stop, "concurrency"):
            reserve(self.db, "five", "particle")

    def test_concurrent_heavy_reservations_cannot_both_succeed(self):
        self.add("first", "minimax")
        self.add("second", "nemotron")
        barrier = Barrier(2)
        database = self.root / "tasks.sqlite"

        def compete(task, actor):
            with closing(connect(database)) as db:
                barrier.wait(timeout=10)
                try:
                    reserve(db, task, actor)
                except Stop as error:
                    return str(error)
                return "reserved"

        with ThreadPoolExecutor(max_workers=2) as pool:
            first = pool.submit(compete, "first", "minimax")
            second = pool.submit(compete, "second", "nemotron")
            self.assertCountEqual(
                (first.result(timeout=15), second.result(timeout=15)),
                ("reserved", "A concurrency limit was reached."),
            )

    def test_nonce_not_recognized_inside_prompt_echo(self):
        self.assertFalse(has_receipt("> Write SENTINELAI-DONE-abc", "abc"))
        self.assertFalse(has_receipt("┃ Finish with SENTINELAI-DONE and -abc. ┃", "abc"))
        self.assertTrue(has_receipt("┃    SENTINELAI-DONE-abc     ┃", "abc"))
        self.assertTrue(has_receipt("SENTINELAI-DONE -abc", "abc"))
        self.assertFalse(has_receipt("PROBE-SENTINELAI-DONE-abc", "abc"))
        self.assertTrue(has_receipt("PROBE-SENTINELAI-DONE-abc", "abc", "PROBE-SENTINELAI-DONE-abc"))
        with self.assertRaisesRegex(Stop, "complete observed receipt"):
            has_receipt("PROBE-SENTINELAI-DONE-abc", "abc", "PROBE-SENTINELAI-DONE-def")
        self.assertTrue(has_receipt("\x1b[32m SENTINELAI-DONE-abc\x1b[0m", "abc"))

    def worker(self, terminal="term-example"):
        return {
            "name": "copilot",
            "agent": "copilot",
            "agent_status": "idle",
            "terminal_id": terminal,
            "state_change_seq": 3,
        }

    def test_ambiguous_submission_is_held_without_resend(self):
        self.add("task")
        herdr = Mock()
        herdr.agents.return_value = {"w4:p1": self.worker()}
        herdr.call.side_effect = subprocess.TimeoutExpired("herdr", 1)
        args = argparse.Namespace(task="task", brief=self.brief, timeout=45, verified_policy=True)
        with self.assertRaisesRegex(Stop, "timed out"):
            send(self.db, herdr, args)
        self.assertEqual(get_task(self.db, "task")["state"], "uncertain")
        with self.assertRaisesRegex(Stop, "not ready"):
            send(self.db, herdr, args)
        herdr.call.assert_called_once()

    def test_post_submission_block_preserves_reservation_without_auto_approval(self):
        self.add("task")
        herdr = Mock()
        herdr.agents.return_value = {"w4:p1": self.worker()}
        herdr.call.return_value = subprocess.CompletedProcess(
            [],
            1,
            '{"error":{"code":"agent_blocked"}}',
            "",
        )
        args = argparse.Namespace(task="task", brief=self.brief, timeout=45, verified_policy=True)
        with self.assertRaisesRegex(Stop, "agent_blocked"):
            send(self.db, herdr, args)
        self.assertEqual(get_task(self.db, "task")["state"], "uncertain")
        herdr.call.assert_called_once()

    def test_all_dispatch_modes_require_policy_verification(self):
        for mode in ("workspace", "tool-free"):
            self.add(mode, mode=mode)
            herdr = Mock()
            args = argparse.Namespace(task=mode, brief=self.brief, timeout=45, verified_policy=False)
            with self.assertRaisesRegex(Stop, "effective policy"):
                send(self.db, herdr, args)
            herdr.agents.assert_not_called()

    @patch("orchestrate.native_executable", return_value="git.exe")
    @patch("orchestrate.subprocess.run")
    def test_workspace_baseline_and_registered_root_must_match(self, run, _which):
        commit = "a" * 40
        agent = {"cwd": str(self.root)}
        found = subprocess.CompletedProcess([], 0, f"{self.root}\n{commit}\n", "")
        clean = subprocess.CompletedProcess([], 0, b"", b"")
        dirty = subprocess.CompletedProcess([], 0, b"?? intended.txt", b"")
        run.side_effect = [found, clean, found, found, dirty, found]
        verify_workspace(agent, commit, self.root)
        with self.assertRaisesRegex(Stop, "does not match"):
            verify_workspace(agent, "b" * 40, self.root)
        with self.assertRaisesRegex(Stop, "authorized absolute path"):
            verify_workspace(agent, commit, self.root / "another-worktree")
        with self.assertRaisesRegex(Stop, "unpublished"):
            verify_workspace(agent, commit, self.root)
        verify_workspace(agent, commit, self.root, inputs_verified=True)
        for invocation in run.call_args_list:
            self.assertIn("core.fsmonitor=false", invocation.args[0])

    def test_sender_lock_keeps_abandonment_from_releasing_a_live_sender(self):
        with closing(connect(self.root / "tasks.sqlite")) as other:
            with sender_lock(self.db, "copilot"):
                with self.assertRaisesRegex(Stop, "Another supervisor"):
                    with sender_lock(other, "copilot"):
                        self.fail("The same agent's sender lock was acquired twice")
                with sender_lock(other, "qwen"):
                    pass
            with sender_lock(other, "copilot"):
                pass

    def test_stale_brief_cannot_reserve_a_new_revision(self):
        self.add("task")
        evidence = argparse.Namespace(action="review", task="task", evidence=self.brief)
        update_run(self.db, "task", reserve(self.db, "task", "copilot"), "reported", "build")
        advance(self.db, evidence)
        update_run(self.db, "task", reserve(self.db, "task", "deepseek"), "reported", "review")
        advance(self.db, argparse.Namespace(action="revise", task="task"))
        with self.assertRaisesRegex(Stop, "phase or revision changed"):
            reserve(self.db, "task", "copilot", expected=("build", 0))
        self.assertEqual(get_task(self.db, "task")["state"], "ready")

    def test_sender_does_not_collect_a_new_phase_after_another_supervisor_advances(self):
        self.add("task")
        herdr = Mock()
        herdr.agents.return_value = {"w4:p1": self.worker()}

        def other_supervisor_collects(*_args, **_kwargs):
            with closing(connect(self.root / "tasks.sqlite")) as other:
                run = get_task(other, "task")
                update_run(other, "task", run["nonce"], "reported", "receipt")
                advance(other, argparse.Namespace(action="review", task="task", evidence=self.brief))
            return subprocess.CompletedProcess([], 0, "", "")

        herdr.call.side_effect = other_supervisor_collects
        args = argparse.Namespace(task="task", brief=self.brief, timeout=45, verified_policy=True)
        send(self.db, herdr, args)
        self.assertEqual(get_task(self.db, "task")["phase"], "review")
        self.assertEqual(get_task(self.db, "task")["state"], "ready")
        herdr.transcript.assert_not_called()

    def test_receipt_cannot_be_collected_from_a_replacement_terminal(self):
        self.add("task")
        reserve(self.db, "task", "copilot", binding=agent_binding(self.worker()))
        herdr = Mock()
        herdr.agents.return_value = {"w4:p1": self.worker("replaced")}
        with self.assertRaisesRegex(Stop, "terminal or session"):
            collect(self.db, herdr, get_task(self.db, "task"))
        herdr.transcript.assert_not_called()

    def test_ended_session_can_be_reconciled_but_live_original_cannot(self):
        self.add("task")
        reserve(self.db, "task", "copilot", binding=agent_binding(self.worker()))
        herdr = Mock()
        herdr.agents.return_value = {"w4:p1": self.worker()}
        with self.assertRaisesRegex(Stop, "still present"):
            abandon(self.db, herdr, "task", session_ended=True)
        herdr.agents.return_value = {"w4:p1": self.worker("replacement")}
        with self.assertRaisesRegex(Stop, "terminal or session"):
            abandon(self.db, herdr, "task", session_ended=False)
        abandon(self.db, herdr, "task", session_ended=True)
        self.assertEqual(get_task(self.db, "task")["state"], "abandoned")

    def test_review_release_cannot_advance_a_later_run_after_evidence_read(self):
        self.add("task")
        initial = reserve(self.db, "task", "copilot")
        update_run(self.db, "task", initial, "reported", "build")
        request = argparse.Namespace(action="review", task="task", evidence=self.brief)

        def other_supervisor_revises(path):
            with closing(connect(self.root / "tasks.sqlite")) as other:
                with patch("orchestrate.evidence_digest", evidence_digest):
                    advance(other, request)
                update_run(other, "task", reserve(other, "task", "deepseek"), "reported", "review")
                advance(other, argparse.Namespace(action="revise", task="task"))
                update_run(other, "task", reserve(other, "task", "copilot"), "reported", "new build")
            return evidence_digest(path)

        with patch("orchestrate.evidence_digest", side_effect=other_supervisor_revises):
            with self.assertRaisesRegex(Stop, "Task run changed"):
                advance(self.db, request)
        run = get_task(self.db, "task")
        self.assertEqual((run["phase"], run["revision"], run["state"]), ("build", 1, "reported"))

    def test_review_dispatch_requires_the_released_evidence(self):
        self.add("task")
        update_run(self.db, "task", reserve(self.db, "task", "copilot"), "reported", "build")
        advance(self.db, argparse.Namespace(action="review", task="task", evidence=self.brief))
        other = self.root / "other.txt"
        other.write_text("different evidence", encoding="utf-8")
        herdr = Mock()
        args = argparse.Namespace(
            task="task", brief=self.brief, timeout=45, verified_policy=True, evidence=other
        )
        with self.assertRaisesRegex(Stop, "does not match the released digest"):
            send(self.db, herdr, args)
        herdr.agents.assert_not_called()
        self.assertEqual(get_task(self.db, "task")["state"], "ready")

    def test_terminal_controls_are_rejected_before_dispatch(self):
        self.add("task")
        self.brief.write_text("prefix\x07suffix", encoding="utf-8")
        herdr = Mock()
        args = argparse.Namespace(task="task", brief=self.brief, timeout=45, verified_policy=True)
        with self.assertRaisesRegex(Stop, "terminal controls"):
            send(self.db, herdr, args)
        herdr.agents.assert_not_called()

    def test_native_executable_lookup_ignores_the_working_directory(self):
        untrusted = self.root / "checkout"
        untrusted.mkdir()
        trusted = self.root / "install"
        trusted.mkdir()
        (untrusted / "herdr.exe").touch()
        executable = trusted / "herdr.exe"
        executable.touch()
        with (
            patch("orchestrate.Path.cwd", return_value=untrusted),
            patch("orchestrate.os.get_exec_path", return_value=[str(untrusted), ".", str(trusted)]),
        ):
            self.assertEqual(native_executable("herdr.exe"), str(executable))

    @patch("orchestrate.native_executable", return_value="herdr.exe")
    def test_invalid_herdr_response_fails_closed(self, _which):
        herdr = Herdr()
        with patch.object(herdr, "read", return_value='{"result":{"agents":[{}]}}'):
            with self.assertRaisesRegex(Stop, "Invalid Herdr agent listing"):
                herdr.agents()

    def test_independent_review_and_evidence_digest(self):
        self.add("task")
        evidence = self.root / "evidence"
        evidence.write_bytes(b"candidate and observed test results")
        update_run(self.db, "task", reserve(self.db, "task", "copilot"), "reported", "build")
        advance(self.db, argparse.Namespace(action="review", task="task", evidence=evidence))
        with self.assertRaisesRegex(Stop, "not ready"):
            reserve(self.db, "task", "copilot")
        update_run(self.db, "task", reserve(self.db, "task", "deepseek"), "reported", "review")
        evidence.write_bytes(b"changed after review")
        with self.assertRaisesRegex(Stop, "same evidence"):
            advance(self.db, argparse.Namespace(action="accept", task="task", evidence=evidence))
        evidence.write_bytes(b"candidate and observed test results")
        advance(self.db, argparse.Namespace(action="accept", task="task", evidence=evidence))
        self.assertEqual(get_task(self.db, "task")["state"], "accepted")

    def test_revision_limit(self):
        self.add("task")
        for _ in range(2):
            for phase, actor in (("build", "copilot"), ("review", "deepseek")):
                update_run(self.db, "task", reserve(self.db, "task", actor), "reported", phase)
                if phase == "build":
                    advance(self.db, argparse.Namespace(action="review", task="task", evidence=self.brief))
            advance(self.db, argparse.Namespace(action="revise", task="task"))
        update_run(self.db, "task", reserve(self.db, "task", "copilot"), "reported", "build")
        advance(self.db, argparse.Namespace(action="review", task="task", evidence=self.brief))
        update_run(self.db, "task", reserve(self.db, "task", "deepseek"), "reported", "review")
        with self.assertRaisesRegex(Stop, "two-cycle"):
            advance(self.db, argparse.Namespace(action="revise", task="task"))

    @patch("orchestrate.time.sleep")
    @patch("orchestrate.native_executable", return_value="herdr.exe")
    def test_read_retries_only_transient_failures_twice(self, _which, _sleep):
        herdr = Herdr()
        with patch.object(herdr, "call", side_effect=subprocess.TimeoutExpired("herdr", 1)) as call:
            with self.assertRaisesRegex(Stop, "two transient retries"):
                herdr.read("agent", "list")
            self.assertEqual(call.call_count, 3)
        with patch.object(
            herdr,
            "call",
            return_value=subprocess.CompletedProcess(
                [],
                1,
                "",
                "PermissionDenied",
            ),
        ) as call:
            with self.assertRaises(Stop):
                herdr.read("agent", "list")
            call.assert_called_once()
