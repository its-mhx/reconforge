"""Subprocess execution engine with retries, timeouts and streaming cleanup."""
from __future__ import annotations

import json
import shlex
import subprocess
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import IO, Iterator, Optional

from rich.console import Console

console = Console(stderr=True)


@dataclass
class RunResult:
    name: str
    returncode: int = 0
    timed_out: bool = False
    stdout_file: Optional[Path] = None
    argv: list[str] = field(default_factory=list)
    lines: int = 0
    error: Optional[str] = None


class ToolError(RuntimeError):
    pass


class ToolRunner:
    def __init__(self, workdir: Path, timeout: int = 900, verbose: bool = False):
        self.workdir = Path(workdir)
        self.workdir.mkdir(parents=True, exist_ok=True)
        self.timeout = timeout
        self.verbose = verbose

    # ------------------------------------------------------------------
    def run(
        self,
        name: str,
        cmd: list[str],
        *,
        input_file: Path | None = None,
        input_text: str | None = None,
        out_file: Path | None = None,
        timeout: Optional[int] = None,
        shell: bool = False,
        ok_codes: tuple[int, ...] = (0, 1, 2),
    ) -> RunResult:
        """Run a command.  Stdout is streamed to *out_file* (side file) when
        given, otherwise it is consumed and discarded.  Returns a RunResult.
        Except protocol: ProcessLookupError kill etc.
        """
        result = RunResult(name=name, argv=list(cmd))
        timeout = timeout or self.timeout

        if self.verbose:
            console.log(f"[dim]$ {' '.join(shlex.quote(c) for c in cmd)}[/]")

        stdout_target: str | IO | None
        fh: Optional[IO] = None
        if out_file is not None:
            out_file = Path(out_file)
            out_file.parent.mkdir(parents=True, exist_ok=True)
            fh = open(out_file, "w", encoding="utf-8", errors="replace")
            stdout_target = fh          # type: ignore[assignment]
            result.stdout_file = out_file
        else:
            stdout_target = subprocess.DEVNULL

        stdin = None
        if input_file is not None:
            stdin = open(input_file, "r", encoding="utf-8", errors="replace")
        elif input_text is not None:
            stdin = subprocess.PIPE

        try:
            proc = subprocess.Popen(
                cmd if not shell else " ".join(shlex.quote(c) for c in cmd),
                stdin=stdin,
                stdout=stdout_target,     # type: ignore[arg-type]
                stderr=subprocess.PIPE,
                text=True,
                shell=shell,
                cwd=str(self.workdir),
            )
            timer = threading.Timer(timeout, self._kill, [proc])
            timer.start()
            try:
                _, stderr = proc.communicate(
                    input=input_text if input_text is not None else None
                )
                if timer.is_alive():
                    timer.cancel()
                else:
                    result.timed_out = True
                result.returncode = proc.returncode
                if result.timed_out:
                    result.error = f"timeout after {timeout}s"
                elif proc.returncode not in ok_codes and stderr:
                    # many recon tools exit 1 with findings; tolerate ok_codes
                    result.error = stderr[-500:]
            finally:
                if timer.is_alive():
                    timer.cancel()
        except FileNotFoundError:
            result.error = f"binary not found: {cmd[0]}"
            result.returncode = 127
        except Exception as e:  # noqa: BLE001
            result.error = str(e)
            result.returncode = 1
        finally:
            if fh:
                fh.close()
            if input_file is not None and stdin:
                stdin.close()

        if result.stdout_file and result.stdout_file.exists():
            with open(result.stdout_file, encoding="utf-8", errors="replace") as f:
                result.lines = sum(1 for _ in f)
        return result

    # ------------------------------------------------------------------
    @staticmethod
    def _kill(proc: subprocess.Popen) -> None:
        try:
            proc.kill()
        except Exception:
            pass

    # ------------------------------------------------------------------
    _ANSI_RE = __import__('re').compile(r'\x1b\[[0-9;]*[a-zA-Z]')

    @classmethod
    def iter_json_lines(cls, path: Path) -> Iterator[dict]:
        """Yield parsed JSON objects from a JSONL file (nuclei/httpx/dnsx...).
        Tolerates ANSI codes, banner garbage interleaved by go tools."""
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                line = cls._ANSI_RE.sub("", line).strip()
                if not line or not line.startswith("{"):
                    continue
                try:
                    yield json.loads(line)
                except json.JSONDecodeError:
                    # last resort — find the first {..} region
                    start = line.find("{")
                    if start >= 0:
                        try:
                            yield json.loads(line[start:])
                        except json.JSONDecodeError:
                            continue

    @staticmethod
    def read_lines(path: Path, lower: bool = False) -> list[str]:
        if not Path(path).exists():
            return []
        items: list[str] = []
        seen = set()
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                s = line.strip()
                if not s:
                    continue
                if lower:
                    s = s.lower()
                if s not in seen:
                    seen.add(s)
                    items.append(s)
        return items
