"""Background verify and import jobs for the console (POST /api/inbox/verify|import).

Hashing a multi-gigabyte bundle takes minutes, so the admin API answers 202
with a job id and the work runs in a small thread pool (two workers). The
registry is in memory: it holds status and progress for the console to poll.
Results are persisted by the importer itself (a `verifications` row and a
`bundle.verify` / `bundle.import` audit event), so a restart loses only the
status of jobs that were still running; their outcome is never half-recorded,
because the importer stages files and writes the registry in one transaction.

On shutdown, running jobs are stopped at their next progress report (the
importer then discards its staging files and audits the failure) and queued
jobs are dropped.
"""

from __future__ import annotations

import logging
import threading
import uuid
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .. import audit
from ..bundle import importer
from ..config import Settings
from ..db import Database
from ..errors import Conflict, FerryError
from ..util import rfc3339

log = logging.getLogger("ferry.gateway.jobs")

JOB_KINDS = ("verify", "import")
JOB_STATES = ("queued", "running", "succeeded", "failed")
WORKERS = 2
MAX_FINISHED = 200
MAX_PENDING = 32


class JobCancelled(FerryError):
    code = "job_cancelled"


@dataclass
class Job:
    job_id: str
    kind: str
    source_name: str
    source_path: Path
    actor_type: str
    actor_id: str
    created_at: str
    state: str = "queued"
    bytes_done: int = 0
    bytes_total: int | None = None
    started_at: str | None = None
    finished_at: str | None = None
    result: dict[str, Any] | None = None
    error: str | None = None

    @property
    def active(self) -> bool:
        return self.state in ("queued", "running")

    def to_dict(self) -> dict[str, Any]:
        """The GET /api/jobs/{id} shape (spec section 9)."""
        return {
            "job_id": self.job_id,
            "kind": self.kind,
            "source_name": self.source_name,
            "state": self.state,
            "progress": {"bytes_done": self.bytes_done, "bytes_total": self.bytes_total},
            "created_at": self.created_at,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "actor": f"{self.actor_type}:{self.actor_id}",
            "result": self.result,
            "error": self.error,
        }


class JobRegistry:
    """In-memory jobs plus the thread pool that runs them."""

    def __init__(self, settings: Settings, database: Database, *, workers: int = WORKERS,
                 max_finished: int = MAX_FINISHED, max_pending: int = MAX_PENDING) -> None:
        self.settings = settings
        self.database = database
        self.max_finished = max_finished
        self.max_pending = max_pending
        self._executor = ThreadPoolExecutor(max_workers=workers, thread_name_prefix="ferry-job")
        self._jobs: OrderedDict[str, Job] = OrderedDict()
        self._lock = threading.Lock()
        self._closing = threading.Event()

    # --- public ---

    def submit(self, kind: str, source_name: str, source_path: Path, *, actor_type: str, actor_id: str) -> Job:
        """Queue a job. An identical job (same kind and source) that is still queued
        or running is returned instead of starting a second one."""
        if kind not in JOB_KINDS:
            raise ValueError(f"unknown job kind {kind!r}")
        with self._lock:
            if self._closing.is_set():
                raise Conflict("the server is shutting down; no new jobs are accepted")
            for job in self._jobs.values():
                if job.active and job.kind == kind and job.source_path == source_path:
                    return job
            if sum(1 for j in self._jobs.values() if j.active) >= self.max_pending:
                raise Conflict(f"{self.max_pending} jobs are already queued or running; wait for some to finish")
            job = Job(job_id=uuid.uuid4().hex, kind=kind, source_name=source_name, source_path=source_path,
                      actor_type=actor_type, actor_id=actor_id, created_at=rfc3339())
            self._jobs[job.job_id] = job
            self._prune()
        self._executor.submit(self._run, job)
        return job

    def get(self, job_id: str) -> dict[str, Any] | None:
        with self._lock:
            job = self._jobs.get(job_id)
            return job.to_dict() if job is not None else None

    def jobs(self) -> list[dict[str, Any]]:
        with self._lock:
            return [j.to_dict() for j in reversed(self._jobs.values())]

    def shutdown(self, *, wait: bool = False) -> None:
        """Stop accepting jobs, drop queued ones and stop running ones at their next progress report."""
        self._closing.set()
        self._executor.shutdown(wait=wait, cancel_futures=True)

    # --- internals ---

    def _prune(self) -> None:
        finished = [jid for jid, j in self._jobs.items() if not j.active]
        for jid in finished[: max(0, len(finished) - self.max_finished)]:
            del self._jobs[jid]

    def _progress(self, job: Job) -> Any:
        def report(done: int, total: int) -> None:
            if self._closing.is_set():
                raise JobCancelled("the server is shutting down; the job was stopped before it finished")
            with self._lock:
                job.bytes_done, job.bytes_total = int(done), int(total)

        return report

    def _run(self, job: Job) -> None:
        with self._lock:
            job.state = "running"
            job.started_at = rfc3339()
        result: dict[str, Any] | None = None
        error: str | None = None
        try:
            if self._closing.is_set():
                raise JobCancelled("the server is shutting down; the job was not started")
            if job.kind == "import":
                outcome = importer.import_bundle(self.settings, self.database, job.source_path,
                                                 actor_type=job.actor_type, actor_id=job.actor_id,
                                                 progress=self._progress(job))
                result = {"verdict": outcome.verdict, "bundle_id": outcome.bundle_id,
                          "report": outcome.report.to_dict(), "already_imported": outcome.already_imported,
                          "verification_id": outcome.verification_id, "stored": list(outcome.stored)}
            else:
                checked = importer.verify_only(self.settings, self.database, job.source_path,
                                               actor_type=job.actor_type, actor_id=job.actor_id,
                                               progress=self._progress(job))
                result = {"verdict": checked.verdict, "bundle_id": checked.bundle_id,
                          "report": checked.report.to_dict(), "already_imported": False,
                          "verification_id": checked.verification_id}
        except FerryError as exc:
            error = exc.message
        except Exception as exc:  # reported on the job; the server keeps running
            log.error("%s job %s failed: %s", job.kind, job.job_id, type(exc).__name__)
            error = f"the {job.kind} failed with an internal error ({type(exc).__name__}); see the server log"
        if error is not None and job.kind == "verify":
            # import_bundle audits its own failures; verify_only does not.
            self._audit_verify_failure(job, error)
        with self._lock:
            job.result = result
            job.error = error
            job.state = "failed" if error is not None else "succeeded"
            job.finished_at = rfc3339()

    def _audit_verify_failure(self, job: Job, error: str) -> None:
        try:
            with self.database.session() as conn:
                audit.append_event(conn, actor_type=job.actor_type, actor_id=job.actor_id, action="bundle.verify",
                                   resource=f"source:{job.source_name}", outcome="error",
                                   details={"source_name": job.source_name, "job_id": job.job_id,
                                            "error": error[:500]})
        except Exception as exc:
            log.error("could not audit the failed verify job %s: %s", job.job_id, type(exc).__name__)
