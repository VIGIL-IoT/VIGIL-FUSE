"""Shared process-tree sampling helpers for FUSE benchmark scripts."""

from __future__ import annotations

import subprocess
from typing import Any


def sample_process_tree_rss(pid: int, psutil: Any) -> tuple[int, int]:
    """Return summed RSS and the number of inaccessible process samples."""
    try:
        root_process = psutil.Process(pid)
        processes = [root_process, *root_process.children(recursive=True)]
    except psutil.NoSuchProcess:
        return 0, 0
    except psutil.AccessDenied:
        return 0, 1

    total_rss = 0
    inaccessible = 0
    for process in processes:
        try:
            total_rss += process.memory_info().rss
        except (psutil.NoSuchProcess, psutil.ZombieProcess):
            continue
        except psutil.AccessDenied:
            inaccessible += 1
    return total_rss, inaccessible


def terminate_process_tree(pid: int, process: subprocess.Popen[str], psutil: Any) -> None:
    """Terminate a timed-out benchmark process and its descendants."""
    try:
        root_process = psutil.Process(pid)
        children = root_process.children(recursive=True)
        for child in reversed(children):
            try:
                child.terminate()
            except psutil.NoSuchProcess:
                pass
        try:
            root_process.terminate()
        except psutil.NoSuchProcess:
            pass
        _, alive = psutil.wait_procs([*children, root_process], timeout=2)
        for remaining in alive:
            try:
                remaining.kill()
            except psutil.NoSuchProcess:
                pass
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        process.kill()
