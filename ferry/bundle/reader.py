"""Read bundle members without ever turning a member name into a filesystem path.

Two sources: a plain tar file (`TarBundleReader`) and an extracted directory
(`DirBundleReader`). Both list every member with its type, size and mode, and
open regular-file members for reading by their position in that listing.
Neither extracts anything, and neither decides what is acceptable; that is the
verifier's job.

Tar: compressed tars are refused (bundles are plain tar on purpose). A corrupt
header, a missing end-of-archive marker, or data after the end of the archive
is an error instead of the silent end of archive `tarfile` reports, so nothing
can hide behind the last member (a ZIP appended to make a polyglot, say).
While headers are parsed, each extended (PAX or GNU long-name) header is
capped at 64 KiB and all of them together at 16 MiB, so a hostile header cannot
make `tarfile` allocate its declared length, and many large headers cannot add
up to gigabytes held in memory before any size limit or signature is checked.
PAX records are dropped once a member's fields are read.

Directory: the walk uses directory file descriptors and O_NOFOLLOW, so a
symlink swapped in during verification is refused rather than followed, and
each file is re-checked (device, inode, size) when it is opened.
"""

from __future__ import annotations

import os
import stat
import tarfile
from dataclasses import dataclass
from pathlib import Path
from typing import IO, Any

from ..errors import FerryError
from ..formats import quote_untrusted

HEADER_READ_CAP = 64 * 1024
HEADER_TOTAL_CAP = 16 * 1024 * 1024
MAX_TRAILER = 1024 * 1024
MAX_DIR_DEPTH = 32

FILE, DIR = "file", "dir"
TYPE_LABELS = {
    "symlink": "symbolic link", "hardlink": "hard link", "chardev": "character device",
    "blockdev": "block device", "fifo": "FIFO", "socket": "socket", "sparse": "sparse file",
    "contiguous": "contiguous file", "other": "special file",
}

_O_DIR = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
_O_FILE = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0)
_COMPRESSED = (
    (b"\x1f\x8b", "gzip"), (b"BZh", "bzip2"), (b"\xfd7zXZ\x00", "xz"), (b"\x28\xb5\x2f\xfd", "zstd"),
    (b"\x04\x22\x4d\x18", "lz4"), (b"7z\xbc\xaf\x27\x1c", "7z"), (b"PK\x03\x04", "ZIP"),
)


class BundleReadError(FerryError):
    code = "bundle_unreadable"


@dataclass(frozen=True)
class Member:
    index: int
    name: str
    type: str
    size: int
    mode: int

    @property
    def is_file(self) -> bool:
        return self.type == FILE


class BundleReader:
    """Common interface: `members`, `listing_complete`, `size`, `open(member)`."""

    source_type = ""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.members: list[Member] = []
        self.listing_complete = True
        self.size = 0

    def open(self, member: Member) -> IO[bytes]:
        raise NotImplementedError

    def close(self) -> None:
        pass

    def __enter__(self) -> BundleReader:
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()


class _CappedFile:
    """The tar file as `tarfile` sees it while listing.

    Any single read over the cap fails, and reads longer than one header block
    (the data of PAX and GNU long-name headers) count against a total cap.
    """

    def __init__(self, fh: IO[bytes], cap: int, total_cap: int):
        self._fh = fh
        self.cap: int | None = cap
        self.total_cap = total_cap
        self.extended = 0

    def read(self, n: int = -1) -> bytes:
        if self.cap is not None:
            if n is None or n < 0 or n > self.cap:
                raise BundleReadError(f"corrupt or hostile tar: a member header needs a {n:,}-byte read, over the "
                                      f"{self.cap // 1024} KiB per-header limit; bundles written by ferry pack stay "
                                      "far below it, so rebuild the bundle with ferry pack")
            if n > tarfile.BLOCKSIZE:
                self.extended += n
                if self.extended > self.total_cap:
                    raise BundleReadError(f"corrupt or hostile tar: the member headers carry more than "
                                          f"{self.total_cap // (1024 * 1024)} MiB of PAX or long-name header data; "
                                          "bundles written by ferry pack need a few hundred bytes per member, so "
                                          "rebuild the bundle with ferry pack")
        return self._fh.read(n)

    def seek(self, offset: int, whence: int = 0) -> int:
        return self._fh.seek(offset, whence)

    def tell(self) -> int:
        return self._fh.tell()

    def seekable(self) -> bool:
        return True

    def readable(self) -> bool:
        return True


def _tar_type(info: tarfile.TarInfo) -> str:
    if info.type in (tarfile.REGTYPE, tarfile.AREGTYPE):
        return "sparse" if info.issparse() else FILE
    return {
        tarfile.DIRTYPE: DIR, tarfile.SYMTYPE: "symlink", tarfile.LNKTYPE: "hardlink",
        tarfile.CHRTYPE: "chardev", tarfile.BLKTYPE: "blockdev", tarfile.FIFOTYPE: "fifo",
        tarfile.CONTTYPE: "contiguous", tarfile.GNUTYPE_SPARSE: "sparse",
    }.get(info.type, "other")


class TarBundleReader(BundleReader):
    source_type = "tar"

    def __init__(self, path: Path, *, max_members: int):
        super().__init__(path)
        self._infos: list[tarfile.TarInfo] = []
        try:
            fd = os.open(path, _O_FILE)
        except OSError as exc:
            raise BundleReadError(f"cannot open bundle: {exc.strerror}") from None
        self._fh = os.fdopen(fd, "rb")
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode):
                raise BundleReadError("bundle is not a regular file")
            self.size = st.st_size
            self._open_tar(max_members)
        except BaseException:
            self._fh.close()
            raise

    def _open_tar(self, max_members: int) -> None:
        head = self._fh.read(512)
        if not head:
            raise BundleReadError("bundle file is empty")
        for magic, label in _COMPRESSED:
            if head.startswith(magic):
                raise BundleReadError(f"bundle is {label}-compressed or not a tar file; bundles must be plain, "
                                      "uncompressed tar files")
        self._fh.seek(0)
        capped = _CappedFile(self._fh, HEADER_READ_CAP, HEADER_TOTAL_CAP)
        try:
            self._tf = tarfile.TarFile(fileobj=capped, mode="r", encoding="utf-8", errors="surrogateescape")  # type: ignore[arg-type]
        except BundleReadError:
            raise
        except RecursionError:
            raise BundleReadError("corrupt or hostile tar: too many chained extended headers") from None
        except (tarfile.TarError, EOFError, ValueError, OverflowError) as exc:
            raise BundleReadError(f"not a readable tar archive ({exc})") from None
        self._list(max_members)
        if self.listing_complete:
            self._check_end()
        capped.cap = None

    def _list(self, max_members: int) -> None:
        while True:
            try:
                info = self._tf.next()
            except BundleReadError:
                raise
            except RecursionError:
                raise BundleReadError("corrupt or hostile tar: too many chained extended headers") from None
            except (tarfile.TarError, EOFError, ValueError, OverflowError, UnicodeError) as exc:
                raise BundleReadError(f"corrupt or truncated tar ({exc})") from None
            if info is None:
                return
            if len(self.members) >= max_members:
                self.listing_complete = False
                return
            kind = _tar_type(info)
            if kind == FILE and info.offset_data + info.size > self.size:
                raise BundleReadError(f"truncated tar: member {quote_untrusted(info.name)} extends past the end of the file")
            info.pax_headers = {}  # path, size and mtime are already applied; nothing else is kept
            self._infos.append(info)
            self.members.append(Member(len(self.members), info.name, kind, info.size if kind == FILE else 0, info.mode))

    def _check_end(self) -> None:
        end = self._tf.offset
        self._fh.seek(end)
        marker = self._fh.read(512)
        if len(marker) < 512:
            raise BundleReadError("truncated tar: the end-of-archive marker is missing")
        if marker.count(0) != 512:
            raise BundleReadError(f"corrupt tar: invalid member header at offset {end:,}")
        trailer = self.size - end - 512
        if trailer > MAX_TRAILER:
            raise BundleReadError(f"unexpected data after the end of the archive (offset {end + 512:,})")
        rest = self._fh.read(trailer)
        if rest.count(0) != len(rest):
            raise BundleReadError(f"unexpected data after the end of the archive (offset {end + 512:,})")

    def open(self, member: Member) -> IO[bytes]:
        if not member.is_file:
            raise BundleReadError(f"member {quote_untrusted(member.name)} is not a regular file")
        fh = self._tf.extractfile(self._infos[member.index])
        if fh is None:
            raise BundleReadError(f"member {quote_untrusted(member.name)} cannot be read")
        return fh

    def close(self) -> None:
        self._fh.close()


def _stat_type(st: os.stat_result) -> str:
    mode = st.st_mode
    if stat.S_ISREG(mode):
        return "hardlink" if st.st_nlink > 1 else FILE
    if stat.S_ISDIR(mode):
        return DIR
    if stat.S_ISLNK(mode):
        return "symlink"
    if stat.S_ISCHR(mode):
        return "chardev"
    if stat.S_ISBLK(mode):
        return "blockdev"
    if stat.S_ISFIFO(mode):
        return "fifo"
    if stat.S_ISSOCK(mode):
        return "socket"
    return "other"


class DirBundleReader(BundleReader):
    source_type = "dir"

    def __init__(self, path: Path, *, max_members: int):
        super().__init__(path)
        if not (os.open in os.supports_dir_fd and os.stat in os.supports_dir_fd and hasattr(os, "O_NOFOLLOW")):
            raise BundleReadError("directory bundles need dir_fd and O_NOFOLLOW support; use the tar file instead")
        self._ids: dict[int, tuple[int, int, int]] = {}
        try:
            self._root = os.open(path, _O_DIR)
        except OSError as exc:
            raise BundleReadError(f"cannot open bundle directory: {exc.strerror}") from None
        try:
            self._walk(max_members)
        except BaseException:
            os.close(self._root)
            raise

    def _walk(self, max_members: int) -> None:
        found: list[tuple[str, str, int, int]] = []
        stack: list[tuple[int, str, int]] = [(self._root, "", 0)]
        try:
            while stack:
                fd, prefix, depth = stack.pop()
                try:
                    with os.scandir(fd) as it:
                        names = sorted(entry.name for entry in it)
                    for name in names:
                        rel = prefix + name
                        st = os.stat(name, dir_fd=fd, follow_symlinks=False)
                        kind = _stat_type(st)
                        if len(found) >= max_members:
                            self.listing_complete = False
                            return
                        found.append((rel, kind, st.st_size if kind == FILE else 0, stat.S_IMODE(st.st_mode)))
                        if kind == FILE:
                            self._ids[len(found) - 1] = (st.st_dev, st.st_ino, st.st_size)
                        elif kind == DIR:
                            if depth + 1 > MAX_DIR_DEPTH:
                                raise BundleReadError(f"directory tree is deeper than {MAX_DIR_DEPTH} levels")
                            sub = os.open(name, _O_DIR, dir_fd=fd)
                            sst = os.fstat(sub)
                            if (sst.st_dev, sst.st_ino) != (st.st_dev, st.st_ino):
                                os.close(sub)
                                raise BundleReadError(f"directory {quote_untrusted(rel)} changed while it was being read")
                            stack.append((sub, rel + "/", depth + 1))
                except OSError as exc:
                    raise BundleReadError(f"cannot read bundle directory: {exc.strerror}") from None
                finally:
                    if fd != self._root:
                        os.close(fd)
        finally:
            for fd, _, _ in stack:
                if fd != self._root:
                    os.close(fd)
            order = sorted(range(len(found)), key=lambda i: found[i][0])
            ids = self._ids
            self._ids = {}
            for new_index, old_index in enumerate(order):
                rel, kind, size, mode = found[old_index]
                self.members.append(Member(new_index, rel, kind, size, mode))
                if old_index in ids:
                    self._ids[new_index] = ids[old_index]
                    self.size += size

    def open(self, member: Member) -> IO[bytes]:
        ident = self._ids.get(member.index)
        if ident is None or not member.is_file:
            raise BundleReadError(f"member {quote_untrusted(member.name)} is not a regular file")
        parts = member.name.split("/")
        opened: list[int] = []
        fd = self._root
        try:
            for part in parts[:-1]:
                fd = os.open(part, _O_DIR, dir_fd=fd)
                opened.append(fd)
            ffd = os.open(parts[-1], _O_FILE, dir_fd=fd)
        except OSError as exc:
            raise BundleReadError(f"cannot open {quote_untrusted(member.name)}: {exc.strerror}") from None
        finally:
            for d in opened:
                os.close(d)
        st = os.fstat(ffd)
        if not stat.S_ISREG(st.st_mode) or (st.st_dev, st.st_ino, st.st_size) != ident:
            os.close(ffd)
            raise BundleReadError(f"{quote_untrusted(member.name)} changed while the bundle was being verified")
        return os.fdopen(ffd, "rb")

    def close(self) -> None:
        os.close(self._root)


def open_bundle(path: str | Path, *, max_members: int) -> BundleReader:
    """Open a tar file or an extracted directory. Symlinks are never followed, even for the bundle itself."""
    path = Path(path)
    try:
        st = os.lstat(path)
    except OSError as exc:
        raise BundleReadError(f"cannot read bundle: {exc.strerror}") from None
    if stat.S_ISLNK(st.st_mode):
        raise BundleReadError("bundle path is a symbolic link; pass the real file or directory")
    if stat.S_ISDIR(st.st_mode):
        return DirBundleReader(path, max_members=max_members)
    if stat.S_ISREG(st.st_mode):
        return TarBundleReader(path, max_members=max_members)
    raise BundleReadError("bundle is neither a regular file nor a directory")
