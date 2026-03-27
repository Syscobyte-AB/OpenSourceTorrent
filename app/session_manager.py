"""
TorrentSessionManager — libtorrent session wrapper.
Handles all torrent lifecycle, stats, file selection, speed limits.
"""

import asyncio
import base64
import logging
from typing import Any, Optional

import libtorrent as lt

logger = logging.getLogger("torrentvault.session")


# ─── State helpers ─────────────────────────────────────────────────────────────
STATE_LABELS = {
    lt.torrent_status.checking_files: "checking",
    lt.torrent_status.downloading_metadata: "fetching_metadata",
    lt.torrent_status.downloading: "downloading",
    lt.torrent_status.finished: "finished",
    lt.torrent_status.seeding: "seeding",
    lt.torrent_status.allocating: "allocating",
    lt.torrent_status.checking_resume_data: "resuming",
}


def _fmt_size(b: int) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if b < 1024:
            return f"{b:.1f} {unit}"
        b /= 1024
    return f"{b:.1f} PB"


def _torrent_info(h: lt.torrent_handle) -> dict:
    s = h.status()
    ti = h.torrent_file()

    info_hash = str(h.info_hash())

    files = []
    if ti:
        fs = ti.files()
        priorities = h.file_priorities()
        for i in range(fs.num_files()):
            files.append({
                "index": i,
                "name": fs.file_name(i),
                "size": fs.file_size(i),
                "size_fmt": _fmt_size(fs.file_size(i)),
                "priority": priorities[i] if i < len(priorities) else 4,
                "progress": h.file_progress()[i] / fs.file_size(i) if fs.file_size(i) > 0 else 0,
            })

    peers = h.get_peer_info()
    peer_list = [
        {
            "ip": str(p.ip),
            "client": p.client.decode("utf-8", errors="replace"),
            "download_rate": p.payload_down_speed,
            "upload_rate": p.payload_up_speed,
            "progress": p.progress,
        }
        for p in peers[:20]  # cap at 20 peers
    ]

    trackers = [
        {
            "url": t.url,
            "tier": t.tier,
            "next_announce": str(t.next_announce_in()),
        }
        for t in h.trackers()
    ]

    # Piece availability map (compact: 0=missing 1=have)
    pieces = []
    if ti:
        bitmask = h.have_piece
        pieces = [1 if h.have_piece(i) else 0 for i in range(ti.num_pieces())]

    return {
        "info_hash": info_hash,
        "name": s.name or "Fetching metadata...",
        "state": STATE_LABELS.get(s.state, "unknown"),
        "paused": s.paused,
        "error": s.errc.message() if s.errc else None,
        "progress": round(s.progress * 100, 2),
        "download_rate": s.download_rate,
        "upload_rate": s.upload_rate,
        "download_rate_fmt": _fmt_size(s.download_rate) + "/s",
        "upload_rate_fmt": _fmt_size(s.upload_rate) + "/s",
        "total_size": s.total_wanted,
        "total_size_fmt": _fmt_size(s.total_wanted),
        "downloaded": s.total_done,
        "downloaded_fmt": _fmt_size(s.total_done),
        "uploaded": s.all_time_upload,
        "ratio": round(s.all_time_upload / max(s.all_time_download, 1), 3),
        "eta_seconds": (
            int((s.total_wanted - s.total_done) / s.download_rate)
            if s.download_rate > 0
            else None
        ),
        "num_peers": s.num_peers,
        "num_seeds": s.num_seeds,
        "num_trackers": len(trackers),
        "save_path": s.save_path,
        "added_time": s.added_time,
        "completed_time": s.completed_time,
        "files": files,
        "peers": peer_list,
        "trackers": trackers,
        "pieces_total": len(pieces),
        "pieces_have": sum(pieces),
        "pieces_map": pieces[:500],  # first 500 for visualisation
        "download_limit": h.download_limit(),
        "upload_limit": h.upload_limit(),
    }


class TorrentSessionManager:
    def __init__(self, download_dir: str, listen_ports: tuple[int, int] = (6881, 6891)):
        self.download_dir = download_dir
        self.listen_ports = listen_ports
        self.session: Optional[lt.session] = None
        self._handles: dict[str, lt.torrent_handle] = {}

    async def start(self):
        settings = {
            "listen_interfaces": f"0.0.0.0:{self.listen_ports[0]}",
            "alert_mask": (
                lt.alert.category_t.error_notification
                | lt.alert.category_t.storage_notification
                | lt.alert.category_t.tracker_notification
                | lt.alert.category_t.status_notification
            ),
            "enable_dht": True,
            "enable_lsd": True,
            "enable_upnp": True,
            "enable_natpmp": True,
            "anonymous_mode": False,  # set True for privacy mode
            "connections_limit": 500,
            "unchoke_slots_limit": 8,
        }

        self.session = lt.session(settings)
        logger.info(f"libtorrent session started on port {self.listen_ports[0]}")

    async def stop(self):
        if self.session:
            # Save resume data for all torrents
            for h in self._handles.values():
                if h.is_valid():
                    h.save_resume_data()
            self.session.pause()
            logger.info("Session stopped")

    async def add_magnet(
        self,
        magnet_uri: str,
        save_path: str,
        max_download_rate: int = -1,
        max_upload_rate: int = -1,
        sequential: bool = False,
    ) -> dict:
        params = lt.parse_magnet_uri(magnet_uri)
        params.save_path = save_path
        params.storage_mode = lt.storage_mode_t.storage_mode_sparse
        if sequential:
            params.flags |= lt.torrent_flags.sequential_download

        h = self.session.add_torrent(params)
        if max_download_rate > 0:
            h.set_download_limit(max_download_rate)
        if max_upload_rate > 0:
            h.set_upload_limit(max_upload_rate)

        info_hash = str(h.info_hash())
        self._handles[info_hash] = h
        logger.info(f"Added magnet: {info_hash}")
        return {"info_hash": info_hash, "status": "added"}

    async def add_torrent_file(self, torrent_data: bytes, save_path: str) -> dict:
        ti = lt.torrent_info(lt.bdecode(torrent_data))
        params = lt.add_torrent_params()
        params.ti = ti
        params.save_path = save_path
        params.storage_mode = lt.storage_mode_t.storage_mode_sparse

        h = self.session.add_torrent(params)
        info_hash = str(h.info_hash())
        self._handles[info_hash] = h
        logger.info(f"Added torrent file: {info_hash}")
        return {"info_hash": info_hash, "name": ti.name(), "status": "added"}

    def get_all_torrents(self) -> list[dict]:
        result = []
        for h in self._handles.values():
            if h.is_valid():
                try:
                    result.append(_torrent_info(h))
                except Exception as e:
                    logger.warning(f"Error reading torrent status: {e}")
        return result

    def get_torrent(self, info_hash: str) -> Optional[dict]:
        h = self._handles.get(info_hash)
        if h and h.is_valid():
            return _torrent_info(h)
        return None

    def pause(self, info_hash: str) -> bool:
        h = self._handles.get(info_hash)
        if h and h.is_valid():
            h.pause()
            return True
        return False

    def resume(self, info_hash: str) -> bool:
        h = self._handles.get(info_hash)
        if h and h.is_valid():
            h.resume()
            return True
        return False

    def remove(self, info_hash: str, delete_files: bool = False) -> bool:
        h = self._handles.get(info_hash)
        if h and h.is_valid():
            flags = lt.options_t.delete_files if delete_files else 0
            self.session.remove_torrent(h, flags)
            del self._handles[info_hash]
            return True
        return False

    def set_file_priorities(self, info_hash: str, selected_indices: list[int]) -> bool:
        h = self._handles.get(info_hash)
        if not h or not h.is_valid():
            return False
        ti = h.torrent_file()
        if not ti:
            return False
        priorities = [0] * ti.num_files()
        for i in selected_indices:
            if 0 <= i < ti.num_files():
                priorities[i] = 4  # normal priority
        h.prioritize_files(priorities)
        return True

    def set_speed_limits(self, info_hash: str, dl_bps: int, ul_bps: int) -> bool:
        h = self._handles.get(info_hash)
        if not h or not h.is_valid():
            return False
        h.set_download_limit(dl_bps)
        h.set_upload_limit(ul_bps)
        return True

    def set_priority(self, info_hash: str, priority: int) -> bool:
        h = self._handles.get(info_hash)
        if not h or not h.is_valid():
            return False
        # Priority 0 = pause effectively
        h.set_priority(priority)
        return True

    def global_stats(self) -> dict:
        if not self.session:
            return {}
        s = self.session.status()
        active = [h for h in self._handles.values() if h.is_valid()]
        downloading = sum(
            1 for h in active if not h.status().paused and h.status().state == lt.torrent_status.downloading
        )
        seeding = sum(
            1 for h in active if h.status().state == lt.torrent_status.seeding
        )
        return {
            "total_download_rate": s.payload_download_rate,
            "total_upload_rate": s.payload_upload_rate,
            "total_download_rate_fmt": _fmt_size(s.payload_download_rate) + "/s",
            "total_upload_rate_fmt": _fmt_size(s.payload_upload_rate) + "/s",
            "total_torrents": len(self._handles),
            "downloading": downloading,
            "seeding": seeding,
            "paused": len(active) - downloading - seeding,
            "dht_nodes": s.dht_nodes,
        }
