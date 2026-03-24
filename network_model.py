"""
IoMT Medical NIDS Simulator — Network Model
Hospital network zones, assets, communication maps, and IP management.
"""

import random
from typing import List, Dict, Optional
from config import (
    Zone, ZONE_SUBNETS, DeviceRole, AssetDef,
    MEDIUM_HOSPITAL_ASSETS, NORMAL_COMM_MAP
)


class Asset:
    """Runtime representation of a network asset."""

    def __init__(self, asset_def: AssetDef):
        self.name = asset_def.name
        self.zone = asset_def.zone
        self.ip = asset_def.ip
        self.device_role = asset_def.device_role
        self.protocols = asset_def.protocols
        self.criticality = asset_def.criticality
        self.internet_exposed = asset_def.internet_exposed

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "zone": self.zone.value,
            "ip": self.ip,
            "device_role": self.device_role.value,
            "protocols": ",".join(self.protocols),
            "criticality": self.criticality,
            "internet_exposed": int(self.internet_exposed),
        }


class HospitalNetwork:
    """Builds and manages the hospital network model."""

    def __init__(self, profile: str = "medium_hospital_v1", seed: int = 42):
        self.profile = profile
        self.rng = random.Random(seed)
        self.assets: List[Asset] = []
        self.assets_by_name: Dict[str, Asset] = {}
        self.assets_by_role: Dict[DeviceRole, List[Asset]] = {}
        self.assets_by_zone: Dict[Zone, List[Asset]] = {}
        self._build_network()

    def _build_network(self):
        """Initialize all assets from the environment profile."""
        asset_defs = MEDIUM_HOSPITAL_ASSETS

        for adef in asset_defs:
            asset = Asset(adef)
            self.assets.append(asset)
            self.assets_by_name[asset.name] = asset

            if asset.device_role not in self.assets_by_role:
                self.assets_by_role[asset.device_role] = []
            self.assets_by_role[asset.device_role].append(asset)

            if asset.zone not in self.assets_by_zone:
                self.assets_by_zone[asset.zone] = []
            self.assets_by_zone[asset.zone].append(asset)

    def get_asset(self, name: str) -> Optional[Asset]:
        return self.assets_by_name.get(name)

    def get_assets_by_role(self, role: DeviceRole) -> List[Asset]:
        return self.assets_by_role.get(role, [])

    def get_assets_by_zone(self, zone: Zone) -> List[Asset]:
        return self.assets_by_zone.get(zone, [])

    def get_random_asset(self, zone: Optional[Zone] = None,
                         role: Optional[DeviceRole] = None) -> Optional[Asset]:
        candidates = self.assets
        if zone:
            candidates = [a for a in candidates if a.zone == zone]
        if role:
            candidates = [a for a in candidates if a.device_role == role]
        if not candidates:
            return None
        return self.rng.choice(candidates)

    def generate_external_ip(self) -> str:
        """Generate a random external attacker IP."""
        return f"198.51.100.{self.rng.randint(1, 254)}"

    def get_comm_pairs(self):
        """
        Yield (src_asset, dst_asset, protocols, flows_per_hour)
        for all normal communication pairs in the network.
        """
        for src_role, dst_role, protocols, base_fph in NORMAL_COMM_MAP:
            src_list = self.get_assets_by_role(src_role)
            dst_list = self.get_assets_by_role(dst_role)
            if not src_list or not dst_list:
                continue
            for src in src_list:
                for dst in dst_list:
                    if src.name != dst.name:
                        # Scale flows per hour by number of pairs
                        fph = max(1, base_fph // (len(src_list) * len(dst_list)))
                        yield src, dst, protocols, fph

    def get_assets_csv_rows(self) -> List[dict]:
        return [a.to_dict() for a in self.assets]
