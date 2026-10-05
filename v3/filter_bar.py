"""Filter controls for the 3D topology view.

Emits filter_changed whenever any control changes.
MainWindow reads current_filter() to apply.
"""
from PySide6.QtCore import Signal
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QComboBox, QCheckBox,
)


RISK_OPTIONS = [
    ("any", "Any risk"),
    ("medium", "MEDIUM+"),
    ("high", "HIGH+"),
    ("critical", "CRITICAL"),
]

_LEVEL_RANK = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3, "NONE": -1}


class FilterBar(QWidget):
    filter_changed = Signal()

    def __init__(self):
        super().__init__()
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 6)
        layout.setSpacing(4)

        layout.addWidget(QLabel("FILTERS"))

        # Risk
        risk_row = QWidget()
        risk_layout = QHBoxLayout(risk_row)
        risk_layout.setContentsMargins(0, 0, 0, 0)
        risk_layout.addWidget(QLabel("Risk:"))
        self.risk_combo = QComboBox()
        for key, label in RISK_OPTIONS:
            self.risk_combo.addItem(label, key)
        self.risk_combo.currentIndexChanged.connect(self._emit)
        risk_layout.addWidget(self.risk_combo, stretch=1)
        layout.addWidget(risk_row)

        # Role
        role_row = QWidget()
        role_layout = QHBoxLayout(role_row)
        role_layout.setContentsMargins(0, 0, 0, 0)
        role_layout.addWidget(QLabel("Role:"))
        self.role_combo = QComboBox()
        self.role_combo.addItem("Any role", "")
        self.role_combo.currentIndexChanged.connect(self._emit)
        role_layout.addWidget(self.role_combo, stretch=1)
        layout.addWidget(role_row)

        # Vendor
        vendor_row = QWidget()
        vendor_layout = QHBoxLayout(vendor_row)
        vendor_layout.setContentsMargins(0, 0, 0, 0)
        vendor_layout.addWidget(QLabel("Vendor:"))
        self.vendor_combo = QComboBox()
        self.vendor_combo.addItem("Any vendor", "")
        self.vendor_combo.currentIndexChanged.connect(self._emit)
        vendor_layout.addWidget(self.vendor_combo, stretch=1)
        layout.addWidget(vendor_row)

        # Only with services
        self.only_services = QCheckBox("Only with services")
        self.only_services.stateChanged.connect(self._emit)
        layout.addWidget(self.only_services)

        # Only changed (for diff mode, later)
        self.only_changed = QCheckBox("Only diff-changed (diff mode)")
        self.only_changed.setEnabled(False)  # enabled when diff mode active
        self.only_changed.stateChanged.connect(self._emit)
        layout.addWidget(self.only_changed)

    def _emit(self):
        self.filter_changed.emit()

    def populate_roles(self, roles: list[str]):
        """Rebuild role dropdown with distinct roles from current scan."""
        current = self.role_combo.currentData()
        self.role_combo.blockSignals(True)
        self.role_combo.clear()
        self.role_combo.addItem("Any role", "")
        for r in sorted(set(roles)):
            self.role_combo.addItem(r, r)
        # Restore selection if still valid
        for i in range(self.role_combo.count()):
            if self.role_combo.itemData(i) == current:
                self.role_combo.setCurrentIndex(i)
                break
        self.role_combo.blockSignals(False)

    def populate_vendors(self, vendors: list[str]):
        current = self.vendor_combo.currentData()
        self.vendor_combo.blockSignals(True)
        self.vendor_combo.clear()
        self.vendor_combo.addItem("Any vendor", "")
        for v in sorted(set(v for v in vendors if v)):
            self.vendor_combo.addItem(v, v)
        for i in range(self.vendor_combo.count()):
            if self.vendor_combo.itemData(i) == current:
                self.vendor_combo.setCurrentIndex(i)
                break
        self.vendor_combo.blockSignals(False)

    def current_filter(self) -> dict:
        return {
            "risk": self.risk_combo.currentData(),
            "role": self.role_combo.currentData(),
            "vendor": self.vendor_combo.currentData(),
            "only_services": self.only_services.isChecked(),
            "only_changed": self.only_changed.isChecked(),
        }

    def reset(self):
        self.risk_combo.blockSignals(True)
        self.role_combo.blockSignals(True)
        self.vendor_combo.blockSignals(True)
        self.only_services.blockSignals(True)
        self.only_changed.blockSignals(True)
        self.risk_combo.setCurrentIndex(0)
        self.role_combo.setCurrentIndex(0)
        self.vendor_combo.setCurrentIndex(0)
        self.only_services.setChecked(False)
        self.only_changed.setChecked(False)
        self.risk_combo.blockSignals(False)
        self.role_combo.blockSignals(False)
        self.vendor_combo.blockSignals(False)
        self.only_services.blockSignals(False)
        self.only_changed.blockSignals(False)


def apply_device_filter(devices: list, f: dict) -> list:
    """Apply filter dict to a list of Device objects.

    Risk filter keeps devices whose risk level rank >= min.
    NONE (no risk row) is treated as rank -1, so passes 'any' only.
    """
    min_rank = {
        "any": -1,
        "medium": 1,
        "high": 2,
        "critical": 3,
    }[f["risk"]]

    out = []
    for d in devices:
        # Risk
        level = d.risk.level if d.risk else "NONE"
        rank = _LEVEL_RANK.get(level, -1)
        if rank < min_rank:
            continue

        # Role
        if f["role"] and (d.role or "") != f["role"]:
            continue

        # Vendor — device may not have vendor attr yet, guard
        if f["vendor"]:
            dev_vendor = getattr(d, "vendor", None)
            if (dev_vendor or "") != f["vendor"]:
                continue

        # Services
        if f["only_services"] and not d.services:
            continue

        out.append(d)
    return out