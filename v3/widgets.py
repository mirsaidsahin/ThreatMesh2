"""V3 widgets: sidebar (filters + scans + timeline + events) + main window (3D + camera + export + details)."""
import csv
import numpy as np
from PySide6.QtCore import Qt, Signal, QTimer
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QListWidget, QLabel,
    QListWidgetItem, QPushButton, QSlider, QFileDialog, QMessageBox,
)
from pyvistaqt import QtInteractor

from v3.topology import TopologyEngine
from v3.database import get_scans, get_devices, get_events
from v3.details_panel import DetailsPanel
from v3.filter_bar import FilterBar, apply_device_filter


class Sidebar(QWidget):
    scan_selected = Signal(int)
    event_selected = Signal(int)   # device_id

    def __init__(self):
        super().__init__()
        self.setFixedWidth(300)
        self._scan_ids = []

        layout = QVBoxLayout(self)

        layout.addWidget(QLabel(
            "<b>THREATMESH V3</b>",
            styleSheet="color: cyan; font-size: 16px;",
        ))

        # Filtre çubuğu
        self.filters = FilterBar()
        layout.addWidget(self.filters)

        layout.addWidget(QLabel("SCANS"))
        self.scan_list = QListWidget()
        self.scan_list.itemClicked.connect(self.on_scan_clicked)
        layout.addWidget(self.scan_list)

        layout.addWidget(QLabel("TIMELINE"))
        self.slider = QSlider(Qt.Horizontal)
        self.slider.setMinimum(0)
        self.slider.setMaximum(0)
        self.slider.setTickPosition(QSlider.TicksBelow)
        self.slider.setTickInterval(1)
        self.slider.valueChanged.connect(self.on_slider_changed)
        layout.addWidget(self.slider)

        layout.addWidget(QLabel("EVENTS"))
        self.event_list = QListWidget()
        self.event_list.itemClicked.connect(self.on_event_clicked)
        layout.addWidget(self.event_list)

        self.load_scans()

    def load_scans(self):
        self.scan_list.clear()
        scans = get_scans()
        self._scan_ids = [s.scan_id for s in scans]
        for s in scans:
            item = QListWidgetItem(
                f"Scan #{s.scan_id:03d} - Devices: {s.device_count}"
            )
            item.setData(1, s.scan_id)
            self.scan_list.addItem(item)
        if self._scan_ids:
            self.slider.blockSignals(True)
            self.slider.setMaximum(len(self._scan_ids) - 1)
            self.slider.setValue(0)
            self.slider.blockSignals(False)

    def on_scan_clicked(self, item):
        scan_id = item.data(1)
        self.load_events(scan_id)
        try:
            idx = self._scan_ids.index(scan_id)
            self.slider.blockSignals(True)
            self.slider.setValue(idx)
            self.slider.blockSignals(False)
        except ValueError:
            pass
        self.scan_selected.emit(scan_id)

    def on_slider_changed(self, value: int):
        if 0 <= value < len(self._scan_ids):
            scan_id = self._scan_ids[value]
            for i in range(self.scan_list.count()):
                item = self.scan_list.item(i)
                if item.data(1) == scan_id:
                    self.scan_list.setCurrentItem(item)
                    break
            self.load_events(scan_id)
            self.scan_selected.emit(scan_id)

    def load_events(self, scan_id):
        self.event_list.clear()
        events = get_events(scan_id)
        if not events:
            self.event_list.addItem("No events for this scan.")
            return
        for e in events:
            item = QListWidgetItem(
                f"[{e.severity}] {e.event_type}\n"
                f"Pts: {e.risk_points} | {e.description}"
            )
            item.setData(1, e.device_id)
            self.event_list.addItem(item)

    def on_event_clicked(self, item):
        device_id = item.data(1)
        if device_id is not None:
            self.event_selected.emit(int(device_id))


class MainWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("ThreatMesh V3 - 3D Network Topology")
        self.resize(1400, 850)
        self.current_scan_id = None

        self.setStyleSheet("""
            QWidget { background-color: #1e1e1e; color: #d4d4d4; font-family: Consolas; }
            QListWidget { background-color: #252526; border: 1px solid #333; }
            QLabel { font-weight: bold; }
        """)

        main_layout = QHBoxLayout(self)

        # Sol sidebar
        self.sidebar = Sidebar()
        self.sidebar.scan_selected.connect(self.update_topology)
        self.sidebar.event_selected.connect(self.highlight_device)
        self.sidebar.filters.filter_changed.connect(self.apply_filters)
        main_layout.addWidget(self.sidebar)

        # Orta: 3D view + kamera + export butonları
        center = QWidget()
        center_layout = QVBoxLayout(center)
        center_layout.setContentsMargins(0, 0, 0, 0)
        center_layout.setSpacing(4)

        self.plotter = QtInteractor(self)
        self.plotter.set_background("#121212")
        center_layout.addWidget(self.plotter.interactor, stretch=1)

        # Kamera preset butonları
        cam_row = QWidget()
        cam_layout = QHBoxLayout(cam_row)
        cam_layout.setContentsMargins(0, 0, 0, 0)
        cam_layout.setSpacing(6)
        for label, slot in (
            ("Top", self.view_top),
            ("Front", self.view_front),
            ("Reset", self.view_reset),
        ):
            btn = QPushButton(label)
            btn.setFixedHeight(28)
            btn.setStyleSheet(
                "QPushButton { background:#252526; color:#d4d4d4; "
                "border:1px solid #333; padding: 4px 14px; }"
                "QPushButton:hover { background:#2f3033; }"
            )
            btn.clicked.connect(slot)
            cam_layout.addWidget(btn)
        cam_layout.addStretch(1)
        center_layout.addWidget(cam_row)

        # Export butonları
        exp_row = QWidget()
        exp_layout = QHBoxLayout(exp_row)
        exp_layout.setContentsMargins(0, 0, 0, 0)
        exp_layout.setSpacing(6)
        for label, slot in (
            ("Export PNG", self.export_png),
            ("Export CSV", self.export_csv),
        ):
            btn = QPushButton(label)
            btn.setFixedHeight(28)
            btn.setStyleSheet(
                "QPushButton { background:#252526; color:#d4d4d4; "
                "border:1px solid #333; padding: 4px 14px; }"
                "QPushButton:hover { background:#2f3033; }"
            )
            btn.clicked.connect(slot)
            exp_layout.addWidget(btn)
        exp_layout.addStretch(1)
        center_layout.addWidget(exp_row)

        main_layout.addWidget(center, stretch=1)

        # Sağ: detay paneli
        self.details = DetailsPanel()
        main_layout.addWidget(self.details)

        # Topoloji motoru
        self.topology = TopologyEngine(self.plotter)

        # Kümeye tıklama
        self.plotter.enable_point_picking(
            callback=self.on_pick,
            show_message=False,
            show_point=False,
        )

        # En son scan'i otomatik seç
        if self.sidebar.scan_list.count() > 0:
            first_item = self.sidebar.scan_list.item(0)
            self.sidebar.scan_list.setCurrentItem(first_item)
            self.sidebar.on_scan_clicked(first_item)

    # ---------- topology ----------

    def update_topology(self, scan_id: int):
        self.current_scan_id = scan_id
        devices = get_devices(scan_id)

        # Filtre dropdown'larını güncelle
        roles = [d.role for d in devices if d.role and d.role != "UNKNOWN"]
        vendors = [getattr(d, "vendor", None) for d in devices]
        self.sidebar.filters.populate_roles(roles)
        self.sidebar.filters.populate_vendors(vendors)

        # Filtreyi uygula
        filtered = apply_device_filter(devices, self.sidebar.filters.current_filter())
        self.topology.build_topology(filtered)
        self.details.show_empty()

    def apply_filters(self):
        """Re-read devices for current scan, apply filters, rebuild topology."""
        if self.current_scan_id is None:
            return
        devices = get_devices(self.current_scan_id)
        filtered = apply_device_filter(devices, self.sidebar.filters.current_filter())
        self.topology.build_topology(filtered)
        self.details.show_empty()

    # ---------- picking ----------

    def on_pick(self, point, *args):
        if point is None or not self.topology.device_by_actor_name:
            return
        best_dev = None
        best_dist = float("inf")
        for idx, dev in enumerate(self.topology.device_by_actor_name.values()):
            pos = np.array([idx * 12.0, 0.0, 0.0])
            d = np.linalg.norm(pos - np.array(point))
            if d < best_dist:
                best_dist = d
                best_dev = dev
        if best_dev is None:
            return
        all_events = get_events(self.current_scan_id) if self.current_scan_id else []
        dev_events = [
            e for e in all_events
            if getattr(e, "device_id", None) == best_dev.device_id
        ]
        self.details.show_device(best_dev, best_dev.services, best_dev.risk, dev_events)

    # ---------- event highlight ----------

    def highlight_device(self, device_id: int):
        if not self.topology.device_by_actor_name:
            return
        name = f"device_{device_id}"
        actor = self.plotter.renderer.actors.get(name)
        if actor is None:
            return
        try:
            old_color = tuple(actor.prop.color)
        except Exception:
            return
        try:
            actor.prop.color = (1.0, 1.0, 1.0)
            self.plotter.render()
        except Exception:
            return

        def restore():
            try:
                actor.prop.color = old_color
                self.plotter.render()
            except Exception:
                pass
        QTimer.singleShot(600, restore)

    # ---------- camera ----------

    def view_top(self):
        self.plotter.view_xy()
        self.plotter.render()

    def view_front(self):
        self.plotter.view_xz()
        self.plotter.render()

    def view_reset(self):
        self.plotter.reset_camera()
        self.plotter.render()

    # ---------- export ----------

    def export_png(self):
        path, _ = QFileDialog.getSaveFileName(
            self, "Save screenshot", "threatmesh.png", "PNG (*.png)"
        )
        if not path:
            return
        try:
            self.plotter.screenshot(path)
        except Exception as e:
            QMessageBox.warning(self, "Export failed", str(e))

    def export_csv(self):
        if self.current_scan_id is None:
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "Save scan as CSV",
            f"scan_{self.current_scan_id:03d}.csv", "CSV (*.csv)"
        )
        if not path:
            return
        devices = get_devices(self.current_scan_id)
        try:
            with open(path, "w", newline="", encoding="utf-8") as f:
                w = csv.writer(f)
                w.writerow([
                    "device_id", "ip", "role", "risk_score", "risk_level",
                    "services", "service_count",
                ])
                for d in devices:
                    score = d.risk.score if d.risk else ""
                    level = d.risk.level if d.risk else ""
                    svc = "; ".join(
                        f"{s.service_name}:{s.port}/{s.protocol}" for s in d.services
                    )
                    w.writerow([
                        d.device_id, d.ip, d.role, score, level, svc, len(d.services),
                    ])
        except Exception as e:
            QMessageBox.warning(self, "Export failed", str(e))