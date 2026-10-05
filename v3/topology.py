import numpy as np
import pyvista as pv
from v3.models import Device

# Risk seviyelerine gore renk haritasi
RISK_COLORS = {
    "LOW": "#2ecc71",       # Yesil
    "MEDIUM": "#f39c12",    # Sari / Turuncu
    "HIGH": "#e67e22",      # Koyu Turuncu
    "CRITICAL": "#e74c3c"   # Kirmizi
}


class TopologyEngine:
    def __init__(self, plotter):
        self.plotter = plotter
        self.actors = []
        self.device_by_actor_name = {}

    def clear(self):
        """Mevcut 3D sahneyi temizler."""
        self.plotter.clear()
        self.actors.clear()
        self.device_by_actor_name.clear()

    def build_topology(self, devices: list[Device]):
        """Cihazlari, servisleri ve baglantilari 3D uzayda olusturur."""
        self.clear()

        if not devices:
            self.plotter.add_text(
                "No devices to display for this scan..",
                position="upper_left",
                color="white",
            )
            return

        spacing_x = 12.0  # Cihazlar arasindaki mesafe

        for idx, dev in enumerate(devices):
            center_x = idx * spacing_x
            center_point = [center_x, 0.0, 0.0]

            # Risk skoruna gore boyut olceklemesi
            risk_score = dev.risk.score if dev.risk else 0
            risk_level = dev.risk.level if dev.risk else "LOW"
            base_radius = 1.0 + (risk_score / 100.0)
            node_color = RISK_COLORS.get(risk_level, "#2ecc71")

            # 1. Cihaz Kuresi (Node)
            dev_mesh = pv.Sphere(radius=base_radius, center=center_point)
            self.plotter.add_mesh(
                dev_mesh,
                color=node_color,
                show_edges=True,
                opacity=0.95,
                name=f"device_{dev.device_id}",
                pickable=True,
            )
            self.device_by_actor_name[f"device_{dev.device_id}"] = dev

            # Cihaz Etiketi
            label = f"{dev.ip}\nRole: {dev.role}\nRisk: {risk_score} ({risk_level})"
            self.plotter.add_point_labels(
                [center_point],
                [label],
                point_size=0,
                text_color="white",
                shape_color="#1e1e1e",
                font_size=11,
                margin=4,
            )

            # 2. Servisleri Cihazin Etrafinda Dairesel Diz
            num_services = len(dev.services) if dev.services else 0
            if num_services > 0:
                angle_step = (2 * np.pi) / num_services
                service_radius = base_radius + 3.2

                for i, srv in enumerate(dev.services):
                    angle = i * angle_step
                    srv_x = center_x + (service_radius * np.cos(angle))
                    srv_y = service_radius * np.sin(angle)
                    srv_point = [srv_x, srv_y, 0.0]

                    # Servis Kuresi
                    srv_mesh = pv.Sphere(radius=0.45, center=srv_point)
                    self.plotter.add_mesh(srv_mesh, color="#3498db")

                    # Cihaz -> Servis Baglanti Hatti (Tube)
                    line = pv.Line(center_point, srv_point)
                    tube = line.tube(radius=0.06)
                    self.plotter.add_mesh(tube, color="#7f8c8d")

                    # Servis Etiketi
                    srv_label = f"{srv.service_name}\n{srv.port}/{srv.protocol}"
                    self.plotter.add_point_labels(
                        [srv_point],
                        [srv_label],
                        point_size=0,
                        text_color="#00ffff",
                        font_size=9,
                        shape_opacity=0.0,
                    )

        self.plotter.reset_camera()