"""Right panel: selected device details."""
from PySide6.QtWidgets import QWidget, QVBoxLayout, QLabel, QTextEdit


class DetailsPanel(QWidget):
    def __init__(self):
        super().__init__()
        self.setFixedWidth(320)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(8)

        title = QLabel("DEVICE DETAILS")
        title.setStyleSheet("color: #00ffff; font-size: 14px; font-weight: bold;")
        layout.addWidget(title)

        self.body = QTextEdit()
        self.body.setReadOnly(True)
        self.body.setStyleSheet("""
            QTextEdit {
                background-color: #15181d;
                color: #d0d0d8;
                border: 1px solid #2a2f36;
                padding: 8px;
                font-family: Consolas;
                font-size: 12px;
            }
        """)
        layout.addWidget(self.body)

        self.show_empty()

    def show_empty(self):
        self.body.setPlainText(
            "Click a device node in the 3D view\nto see details here."
        )

    def show_device(self, device, services, risk, events):
        lines = []
        lines.append(f"IP:       {device.ip}")
        lines.append(f"Role:     {device.role}")
        lines.append("")
        lines.append("─── SERVICES ───")
        if services:
            for s in services:
                name = s.service_name.upper()
                lines.append(f"  {name} :{s.port}/{s.protocol}")
        else:
            lines.append("  No services observed.")
        lines.append("")
        lines.append("─── RISK ───")
        if risk:
            lines.append(f"  Score: {risk.score}  [{risk.level}]")
        else:
            lines.append("  Risk: N/A")
        lines.append("")
        lines.append("─── EVENTS ───")
        if events:
            for e in events:
                lines.append(f"  [{e.severity}] {e.event_type}")
                if e.description:
                    lines.append(f"      {e.description[:60]}")
        else:
            lines.append("  No events for this device.")
        self.body.setPlainText("\n".join(lines))