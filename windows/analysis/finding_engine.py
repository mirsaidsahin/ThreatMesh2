"""Finding/Explanation engine: Change -> 7 alanli aciklama. Sablonlar KB'den, AI yok."""
from dataclasses import asdict, dataclass

SERVICE_TEXT_FIELDS = ("why_it_matters", "recommended_state", "investigate", "do_not", "mitigation")


class _Safe(dict):
    def __missing__(self, key):
        return "unknown"


def _fmt(text, ctx):
    return text.format_map(_Safe(ctx))


def _fmt_list(items, ctx):
    return [_fmt(i, ctx) for i in items]


@dataclass
class Finding:
    title: str
    summary: str
    severity: str | None
    what_happened: str
    why_it_matters: str
    how_detected: str
    recommended_state: str
    investigate: list
    do_not: list
    mitigation: list
    context: str
    disclaimer: str

    def to_dict(self):
        return asdict(self)


def build_finding(kb, change, scan_id, role=None):
    if change.event_type not in kb.events:
        raise KeyError(f"Knowledge base'de event tipi yok: {change.event_type}")
    tmpl = kb.events[change.event_type]

    ctx = {k: ("unknown" if v is None else v) for k, v in change.data.items()}
    ctx.update(scan=scan_id, role=role or "unset",
               prev_scan=change.prev_scan if change.prev_scan is not None else "n/a")
    if change.service_id:
        ctx["service"] = kb.display(change.service_id)
        ctx["category"] = kb.category(change.service_id)

    if change.event_type == "EXPOSED_SERVICE":
        info = kb.services.get(change.service_id or "", {})
        body = dict(kb.generic)
        body.update({k: v for k, v in info.items() if k in SERVICE_TEXT_FIELDS})
    else:
        body = tmpl

    context = ""
    if change.service_id:
        key = change.expectation
        if key == "UNKNOWN" and role:
            key = "UNKNOWN_SERVICE"
        context = _fmt(kb.context[key], ctx)

    return Finding(
        title=change.event_type,
        summary=_fmt(tmpl["summary"], ctx),
        severity=tmpl.get("severity"),
        what_happened=_fmt(tmpl["what_happened"], ctx),
        why_it_matters=_fmt(body["why_it_matters"], ctx),
        how_detected=_fmt(tmpl["how_detected"], ctx),
        recommended_state=_fmt(body["recommended_state"], ctx),
        investigate=_fmt_list(body["investigate"], ctx),
        do_not=_fmt_list(body["do_not"], ctx),
        mitigation=_fmt_list(body["mitigation"], ctx),
        context=context,
        disclaimer=kb.disclaimer,
    )