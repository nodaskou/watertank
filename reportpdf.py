"""One-language PDF site report (English or Greek) with DejaVu for Greek letters."""
import os
from io import BytesIO

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import Image, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

NAVY = colors.HexColor("#0b2a55")
BLUE = colors.HexColor("#1d5fbf")
MUTED = colors.HexColor("#475569")
LINE = colors.HexColor("#e2e8f0")
ZEBRA = colors.HexColor("#f8fafc")

FONT_PATHS = (
    "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
    "/usr/share/fonts/dejavu/DejaVuSans.ttf",
    "/usr/share/fonts/TTF/DejaVuSans.ttf",
)
BOLD_PATHS = (
    "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
    "/usr/share/fonts/dejavu/DejaVuSans-Bold.ttf",
    "/usr/share/fonts/TTF/DejaVuSans-Bold.ttf",
)

TEXT = {
    "en": {
        "kicker": "Wirewave Network Infrastructure Monitor",
        "title": "Site report",
        "site": "Site",
        "period": "Period",
        "generated": "Generated",
        "uptime": "Uptime by host",
        "host": "Host",
        "address": "Address",
        "group": "Group",
        "pct": "Uptime",
        "outages": "Outages",
        "start": "Start",
        "end": "End",
        "duration": "Duration",
        "internet": "Internet quality",
        "loss": "Average loss",
        "latency": "Average latency",
        "jitter": "Average jitter",
        "down_count": "Probes with no internet",
        "cameras": "Recorders, cameras and disks",
        "status": "Status",
        "bandwidth": "Bandwidth (average)",
        "iface": "Interface",
        "in": "In",
        "out": "Out",
        "alerts": "Alerts in the log",
        "critical": "Critical",
        "warning": "Warning",
        "info": "Info",
        "power": "Power (UPS)",
        "events": "Power events",
        "none": "Nothing in this period.",
        "ongoing": "ongoing",
        "footer": "Wirewave  ·  Lefkada  ·  confidential, for the client",
    },
    "el": {
        "kicker": "Wirewave Network Infrastructure Monitor",
        "title": "Αναφορά εγκατάστασης",
        "site": "Εγκατάσταση",
        "period": "Περίοδος",
        "generated": "Δημιουργήθηκε",
        "uptime": "Διαθεσιμότητα ανά συσκευή",
        "host": "Συσκευή",
        "address": "Διεύθυνση",
        "group": "Ομάδα",
        "pct": "Διαθεσιμότητα",
        "outages": "Διακοπές",
        "start": "Έναρξη",
        "end": "Λήξη",
        "duration": "Διάρκεια",
        "internet": "Ποιότητα διαδικτύου",
        "loss": "Μέση απώλεια",
        "latency": "Μέση καθυστέρηση",
        "jitter": "Μέσο jitter",
        "down_count": "Μετρήσεις χωρίς διαδίκτυο",
        "cameras": "Καταγραφικά, κάμερες και δίσκοι",
        "status": "Κατάσταση",
        "bandwidth": "Κίνηση (μέσος όρος)",
        "iface": "Διεπαφή",
        "in": "Είσοδος",
        "out": "Έξοδος",
        "alerts": "Ειδοποιήσεις στο ημερολόγιο",
        "critical": "Κρίσιμες",
        "warning": "Προειδοποιήσεις",
        "info": "Ενημερώσεις",
        "power": "Τροφοδοσία (UPS)",
        "events": "Συμβάντα ρεύματος",
        "none": "Καμία εγγραφή σε αυτή την περίοδο.",
        "ongoing": "σε εξέλιξη",
        "footer": "Wirewave  ·  Λευκάδα  ·  εμπιστευτικό, για τον πελάτη",
    },
}


def font_file():
    for path in FONT_PATHS:
        if os.path.isfile(path):
            bold = next((p for p in BOLD_PATHS if os.path.isfile(p)), path)
            return path, bold
    raise RuntimeError("DejaVu Sans is not installed (apt install fonts-dejavu-core)")


def _styles(font, bold):
    return {
        "h1": ParagraphStyle("h1", fontName=bold, fontSize=18, textColor=colors.white, leading=22),
        "kicker": ParagraphStyle("kicker", fontName=font, fontSize=9, textColor=colors.HexColor("#cfe1ff"), leading=12),
        "h2": ParagraphStyle("h2", fontName=bold, fontSize=12, textColor=NAVY, spaceBefore=8, spaceAfter=4, leading=15),
        "body": ParagraphStyle("body", fontName=font, fontSize=9, textColor=colors.HexColor("#1c2b4a"), leading=12),
        "small": ParagraphStyle("small", fontName=font, fontSize=8, textColor=MUTED, leading=11),
        "th": ParagraphStyle("th", fontName=bold, fontSize=8, textColor=colors.white, leading=10),
        "td": ParagraphStyle("td", fontName=font, fontSize=8, textColor=colors.HexColor("#1c2b4a"), leading=10),
        "footer": ParagraphStyle("footer", fontName=font, fontSize=8, textColor=MUTED, alignment=TA_LEFT),
    }


def _table(headers, rows, styles, col_widths):
    head = [Paragraph(h, styles["th"]) for h in headers]
    data = [head]
    for row in rows:
        data.append([Paragraph("" if v is None else str(v), styles["td"]) for v in row])
    if len(data) == 1:
        data.append([Paragraph(styles.get("_none", ""), styles["td"])] + [""] * (len(headers) - 1))
    tbl = Table(data, colWidths=col_widths, repeatRows=1)
    cmds = [
        ("BACKGROUND", (0, 0), (-1, 0), NAVY),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), styles["th"].fontName),
        ("BACKGROUND", (0, 1), (-1, -1), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.3, LINE),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]
    for i in range(1, len(data)):
        if i % 2 == 0:
            cmds.append(("BACKGROUND", (0, i), (-1, i), ZEBRA))
    tbl.setStyle(TableStyle(cmds))
    return tbl


def build_pdf(data, logo_path=None):
    """data uses already-localised display strings for dates. Structural labels come from lang."""
    lang = data.get("lang") if data.get("lang") in TEXT else "en"
    t = TEXT[lang]
    font, bold = font_file()
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont
    pdfmetrics.registerFont(TTFont("DejaVu", font))
    pdfmetrics.registerFont(TTFont("DejaVuBold", bold))
    styles = _styles("DejaVu", "DejaVuBold")
    styles["_none"] = t["none"]
    buf = BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=14 * mm, rightMargin=14 * mm,
                            topMargin=14 * mm, bottomMargin=16 * mm, title=t["title"])
    width = A4[0] - 28 * mm
    story = []
    banner = []
    if logo_path and os.path.isfile(logo_path):
        img = Image(logo_path, 12 * mm, 12 * mm)
        img.hAlign = "LEFT"
        banner.append(img)
    banner.append(Paragraph(t["kicker"] + "<br/>" + t["title"], styles["h1"]))
    head = Table([banner], colWidths=[16 * mm, width - 16 * mm])
    head.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), NAVY),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
    ]))
    story.append(head)
    story.append(Spacer(1, 4 * mm))
    story.append(Paragraph(f"<b>{t['site']}:</b> {data.get('site') or ''}", styles["body"]))
    story.append(Paragraph(f"<b>{t['period']}:</b> {data.get('period') or ''}", styles["body"]))
    story.append(Paragraph(f"<b>{t['generated']}:</b> {data.get('generated') or ''}", styles["small"]))

    story.append(Paragraph(t["uptime"], styles["h2"]))
    hosts = data.get("hosts") or []
    story.append(_table(
        [t["host"], t["address"], t["group"], t["pct"]],
        [[h.get("name"), h.get("ip"), h.get("group") or "", h.get("uptime")] for h in hosts] or [],
        styles, [width * 0.34, width * 0.28, width * 0.2, width * 0.18]))

    story.append(Paragraph(t["outages"], styles["h2"]))
    outs = data.get("outages") or []
    story.append(_table(
        [t["host"], t["start"], t["end"], t["duration"]],
        [[o.get("host"), o.get("start"), o.get("end") or t["ongoing"], o.get("duration")] for o in outs],
        styles, [width * 0.28, width * 0.27, width * 0.27, width * 0.18]))

    story.append(Paragraph(t["internet"], styles["h2"]))
    net = data.get("internet") or {}
    if not net:
        story.append(Paragraph(t["none"], styles["body"]))
    else:
        story.append(Paragraph(
            f"{t['loss']}: {net.get('loss', '—')} · {t['latency']}: {net.get('latency', '—')} · "
            f"{t['jitter']}: {net.get('jitter', '—')} · {t['down_count']}: {net.get('down', 0)}",
            styles["body"]))

    story.append(Paragraph(t["cameras"], styles["h2"]))
    cams = data.get("cameras") or []
    story.append(_table(
        [t["host"], t["status"]],
        [[c.get("host"), c.get("status")] for c in cams],
        styles, [width * 0.32, width * 0.68]))

    story.append(Paragraph(t["bandwidth"], styles["h2"]))
    bands = data.get("bandwidth") or []
    story.append(_table(
        [t["host"], t["iface"], t["in"], t["out"]],
        [[b.get("host"), b.get("iface"), b.get("in"), b.get("out")] for b in bands],
        styles, [width * 0.3, width * 0.28, width * 0.21, width * 0.21]))

    story.append(Paragraph(t["power"], styles["h2"]))
    power = data.get("power") or []
    story.append(_table(
        [t["host"], t["events"], t["status"]],
        [[p.get("host"), p.get("events"), p.get("status")] for p in power],
        styles, [width * 0.28, width * 0.22, width * 0.5]))

    counts = data.get("alerts") or {}
    story.append(Paragraph(t["alerts"], styles["h2"]))
    story.append(Paragraph(
        f"{t['critical']}: {counts.get('critical', 0)} · {t['warning']}: {counts.get('warning', 0)} · "
        f"{t['info']}: {counts.get('info', 0)}",
        styles["body"]))
    story.append(Spacer(1, 6 * mm))
    ver = data.get("version") or ""
    story.append(Paragraph(t["footer"] + (f"  ·  v{ver}" if ver else ""), styles["footer"]))

    def _page(canvas, doc_):
        canvas.saveState()
        canvas.setFillColor(NAVY)
        canvas.rect(0, A4[1] - 6, A4[0], 6, fill=1, stroke=0)
        canvas.setFillColor(BLUE)
        canvas.rect(0, 0, A4[0], 4, fill=1, stroke=0)
        canvas.restoreState()

    doc.build(story, onFirstPage=_page, onLaterPages=_page)
    return buf.getvalue()
