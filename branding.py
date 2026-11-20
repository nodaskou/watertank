"""Client logo checks. SVG is reduced to a small set of drawing tags so it cannot run script."""
import os
from xml.etree import ElementTree as ET

MAX_LOGO = 512 * 1024
_PNG = b"\x89PNG\r\n\x1a\n"
_JPEG = b"\xff\xd8\xff"
_TAGS = {
    "svg", "g", "path", "rect", "circle", "ellipse", "line", "polyline", "polygon",
    "text", "tspan", "defs", "linearGradient", "radialGradient", "stop", "title", "desc",
    "clipPath", "mask", "symbol",
}
_ATTRS = {
    "viewbox", "width", "height", "fill", "stroke", "stroke-width", "d", "cx", "cy", "r",
    "rx", "ry", "x", "y", "x1", "y1", "x2", "y2", "points", "transform", "opacity",
    "fill-opacity", "stroke-opacity", "id", "offset", "stop-color", "stop-opacity",
    "font-size", "text-anchor", "font-family", "cx", "gradientunits", "spreadmethod",
}


class LogoError(Exception):
    pass


def _local(tag):
    return tag.rsplit("}", 1)[-1] if tag else ""


def sanitize_svg(raw):
    """Return a safe SVG document, or raise LogoError."""
    text = raw.decode("utf-8", "replace")
    upper = text.upper()
    if "<!DOCTYPE" in upper or "<!ENTITY" in upper or "<SCRIPT" in upper:
        raise LogoError("This SVG is not allowed.")
    try:
        root = ET.fromstring(text.encode("utf-8"))
    except ET.ParseError as exc:
        raise LogoError("This SVG could not be read.") from exc
    if _local(root.tag).lower() != "svg":
        raise LogoError("This file is not an SVG image.")

    def clean(el):
        tag = _local(el.tag)
        if tag not in _TAGS:
            return None
        attrib = {}
        for key, value in el.attrib.items():
            name = _local(key).lower()
            if name.startswith("on") or name in ("style", "xmlns"):
                continue
            if name in ("href", "xlink:href"):
                if value.startswith("#") and "<" not in value and '"' not in value:
                    attrib["href"] = value
                continue
            if name in _ATTRS and "<" not in value and "javascript:" not in value.lower():
                attrib[name] = value
        node = ET.Element(tag, attrib)
        if el.text and "<" not in el.text:
            node.text = el.text
        for child in list(el):
            kept = clean(child)
            if kept is not None:
                node.append(kept)
        return node

    cleaned = clean(root)
    if cleaned is None:
        raise LogoError("This SVG is not allowed.")
    cleaned.set("xmlns", "http://www.w3.org/2000/svg")
    return ET.tostring(cleaned, encoding="utf-8", xml_declaration=True)


def sniff(raw):
    """png, jpeg, webp, or svg. Anything else is rejected."""
    if not raw or len(raw) > MAX_LOGO:
        raise LogoError("The logo must be a PNG, JPG, WebP, or SVG under 512 KB.")
    if raw.startswith(_PNG):
        return "png"
    if raw.startswith(_JPEG):
        return "jpeg"
    if raw.startswith(b"RIFF") and raw[8:12] == b"WEBP":
        return "webp"
    head = raw.lstrip()[:200].lower()
    if head.startswith(b"<svg") or (head.startswith(b"<?xml") and b"<svg" in raw[:2000].lower()):
        return "svg"
    raise LogoError("The logo must be a PNG, JPG, WebP, or SVG under 512 KB.")


def prepare(raw):
    kind = sniff(raw)
    if kind == "svg":
        return "svg", sanitize_svg(raw)
    return kind, raw


def store(data_dir, raw):
    """Write one client logo and remove any previous file. Returns the filename."""
    kind, body = prepare(raw)
    ext = {"png": "png", "jpeg": "jpg", "webp": "webp", "svg": "svg"}[kind]
    folder = os.path.join(data_dir, "brand")
    os.makedirs(folder, mode=0o750, exist_ok=True)
    for name in os.listdir(folder):
        if name.startswith("client-logo."):
            try:
                os.remove(os.path.join(folder, name))
            except OSError:
                pass
    filename = "client-logo." + ext
    path = os.path.join(folder, filename)
    with open(path, "wb") as fh:
        fh.write(body)
    os.chmod(path, 0o640)
    return filename


def find(data_dir, filename):
    if not data_dir or not filename:
        return None
    safe = os.path.basename(filename)
    if safe != filename or not safe.startswith("client-logo."):
        return None
    path = os.path.join(data_dir, "brand", safe)
    return path if os.path.isfile(path) else None


def remove(data_dir):
    folder = os.path.join(data_dir or "", "brand")
    if not os.path.isdir(folder):
        return
    for name in os.listdir(folder):
        if name.startswith("client-logo."):
            try:
                os.remove(os.path.join(folder, name))
            except OSError:
                pass
