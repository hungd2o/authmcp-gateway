"""Cross-platform System Tray support for AuthMCP Gateway.

The tray support is bundled with the application and relies on the
``pystray`` and ``Pillow`` dependencies installed with the package.

pystray supports Windows (win32), macOS (AppKit), and Linux (GTK /
AppIndicator / Xorg) out of the box.

Usage (called internally by the CLI):
    from authmcp_gateway.tray import run_tray
    run_tray(port=8000, host="0.0.0.0", server=uvicorn_server)
"""

from __future__ import annotations

import webbrowser
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import uvicorn


def is_tray_available() -> bool:
    """Return *True* if pystray and Pillow are both importable.

    Used by the CLI to decide whether to start in tray mode without
    requiring the caller to catch ImportError.
    """
    try:
        import pystray  # noqa: F401
        from PIL import Image  # noqa: F401

        return True
    except Exception:
        return False


def _create_icon_image():
    """Generate a simple coloured circle icon with 'M' text using Pillow."""
    try:
        from PIL import Image, ImageDraw, ImageFont
    except ImportError as exc:
        raise ImportError(
            "Pillow is required for the system tray icon. "
            "Reinstall authmcp-gateway to restore bundled tray dependencies."
        ) from exc

    size = 64
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    # Background circle – a shade of blue
    draw.ellipse([2, 2, size - 2, size - 2], fill=(30, 120, 200, 255))

    # Attempt to draw a centred letter; fall back gracefully if no font available
    try:
        font = ImageFont.load_default()
        bbox = draw.textbbox((0, 0), "M", font=font)
        text_w = bbox[2] - bbox[0]
        text_h = bbox[3] - bbox[1]
        x = (size - text_w) // 2
        y = (size - text_h) // 2
        draw.text((x, y), "M", fill=(255, 255, 255, 255), font=font)
    except Exception:  # noqa: BLE001
        pass

    return img


def _load_icon_image(icon_path: str | None):
    """Load a custom .ico/.png file if provided, otherwise generate one."""
    if icon_path:
        try:
            from PIL import Image

            return Image.open(icon_path).convert("RGBA")
        except Exception:  # noqa: BLE001
            pass
    return _create_icon_image()


def run_tray(
    port: int,
    host: str = "0.0.0.0",
    server: "uvicorn.Server | None" = None,
    icon_path: str | None = None,
    whitelist_token: str | None = None,
) -> None:
    """Start the system tray icon and block until the user clicks Exit.

    This function is **blocking** and must be called from the **main thread**
    (required on all platforms by pystray).

    Parameters
    ----------
    port:
        The port the gateway is listening on.
    host:
        The bind host (``0.0.0.0`` is shown as ``localhost`` in the menu).
    server:
        A running :class:`uvicorn.Server` instance.  When the user clicks
        *Exit* its ``should_exit`` flag is set so uvicorn shuts down cleanly.
    icon_path:
        Optional path to a custom ``.ico`` or ``.png`` file.  Defaults to a
        programmatically generated placeholder icon.
    """
    try:
        import pystray
    except ImportError as exc:
        raise ImportError(
            "pystray is required for the system tray. "
            "Reinstall authmcp-gateway to restore bundled tray dependencies."
        ) from exc

    display_host = "localhost" if host in ("0.0.0.0", "") else host
    dashboard_url = f"http://{display_host}:{port}"
    whitelist_url = (
        f"http://{display_host}:{port}/{whitelist_token}/whitelist" if whitelist_token else ""
    )

    icon_image = _load_icon_image(icon_path)

    def open_dashboard(_icon: pystray.Icon, _item: pystray.MenuItem) -> None:
        webbrowser.open(dashboard_url)

    def open_whitelist(_icon: pystray.Icon, _item: pystray.MenuItem) -> None:
        if whitelist_url:
            webbrowser.open(whitelist_url)

    def on_exit(_icon: pystray.Icon, _item: pystray.MenuItem) -> None:
        if server is not None:
            server.should_exit = True
        _icon.stop()

    menu = pystray.Menu(
        pystray.MenuItem(
            f"Running on port: {port}",
            action=None,
            enabled=False,
        ),
        pystray.Menu.SEPARATOR,
        pystray.MenuItem("Open Dashboard", open_dashboard),
        pystray.MenuItem("Open Whitelist", open_whitelist, enabled=bool(whitelist_token)),
        pystray.MenuItem("Exit", on_exit),
    )

    tray_icon = pystray.Icon(
        name="authmcp-gateway",
        icon=icon_image,
        title="AuthMCP Gateway",
        menu=menu,
    )

    tray_icon.run()
