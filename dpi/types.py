# dpi/types.py
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Optional
import hashlib


class AppType(Enum):
    UNKNOWN    = "Unknown"
    HTTP       = "HTTP"
    HTTPS      = "HTTPS"
    DNS        = "DNS"
    TLS        = "TLS"
    QUIC       = "QUIC"
    GOOGLE     = "Google"
    FACEBOOK   = "Facebook"
    YOUTUBE    = "YouTube"
    TWITTER    = "Twitter/X"
    INSTAGRAM  = "Instagram"
    NETFLIX    = "Netflix"
    AMAZON     = "Amazon"
    MICROSOFT  = "Microsoft"
    APPLE      = "Apple"
    WHATSAPP   = "WhatsApp"
    TELEGRAM   = "Telegram"
    TIKTOK     = "TikTok"
    SPOTIFY    = "Spotify"
    ZOOM       = "Zoom"
    DISCORD    = "Discord"
    GITHUB     = "GitHub"
    CLOUDFLARE = "Cloudflare"


@dataclass(frozen=True)
class FiveTuple:
    src_ip:   int
    dst_ip:   int
    src_port: int
    dst_port: int
    protocol: int   # TCP=6, UDP=17

    def reverse(self) -> "FiveTuple":
        return FiveTuple(self.dst_ip, self.src_ip,
                         self.dst_port, self.src_port, self.protocol)

    def __str__(self) -> str:
        def fmt(ip):
            return ".".join(str((ip >> s) & 0xFF) for s in (0, 8, 16, 24))
        proto = {6: "TCP", 17: "UDP"}.get(self.protocol, "?")
        return f"{fmt(self.src_ip)}:{self.src_port} -> {fmt(self.dst_ip)}:{self.dst_port} ({proto})"


@dataclass
class Flow:
    tuple:    FiveTuple
    app_type: AppType = AppType.UNKNOWN
    sni:      str     = ""
    packets:  int     = 0
    bytes:    int     = 0
    blocked:  bool    = False


# SNI/domain → AppType mapping
_SNI_RULES: list[tuple[list[str], AppType]] = [
    (["youtube", "ytimg", "youtu.be"],                          AppType.YOUTUBE),
    (["google", "gstatic", "googleapis", "ggpht", "gvt1"],     AppType.GOOGLE),
    (["facebook", "fbcdn", "fb.com", "fbsbx", "meta.com"],     AppType.FACEBOOK),
    (["instagram", "cdninstagram"],                             AppType.INSTAGRAM),
    (["whatsapp", "wa.me"],                                     AppType.WHATSAPP),
    (["twitter", "twimg", "x.com", "t.co"],                    AppType.TWITTER),
    (["netflix", "nflxvideo", "nflximg"],                       AppType.NETFLIX),
    (["amazon", "amazonaws", "cloudfront", "aws"],              AppType.AMAZON),
    (["microsoft", "msn.com", "office", "azure",
      "live.com", "outlook", "bing"],                           AppType.MICROSOFT),
    (["apple", "icloud", "mzstatic", "itunes"],                 AppType.APPLE),
    (["telegram", "t.me"],                                      AppType.TELEGRAM),
    (["tiktok", "tiktokcdn", "musical.ly", "bytedance"],        AppType.TIKTOK),
    (["spotify", "scdn.co"],                                    AppType.SPOTIFY),
    (["zoom"],                                                   AppType.ZOOM),
    (["discord", "discordapp"],                                  AppType.DISCORD),
    (["github", "githubusercontent"],                           AppType.GITHUB),
    (["cloudflare", "cf-"],                                     AppType.CLOUDFLARE),
]


def sni_to_app_type(sni: str) -> AppType:
    if not sni:
        return AppType.UNKNOWN
    lower = sni.lower()
    for keywords, app in _SNI_RULES:
        if any(kw in lower for kw in keywords):
            return app
    return AppType.HTTPS  # SNI present but unrecognised → still HTTPS