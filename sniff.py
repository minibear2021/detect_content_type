from typing import List

# The algorithm uses at most sniffLen bytes to make its decision.
sniff_len = 512


def detect_content_type(data: bytes) -> str:
    # DetectContentType implements the algorithm described
    # at https://mimesniff.spec.whatwg.org/ to determine the
    # Content-Type of the given data. It considers at most the
    # first 512 bytes of data. DetectContentType always returns
    # a valid MIME type: if it cannot determine a more specific one, it
    # returns "application/octet-stream".
    if len(data) > sniff_len:
        data = data[:sniff_len]

    # Index of the first non-whitespace byte in data.
    first_non_ws = 0
    while first_non_ws < len(data) and is_ws(data[first_non_ws]):
        first_non_ws += 1

    for sig in sniff_signatures:
        ct = sig.match(data, first_non_ws)
        if ct != "":
            return ct

    return "application/octet-stream"  # fallback


def is_ws(b: int) -> bool:
    # isWS reports whether the provided byte is a whitespace byte (0xWS)
    # as defined in https://mimesniff.spec.whatwg.org/#terminology.
    if b in (b'\t', b'\n', b'\x0c', b'\r', b' '):
        return True
    return False


def is_tt(b: int) -> bool:
    # isTT reports whether the provided byte is a tag-terminating byte (0xTT)
    # as defined in https://mimesniff.spec.whatwg.org/#terminology.
    if b in (b' ', b'>'):
        return True
    return False


class SniffSig:
    def match(self, data: bytes, first_non_ws: int) -> str:
        return ""


class ExactSig(SniffSig):
    def __init__(self, sig: bytes, ct: str):
        self.sig = sig
        self.ct = ct

    # match returns the MIME type of the data, or "" if unknown.
    def match(self, data: bytes, first_non_ws: int) -> str:
        if data.startswith(self.sig):
            return self.ct
        return ""


class MaskedSig(SniffSig):
    def __init__(self, mask: bytes, pat: bytes, skip_ws: bool, ct: str):
        self.mask = mask
        self.pat = pat
        self.skip_ws = skip_ws
        self.ct = ct

    def match(self, data: bytes, first_non_ws: int) -> str:
        # pattern matching algorithm section 6
        # https://mimesniff.spec.whatwg.org/#pattern-matching-algorithm

        if self.skip_ws:
            data = data[first_non_ws:]
        if len(self.pat) != len(self.mask):
            return ""
        if len(data) < len(self.pat):
            return ""
        for i, pb in enumerate(self.pat):
            masked_data = data[i] & self.mask[i]
            if masked_data != pb:
                return ""
        return self.ct


class HtmlSig(SniffSig):
    def __init__(self, pat: bytes):
        self.pat = pat

    def match(self, data: bytes, first_non_ws: int) -> str:
        data = data[first_non_ws:]
        if len(data) < len(self.pat) + 1:
            return ""
        for i, b in enumerate(self.pat):
            db = data[i]
            if ord('A') <= b <= ord('Z'):
                db &= 0xDF
            if b != db:
                return ""
        # Next byte must be a tag-terminating byte(0xTT).
        if not is_tt(data[len(self.pat)]):
            return ""
        return "text/html; charset=utf-8"


class Mp4Sig(SniffSig):
    def match(self, data: bytes, first_non_ws: int) -> str:
        # https://mimesniff.spec.whatwg.org/#signature-for-mp4
        # c.f. section 6.2.1
        if len(data) < 12:
            return ""
        box_size = int.from_bytes(data[:4], byteorder='big')
        if len(data) < box_size or box_size % 4 != 0:
            return ""
        if not data[4:8] == b'ftyp':
            return ""
        for st in range(8, box_size, 4):
            if st == 12:
                # Ignores the four bytes that correspond to the version number of the "major brand".
                continue
            if data[st:st + 3] == b'mp4':
                return "video/mp4"
        return ""


class TextSig(SniffSig):
    def match(self, data: bytes, first_non_ws: int) -> str:
        # c.f. section 5, step 4.
        for b in data[first_non_ws:]:
            if (b <= 0x08 or
                b == 0x0B or
                0x0E <= b <= 0x1A or
                    0x1C <= b <= 0x1F):
                return ""
        return "text/plain; charset=utf-8"


sniff_signatures: List[SniffSig] = [
    # Data matching the table in section 6.
    HtmlSig(b'<!DOCTYPE HTML'),
    HtmlSig(b"<HTML"),
    HtmlSig(b"<HEAD"),
    HtmlSig(b"<SCRIPT"),
    HtmlSig(b"<IFRAME"),
    HtmlSig(b"<H1"),
    HtmlSig(b"<DIV"),
    HtmlSig(b"<FONT"),
    HtmlSig(b"<TABLE"),
    HtmlSig(b"<A"),
    HtmlSig(b"<STYLE"),
    HtmlSig(b"<TITLE"),
    HtmlSig(b"<B"),
    HtmlSig(b"<BODY"),
    HtmlSig(b"<BR"),
    HtmlSig(b"<P"),
    HtmlSig(b"<!--"),
    MaskedSig(
        b"\xFF\xFF\xFF\xFF\xFF", 
        b"<?xml", 
        True, 
        "text/xml; charset=utf-8"),
    ExactSig(b"%PDF-", "application/pdf"),
    ExactSig(b"%!PS-Adobe-", "application/postscript"),

    # UTF BOMs.
    MaskedSig(
        b"\xFF\xFF\x00\x00", 
        b"\xFE\xFF\x00\x00", 
        False, 
        "text/plain; charset=utf-16be"),
    MaskedSig(
        b"\xFF\xFF\x00\x00", 
        b"\xFF\xFE\x00\x00", 
        False, 
        "text/plain; charset=utf-16le"),
    MaskedSig(
        b"\xFF\xFF\xFF\x00", 
        b"\xEF\xBB\xBF\x00", 
        False, 
        "text/plain; charset=utf-8"),

    # Image types
    # For posterity, we originally returned "image/vnd.microsoft.icon" from
    # https://tools.ietf.org/html/draft-ietf-websec-mime-sniff-03#section-7
    # https://codereview.appspot.com/4746042
    # but that has since been replaced with "image/x-icon" in Section 6.2
    # of https://mimesniff.spec.whatwg.org/#matching-an-image-type-pattern

    ExactSig(b"\x00\x00\x01\x00", "image/x-icon"),
    ExactSig(b"\x00\x00\x02\x00", "image/x-icon"),
    ExactSig(b"BM", "image/bmp"),
    ExactSig(b"GIF87a", "image/gif"),
    ExactSig(b"GIF89a", "image/gif"),
    MaskedSig(
        b"\xFF\xFF\xFF\xFF\x00\x00\x00\x00\xFF\xFF\xFF\xFF\xFF\xFF",
        b"RIFF\x00\x00\x00\x00WEBPVP",
        False, 
        "image/webp"),
    ExactSig(b"\x89PNG\x0D\x0A\x1A\x0A", "image/png"),
    ExactSig(b"\xFF\xD8\xFF", "image/jpeg"),

    # Audio and Video types
    # Enforce the pattern match ordering as prescribed in
    # https://mimesniff.spec.whatwg.org/#matching-an-audio-or-video-type-pattern
    MaskedSig(
        b"\xFF\xFF\xFF\xFF\x00\x00\x00\x00\xFF\xFF\xFF\xFF",
        b"FORM\x00\x00\x00\x00AIFF",
        False, 
        "audio/aiff"),
    MaskedSig(
        b"\xFF\xFF\xFF", 
        b"ID3", 
        False, 
        "audio/mpeg"),
    MaskedSig(
        b"\xFF\xFF\xFF\xFF\xFF", 
        b"OggS\x00", 
        False, 
        "application/ogg"),
    MaskedSig(
        b"\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF",
        b"MThd\x00\x00\x00\x06",
        False, 
        "audio/midi"),
    MaskedSig(
        b"\xFF\xFF\xFF\xFF\x00\x00\x00\x00\xFF\xFF\xFF\xFF",
        b"RIFF\x00\x00\x00\x00AVI ",
        False, 
        "video/avi"),
    MaskedSig(
        b"\xFF\xFF\xFF\xFF\x00\x00\x00\x00\xFF\xFF\xFF\xFF",
        b"RIFF\x00\x00\x00\x00WAVE",
        False, 
        "audio/wave"),
    # 6.2.0.2. video/mp4
    Mp4Sig(),
    # 6.2.0.3. video/webm
    ExactSig(b"\x1A\x45\xDF\xA3", "video/webm"),
    # Font types
    MaskedSig(
        # 34 NULL bytes followed by the string "LP"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00LP",
        # 34 NULL bytes followed by \xF\xF
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xFF\xFF",
        False,
        "application/vnd.ms-fontobject"),
    ExactSig(b"\x00\x01\x00\x00", "font/ttf"),
    ExactSig(b"OTTO", "font/otf"),
    ExactSig(b"ttcf", "font/collection"),
    ExactSig(b"wOFF", "font/woff"),
    ExactSig(b"wOF2", "font/woff2"),

    # Archive types
    ExactSig(b"\x1F\x8B\x08", "application/x-gzip"),
    ExactSig(b"PK\x03\x04", "application/zip"),
    # RAR's signatures are incorrectly defined by the MIME spec as per
    #    https://github.com/whatwg/mimesniff/issues/63
    # However, RAR Labs correctly defines it at:
    #    https://www.rarlab.com/technote.htm#rarsign
    # so we use the definition from RAR Labs.
    # TODO: do whatever the spec ends up doing.
    ExactSig(b"Rar!\x1A\x07\x00", "application/x-rar-compressed"),
    ExactSig(b"Rar!\x1A\x07\x01\x00", "application/x-rar-compressed"),
    ExactSig(b"\x00\x61\x73\x6D", "application/wasm"),
    TextSig()  # should be last
]

if __name__ == '__main__':
    with open('./demo.png', '+rb') as f:
        data = f.read()
        result = detect_content_type(data)
        print(result)
