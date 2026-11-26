"""Free-text and value scrubbing (shared by every format handler)."""
from __future__ import annotations

import base64
import binascii
import os
import re
from urllib.parse import unquote_plus

from . import lexicon as L
from .engine import STOP_WORDS as STOPW
from .engine import INDIC_DIG, RX_DOTTED_AADHAAR, RX_DOTTED_PHONE, _INDIC_DIGITS
from .engine import (CLIN_PROTECT, COMMON_WORDS, DEVA, NAME_SEQ, NAME_TOK, RX_DIGITRUN, RX_DOCTOR, RX_EMAIL, RX_IDTOK,
                     RX_MASKED_AADHAAR, RX_PAN, classify_digits, clean_name_seq, id_digits_ok, norm,
                     shift_dates_in)

_M0, _M1, _MB = "", "", 0xE100
_MARK = re.compile("([-]+)")


class Masker:
    def __init__(self):
        self.store: list[str] = []

    def put(self, s: str) -> str:
        self.store.append(s)
        return _M0 + "".join(chr(_MB + int(c)) for c in str(len(self.store) - 1)) + _M1

    def restore(self, t: str) -> str:
        for _ in range(6):
            n = _MARK.sub(lambda m: self.store[int("".join(str(ord(c) - _MB) for c in m.group(1)))], t)
            if n == t:
                break
            t = n
        return t


class Ctx:
    """Per-record scrubbing context."""

    def __init__(self, H, psn: str | None, days: int, order: str, band, stats, rule=None):
        self.H, self.psn, self.days, self.order, self.band, self.stats = H, psn, days, order, band, stats
        self.rule = rule

    @property
    def patient_token(self) -> str:
        return self.psn or "[PATIENT]"


# ---------------------------------------------------------------- compiled sweeps (built once per run)
class Sweeper:
    def __init__(self, H):
        self.H = H
        lat_full = sorted({n for n in H.full_names if not re.search(rf"[{DEVA}]", n)}, key=len, reverse=True)
        dev_full = sorted({n for n in H.full_names if re.search(rf"[{DEVA}]", n)}, key=len, reverse=True)
        lat_tok = sorted({t for t in H.name_tokens if not re.search(rf"[{DEVA}]", t)}, key=len, reverse=True)
        dev_tok = sorted({t for t in H.name_tokens if re.search(rf"[{DEVA}]", t)}, key=len, reverse=True)
        sep = r"[\s_.\-]+"

        def alt(items, f=lambda x: x):
            return "|".join(f(i) for i in items) or r"(?!x)x"

        latf = alt(lat_full, lambda n: sep.join(re.escape(p) for p in n.split()))
        self.rx_lat_full = re.compile(rf"(?i)(?<![A-Za-z])(?:{latf})(?![A-Za-z])")
        devf = alt(dev_full, lambda n: r"\s+".join(re.escape(p) for p in n.split()))
        self.rx_dev_full = re.compile(rf"(?<![{DEVA}])(?:{devf})(?![{DEVA}])")
        self.rx_lat_tok = re.compile(rf"(?i)(?<![A-Za-z])(?:{alt(lat_tok, re.escape)})(?![A-Za-z])")
        self.rx_dev_tok = re.compile(rf"(?<![{DEVA}])(?:{alt(dev_tok, re.escape)})(?![{DEVA}])")
        places = sorted((p for p in H.places if p not in H.safe_places), key=len, reverse=True)
        self.rx_place = re.compile(
            rf"(?i)(?<![A-Za-z{DEVA}])(?:{alt(places, lambda n: sep.join(re.escape(x) for x in n.split()))})(?![A-Za-z{DEVA}])")
        ids = sorted(H.ids, key=len, reverse=True)
        self.rx_ids = re.compile(
            rf"(?i)(?<![A-Za-z0-9])(?:{alt(ids, lambda i: r'[\s/\-_.]*'.join(re.escape(c) for c in i))})(?![A-Za-z0-9])")
        digs = sorted(H.id_digits | H.phones, key=len, reverse=True)
        self.rx_digits = re.compile(rf"(?<!\d)(?:{alt(digs, re.escape)})(?!\d)")


# ---------------------------------------------------------------- pieces
RX_B64 = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{24,65536}={0,2}")
RX_HEX = re.compile(r"(?<![0-9A-Za-z])(?:[0-9A-Fa-f]{2}){6,128}(?![0-9A-Za-z])")
RX_ADDR_LINE = re.compile(L.ADDRESS_LABEL.pattern + r"([^\n]*)", re.I)
RX_KEEP_ADMIN = re.compile(rf"(?i)^\s*(?:distt?\.?|district|jila|zila|jillo|ji\.|jilha|जि\.?|ज़िला|जिला|जिल्हा|जनपद)\s*[:.]?\s*([A-Za-z{DEVA} ]+?)\s*$")
RX_PIN_TAIL = re.compile(r"(?<!\d)([1-8]\d{2})\s?(\d{3})(?!\d)")
RX_HOUSE = re.compile(rf"(?i)(?:(?:घर|मकान|म\.|कोठी)\s*(?:क्र\.?|क्रमांक|नं\.?|नंबर|सं\.?)?\s*[{INDIC_DIG}]+|(?<![\w&])#\s?\d+[A-Za-z]?\b|\b(?:H\.?\s?No\.?|Ghar\s*(?:No\.?|number)|House\s*(?:No\.?)?|Makan\s*(?:No\.?)?|Flat\s*(?:No\.?)?|Plot\s*(?:No\.?)?|Qtr\.?\s*No\.?|Kothi\s*(?:No\.?|number)?|Block\s*(?:No\.?)?)\s*[:\-]?\s*(?=\S*[{INDIC_DIG}])[\w/\-{INDIC_DIG}]+|मकान\s*(?:नं\.?|नंबर)?\s*[:\-]?\s*[\w/\-{INDIC_DIG}]+|म\.\s*नं\.?\s*[:\-]?\s*[\w/\-{INDIC_DIG}]+)")
RX_MOHALLA = re.compile(rf"(?i)\b(?:Mohalla|Mohallah|Mohala|Muhalla|Colony|Nagar\s+Colony|Ward\s+No\.?|Faliyu|Tola)\s+[A-Z][\w]*(?:\s+[A-Z][\w]*)?|\bGali\s+(?:No\.?\s*)?\d+|\bPara\s+[A-Z][a-zA-Z]{{2,}}(?:\s+[A-Z][a-zA-Z]{{2,}})?|मोहल्ला\s+[{DEVA}]+(?:\s+[{DEVA}]+)?")
RX_DEVA_VILLAGE = re.compile(rf"(?<![{DEVA}])[{DEVA}]{{2,}}(?:पुर|पुरा|गांव|गाँव|गाव|पट्टी|वाडी|नगर|खेड़ा|खेडा|डीह|सराय|गंज|वाव|कोट|वाला|डांगा)(?:\s+(?:टांडा|बुद्रुक|खुर्द|कलां|कला|पूर्वी|पश्चिमी|मोटा|नाना))?(?![{DEVA}])"
                             rf"|(?<![{DEVA}])[{DEVA}]{{2,}}\s+(?:टांडा|बुद्रुक|खुर्द|कलां|मोटा|नाना)(?![{DEVA}])")
RX_WARD_ADDR = re.compile(r"(?i)(?<=,\s)Ward\s*(?:No\.?)?\s*\d+\b(?!\s*[(/])|\bWard\s*(?:No\.?)?\s*\d+(?=\s*,)")
RX_WARDNUM = re.compile(r"(?i)\bWard\s*(?:No\.?)?\s*\d+(?!\s*\()")
RX_LANDMARK = re.compile(rf"(?i)\b(?:near|opp\.?|opposite|behind|beside|in\s+front\s+of|next\s+to)\s+(?:the\s+)?[A-Z][\w]*(?:\s+[A-Z][\w]*){{0,3}}"
                         rf"|\b[A-Za-z0-9'\-]{{2,}}(?:\s+[A-Za-z0-9'\-]{{2,}}){{0,3}}\s+(?:pase|pashe|de\s+kol)\b"
                         rf"|[{DEVA}]+(?:\s+[{DEVA}]+){{0,3}}\s+(?:के\s+)?(?:पास|पीछे|सामने|दे\s+कोल|पासे|पाशे)"
                         rf"|[{DEVA}]+(?:\s+[{DEVA}]+){{0,2}}(?:जवळ|समोर|मागे)")
RX_VILL = re.compile(rf"(?i)\b(?:Vill\.?|Village|Gram|Gaon|Gam|Mu\.?\s*Po\.?|Mukkam|Ta\.|Taluka)(?![A-Za-z])\s*[:\-.]?\s*([A-Z][\w]*(?:\s+[A-Z][\w]*){{0,2}})|(?:ग्राम|गाँव|गांव|गाम|पिंड)\s*[:\-]?\s*([{DEVA}]+(?:\s+[{DEVA}]+){{0,2}})")
RX_PIN_CTX = re.compile(r"(?i)(?:\bPIN(?:\s*code)?|\bPincode|पिन(?:\s*कोड)?)\s*[:\-]?\s*([1-8]\d{2})\s?(\d{3})\b|(?<=[\s,\-])([1-8]\d{2})\s?(\d{3})(?=\s*$|\s*\n)")
RX_AGE = re.compile(rf"(?i)((?:\bAge(?:/(?:Sex|Gender|Sx|Jati))?|\bAge\s*/\s*Gender|\bYrs?(?:/(?:Sex|Gender|Sx))?|(?:आयु|उम्र|उमर|वय)(?:/(?:लिंग|लिग|sex|gender|sx))?|\bUmar(?:/(?:Jati|Sx|Sex))?|\bUmra)\s*[:\-]?\s*)([{INDIC_DIG}]{{1,3}})(\s*(?:Yrs?\.?|Years?|Y|वर्ष|साल|saal|sal|/\s*[MFmf])?)"
                    rf"|(?<![\w.x×])([{INDIC_DIG}]{{1,3}})(\s*(?:Yrs?|Y|years)\s*/\s*[MFmf]\b)")
RX_URL = re.compile(r"(?i)\bhttps?://[^\s\"'<>]+|\burn:(?:uuid|oid):[\w.\-]+")
RX_AGE_FREE = re.compile(r"(?i)(?<![\w.\-/×])(\d{1,3})(\s*(?:-\s*)?(?:yrs?|years?|yo|y/o|y|वर्ष|साल|saal|sal)\b\.?(?:\s*old)?)(?=\s*[,/|;)]?\s*(?:male|female|man|woman|boy|girl|m\b|f\b|पुरुष|महिला|$|,|\||/|\)|;))")
RX_PRE_KIN = re.compile(rf"(?i)(?:^|(?<=[\n,;|(\[]))\s*({NAME_SEQ}),\s*(?=(?:S/O|D/O|W/O|H/O|S\.O\.|D\.O\.|W\.O\.|Son\s+of|Daughter\s+of|Wife\s+of|Husband\s+of)\b)")
RX_PRE_PAREN_KIN = re.compile(rf"(?<![A-Za-z/])({NAME_TOK}(?:[ \t]{{1,2}}{NAME_TOK}){{0,3}})\s*\(\s*(?i:S/O|D/O|W/O|H/O|S\.O\.|D\.O\.|W\.O\.|Son\s+of|Daughter\s+of|Wife\s+of|Husband\s+of|पुत्र|पुत्री|पत्नी|पति|बेटा|बेटी)\.?\s*[:\-]?\s*({NAME_TOK}(?:[ \t]{{1,2}}{NAME_TOK}){{0,3}})\s*\)")
RX_KIN_POSS = re.compile(rf"(?i)\b(?:Shri|Sri|Smt\.?|Shrimati|श्री|श्रीमती)\s+({NAME_SEQ})'s\s+(?:wife|husband|son|daughter|father|mother)\b")
RX_KIN = re.compile(rf"(?i)\b({L.KIN})\.?\s*[:\-]?\s*(?:\(\s*)?({NAME_SEQ})")
RX_LABEL = re.compile(L.NAME_LABEL.pattern + rf"({NAME_SEQ})")
RX_HON_AFTER = re.compile(rf"({NAME_SEQ})(\s+(?i:{L.HONORIFIC_AFTER}))\b")
RX_HON_BEFORE = re.compile(rf"\b({L.HONORIFIC_BEFORE})\s+({NAME_SEQ})")
RX_ATTACH_FILE = re.compile(r"\b([A-Za-z0-9][A-Za-z0-9_\-.]{3,80}\.(?:pdf|docx?|xlsx?|pptx?|jpe?g|png|tiff?|bmp|txt|csv|tsv|json|xml|rtf|dcm))\b", re.I)


def _name_ok(toks: list[str]) -> bool:
    if not toks:
        return False
    for t in toks:
        tl = t.strip(".").lower()
        if tl in COMMON_WORDS or tl in L.CLINICAL_WORDS or tl in L.MED_ACRONYMS or re.search(r"\d", t):
            return False
    if len(toks) == 1 and toks[0].isupper() and len(toks[0]) <= 3:
        return False
    return True


_SURN = "|".join(sorted(L.SURNAMES, key=len, reverse=True))
RX_SURNAME = re.compile(rf"(?<![A-Za-z.])((?:[A-Z][a-z]+\s+){{1,2}})({_SURN})\b", re.I)
RX_CTX_NAME = re.compile(rf"(?i)\b(?:called\s+by|informed\s+by|brought\s+by|accompanied\s+by|visited\s+by|reported\s+by|"
                         rf"handed\s+over\s+to|shikayatkarta|shikayatkarta|complainant|aavedak|avedak|prarthi|informant|caller\s*name|"
                         rf"शिकायतकर्ता|आवेदक|प्रार्थी|सूचक|(?:complaint|shikayat|request|application|letter|statement|feedback|query)\s+(?:by|from)|"
                         rf"filed\s+by|submitted\s+by|signature|signed|sign\.?|हस्ताक्षर|sahi|regards|from|to|cc|bcc|attn\.?|"
                         rf"raised\s+by|lodged\s+by|written\s+by|witnessed\s+by|witness|signed\s+by|consent\s+given\s+by|caller|visitor|contact\s+person|escort|relative|attendant)\s*[:\-]?\s*({NAME_SEQ})")
RX_CONSENT = re.compile(rf"(?i)\b(?:I|मैं)\s*,?\s+({NAME_SEQ})\s*,?\s+(?:S/O|D/O|W/O|consent|agree|hereby|authori[sz]e|declare|give|am|aged|resident)\b")
RX_SIGN_PAREN = re.compile(rf"(?im)^((?=.*(?:sign|witness|attendant|relative|guardian|हस्ताक्षर|gawah|sakshi)).*?\(\s*)({NAME_TOK}(?:\s+{NAME_TOK}){{1,3}})(\s*\))")
RX_NAME_VERB = re.compile(rf"(?<![A-Za-z.])({NAME_TOK}(?:[ \t]{NAME_TOK}){{1,3}})\s+(?:visited|came|called|met|brought|accompanied|"
                          rf"signed|left|arrived|requested|collected|took|stayed|attended|enquired)\b")
NAME_VALUE = re.compile(rf"(?:[A-Z][a-z]+(?:\s+[A-Z][a-z]+){{1,3}}|[{DEVA}]+(?:\s+[{DEVA}]+){{1,3}})")
RX_ID_LABEL = re.compile(r"(?i)\b(?:UHID|MRN|MR\s*No|CR\s*No|Reg(?:istration)?\.?\s*(?:No|Number|#)|IP\s*No|IPD\s*No|OPD\s*No|"
                         r"Patient\s*ID|Pt\.?\s*ID|Hospital\s*No|Case\s*No|Admission\s*No|Record\s*No|File\s*No|"
                         r"पंजीकरण\s*(?:संख्या|सं\.?|नं\.?)|पंजीयन\s*(?:संख्या|सं\.?)|UID|Aadhaar|Aadhar|ABHA)\s*[:#.\-]?\s*([A-Za-z]{0,6}[\s/\-]?\d[\w/\-.]*(?:\s\d[\w/\-.]*){0,3})")
RX_NAME_ROLE = re.compile(rf"({NAME_SEQ})\s*\((?:attendant|relative|visitor|caller|wife|husband|son|daughter|father|"
                          rf"mother|brother|sister|guardian|neighbour|friend|raahgir|rahgir|padosi|padosan|rishtedaar|rishtedar|mitra|dost|saathi|"
                          rf"gawah|beta|beti|bhai|behen|bahan|pati|patni|maa|pita|chacha|chachi|mama|mami|bua|nana|nani|dada|dadi|"
                          rf"बेटा|बेटी|पुत्र|पुत्री|पत्नी|पति|पिता|माता|दादा|दादी|नाना|नानी|चाचा|चाची|मामा|मामी|भाई|बहन|अभिभावक)(?![A-Za-z{DEVA}])", re.I)


def generalize_address(value: str, band_pin: bool = False) -> str:
    """Keep only district-level information (and a 3-digit PIN prefix)."""
    parts = [p.strip() for p in re.split(r"[,;]| - |\n", value) if p.strip()]
    kept = []
    for p in parts:
        m = RX_KEEP_ADMIN.match(p)
        if m:
            kept.append(p.strip())
    pin = RX_PIN_TAIL.search(value)
    out = ", ".join(kept)
    if pin and band_pin:
        out = (out + " - " if out else "") + pin.group(1) + "XXX"
    return out or "[ADDRESS]"


_HOMOGLYPHS = str.maketrans({
    "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H", "О": "O", "Р": "P", "С": "C", "Т": "T", "Х": "X", "І": "I",
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i", "ѕ": "s", "ј": "j",
})
_NONCONF_CYR = re.compile(r"[\u0400-\u04FF]")
_HOMO_TOK = re.compile(r"[A-Za-z0-9\u0400-\u04FF]{2,}")
_RX_UESC = re.compile(r"\\u([0-9a-fA-F]{4})")
_RX_HTML_NUM = re.compile(r"&#(?:x([0-9a-fA-F]{2,4})|(\d{2,5}));")
_RX_PCT = re.compile(r"(?:%[0-9a-fA-F]{2}){2,}")


def _decode_hidden(text: str) -> str:
    """Normalise zero-width joiners, homoglyph spoofs, unicode/HTML/percent escapes before scrubbing."""
    t = re.sub(r"[\u200b\u2060\ufeff]", "", text)
    t = re.sub(r"(?<=[A-Za-z0-9])[\u200c\u200d]+(?=[A-Za-z0-9])", "", t)
    if _NONCONF_CYR.search(t):
        def _fix_homo(m):
            tok = m.group(0)
            rep = tok.translate(_HOMOGLYPHS)
            return rep if not _NONCONF_CYR.search(rep) else tok
        t = _HOMO_TOK.sub(_fix_homo, t)
    if "\\u" in t:
        def _uesc(m):
            cp = int(m.group(1), 16)
            if cp >= 0x20 and not (0xD800 <= cp <= 0xDFFF) and cp not in (0x22, 0x27, 0x5C, 0x7F):
                return chr(cp)
            return m.group(0)
        t = _RX_UESC.sub(_uesc, t)
    if "&#" in t:
        def _hnum(m):
            cp = int(m.group(1), 16) if m.group(1) else int(m.group(2))
            if cp >= 0x20 and cp <= 0x10FFFF and not (0xD800 <= cp <= 0xDFFF) and cp not in (0x22, 0x27, 0x5C, 0x7F):
                return chr(cp)
            return m.group(0)
        t = _RX_HTML_NUM.sub(_hnum, t)
    if "%" in t:
        def _pct(m):
            if re.search(r"https?://\S*$", t[:m.start()], re.I):
                return m.group(0)
            try:
                dec = bytes.fromhex(m.group(0).replace("%", "")).decode("utf-8")
            except ValueError:
                return m.group(0)
            if dec and all((c.isprintable() or c == " ") and c not in "\r\n" for c in dec):
                return dec
            return m.group(0)
        t = _RX_PCT.sub(_pct, t)
    return t


def hex_scrub(tok: str, ctx: "Ctx", sw: "Sweeper") -> str:
    try:
        txt = bytes.fromhex(tok).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return tok
    if not txt or sum(c.isprintable() or c in "\n\r\t" for c in txt) / len(txt) < 0.95:
        return tok
    if not any(c.isalpha() or "\u0900" <= c <= "\u0aff" for c in txt):
        return tok
    clean = scrub_text(txt, ctx, sw, allow_b64=False)
    if clean == txt:
        return tok
    ctx.stats["identifiers"] += 1
    return clean.encode("utf-8").hex()


def b64_scrub(tok: str, ctx: "Ctx", sw: "Sweeper") -> str:
    try:
        raw = base64.b64decode(tok + "=" * (-len(tok) % 4), validate=True)
        txt = raw.decode("utf-8")
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return tok
    if not txt or sum(c.isprintable() or c in "\n\r\t" for c in txt) / len(txt) < 0.9:
        return tok
    clean = scrub_text(txt, ctx, sw, allow_b64=False)
    if clean == txt:
        return tok
    ctx.stats["identifiers"] += 1
    return base64.b64encode(clean.encode("utf-8")).decode("ascii")


_SAFE_URL_HOSTS = ("hl7.org", "snomed.info", "loinc.org", "w3.org", "abdm.gov.in", "nrces.in", "unitsofmeasure.org", "fhir.org")
_SAFE_URL_WORDS = {"discharge", "summary", "report", "nursing", "notes", "rx", "lab", "opd", "ipd", "bundle",
                   "export", "visits", "patients", "results", "claims", "registration", "file", "data", "json",
                   "csv", "txt", "tsv", "pdf", "fmt", "lang", "view", "page", "index", "static", "app", "api"}
_URL_PII_KEYS = {"patient", "pt", "name", "naam", "mr", "mrn", "uhid", "id", "pid", "phone", "mob", "mobile",
                 "email", "dob", "aadhaar", "abha", "pan", "user", "query", "q"}


def _scrub_url(url: str, ctx: Ctx, sw: Sweeper, put) -> str:
    if url.lower().startswith("urn:"):
        return put(url)
    base, sep, query = url.partition("?")
    host_part = base.split("://", 1)[1].split("/", 1)[0].lower() if "://" in base else ""
    if any(host_part == h or host_part.endswith("." + h) for h in _SAFE_URL_HOSTS):
        return put(url)
    # Scrub PII inside URL path segments (beyond scheme+host) and query parameters
    if query:
        parts = []
        for pair in query.split("&"):
            k, eq, v = pair.partition("=")
            kl = k.lower()
            if eq and (kl in _URL_PII_KEYS or L.classify_key(k) in ("NAME", "MRN", "PHONE", "AADHAAR", "ABHA", "EMAIL", "PAN")):
                ctx.stats["identifiers"] += 1
                parts.append(f"{k}=REDACTED")
            elif eq:
                raw_v = unquote_plus(v)
                sv = scrub_text(raw_v, ctx, sw, allow_b64=False)
                parts.append(f"{k}={sv.replace(' ', '+')}" if sv != raw_v else pair)
            else:
                parts.append(pair)
        query = "&".join(parts)
    # Only mask scheme+host+safe-path so FHIR/portal base URLs survive without hiding PII
    return put(base) + (sep + query if sep else "")


def _scrub_attach(m, ctx: Ctx, sw: Sweeper, put) -> str:
    comp = m.group(1)
    stem, ext = os.path.splitext(comp)
    parts = re.split(r"([_\-.]+)", stem)
    toks = [p for p in parts if p and not re.fullmatch(r"[_\-.]+", p)]
    safe_words = _SAFE_URL_WORDS | COMMON_WORDS | L.CLINICAL_WORDS | L.MED_ACRONYMS
    flagged = set()
    for p in toks:
        pl = p.lower()
        if pl in safe_words:
            continue
        if pl in sw.H.name_tokens or re.sub(r"[^0-9A-Za-z]", "", p).upper() in sw.H.ids:
            flagged.add(p)
    for a, b in zip(toks, toks[1:]):
        if (re.fullmatch(r"[A-Z][a-z]{2,}", a) and re.fullmatch(r"[A-Z][a-z]{2,}", b)
                and not ({a.lower(), b.lower()} & safe_words)):
            flagged.add(a)
            flagged.add(b)
    if not flagged:
        return comp
    ctx.stats["identifiers"] += 1
    out = []
    for p in parts:
        if p in flagged:
            if not out or out[-1] != "[NAME]":
                out.append("[NAME]")
        else:
            out.append(p)
    cleaned = re.sub(r"[_\-.]{2,}", "_", "".join(out)).strip("_-. ") or "[FILE]"
    return put(cleaned + ext)


def scrub_text(text: str, ctx: Ctx, sw: Sweeper, allow_b64: bool = True) -> str:
    if not text or not text.strip():
        return text
    st = ctx.stats
    M = Masker()
    t = _decode_hidden(text)

    def put(s):
        return M.put(s)

    def red(tag):
        def f(m):
            st["identifiers"] += 1
            return put(tag)
        return f

    if allow_b64:
        t = RX_B64.sub(lambda m: put(b64_scrub(m.group(0), ctx, sw)), t)
        t = RX_HEX.sub(lambda m: put(hex_scrub(m.group(0), ctx, sw)), t)

    # 1. labelled address lines -> district level only
    def addr(m):
        st["identifiers"] += 1
        head = m.group(0)[: m.start(1) - m.start(0)]
        if ctx.rule is not None and ctx.rule.dist == "drop":
            return head + put("[ADDRESS]")
        return head + put(generalize_address(m.group(1)))
    t = RX_ADDR_LINE.sub(addr, t)

    # 2. protect URLs (scrubbing query params first), attachment filenames, doctor names
    t = RX_URL.sub(lambda m: _scrub_url(m.group(0), ctx, sw, put), t)
    t = RX_ATTACH_FILE.sub(lambda m: _scrub_attach(m, ctx, sw, put), t)
    t = RX_DOCTOR.sub(lambda m: put(m.group(0)), t)

    # 3. dates -> per-patient shift (masked so later digit rules never touch them)
    t = shift_dates_in(t, ctx.days, ctx.order, wrap=put)

    # 4. strong identifiers
    t = RX_EMAIL.sub(red("[EMAIL]"), t)
    t = RX_MASKED_AADHAAR.sub(red("[AADHAAR]"), t)
    t = RX_DOTTED_AADHAAR.sub(red("[AADHAAR]"), t)
    t = RX_DOTTED_PHONE.sub(red("[PHONE]"), t)
    t = sw.rx_ids.sub(lambda m: (st.__setitem__("identifiers", st["identifiers"] + 1), put(ctx.psn or "[ID]"))[1], t)

    def digrun(m):
        kind = classify_digits(m.group(1))
        if not kind:
            return m.group(0)
        st["identifiers"] += 1
        return put(f"[{kind}]")
    t = RX_DIGITRUN.sub(digrun, t)
    t = RX_PAN.sub(red("[PAN]"), t)

    def idtok(m):
        tok = m.group(0)
        if not id_digits_ok(tok):
            return tok
        st["identifiers"] += 1
        return put(ctx.psn or "[ID]")
    t = RX_IDTOK.sub(idtok, t)
    t = sw.rx_digits.sub(red("[ID]"), t)

    def idlab(m):
        st["identifiers"] += 1
        return m.group(0)[: m.start(1) - m.start(0)] + put(ctx.psn or "[ID]")
    t = RX_ID_LABEL.sub(idlab, t)

    if os.environ.get("RAKSHAK_P_CLINICAL_PROTECT") != "off":   # ablation switch
        for rx in L_CLIN:
            t = rx.sub(lambda m: put(m.group(0)), t)

    # 5. labelled names / kinship / honorifics
    def lab(m):
        toks = clean_name_seq(m.group(m.lastindex))
        if not _name_ok(toks):
            return m.group(0)
        seq = m.group(m.lastindex)
        joined = " ".join(toks)
        idx = seq.find(joined)
        end = (idx + len(joined)) if idx >= 0 else len(seq)
        st["identifiers"] += 1
        return m.group(0)[: m.start(m.lastindex) - m.start(0)] + put(ctx.patient_token) + seq[end:]
    t = RX_LABEL.sub(lab, t)

    def pre_kin(m):
        toks = clean_name_seq(m.group(1))
        if not _name_ok(toks) or not (toks[0][:1].isupper() or re.search(rf"[{DEVA}]", toks[0])):
            return m.group(0)
        seq = m.group(1)
        joined = " ".join(toks)
        idx = seq.find(joined)
        end = (idx + len(joined)) if idx >= 0 else len(seq)
        st["identifiers"] += 1
        lead = m.group(0)[: m.start(1) - m.start(0)]
        return lead + put(ctx.patient_token) + seq[end:] + m.group(0)[m.end(1) - m.start(0):]
    t = RX_PRE_KIN.sub(pre_kin, t)

    def pre_paren_kin(m):
        if "." in m.group(1):
            return m.group(0)
        toks = clean_name_seq(m.group(1))
        rtoks = clean_name_seq(m.group(2))
        if (not toks or not _name_ok(toks) or not (toks[0][:1].isupper() or re.search(rf"[{DEVA}]", toks[0]))
                or (len(toks) == 1 and len(toks[0]) <= 2 and toks[0].isascii())
                or toks[-1].lower() in ("attendant", "relative", "visitor", "guardian", "witness")
                or not rtoks or not _name_ok(rtoks) or not (rtoks[0][:1].isupper() or re.search(rf"[{DEVA}]", rtoks[0]))):
            return m.group(0)
        seq = m.group(1)
        joined = " ".join(toks)
        idx = seq.find(joined)
        end = (idx + len(joined)) if idx >= 0 else len(seq)
        st["identifiers"] += 1
        rel_part = put("[RELATIVE]")
        between = m.group(0)[m.end(1) - m.start(0):m.start(2) - m.start(0)]
        tail = m.group(0)[m.end(2) - m.start(0):]
        return put(ctx.patient_token) + seq[end:] + between + rel_part + tail
    t = RX_PRE_PAREN_KIN.sub(pre_paren_kin, t)

    def kin_poss(m):
        toks = clean_name_seq(m.group(1))
        if not _name_ok(toks):
            return m.group(0)
        st["identifiers"] += 1
        return m.group(0)[: m.start(1) - m.start(0)] + put("[RELATIVE]") + m.group(0)[m.end(1) - m.start(0):]
    t = RX_KIN_POSS.sub(kin_poss, t)

    def kin(m):
        rel, seq = m.group(1), m.group(2)
        toks = clean_name_seq(seq)
        if not toks:
            return m.group(0)
        if rel.upper().startswith("C/O") and (L.COMPLAINT_WORDS.match(toks[0]) or toks[0][:1].islower()):
            return m.group(0)
        if not _name_ok(toks):
            return m.group(0)
        st["identifiers"] += 1
        head = m.group(0)[: m.start(2) - m.start(0)]
        joined = " ".join(toks)
        rest = seq[len(joined):] if seq.startswith(joined) else ""
        return head + put("[RELATIVE]") + rest
    t = RX_KIN.sub(kin, t)

    def hon_after(m):
        toks = clean_name_seq(m.group(1))
        if not _name_ok(toks):
            return m.group(0)
        st["identifiers"] += 1
        return put(ctx.patient_token) + m.group(2)
    t = RX_HON_AFTER.sub(hon_after, t)

    def hon_before(m):
        toks = clean_name_seq(m.group(2))
        if not _name_ok(toks):
            return m.group(0)
        st["identifiers"] += 1
        return m.group(1) + " " + put(ctx.patient_token)
    t = RX_HON_BEFORE.sub(hon_before, t)

    def ctxname(m):
        g = m.lastindex
        toks = clean_name_seq(m.group(g))
        if not _name_ok(toks) or not toks[0][:1].isupper() and not re.search(rf"[{DEVA}]", toks[0]):
            return m.group(0)
        seq = m.group(g)
        joined = " ".join(toks)
        rest = seq[len(joined):] if seq.startswith(joined) else ""
        st["identifiers"] += 1
        return m.group(0)[: m.start(g) - m.start(0)] + put("[NAME]") + rest + m.group(0)[m.end(g) - m.start(0):]
    t = RX_CTX_NAME.sub(ctxname, t)
    t = RX_CONSENT.sub(ctxname, t)
    t = RX_SIGN_PAREN.sub(lambda m: m.group(1) + put("[NAME]") + m.group(3) if _name_ok(m.group(2).split()) else m.group(0), t)

    def nverb(m):
        toks = m.group(1).split()
        if not _name_ok(toks) or any(w.lower() in STOPW for w in toks):
            return m.group(0)
        st["identifiers"] += 1
        return put("[NAME]") + m.group(0)[m.end(1) - m.start(0):]
    t = RX_NAME_VERB.sub(nverb, t)
    def _name_role(m):
        toks = clean_name_seq(m.group(1))
        if not toks or not _name_ok(toks) or not (toks[0][:1].isupper() or re.search(rf"[{DEVA}]", toks[0])):
            return m.group(0)
        st["identifiers"] += 1
        return put("[RELATIVE]") + m.group(0)[m.end(1) - m.start(0):]
    t = RX_NAME_ROLE.sub(_name_role, t)

    def surname(m):
        first = m.group(1).split()
        if any(w.lower() in COMMON_WORDS or w.lower() in L.CLINICAL_WORDS or w.lower() in L.MED_ACRONYMS for w in first):
            return m.group(0)
        st["identifiers"] += 1
        return put("[NAME]")
    t = RX_SURNAME.sub(surname, t)

    # 6. harvested names anywhere (full names first, then single tokens)
    for rx in (sw.rx_lat_full, sw.rx_dev_full):
        t = rx.sub(red("[NAME]"), t)
    for rx in (sw.rx_lat_tok, sw.rx_dev_tok):
        t = rx.sub(red("[NAME]"), t)

    # 7. address fragments
    t = RX_HOUSE.sub(red("[ADDRESS]"), t)
    t = RX_MOHALLA.sub(red("[LOCALITY]"), t)
    t = RX_LANDMARK.sub(red("[LANDMARK]"), t)

    def vill(m):
        g = 1 if m.group(1) else 2
        if m.group(g).strip().lower() in ("mohalla", "locality", "name", "type", "ward", "tehsil"):
            return m.group(0)
        st["identifiers"] += 1
        return m.group(0)[: m.start(g) - m.start(0)] + put("[VILLAGE]")
    t = RX_VILL.sub(vill, t)
    t = sw.rx_place.sub(red("[PLACE]"), t)

    def dvill(m):
        if norm(m.group(0)) in ctx.H.safe_places:
            return m.group(0)
        st["identifiers"] += 1
        return put("[VILLAGE]")
    t = RX_DEVA_VILLAGE.sub(dvill, t)

    def pin(m):
        st["identifiers"] += 1
        g = 1 if m.group(1) else 3
        keep = ctx.rule is None or ctx.rule.pin != "drop"
        return m.group(0)[: m.start(g) - m.start(0)] + put(m.group(g) + "XXX" if keep else "[PIN]")
    t = RX_PIN_CTX.sub(pin, t)
    t = RX_WARD_ADDR.sub(red("[LOCALITY]"), t)

    # 8. labelled ages -> truthful bands
    def age(m):
        if m.group(2):
            a = int(m.group(2).translate(_INDIC_DIGITS))
            return m.group(1) + put(ctx.band(a)) + (m.group(3) or "")
        a = int(m.group(4).translate(_INDIC_DIGITS))
        return put(ctx.band(a)) + m.group(5)
    t = RX_AGE.sub(age, t)

    def age_free(m):
        a = int(m.group(1))
        if a > 120:
            return m.group(0)
        pre = t_view[max(0, m.start() - 12):m.start()].lower()
        if re.search(r"(?:\bx|since|for|from|past|last|back|ago|×)\s*$", pre):
            return m.group(0)
        return put(ctx.band(a)) + m.group(2)
    t_view = t
    t = RX_AGE_FREE.sub(age_free, t)

    return M.restore(t)


L_CLIN = CLIN_PROTECT
