"""Language resources written for this project (no external gazetteers).

Everything here is generic Indian-language structure (labels, honorifics, kinship
markers, clinical vocabulary, a transliteration table). No practice-data patient
names are stored: patient names are harvested from each input at run time.
"""
import re

DEVA = "ऀ-ॿ"

# ---------------------------------------------------------------- transliteration (Devanagari -> Latin)
_CONS = {
    "क": "k", "ख": "kh", "ग": "g", "घ": "gh", "ङ": "n", "च": "ch", "छ": "chh", "ज": "j", "झ": "jh",
    "ञ": "n", "ट": "t", "ठ": "th", "ड": "d", "ढ": "dh", "ण": "n", "त": "t", "थ": "th", "द": "d",
    "ध": "dh", "न": "n", "प": "p", "फ": "ph", "ब": "b", "भ": "bh", "म": "m", "य": "y", "र": "r",
    "ल": "l", "ळ": "l", "व": "v", "श": "sh", "ष": "sh", "स": "s", "ह": "h",
    "क़": "q", "ख़": "kh", "ग़": "g", "ज़": "z", "ड़": "r", "ढ़": "rh", "फ़": "f", "य़": "y",
}
_VOW = {"अ": "a", "आ": "aa", "इ": "i", "ई": "ii", "उ": "u", "ऊ": "uu", "ऋ": "ri", "ए": "e", "ऐ": "ai",
        "ओ": "o", "औ": "au", "ऑ": "o", "ॲ": "e"}
_MATRA = {"ा": "aa", "ि": "i", "ी": "ii", "ु": "u", "ू": "uu", "ृ": "ri", "े": "e", "ै": "ai",
          "ो": "o", "ौ": "au", "ॉ": "o", "ॅ": "e"}
_NASAL = {"ं": "n", "ँ": "n", "ः": "h"}
NUKTA, HALANT = "़", "्"


def deva_to_latin(s: str) -> str:
    out, i, n = [], 0, len(s)
    while i < n:
        ch = s[i]
        if i + 1 < n and s[i + 1] == NUKTA:
            ch = s[i:i + 2]
            i += 1
        if ch in _CONS or (len(ch) == 2 and ch[0] in _CONS):
            base = _CONS.get(ch) or _CONS.get(ch[0], "")
            nxt = s[i + 1] if i + 1 < n else ""
            if nxt in _MATRA:
                out.append(base + _MATRA[nxt]); i += 2; continue
            if nxt == HALANT:
                out.append(base); i += 2; continue
            # inherent 'a' unless word-final
            final = not (nxt and ("ऀ" <= nxt <= "ॿ"))
            out.append(base if final else base + "a"); i += 1; continue
        if ch in _VOW:
            out.append(_VOW[ch])
        elif ch in _NASAL:
            out.append(_NASAL[ch])
        elif ch in _MATRA:
            out.append(_MATRA[ch])
        elif ch in (NUKTA, HALANT):
            pass
        else:
            out.append(ch)
        i += 1
    return "".join(out)


_ALIASES = {"mohd": "mohammad", "md": "mohammad", "mohammed": "mohammad", "muhammad": "mohammad",
            "mohamad": "mohammad", "mohammad": "mohammad", "mhd": "mohammad"}


def skel(token: str) -> str:
    """Script- and spelling-tolerant key for one name token (Latin or Devanagari)."""
    t = token.strip(".").lower()
    if any("ऀ" <= c <= "ॿ" for c in t):
        t = deva_to_latin(t)
    t = re.sub(r"[^a-z]", "", t)
    t = _ALIASES.get(t, t)
    if not t:
        return ""
    for a, b in (("chh", "c"), ("ph", "f"), ("bh", "b"), ("th", "t"), ("dh", "d"), ("kh", "k"),
                 ("gh", "g"), ("sh", "s"), ("ch", "c"), ("jh", "j"), ("w", "v"), ("z", "j"),
                 ("q", "k"), ("x", "ks"), ("ee", "i"), ("oo", "u")):
        t = t.replace(a, b)
    head, rest = t[0], re.sub(r"[aeiouhy]", "", t[1:])
    k = head + rest
    return re.sub(r"(.)\1+", r"\1", k)


# ---------------------------------------------------------------- name structure
HONORIFIC_AFTER = r"(?:ji|jee|sahab|saheb|sahib|didi|bhai|bhaiya|ben|bai|bibi|amma|baba|मैडम|जी|साहब|दीदी|भाई|बहन)"
HONORIFIC_BEFORE = r"(?:Shri|Sri|Smt\.?|Shrimati|Kumari|Km\.?|Mr\.?|Mrs\.?|Ms\.?|Miss|Sh\.?|Late|Baby|Master|श्री|श्रीमती|सुश्री|कुमारी|स्व\.?)"
GENERIC_NAME_TOKENS = {"devi", "kumar", "kumari", "md", "mohd", "ji", "bai", "bibi", "begum", "lal", "ram",
                       "prasad", "singh", "shri", "smt", "sahab", "didi", "देवी", "कुमार", "कुमारी", "जी"}

KIN = r"(?:S/O|D/O|W/O|F/O|M/O|(?<![A-Za-z]/)C/O|S\.O\.|D\.O\.|W\.O\.|Son of|Daughter of|Wife of|Husband of|Father|Mother|Husband|Wife|Guardian|Attendant|पुत्र|पुत्री|पत्नी|पति|पिता|माता|बेटा|बेटी)"

# Words that may follow "C/O" when it means "complaint of"
COMPLAINT_WORDS = re.compile(
    r"(?i)^(?:fever|pain|cough|cold|vomit|loose|weak|head|chest|abd|abdominal|burning|breath|giddi|dizz|"
    r"swelling|bleed|rash|itch|fatigue|body|joint|back|throat|sore|nausea|diarr|constip|palpit|decreased|"
    r"increased|difficulty|low|high|yellow|blood|chills|altered|loss|shortness|sob|dysuria|frequent|burn|"
    r"pet|sir|bukhar|khansi|dard|ulti|kamzori|बुखार|दर्द|खांसी|उल्टी|कमजोरी|सिर|पेट)")

# Field-label lexicon (EN / Hindi / Hinglish) -> field kind. Each pattern must FULLY match one
# token of the key (keys are split on separators and camelCase), or a phrase given with spaces.
# Order matters: first match wins.
FIELD_RULES = [
    ("AADHAAR", r"aadha\w*|adhar\w*|aadhar\w*|adhaar\w*|uid|आधार"),
    ("ABHA", r"abha\w*|आभा|healthid"),
    ("PAN", r"pan|panno|pannumber"),
    ("EMAIL", r"e?mail|email\w*|ईमेल"),
    ("PHONE", r"phone\w*|mobile\w*|mob|contact\w*|tel|telephone|whatsapp|cell|मोबाइल|फोन|फ़ोन|sampark|telecom"),
    ("INSURANCE", r"pmjay\w*|insur\w*|policy\w*|ayushman|beema|बीमा|claimid|memberid|cardno|scheme"),
    ("MRN", r"uhid|mrn|patientid|patid|pid|regno|registration|reg|ipd\w*|opdno|adm\w*no|admission|crn|crno|"
            r"पंजीकरण|पंजीयन|recordno|caseno|ipno|identifier|patientref|patref|mr"),
    ("DOB", r"dob|birth\w*|birthdate|janm|जन्म|dateofbirth"),
    ("PIN", r"pin|pincode|zip|zipcode|postal\w*|postcode|पिन|पिनकोड"),
    ("REL_NAME", r"relative\w*|guardian\w*|father\w*|husband\w*|mother\w*|wife|spouse|attendant\w*|kin|"
                 r"pita|pati|पिता|पति|संबंधी|अभिभावक|nok|parent\w*"),
    ("RELATION", r"relation|rel|relationship|रिश्ता|sambandh|relation_type"),
    ("DOCTOR", r"doctor\w*|dr|consultant\w*|physician\w*|surgeon\w*|referr\w*|referred|attending|treating|"
               r"nurse|staff|clerk|exported|exportedby|practitioner|performer|author|signedby|verifiedby"),
    ("SAFE", r"hospital|facility|lab|department|dept|specialty|speciality|ward|bed|"
             r"diagnos\w*|icd\w*|condition|complaint\w*|history|procedure\w*|package\w*|drug\w*|medicin\w*|"
             r"medication\w*|dose|dosage|test\w*|loinc|result\w*|value|unit\w*|range|amount\w*|status|vital\w*|"
             r"bp|pulse|temp\w*|spo2|weight\w*|height\w*|bmi|rbs|gender|sex|ling|लिंग|tehsil|तहसील|district|"
             r"distt|jila|जिला|zila|state|visitid|bill\w*|panel\w*|schema|system|type|code|display|frequency|"
             r"route|duration|advice|notes?|remarks?|comment\w*|summary|course|investigation\w*|finding\w*"),
    ("NAME", r"name|naam|नाम|patient|pt|beneficiary|insured|rogi|मरीज|मरीज़|रोगी|first|last|given|family|"
             r"surname|fullname|firstname|lastname|middle|local|alias"),
    ("AGE", r"age|umar|umra|आयु|उम्र|ageyears|yrs"),
    ("VILLAGE", r"village|gaon|gram|mohalla|locality|ग्राम|गाँव|गांव|मोहल्ला|city|town|basti|ward_no"),
    ("ADDRESS", r"address\w*|addr|street|house|hno|line|pata|पता|makan|landmark|colony|sector|area|residence"),
    ("DATE", r"date|dated|at|time|timestamp|tithi|तारीख|तिथि|admitted|discharged|collected|registered|on|"
             r"period|start|end|issued|effective|recorded|authored"),
]
FIELD_RX = [(k, re.compile(rf"(?:{p})", re.I)) for k, p in FIELD_RULES]


def key_tokens(key: str) -> list[str]:
    k = re.sub(r"([a-z])([A-Z])", r"\1 \2", key)
    return [t for t in re.split(rf"[^0-9A-Za-z{DEVA}]+", k.lower()) if t]


_DATE_TOK = re.compile(r"date|dated|tithi|तारीख|तिथि|dt", re.I)


def classify_key(key: str) -> str | None:
    toks = key_tokens(key)
    joined = "".join(toks)
    if FIELD_RX[7][1].fullmatch(joined) or any(FIELD_RX[7][1].fullmatch(t) for t in toks):
        return "DOB"
    if any(_DATE_TOK.fullmatch(t) for t in toks):
        return "DATE"
    if any(t in ("address", "addr", "pata", "पता", "residence") for t in toks):
        return "ADDRESS"
    for kind, rx in FIELD_RX:
        if any(rx.fullmatch(t) for t in toks) or rx.fullmatch(joined):
            return kind
    return None


# Labels that introduce a patient name inside free text
NAME_LABEL = re.compile(
    r"(?i)(?:patient(?:'s)?\s*name|pt\.?\s*name|name\s*of\s*(?:the\s*)?patient|patient|pt\.|naam|rogi\s*ka\s*naam|"
    r"mareez|beneficiary|name|नाम|मरीज़?\s*का\s*नाम|मरीज़?|रोगी\s*का\s*नाम|रोगी)\s*[:：\-]\s*")
ADDRESS_LABEL = re.compile(r"(?i)(?:address|addr\.?|residence|resident\s*of|r/o|पता|निवास)\s*[:：\-]\s*")
VILLAGE_LABEL = re.compile(r"(?i)(?:vill(?:age)?\.?|gaon|gram|ग्राम|गाँव|गांव|मोहल्ला|mohalla)\s*[:：\-.]?\s*")
DOB_LABEL = re.compile(r"(?i)(?:dob|d\.o\.b\.?|date\s*of\s*birth|birth\s*date|जन्म\s*(?:तिथि|तारीख)|janm\s*tithi)\s*[:：\-]?\s*")

# Clinical vocabulary used to protect spans (never PII on their own)
CLINICAL_WORDS = {
    "fever", "pain", "disease", "syndrome", "infection", "tablet", "tab", "cap", "inj", "syrup", "syp",
    "mg", "ml", "mcg", "iu", "bd", "od", "tds", "qid", "hs", "sos", "stat", "daily", "days", "weeks",
    "medicine", "surgery", "ward", "bed", "icu", "opd", "ipd", "diabetes", "hypertension", "anaemia",
    "anemia", "tuberculosis", "typhoid", "malaria", "dengue", "pneumonia", "fracture", "cataract",
}


# Medical / administrative acronyms that look like names in caps (never redact)
MED_ACRONYMS = {"tb", "dm", "dm2", "htn", "ckd", "copd", "cad", "ihd", "mi", "cva", "uti", "aki", "ards", "hiv",
                "hbsag", "hcv", "ecg", "ekg", "usg", "ct", "mri", "cbc", "lft", "kft", "rft", "esr", "crp", "rbs",
                "fbs", "ppbs", "hba1c", "icu", "nicu", "ot", "er", "opd", "ipd", "anm", "aww", "phc",
                "chc", "pmjay", "abha", "uhid", "mrn", "bp", "spo2", "ors", "iv", "im", "sos", "bd", "od", "tds",
                "na", "nil", "ncd", "dengue", "covid"}

# Common Indian surnames / family names (written for this project; used ONLY as a context cue:
# "Capitalised-word + known surname" is treated as a person name).
SURNAMES = set("""
agarwal aggarwal ahmad ahmed alam ali ansari arora awasthi bajpai bajwa banerjee bano begum bhardwaj bhatt bhatia
bose chaudhary chaudhari chauhan chopra das dasgupta desai dixit dubey dwivedi fernandes gandhi garg ghosh gill goel
gupta haider hussain iyer jain jaiswal jha joshi kapoor kaur khan khanna khatri kulkarni kumari kushwaha lal lodhi
malhotra masih mehta mishra mittal mukherjee nair nambiar naqvi nishad pandey patel pathak pillai prajapati qadri
qureshi rai rajput rana rao rathore rawat reddy rizvi saxena sen sengupta shah sharma shaikh shukla siddiqui singh
sinha solanki srivastava sahu tiwari tripathi trivedi upadhyay verma yadav zaidi chaturvedi maurya kashyap kohli
sethi sood bisht negi rawal thakur thakkar parmar chawla bhatnagar mathur nigam kesarwani gautam jatav valmiki
paswan manjhi mahto kurmi pal baghel tomar sengar bundela bhadauria sisodia ranawat shekhawat rathod chavan pawar
jadhav shinde patil deshmukh gaikwad more naik menon panicker kurup warrier namboodiri iyengar subramanian krishnan
ramachandran venkatesh murthy gowda hegde shetty pai kamath bhat fernandes dsouza dcosta pereira gomes rodrigues
lobo sequeira mascarenhas francis thomas joseph varghese mathew george kurian abraham chacko cherian
""".split())
