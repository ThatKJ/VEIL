"""Language resources written for this project (no external gazetteers).

Everything here is generic Indian-language structure (labels, honorifics, kinship
markers, clinical vocabulary, a transliteration table). No practice-data patient
names are stored: patient names are harvested from each input at run time.
"""
from functools import lru_cache
import re
import unicodedata

DEVA = "\u0900-\u097F\u0980-\u09FF\u0A00-\u0A7F\u0A80-\u0AFF\u0B80-\u0DFF"

# Map Bengali (+0x80), Gurmukhi (+0x100), Gujarati (+0x180), Tamil (+0x280), Telugu (+0x300),
# Kannada (+0x380), and Malayalam (+0x400) codepoints to Devanagari
# for unified transliteration and cross-script identity skeletons.
_SCRIPT_SPECIAL = {
    "\u09CE": "त्", "\u09DC": "ड़", "\u09DD": "ढ़", "\u09DF": "य",
    "\u0A59": "ख़", "\u0A5A": "ग़", "\u0A5B": "ज़", "\u0A5C": "ड़", "\u0A5E": "फ़",
    "\u0A70": "ं", "\u0A71": "", "\u0A72": "इ", "\u0A73": "उ", "\u0A74": "ओ",
    "\u0BFA": "", "\u0B83": "ः", "\u0BB3": "ल", "\u0BB4": "ल", "\u0BB1": "र",
    "\u0C31": "र", "\u0C33": "ल", "\u0CB1": "र", "\u0CB3": "ल", "\u0CDE": "फ",
    "\u0D29": "न", "\u0D31": "र", "\u0D33": "ल", "\u0D34": "ल", "\u0D3A": "ट",
    "\u0D7A": "ण", "\u0D7B": "न", "\u0D7C": "र", "\u0D7D": "ल", "\u0D7E": "ल", "\u0D7F": "क",
    "\u0D4E": "र्",
}


def _to_deva(s: str) -> str:
    out = []
    for ch in s:
        if ch in _SCRIPT_SPECIAL:
            out.append(_SCRIPT_SPECIAL[ch])
            continue
        o = ord(ch)
        if 0x0980 <= o <= 0x09FF:
            out.append(chr(o - 0x0080))
        elif 0x0A00 <= o <= 0x0A7F:
            out.append(chr(o - 0x0100))
        elif 0x0A80 <= o <= 0x0AFF:
            out.append(chr(o - 0x0180))
        elif 0x0B80 <= o <= 0x0BFF:
            out.append(chr(o - 0x0280))
        elif 0x0C00 <= o <= 0x0C7F:
            out.append(chr(o - 0x0300))
        elif 0x0C80 <= o <= 0x0CFF:
            out.append(chr(o - 0x0380))
        elif 0x0D00 <= o <= 0x0D7F:
            out.append(chr(o - 0x0400))
        else:
            out.append(ch)
    return "".join(out)

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
    s = _to_deva(unicodedata.normalize("NFD", s))
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


_RX_NON_AZ = re.compile(r"[^a-z]")
_RX_AEIOUHY = re.compile(r"[aeiouhy]")
_RX_DUP_CHAR = re.compile(r"(.)\1+")
_RX_KEY_CAMEL = re.compile(r"([a-z])([A-Z])")
_RX_KEY_SPLIT = re.compile(rf"[^0-9A-Za-z{DEVA}]+")


@lru_cache(maxsize=16384)
def skel(token: str) -> str:
    """Script- and spelling-tolerant key for one name token (Latin or Indic)."""
    t = token.strip(".").lower()
    if any("\u0900" <= c <= "\u0DFF" for c in t):
        t = deva_to_latin(t)
    t = _RX_NON_AZ.sub("", t)
    t = _ALIASES.get(t, t)
    if not t:
        return ""
    for a, b in (("chh", "c"), ("ph", "f"), ("bh", "b"), ("th", "t"), ("dh", "d"), ("kh", "k"),
                 ("gh", "g"), ("sh", "s"), ("ch", "c"), ("jh", "j"), ("w", "v"), ("z", "j"),
                 ("q", "k"), ("x", "ks"), ("ee", "i"), ("oo", "u")):
        t = t.replace(a, b)
    head, rest = t[0], _RX_AEIOUHY.sub("", t[1:])
    return _RX_DUP_CHAR.sub(r"\1", head + rest)


# ---------------------------------------------------------------- name structure
HONORIFIC_AFTER = r"(?:ji|jee|sahab|saheb|sahib|didi|bhai|bhaiya|ben|bai|bibi|amma|baba|paaji|kaka|bhau|tai|dada|dadi|aaji|babu|chacha|chachi|chachu|mama|mami|papa|mausi|fufa|bua|nana|nani|garu|anna|akka|banna|hukum|bhaisa|apa|मैडम|जी|साहब|दीदी|भाई|बहन)"
HONORIFIC_BEFORE = r"(?:Shri|Sri|Smt\.?|Shrimati|Kumari|Km\.?|Mr\.?|Mrs\.?|Ms\.?|Miss|Sh\.?|Late|Baby|Master|श्रीमान|श्री|श्रीमती|सुश्री|कुमारी|स्व\.?|सौ\.?|कै\.?|बीबी|रोगी|मरीज़|मरीज|রোগী)"
GENERIC_NAME_TOKENS = {"devi", "kumar", "kumari", "md", "mohd", "ji", "bai", "bibi", "begum", "lal", "ram",
                       "prasad", "singh", "kaur", "shri", "shriman", "smt", "sahab", "saheb", "didi", "bhai", "ben",
                       "kaka", "paaji", "bhau", "tai", "dada", "aaji", "babu", "chacha", "chachaji", "babuji",
                       "bhaiya", "amma", "garu", "anna", "akka", "sir", "banna", "hukum", "bhaisa", "da", "di", "apa",
                       "देवी", "कुमार", "कुमारी", "जी", "श्री", "श्रीमान", "श्रीमती", "बीबी"}
SURNAME_GENERICS = {"devi", "kumar", "kumari", "begum", "bibi", "bai", "singh", "kaur", "lal", "ram", "prasad",
                    "देवी", "कुमार", "कुमारी", "बीबी"}

KIN = r"(?:S/O|D/O|W/O|F/O|M/O|(?<![A-Za-z]/)C/O|S\.O\.|D\.O\.|W\.O\.|Son of|Daughter of|Wife of|Husband of|Father|Mother|Husband|Wife|Guardian|Attendant|Dikri|Patni|Puttar|Vali|पुत्री|पुत्र|पत्नी|पति|पिता|माता|बेटा|बेटी|पुत्तर|धी|घरवाली|मुलगी|मुलगा|नवरा)"

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
    ("PHONE", r"phone\w*|durawani|dooravani|ph|phno|mobile\w*|mobail|mob|mo|contact\w*|tel|telephone|whatsapp|cell|मोबाइल|फोन|फ़ोन|sampark|samparkam|fon|phon|telecom|भ्रमणध्वनी"),
    ("FAMILY_ID", r"ration\w*|bpl\w*|familyid|kasp\w*|chirayu\w*|ppp\w*"),
    ("INSURANCE", r"pmjay\w*|insur\w*|policy\w*|ayushman|beema|बीमा|claimid|memberid|cardno|scheme"),
    ("MRN", r"uhid\w*|mrn|mrno|patientid|patid|pid|regno|registration|regn?|panjikaran|पंजीकरण|पंजीयन|ipd\w*|opdno|opno|opipno|opip|opnambar|ipnambar|adm\w*(?:no|id)|admissionno|admissionid|crn|crno|"
            r"recordno|caseno|ipno|identifier|patientref|patref|refno|mr|नोंदणी"),
    ("DOB", r"dob|birth\w*|birthdate|janm|janam|huttida|huttidadinanka|jonmo|janmo|jonmotarikh|janana|jananam|जन्म|dateofbirth|dtb"),
    ("PIN", r"pin|pincode|zip|zipcode|postal\w*|postcode|पिन|पिनकोड"),
    ("REL_NAME", r"relative\w*|guardian\w*|father\w*|husband\w*|mother\w*|wife|spouse|attendant\w*|kin|vali|tande|ganda|tandegand|deuta|swami|pitri|bandhu|bandhuperu|rakshithav|"
                 r"pita|pati|पिता|पति|संबंधी|अभिभावक|nok|parent\w*|caller|callername|visitor\w*|witness\w*|"
                 r"informant|escort|contactperson|requester|applicant|claimant|nominee|sender|forwardedby|mergedfrom|"
                 r"broughtby|accompanied\w*|consenter|signatory|gdn|babuji|marad|mehraru|bhatar|baap|aai|vadil|vyakti|vyaktiyon|vyaktinaam|aagantuk|gawah|sakshi|parijan"),
    ("RELATION", r"relation|rel|relationship|रिश्ता|sambandh|bandham|relation_type"),
    ("DOCTOR", r"doctor\w*|dr|vaidyan|consultant\w*|physician\w*|surgeon\w*|referr\w*|referred|attending|treating|"
               r"careteam|team|teams|nurses?|nursing_staff|roster|dutyroster|rota|anaesthetist\w*|intern\w*|resident_doctor|"
               r"seenby|assistedby|careprovider\w*|attendingstaff|bharnewala|enteredby|filledby|collectedby|updatedby|sahayak|pariseedhichathu|reportkarta|"
               r"nurse|staff|clerk|exportedby|practitioner|performer|author|signedby|verifiedby"),
    ("SAFE", r"aushadhi|aushadh|lakshanam|pani|chuma|rogam|marunnu|parathi|veekkam|dawa|dawai|oushadha|vaidyakiya|roganirnaya|pariksha|dooru|hospital|facility|lab|department|dept|specialty|speciality|ward|bed|"
             r"diagnos\w*|icd\w*|condition|complaint\w*|history|procedure\w*|package\w*|drug\w*|medicin\w*|"
             r"medication\w*|dose|dosage|test\w*|loinc|result\w*|value|unit\w*|range|amount\w*|status|vital\w*|"
             r"bp|pulse|temp\w*|spo2|weight\w*|height\w*|bmi|rbs|gender|sex|ling|लिंग|tehsil|तहसील|district|"
             r"distt|jila|jillo|जिला|ज़िला|zila|state|visitid|bill\w*|panel\w*|schema|system|type|code|display|frequency|"
             r"route|duration|advice|notes?|remarks?|comment\w*|summary|course|investigation\w*|finding\w*|khana|keemat|analyte|parameter"),
    ("NAME", r"name|naam|hesaru|peru|rugir|rugi|rogir|नाम|नाँव|nm|naav|nav|नाव|रुग्ण|रुग्णाचे|रुग्णनाव|patient|pt|beneficiary|labharthi|लाभार्थी|insured|rogi|dardi|daradi|client|"
             r"मरीज|मरीज़|रोगी|નામ|દર્દી|ਨਾਮ|রোগী|first|last|given|family|"
             r"surname|fullname|firstname|lastname|middle|local|alias"),
    ("AGE", r"age|umar|umr|umra|umir|vayassu|vayasu|prayam|boyos|boyosh|bayas|bayos|आयु|उम्र|उमर|उमिर|ageyears|yrs|yr|vaya|वय"),
    ("VILLAGE", r"village|gaon|gaanv|gam|gram|graan|garan|ooru|desam|desham|taluk|thaluk|panchayat\w*|mupo|mohalla|locality|ग्राम|गाँव|गांव|पिंड|मोहल्ला|city|town|basti|ward_no"),
    ("ADDRESS", r"address\w*|addr|street|house|hno|houseno|door|doorno|melvilasam|vilasam|vilaasa|vilasa|line|pata|पता|makan|landmark|colony|sector|area|residence|sarnamu|rihaish|रिहाइश|thikana|ठिकाना|ghar|makaan|kothi|tola|tolla|haveli|ghar_no|gharno|thikona|thikonna"),
    ("DATE", r"date|dated|at|time|timestamp|tithi|theeyathi|theeyati|तारीख|तिथि|tarikh|nondh|dakhal|raja|din|aail|admission|admitted|discharged|collected|registered|on|"
             r"period|start|end|issued|effective|recorded|authored|lastupdated|updated|created|दाखला|रिलीज़|सुट्टी"),
]
FIELD_RX = [(k, re.compile(rf"(?:{p})", re.I)) for k, p in FIELD_RULES]
_DOB_RX = dict(FIELD_RX)["DOB"]


@lru_cache(maxsize=16384)
def key_tokens(key: str) -> tuple[str, ...]:
    k = _RX_KEY_CAMEL.sub(r"\1 \2", key)
    return tuple(t for t in _RX_KEY_SPLIT.split(k.lower()) if t)


_DATE_TOK = re.compile(r"date|dated|dinanka|tithi|तारीख|तिथि|dt|lastupdated|updated|timestamp", re.I)


@lru_cache(maxsize=16384)
def classify_key(key: str) -> str | None:
    toks = key_tokens(key)
    joined = "".join(toks)
    if _DOB_RX.fullmatch(joined) or any(_DOB_RX.fullmatch(t) for t in toks):
        return "DOB"
    if _DATE_TOK.fullmatch(joined) or any(_DATE_TOK.fullmatch(t) for t in toks):
        return "DATE"
    if toks == ("op",):
        return "MRN"
    if any(t in ("address", "addr", "pata", "पता", "residence", "house", "vilasam", "melvilasam") for t in toks):
        return "ADDRESS"
    for kind, rx in FIELD_RX:
        if any(rx.fullmatch(t) for t in toks) or rx.fullmatch(joined):
            return kind
    return None


# Labels that introduce a patient name inside free text
NAME_LABEL = re.compile(
    rf"(?i)(?:^|(?<=[\s,;|(\[]))(?:patient(?:'s)?\s*name|pt\.?\s*name|name\s*of\s*(?:the\s*)?patient|patient|pt\.|"
    rf"dardi(?:\s*nu\s*naam)?|naam|rogi\s*ka\s*naam|mareez|beneficiary|labharthi|name|nm\.?|"
    rf"नाम|नाँव|रुग्णाचे\s*नाव|रुग्ण\s*नाव|लाभार्थी|नाव|मरीज़?\s*(?:का|दा)\s*नाम|मरीज़?|रोगी\s*(?:का|दा)?\s*नाम|रोगी|ਨਾਮ|রোগী|രോഗി|പേര്)\s*[:：=\-]+\s*")
ADDRESS_LABEL = re.compile(
    r"(?i)(?:^|(?<=[\s,;|(\[]))(?:(?:address|addr\.?|residence|thamasa\s*sthalam|"
    r"patta|sarnamu|rihaish|thikana|vilasam|melvilasam|पता|पत्ता|राहणार|मुक्काम|निवास|निवासी|रिहाइश|ठिकाना|വിലാസം)\s*[:：\-]+\s*"
    r"|(?:resident\s*of|residing\s*at|r/o|nivasi|niwasi|rehne\s*wala)\s*[:：\-]*\s*(?=(?-i:[A-Z0-9#\u0900-\u097F])))")
VILLAGE_LABEL = re.compile(r"(?i)(?:^|(?<=[\s,;|(\[]))(?:vill(?:age)?\.?|gaon|gam|gram|ग्राम|गाँव|गांव|पिंड|मोहल्ला|mohalla)\s*[:：\-.]?\s*")
DOB_LABEL = re.compile(r"(?i)(?:^|(?<=[\s,;|(\[]))(?:dob|d\.o\.b\.?|date\s*of\s*birth|birth\s*date|जन्म\s*(?:तिथि|तारीख)?|janam(?:\s*(?:tithi|tarikh|din))?|janm\s*(?:tithi|tarikh))\s*[:：\-]+\s*")

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
vohra memon makwana brar sandhu biswas deshmukh kulkarni wankhede bhoyar kharwar ojha gond mulla pathan
manjhi paswan sahni mandal rajak bhagat bhat
""".split())
