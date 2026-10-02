"""
Guardrails that run in plain code, before and after the model.

  scan_input(text)   looks for prompt-injection in the customer's text,
                     including text that is disguised (spaced-out letters,
                     look-alike characters, leetspeak, scrambled words,
                     base64 / hex / ROT13).
  check_reply(...)   the output gate. Looks at a reply the MODEL wrote before
                     it is sent, and rejects it if it commits the company to
                     anything, states a price we never gave it, contains a
                     link, or leaks the prompt.

Honest limit: pattern checks cannot catch every attack. Research on adaptive
attackers shows every detector can be bypassed with enough tries. So these
checks are one layer. The real protection is the design: the model cannot
take any action, and nothing it writes is sent without passing check_reply().

Sources for the attack types covered here: OWASP "LLM Prompt Injection
Prevention Cheat Sheet", promptfoo red-team strategies, and "The Attacker
Moves Second" (Nasr et al., 2025).
"""

import base64
import binascii
import codecs
import re
import unicodedata

import rules

# ---------------------------------------------------------------------------
# Making disguised text readable
# ---------------------------------------------------------------------------

# Letters from other alphabets that look like Latin letters (Cyrillic, Greek).
LOOKALIKES = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x",
    "і": "i", "ј": "j", "ѕ": "s", "ԁ": "d", "һ": "h", "к": "k", "м": "m",
    "т": "t", "в": "b", "н": "h", "ο": "o", "α": "a", "ε": "e", "ι": "i",
    "ρ": "p", "τ": "t", "υ": "u", "ν": "v", "κ": "k",
})
# Leetspeak: digits and symbols standing in for letters ("1gn0re").
LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t"})

# Words attackers scramble ("ignroe prevoius instrcutions") to dodge filters.
KEYWORDS = [
    "ignore", "disregard", "forget", "override", "bypass", "previous", "prior",
    "instructions", "instruction", "system", "prompt", "developer",
    "administrator", "jailbreak", "restrictions", "pretend", "reveal",
]


def unscramble(word):
    """If word is a keyword with its middle letters shuffled, return the keyword."""
    if len(word) < 5:
        return word
    for keyword in KEYWORDS:
        if (len(word) == len(keyword) and word[0] == keyword[0] and word[-1] == keyword[-1]
                and sorted(word) == sorted(keyword)):
            return keyword
    return word


def readable(text):
    """Return a lowercase copy of text with the common disguises removed."""
    text = unicodedata.normalize("NFKC", text)  # full-width, fancy fonts -> plain letters
    # Drop invisible characters (zero-width spaces, direction marks, hidden "tag" letters).
    text = "".join(ch for ch in text if unicodedata.category(ch) not in ("Cf", "Cc") or ch in "\n\t")
    text = text.lower().translate(LOOKALIKES)
    # "i g n o r e" or "i.g.n.o.r.e" -> "ignore": join runs of single characters.
    text = re.sub(r"\b(?:\w[\s.\-_*|/]{1,3}){3,}\w\b",
                  lambda match: re.sub(r"[\s.\-_*|/]", "", match.group(0)), text)
    words = []
    for word in re.findall(r"\w+|\W+", text):  # keep punctuation between the words
        if word[0].isalnum() or word[0] == "_":
            if any(ch.isalpha() for ch in word) and any(ch in "013457" for ch in word):
                word = word.translate(LEET)    # only words that mix letters and digits
            word = unscramble(word)
        words.append(word)
    return " ".join("".join(words).split())


def strip_invisible(text):
    """Remove invisible characters. Zero-width joiners stay: Hindi and emoji need them."""
    return "".join(ch for ch in text
                   if unicodedata.category(ch) != "Cf" or ch in "\u200c\u200d")


def decoded_parts(text):
    """Find hidden text: base64 chunks, hex chunks and invisible "tag" letters."""
    found = []
    # Unicode tag characters are invisible copies of ASCII letters. A person
    # sees nothing; a model can still read them ("ASCII smuggling").
    tags = "".join(chr(ord(ch) - 0xE0000) for ch in text if 0xE0020 <= ord(ch) <= 0xE007E)
    if tags:
        found.append(tags)
    for chunk in re.findall(r"[A-Za-z0-9+/=_-]{16,}", text):
        try:
            padded = chunk.replace("-", "+").replace("_", "/")
            padded += "=" * (-len(padded) % 4)
            plain = base64.b64decode(padded, validate=True).decode("utf-8")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            continue
        # Real hidden text is mostly letters and spaces; random IDs are not.
        if len(plain) >= 8 and sum(ch.isalpha() or ch == " " for ch in plain) / len(plain) > 0.8:
            found.append(plain)
    for chunk in re.findall(r"\b(?:[0-9a-fA-F]{2}){8,}\b", text):
        try:
            plain = bytes.fromhex(chunk).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            continue
        if sum(ch.isalpha() or ch == " " for ch in plain) / len(plain) > 0.8:
            found.append(plain)
    return found


# ---------------------------------------------------------------------------
# Injection patterns
# A space in a pattern means "any gap": spaces, punctuation or nothing at all.
# ---------------------------------------------------------------------------
INJECTION_PATTERNS = [
    # 1. Overriding instructions. A qualifier such as "all", "previous" or
    #    "your" is required, so "I always forget the instructions" is not a hit.
    r"(ignore|disregard|forget|override|bypass|skip|drop) (the |my |these |those )*"
    r"(all|any|your|every|previous|prior|above|earlier|preceding|system|initial|original|existing|safety) (\w+ ){0,2}?"
    r"(instructions?|prompts?|rules|guidelines|directives|programming|training|restrictions|guardrails|filters)",
    r"(ignore|disregard|forget) (everything|all|anything) (above|you were told|you have been told|you know)",
    r"(new|updated|revised|real|actual) (system )?(instructions?|prompt) (are|is|follow|below|:)",
    r"from now on (you|u) (are|will|must|should|can)",
    r"you are no longer",
    r"you are now (in |an? |the )?(\w+ mode|dan|unrestricted|jailbroken|free|ai|assistant|bot|model|admin|agent)",
    # 2. Fake authority and special modes
    r"system (prompt|override|command|instructions?)",
    r"(administrator|admin|developer|dev|debug|god|sudo|root|dan|jailbreak|unrestricted) mode",
    r"do anything now",
    r"jailbr(eak|oken)",
    r"(without|remove|disable|turn off) (any |all |your )+(restrictions|filters|limitations|guardrails|safety)",
    r"(i am|i'm|im|this is|speaking as) your (developer|administrator|admin|creator|programmer|owner|boss|manager)",
    r"(openai|anthropic) (staff|team|employee|engineer|here)",
    r"(authorized|authorised|pre ?approved|approved) by (the )?(admin|administrator|management|developer|system|ceo|owner)",
    r"(override|admin) code",
    r"(security|penetration|pen|red team) (test|audit|exercise)",
    # 3. Role-play
    r"pretend (to be|you are|you're|that you)",
    r"act as (if you are |if you were )?(an? |the |my )?(ai|admin|administrator|assistant|agent|developer|system|manager|supervisor|human|refund)",
    r"(roleplay|role play) as",
    r"stay in character",
    r"(lets|let's|we will|we'll) play a game",
    r"in this (hypothetical|fictional|imaginary) (scenario|world|story)",
    # 4. Dictating what the bot must say or do
    r"(reply|respond|answer|say|print|output|write|type) (back )?(only |just |exactly |with |the word |the phrase )*[\"'“‘]?(confirmed|approved|granted)\b",
    r"repeat after me",
    r"(end|start|begin|finish) (each|every|all|your) (reply|response|message|answer|sentence)s? with",
    r"legally binding",
    r"no takesies",
    r"(do not|don't|dont|never|must not|should not) (escalate|flag|route) ",
    r"(do not|don't|dont|never|must not|should not) (involve|loop in|notify|tell|alert|forward (this |it )?to) (a |the |any )?(human|agent|staff|team|manager|supervisor|person)",
    r"without (escalating|escalation|(a |any )?human)",
    r"mark (this|me|my|the) (customer|account|user|ticket|profile|message|order)? ?(as )?(vip|approved|verified|refunded)",
    r"(grant|give) (me |us )?(admin|vip|full|elevated|root) (access|status|tier|privileges|rights)",
    r"(update|change|rewrite|modify) your (rules|instructions|prompt|guidelines|programming|settings)",
    # 5. Pulling out the prompt
    r"your (initial|original|hidden|exact|secret|internal|full|entire) (prompt|instructions|rules|guidelines|configuration|directives)",
    r"(reveal|print|repeat|leak|dump|show|output) (me |us )?(your|the) (prompt|instructions)",
    r"repeat (the|all|everything|every) (text|words|word|thing|message)s? (above|before|so far)",
    r"what were you told",
    # 6. Fake structure: pretending to be a system or assistant turn
    r"</?\s*(system|assistant|instructions?|admin|developer|im_start|im_end|inst|sys)\s*>",
    r"\[\s*/?\s*(system|inst|admin|assistant|sys)\s*\]",
    r"<\|.{0,20}\|>",
    r"#{2,}\s*(system|instructions?|admin|assistant)",
    r"(^|[.!?\n])\s*(system|assistant|developer|admin)( notice| message| alert| update)?\s*:",
    r"\"role\"\s*:\s*\"(system|assistant|developer)\"",
    r"(begin|end) (of )?(system|admin|developer) (message|prompt|instructions?)",
    r"end of (customer|user) (message|input|text)",
    # 7. Other languages (Hindi, Hinglish, Spanish, French, German)
    r"(pichle|pichhle|pehle|purane|upar)( ke| wale| diye gaye)? (nirdesh|instructions?|rules|niyam)(on)?( ko)? (bhool|ignore|nazarandaz|andekha|chhod)",
    r"(nirdesh|instructions?)(on)? ko (bhool|ignore|nazarandaz|andekha)",
    r"(sab|saare|sabhi) (nirdesh|niyam|instructions?) (bhool|ignore)",
    r"पिछले (सभी )?निर्देश(ों)? (को )?(अनदेखा|भूल|नज़रअंदाज़)",
    r"निर्देश(ों)? को (अनदेखा|भूल|नज़रअंदाज़)",
    r"ignora (todas )?(las )?instrucciones",
    r"ignore[rz]? (toutes )?(les )?instructions",
    r"ignoriere (alle )?(vorherigen |bisherigen )?anweisungen",
]
INJECTION = re.compile("|".join(f"(?:{p})" for p in INJECTION_PATTERNS).replace(" ", r"[\W_]*"),
                       re.IGNORECASE)


def scan_input(text):
    """
    Look for injection in text. Returns (injection_found, encoded_found, evidence).
    The text is checked as written, with disguises removed, ROT13-decoded,
    and with any base64 / hex chunks decoded.
    """
    hidden = decoded_parts(text)
    versions = [text, readable(text)] + [readable(part) for part in hidden]
    versions.append(codecs.decode(readable(text), "rot13"))
    for version in versions:
        match = INJECTION.search(version)
        if match:
            return True, bool(hidden), match.group(0)[:80]
    return False, bool(hidden), None


# ---------------------------------------------------------------------------
# The output gate
# ---------------------------------------------------------------------------
REPLY_BLOCKLIST = [
    # Commitments only a human may make.
    (r"refund (has been|is|was|will be) (approved|processed|issued|initiated|granted|confirmed|credited)", "promises a refund"),
    (r"(we|i)('ll| will| have|'ve| can) (refund|reimburse|credit|compensate|waive)", "promises money"),
    (r"(it|this|that)('s| has| is| was) (been )?(now )?(cancelled|canceled|rescheduled|rebooked|booked|upgraded|approved|refunded|processed|replaced)\b", "claims an action was done"),
    (r"(i|we)('ve| have)? (cancelled|canceled|rescheduled|rebooked|booked|approved|upgraded|processed)", "claims an action was done"),
    (r"your (new )?(booking|appointment|order|subscription|refund|payment|request|flight|ticket|slot|membership|account|replacement) (is|has been|is now) (confirmed|approved|cancelled|canceled|changed|processed|rescheduled|rebooked|upgraded|refunded|booked)", "confirms an outcome"),
    (r"(?<!be )\bconfirmed\b(?! by| with| after| once| before)", "confirms something"),
    (r"legally binding|guarantee|no (extra |additional |change )?(fee|charge|cost)s?\b|free of charge|for free|\bvip\b", "makes a commitment"),
    # Medical advice.
    (r"safe (to|for) (take|use|consume|combine)|safe with|recommended (dose|dosage)|side effects? (are|is|include)|you (can|should|may) (safely )?take (it|this|them|both|the \w+) (with|along|together|daily|twice)", "gives medical advice"),
    # Links (we never send links; payment links come from a named consultant).
    (r"https?://|www\.|\bt\.me/|\b[a-z0-9-]+\.(com|in|net|org|io|co)\b", "contains a link"),
    # Signs the prompt leaked or the model was steered.
    (r"untrusted|risk_flags?|brand facts|previous_messages|system prompt|my instructions|as an ai|language model|injection|administrator mode|developer mode", "leaks the prompt or echoes an attack"),
]
REPLY_BLOCKLIST = [(re.compile(pattern, re.IGNORECASE), why) for pattern, why in REPLY_BLOCKLIST]

# A money amount or percentage: "INR 6,500", "₹4500", "$1", "20%", "500 rupees".
MONEY = re.compile(r"(?:₹|\$|€|£|(?<![a-z])(?:rs\.?|inr|usd|cad))\s?(\d[\d,.]*)|(\d[\d,.]*)\s?(?:%|percent|rupees|dollars|rs\b|inr\b)",
                   re.IGNORECASE)


def check_reply(reply, facts):
    """
    Return a list of problems with a model-written reply. Empty list = safe to send.
    facts: the brand facts, the only place a money amount in a reply may come from.
    """
    problems = []
    if len(reply) > rules.MAX_REPLY_CHARS:
        problems.append("too long")
    for pattern, why in REPLY_BLOCKLIST:
        if pattern.search(reply):
            problems.append(why)
    # A price or percentage may only come from the brand facts. Not from the
    # customer's message either: "sell it to me for $1" must not be echoed back.
    allowed = {number.replace(",", "").rstrip(".")
               for number in re.findall(r"\d[\d,.]*", " ".join(facts or []))}
    for match in MONEY.finditer(reply):
        number = (match.group(1) or match.group(2)).replace(",", "").rstrip(".")
        if number not in allowed:
            problems.append(f"states an amount we never gave it ({match.group(0).strip()})")
    return sorted(set(problems))
