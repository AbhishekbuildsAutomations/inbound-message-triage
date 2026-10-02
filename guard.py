"""
Guardrails that run in plain code, before and after the model.

  scan_input(text)   looks for prompt injection in the text the model is
                     about to read, including disguised text (spaced-out
                     letters, look-alike characters, leetspeak, scrambled
                     words, base64, hex, ROT13, invisible characters).
  check_reply(...)   the output gate. Looks at a reply the MODEL wrote before
                     it is sent, and rejects it if it commits the company to
                     anything, states an amount of money, gives medical
                     advice, contains a link, or leaks the prompt.

Honest limits. Both checks are lists of patterns, so neither is complete:
  - Research on adaptive attackers shows every detector can be bypassed with
    enough tries. Detection is one layer, not the protection.
  - The output gate is a blocklist. It stops the common ways a reply can go
    wrong; it cannot prove a reply is harmless.
The protection that holds is the design: the model cannot take any action,
and a human is called for anything that involves risk or money.

Two rules keep these patterns safe to run on hostile text:
  - A pattern never repeats two things that can match the same character
    (no "catastrophic backtracking"). Letters and separators are kept as
    separate character classes for that reason.
  - Patterns are written to miss ordinary customer phrases such as "please
    ignore my previous delivery instructions". test_triage.py holds a list
    of those phrases and fails if one is flagged.

Sources for the attack types: OWASP "LLM Prompt Injection Prevention Cheat
Sheet", promptfoo red-team strategies, "The Attacker Moves Second" (2025).
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
# Leetspeak: digits standing in for letters ("1gn0re").
LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t"})

# Words attackers scramble ("ignroe prevoius instrcutions") to dodge filters.
KEYWORDS = [
    "ignore", "disregard", "forget", "override", "bypass", "previous", "prior",
    "instructions", "instruction", "system", "prompt", "developer",
    "administrator", "jailbreak", "restrictions", "pretend", "reveal",
]

# "[^\W_]" means one letter or digit, never an underscore. Separators are a
# different set of characters, so the two can never compete for the same one.
SPACED_OUT = re.compile(r"(?<![^\W_])(?:[^\W_][\s.\-_*|/]{1,3}){3,}[^\W_](?![^\W_])")


def strip_invisible(text):
    """Remove invisible and control characters. Zero-width joiners stay
    (Hindi and emoji need them), and so do ordinary line breaks and tabs."""
    return "".join(ch for ch in text
                   if unicodedata.category(ch) not in ("Cf", "Cc", "Cs") or ch in "‌‍\n\t")


def plain(text):
    """Lowercase text with fancy, invisible and look-alike characters folded
    into ordinary ones. Used on both customer text and model replies."""
    text = unicodedata.normalize("NFKC", text)  # full-width, fancy fonts -> plain letters
    text = "".join(ch for ch in text if unicodedata.category(ch) not in ("Cf", "Cc", "Cs") or ch in "\n\t")
    return text.lower().translate(LOOKALIKES)


def unscramble(word):
    """If word is a keyword with its letters shuffled (same first letter,
    same letters overall), return the keyword. "systme" -> "system"."""
    if len(word) < 5:
        return word
    for keyword in KEYWORDS:
        if len(word) == len(keyword) and word[0] == keyword[0] and sorted(word) == sorted(keyword):
            return keyword
    return word


def readable(text):
    """plain() plus the heavier un-disguising used only for the injection scan."""
    text = plain(text)
    # "i g n o r e" or "i.g.n.o.r.e" -> "ignore": join runs of single characters.
    text = SPACED_OUT.sub(lambda match: re.sub(r"[\s.\-_*|/]", "", match.group(0)), text)
    pieces = []
    for piece in re.findall(r"[^\W_]+|[\W_]+", text):  # words, and the gaps between them
        if piece[0].isalnum():
            if any(ch.isalpha() for ch in piece) and any(ch in "013457" for ch in piece):
                piece = piece.translate(LEET)  # only words that mix letters and digits
            piece = unscramble(piece)
        pieces.append(piece)
    return " ".join("".join(pieces).split())


def hidden_tags(text):
    """Unicode "tag" characters are invisible copies of ASCII letters. A person
    sees nothing; a model can read them ("ASCII smuggling"). Return what they spell."""
    return "".join(chr(ord(ch) - 0xE0000) for ch in text if 0xE0020 <= ord(ch) <= 0xE007E)


def decoded_parts(text):
    """Find base64 or hex chunks in text and return whatever readable text they hide."""
    found = []
    for chunk in re.findall(r"[A-Za-z0-9+/=_-]{16,}", text):
        try:
            padded = chunk.replace("-", "+").replace("_", "/")
            padded += "=" * (-len(padded) % 4)
            decoded = base64.b64decode(padded, validate=True).decode("utf-8")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            continue
        # Real hidden text is mostly letters and spaces; random IDs are not.
        if len(decoded) >= 8 and sum(ch.isalpha() or ch == " " for ch in decoded) / len(decoded) > 0.8:
            found.append(decoded)
    for chunk in re.findall(r"\b(?:[0-9a-fA-F]{2}){8,}\b", text):
        try:
            decoded = bytes.fromhex(chunk).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            continue
        if sum(ch.isalpha() or ch == " " for ch in decoded) / len(decoded) > 0.8:
            found.append(decoded)
    return found


# ---------------------------------------------------------------------------
# Injection patterns
# ---------------------------------------------------------------------------
# In WORD_PATTERNS a space means "any gap inside one sentence": spaces,
# commas, dashes, underscores, or nothing at all. It never crosses a full
# stop, so "I like your system. Prompt reply please" is not "system prompt".

# Words that point at the bot's own instructions rather than, say, a
# customer's delivery instructions.
Q = "(all|any|every|previous|prior|above|earlier|preceding|system|initial|original|existing|safety)"
N = "(instructions?|prompts?|rules|guidelines|directives|programming|training|restrictions|guardrails|filters)"

WORD_PATTERNS = [
    # 1. Overriding instructions. "ignore all previous instructions" is a hit;
    #    "ignore my previous delivery instructions" and "ignore the instructions" are not.
    rf"(ignore|disregard|forget|override|bypass|skip|drop) ((the|these|those|your) )?{Q} (({Q}|of|the) ){{0,4}}{N}",
    r"(ignore|disregard|forget) (everything|all|anything) (above|you were told|you have been told)",
    r"(new|updated|revised) system (instructions?|prompt)",
    r"your (new|real|actual|updated) instructions",
    r"from now on (you|u) (are (an?|the|in|no longer)|(will|must|should) (act|be|respond|answer|reply|ignore|obey|follow))",
    r"you are no longer (an?|the|bound|restricted|required|limited)",
    r"you are now (in |an? |the )?([^\W_]+ mode|dan|unrestricted|jailbroken|ai|assistant|bot|model|admin|agent)",
    # 2. Fake authority and special modes
    r"system (prompt|override|command|instructions?)",
    r"(administrator|admin|developer|dev|debug|god|sudo|root|dan|jailbreak|unrestricted) mode",
    r"do anything now",
    r"(jailbreak|jailbroken) (you|mode|prompt|the (ai|bot|assistant|model))",
    r"(remove|disable|turn off) your (restrictions|filters|limitations|guardrails|safety)",
    r"(respond|answer|reply|act|speak) without (any )?(restrictions|filters|limitations|rules)",
    r"(i am|i'm|im|this is|speaking as) your (developer|administrator|admin|creator|programmer|owner|boss)",
    r"(openai|anthropic) (staff|team|employee|engineer)",
    r"(authorized|authorised|pre ?approved|approved) by (the )?(admin|administrator|developer|system)",
    r"(override|admin) code",
    r"(this is|as part of) (an? |the )?(security|penetration|pen|red team) (test|audit|exercise)",
    # 3. Role-play
    r"pretend (to be|you are|you're|that you)",
    r"act as (if you are |if you were )?(an? |the )?(ai|admin|administrator|assistant|developer|system|supervisor|dan|refund ?bot)",
    r"(roleplay|role play) as",
    r"stay in character",
    r"(lets|let's|we will|we'll) play a game",
    r"in this (hypothetical|fictional|imaginary) (scenario|world|story)",
    # 4. Dictating what the bot must say or do
    r"(reply|respond|answer|say|print|output|write|type) (back )?((only|just|exactly|with|the word|the phrase) ){0,3}[\"'“‘]?(confirmed|approved|granted)(?![^\W_])",
    r"repeat after me",
    r"(end|start|begin|finish) (each|every|all|your) (reply|response|message|answer|sentence)s? with",
    r"(do not|don't|dont|never|must not|should not) escalate",
    r"(do not|don't|dont|never|must not|should not) (involve|loop in|notify|tell|alert|forward (this |it )?to) (an? |the |any )?(human|agent|staff|team|manager|supervisor)(?![^\W_])",
    r"without (escalating|escalation|human (review|approval|intervention|involvement)|involving (an? |any )?human)",
    r"mark (this|me|my|the) ((customer|account|user|ticket|profile|message|order) )?(as )?(vip|approved|verified)(?![^\W_])",
    r"(grant|give) (me |us )?(admin|vip|elevated|root) (access|status|tier|privileges|rights)",
    r"(update|change|rewrite|modify) your (instructions|prompt|guidelines|programming)",
    # 5. Pulling out the prompt
    r"your (initial|original|hidden|secret|internal|system) (prompt|instructions|rules|guidelines|configuration)",
    r"(reveal|leak|dump|print|repeat|show|output|share|tell) (me |us )?(your|the) (system )?prompt",
    r"(reveal|leak|dump|print|repeat) (me |us )?your instructions",
    r"repeat (the|all|everything|every) (text|words|word|thing|message)s? (above|before|so far)",
    # 6. Other languages (Hindi, Hinglish, Spanish, French, German)
    r"(pichle|pichhle|pehle|purane|upar)( ke| wale| diye gaye)? (nirdesh|instructions?|rules|niyam)(on)?( ko)? (bhool|ignore|nazarandaz|andekha|chhod)",
    r"(nirdesh|instructions?)(on)? ko (bhool|ignore|nazarandaz|andekha)",
    r"(sab|saare|sabhi) (nirdesh|niyam|instructions?) (bhool|ignore)",
    r"पिछले (सभी )?निर्देश(ों)? (को )?(अनदेखा|भूल|नज़रअंदाज़)",
    r"निर्देश(ों)? को (अनदेखा|भूल|नज़रअंदाज़)",
    r"ignora (todas )?(las )?instrucciones",
    r"ignore[rz]? (toutes )?(les )?instructions",
    r"ignoriere (alle )?(vorherigen |bisherigen )?anweisungen",
]
# Fake structure: text pretending to be a system or assistant turn.
MARKUP_PATTERNS = [
    r"</?\s*(system|assistant|instructions?|admin|developer|im_start|im_end|inst|sys)\s*>",
    r"\[\s*/?\s*(system|inst|admin|assistant|sys)\s*\]",
    r"<\|.{0,20}\|>",
    r"#{2,}\s*(system|instructions?|admin|assistant)\b",
    r"(^|[.!?\n])\s*(system|assistant|developer|admin)( notice| message| alert| update)?\s*:",
    r"\"role\"\s*:\s*\"(system|assistant|developer)\"",
    r"(begin|end) (of )?(system|admin|developer) (message|prompt|instructions?)",
    r"end of (customer|user) (message|input|text)",
]
GAP = r"(?:[^\w.!?]|_)*"  # one character class repeated; cannot backtrack badly
INJECTION = re.compile(
    "|".join(rf"(?<![^\W_])(?:{pattern})".replace(" ", GAP) for pattern in WORD_PATTERNS)
    + "|" + "|".join(f"(?:{pattern})" for pattern in MARKUP_PATTERNS),
    re.IGNORECASE,
)


def scan_input(text, hidden=""):
    """
    Look for injection in text. Returns (injection_found, encoded_found, evidence).
    text:   the cleaned message, exactly as the model would read it.
    hidden: anything invisible found in the raw message (see hidden_tags).
    The text is checked as written, with disguises removed, ROT13-decoded,
    and with any base64 or hex chunks decoded.
    """
    decoded = decoded_parts(text)
    unmasked = readable(text)
    versions = [text, unmasked, codecs.decode(unmasked, "rot13")]
    versions += [readable(part) for part in decoded + ([hidden] if hidden else [])]
    for version in versions:
        match = INJECTION.search(version)
        if match:
            return True, bool(decoded or hidden), match.group(0)[:80]
    return False, bool(decoded or hidden), None


# ---------------------------------------------------------------------------
# The output gate
# ---------------------------------------------------------------------------
REPLY_BLOCKLIST = [
    # Commitments only a human may make.
    (r"refund (has been|is|was|will be) (approved|processed|issued|initiated|granted|confirmed|credited)", "promises a refund"),
    (r"(we|i)('ll| will| have|'ve| can) (refund|reimburse|credit|compensate|waive)", "promises money"),
    (r"money back|get (a |your )?(full )?refund|(eligible|entitled) (for|to)", "promises money"),
    (r"(it|this|that)('s| has| is| was) (been )?(now )?(cancelled|canceled|rescheduled|rebooked|booked|upgraded|approved|refunded|processed|replaced)\b", "claims an action was done"),
    (r"(i|we)('ve| have)? (issued|cancelled|canceled|rescheduled|rebooked|booked|approved|upgraded|processed|refunded|applied|credited|waived)\b", "claims an action was done"),
    (r"your (new )?(booking|appointment|order|subscription|refund|payment|request|flight|ticket|slot|membership|account|replacement) (is|has been|is now) (confirmed|approved|cancelled|canceled|changed|processed|rescheduled|rebooked|upgraded|refunded|booked)", "confirms an outcome"),
    (r"(?<!be )\bconfirmed\b(?! by| with| after| once| before)", "confirms something"),
    (r"\b(approved|granted|waived|refunded|reimbursed|guaranteed?|deal|agreed|i agree|we agree)\b", "agrees to or grants something"),
    (r"legally binding|no (extra |additional |change )?(fee|charge|cost)s?\b|free of charge|for free|\bvip\b", "makes a commitment"),
    # The same in Hinglish, Hindi, Spanish, French and German (short list).
    (r"(refund|cancel|booking|approve|reschedule|discount|order)\w* (\w+ )?(ho gaya|ho gayi|ho chuka|ho chuki|kar diya|kar di|kr diya|mil jayega|mil jaega|pakka)", "claims an action was done"),
    (r"स्वीकृत|मंज़ूर|aprobado|confirmado|reembolsado|approuv[ée]|confirm[ée]e?\b|rembours[ée]|genehmigt|bestätigt|erstattet", "confirms something"),
    # Medical advice.
    (r"safe (to|for) (take|use|consume|combine)|safe with|recommended (dose|dosage)|side effects? (are|is|include)", "gives medical advice"),
    (r"\b(take|consume)\b[^.?!]{0,30}\b(\d+|one|two|three|four)\b[^.?!]{0,15}\b(capsules?|tablets?|pills?|doses?|mg|ml)\b|\b(once|twice|\d+ times|three times) (a|per) day", "gives medical advice"),
    # Links. We never send links; payment links come from a named consultant.
    (r"https?://|www\.|\b[a-z0-9-]+\.[a-z]{2,}/\S|\b[a-z0-9-]{2,}\.(com|in|net|org|io|co|xyz|ly|me|app|ai|info|biz|link|shop|site|online)\b", "contains a link"),
    # Signs the prompt leaked or the model was steered.
    (r"untrusted|risk_flags?|brand facts|previous_messages|system prompt|my instructions|as an ai|language model|injection|administrator mode|developer mode", "leaks the prompt or echoes an attack"),
]
REPLY_BLOCKLIST = [(re.compile(pattern, re.IGNORECASE), why) for pattern, why in REPLY_BLOCKLIST]

# An amount of money or a percentage: "INR 6,500", "₹4500", "$1", "20%", "450 CAD", "4,500/-".
CURRENCY = r"rs\.?|inr|usd|cad|eur|aed|gbp"
MONEY = re.compile(
    rf"(?:₹|\$|€|£|(?<![a-z])(?:{CURRENCY}))\s?(\d[\d,.]*)"
    rf"|(\d[\d,.]*)\s?(?:%|/-|(?:percent|rupees?|dollars?|euros?|pounds?|bucks|{CURRENCY})(?![a-z]))",
    re.IGNORECASE,
)
# The same spelled out: "four hundred dollars", "fifty percent".
MONEY_WORDS = re.compile(
    r"\b(one|two|three|four|five|six|seven|eight|nine|ten|twenty|thirty|forty|fifty|sixty|seventy|eighty|"
    r"ninety|hundred|thousand|lakh|crore|half)\b[\w\s-]{0,20}\b(rupees?|dollars?|percent|euros?|pounds?|bucks)\b",
    re.IGNORECASE,
)


def amounts_in(text):
    """Every money amount in text, as plain digit strings ("6,500" -> "6500")."""
    return {(a or b).replace(",", "").rstrip(".") for a, b in MONEY.findall(text)}


def check_reply(reply, facts):
    """
    Return a list of problems with a model-written reply. Empty list = may be sent.
    facts: the brand facts, the only place an amount of money in a reply may come from.
    """
    problems = []
    if len(reply) > rules.MAX_REPLY_CHARS:
        problems.append("too long")
    text = plain(reply)  # so a zero-width space or a Cyrillic letter cannot hide a word
    for pattern, why in REPLY_BLOCKLIST:
        if pattern.search(text):
            problems.append(why)
    # An amount may only be repeated from the brand facts. Not from the customer's
    # message either: "sell it to me for $1" must not be echoed back.
    extra = amounts_in(text) - amounts_in(plain(" ".join(facts or [])))
    if extra or MONEY_WORDS.search(text):
        problems.append("states an amount of money we never gave it")
    return sorted(set(problems))
