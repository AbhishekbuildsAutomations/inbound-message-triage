"""
Business rules for the triage service.

This file is plain data on purpose: no logic, no AI. If you want to know
"why did message X go to team Y?" or "why did the bot say that?", the answer
is in one of these tables. The model only *describes* a message; these tables
*decide* what happens.
"""

# ---------------------------------------------------------------------------
# The six things that can happen to a message, from most to least cautious.
# When one message contains several requests, the MOST cautious one wins.
# In every case the customer gets an immediate reply. What differs is whether
# a human is called in, and how urgently.
# ---------------------------------------------------------------------------
ACTIONS_BY_CAUTION = [
    "escalate",        # risk or money: bot acknowledges, a human takes over with priority
    "route_internal",  # not a customer (vendor, job seeker, wholesale buyer): bot acknowledges, right team is called
    "handoff",         # bot acknowledges and collects details, a team member does the actual work
    "ask_customer",    # bot asks one question; no human needed until the answer comes
    "auto_reply",      # bot answers fully from the brand facts file
    "thank_and_log",   # praise: bot says thanks, nothing else to do
]

# Actions where a human must do something. For the rest the bot is done.
HUMAN_ACTIONS = {"escalate", "route_internal", "handoff"}

# "frontline" is replaced by the brand's own first-line team (see below).
FRONTLINE_BY_BRAND = {
    "vitalis-wellness": "support",
    "hair-studio": "salon_front_desk",
    "voyage-travel": "travel_ops",
}
DEFAULT_OWNER = "support"  # used when the brand is unknown

KNOWN_CHANNELS = {"whatsapp", "email", "instagram", "telegram"}  # telegram = our test bench

# ---------------------------------------------------------------------------
# Routing table: intent -> (default action, owner, entity we need to act on it)
# The model must pick intents from exactly this list.
# ---------------------------------------------------------------------------
INTENT_RULES = {
    # intent                     action            owner         needs
    "general_question":         ("auto_reply",     "frontline",  None),
    "positive_feedback":        ("thank_and_log",  "frontline",  None),
    "order_status":             ("handoff",        "support",    "order_id"),
    "wrong_or_damaged_item":    ("handoff",        "support",    "order_id"),
    "new_order":                ("handoff",        "sales",      None),
    "ready_to_buy":             ("handoff",        "sales",      None),
    "sales_enquiry":            ("handoff",        "frontline",  None),
    "booking_new":              ("handoff",        "frontline",  None),
    "booking_change":           ("handoff",        "frontline",  None),
    "booking_cancel":           ("handoff",        "frontline",  None),
    "subscription_cancel":      ("handoff",        "billing",    None),
    "retention_offer_accepted": ("handoff",        "billing",    None),
    "marketing_unsubscribe":    ("handoff",        "support",    None),
    "complaint":                ("handoff",        "frontline",  None),
    # Money moves -> always a human with priority.
    "refund_request":           ("escalate",       "billing",    "order_id"),
    "billing_dispute":          ("escalate",       "billing",    None),
    # People in trouble or asking for medical advice -> always a human with priority.
    "travel_disruption":        ("escalate",       "emergency_on_call", None),
    "medical_question":         ("escalate",       "support",    None),
    # Not customers.
    "wholesale_enquiry":        ("route_internal", "sales",      None),
    "vendor_invoice":           ("route_internal", "finance",    None),
    "job_application":          ("route_internal", "hr",         None),
    # The model could not tell what the person wants.
    "unclear":                  ("ask_customer",   "frontline",  None),
}

# ---------------------------------------------------------------------------
# Urgency. The model suggests one; these floors can only raise it.
# Anything involving time (shipping, rescheduling), money or a warm lead is
# at least "high". Health and stranded travellers are "critical".
# ---------------------------------------------------------------------------
URGENCY_ORDER = ["low", "normal", "high", "critical"]
MIN_URGENCY_BY_INTENT = {
    "order_status": "high",
    "wrong_or_damaged_item": "high",
    "booking_new": "high",
    "booking_change": "high",
    "booking_cancel": "high",
    "sales_enquiry": "high",
    "ready_to_buy": "high",
    "new_order": "high",
    "wholesale_enquiry": "high",
    "refund_request": "high",
    "billing_dispute": "high",
    "travel_disruption": "critical",
    "medical_question": "critical",
}
MIN_URGENCY_BY_FLAG = {
    "medical": "critical",
    "safety_urgent": "critical",
    "self_harm": "critical",
    "payment_dispute": "high",
    "legal_threat": "high",
    "product_safety": "high",
}

# ---------------------------------------------------------------------------
# Risk flags.
# HARD flags force "escalate" no matter what the intent is.
# SOFT flags mean a human must be involved (at least "handoff").
# ---------------------------------------------------------------------------
HARD_FLAGS = {
    "medical",            # health, dosage or drug-interaction question
    "payment_dispute",    # double charge, chargeback or bank threat
    "injection_attempt",  # text that tries to give the system instructions
    "safety_urgent",      # someone stranded, in danger or needing a call now
    "legal_threat",       # lawyer, court, regulator, consumer forum
    "self_harm",          # the sender may hurt themselves
    "abusive",            # threats or abuse aimed at staff
    "data_request",       # asks for someone else's details or internal data
}
SOFT_FLAGS = {
    "possible_fraud",        # e.g. unknown invoice with new bank details
    "product_safety",        # broken seal, wrong dosage
    "accessibility",         # wheelchair, elderly traveller
    "attachment_mentioned",  # we cannot see attachments, a human must look
    "encoded_content",       # message hides text in base64 / hex
    "truncated",             # message was too long and got cut
    "unknown_brand",         # brand not in FRONTLINE_BY_BRAND
    "unknown_channel",       # channel not in KNOWN_CHANNELS
}

# Some flags also change WHO should look at the message.
FLAG_OWNER = {
    "injection_attempt": "support",          # treat as a security review
    "safety_urgent": "emergency_on_call",
    "self_harm": "emergency_on_call",
}

# ---------------------------------------------------------------------------
# Confidence. The bot fully handles a message alone only at or above this.
# 0.7 is a starting point, not a measured optimum: with real traffic we would
# tune it against the "wrong call" corrections humans make.
# ---------------------------------------------------------------------------
CONFIDENCE_THRESHOLD = 0.7
MISSING_ENTITY_PENALTY = 0.15  # e.g. "where is my order?" with no order ID
MANY_INTENTS_PENALTY = 0.10    # applied when a message has more than 2 intents
MAX_INTENTS_FOR_AUTO = 2       # more requests than this -> a human reads it

# ---------------------------------------------------------------------------
# Fixed replies. These are written by us, not by the model, for the cases
# where the wording matters too much to leave to a model.
# ---------------------------------------------------------------------------
REPLY_UNREADABLE = (
    "Sorry, we couldn't read your last message. "
    "Could you type what you need help with?"
)
REPLY_NO_CONTEXT = "Thanks for getting in touch. How can we help you today?"

# Fallback when the model's own reply is missing or fails the output gate.
REPLY_HOLDING = (
    "Thank you for your message. Someone from our team will be with you shortly."
)
REPLY_HOLDING_URGENT = (
    "Thank you for telling us. I've flagged this to our team as urgent and "
    "someone will be with you as soon as possible."
)
REPLY_INJECTION_WARNING = (
    "This is your first and final warning. Trying this again could result in "
    "a permanent ban from the platform. If you need any help, I can get the "
    "support team here."
)
REPLY_BLOCKED = (
    "This conversation has been restricted and passed to our team for review."
)
REPLY_MEDICAL = (
    "Thank you for checking before you start. We can't give medical advice "
    "here, so if you are unsure about the dosage or about taking this with "
    "your medication, please confirm with your doctor. I've flagged this as "
    "urgent and someone from our team will be with you as soon as possible."
)
REPLY_SLOW_DOWN = "You're sending messages very quickly. Please wait a minute and try again."

# Retention: before a subscription is cancelled, the bot offers this once.
RETENTION_DISCOUNT_PERCENT = 20
REPLY_RETENTION_OFFER = (
    "We're sorry to see you go. Before we cancel, would you like "
    f"{RETENTION_DISCOUNT_PERCENT}% off your next billing instead? "
    "Reply YES to keep your subscription with the discount, or NO and we'll "
    "go ahead with the cancellation."
)
REPLY_RETENTION_ACCEPTED = (
    f"Great, thank you for staying with us. I've asked our billing team to "
    f"apply {RETENTION_DISCOUNT_PERCENT}% off your next billing, and a team "
    "member will confirm it with you shortly."
)

# ---------------------------------------------------------------------------
# Limits
# ---------------------------------------------------------------------------
MAX_TEXT_CHARS = 4000        # longer messages are cut here to keep cost bounded
MAX_REPLY_CHARS = 700        # a model-written reply longer than this is rejected
MAX_MESSAGES_PER_MINUTE = 8  # per chat, in the bot (slows down trial-and-error attacks)
INJECTION_STRIKES_BEFORE_BLOCK = 2  # first attempt: warning. second: chat restricted
