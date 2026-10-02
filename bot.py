"""
Telegram test bench for the triage brain.

  Customer side: message the bot in a private chat. /start picks the brand.
                 Every message gets an immediate reply.
  Staff side:    a Telegram group. Every decision shows up there as a card
                 with the message, what the bot understood, the urgency and
                 what the bot already told the customer.

  On a card, staff can:
    - reply to the card (normal Telegram reply) to answer the customer
    - press "Wrong call" to log that the bot decided badly

Run:  python bot.py        (needs TELEGRAM_BOT_TOKEN in .env; OPENAI_API_KEY
                            is optional, without it every message goes to a human)

The bot uses long polling: it keeps asking Telegram "anything new?", so it
runs from a laptop with no public URL or hosting.
Everything is kept in memory. Restarting the bot forgets open cards,
conversation history and blocked chats.
"""

import asyncio
import json
import os
import time
from datetime import datetime, timezone

import httpx2 as httpx  # the HTTP library the openai package already installs

import rules
from triage import DEFAULT_MODEL, HERE, load_brand_facts, load_env, make_client, triage_message

load_env()
TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
API = f"https://api.telegram.org/bot{TOKEN}/"
STAFF_FILE = HERE / "staff_chat.txt"       # remembers which group is the staff queue
CORRECTIONS = HERE / "corrections.jsonl"   # one line per "Wrong call" press

http = httpx.AsyncClient(timeout=70)       # longer than the 50s long-poll below
brand_facts = load_brand_facts()
openai_client = None                       # set in main() if a key exists

# --- in-memory state -------------------------------------------------------
staff_chat = int(STAFF_FILE.read_text()) if STAFF_FILE.exists() else None
brand_of = {}     # customer chat id -> brand they picked
history_of = {}   # customer chat id -> last few lines: {"from": "customer" or "us", "text": ...}
cards = {}        # staff card message id -> {"customer": chat id, "result": {...}}
recent = {}       # customer chat id -> times of their recent messages (rate limit)
strikes = {}      # customer chat id -> number of injection attempts
background = set()  # keeps running tasks alive until they finish

ICON = {"escalate": "🔴", "route_internal": "🟣", "handoff": "🟡",
        "ask_customer": "🔵", "auto_reply": "🟢", "thank_and_log": "🟢"}


# ---------------------------------------------------------------------------
# Talking to Telegram
# ---------------------------------------------------------------------------

async def tg(method, **params):
    """Call one Bot API method. Returns the result, or None if it failed."""
    for attempt in (1, 2):
        try:
            reply = (await http.post(API + method, json=params)).json()
        except httpx.HTTPError as problem:
            # Usually an idle connection that Telegram closed. Try once more
            # so a customer reply is not lost to a hiccup.
            print(f"telegram {method}: network problem ({type(problem).__name__}), attempt {attempt}")
            if attempt == 1:
                continue
            return None
        if reply.get("ok"):
            return reply["result"]
        # 429 = we are sending too fast. Telegram says how long to wait.
        wait = reply.get("parameters", {}).get("retry_after")
        if wait and attempt == 1:
            await asyncio.sleep(wait + 1)
            continue
        print(f"telegram {method} failed: {reply.get('description')}")
        return None


async def say(chat, text, buttons=None):
    """Send plain text. No Markdown/HTML mode, so customer text can never
    be interpreted as formatting."""
    params = {"chat_id": chat, "text": text[:4000]}  # Telegram's limit is 4096
    if buttons:
        # One row of buttons: [(label, callback data), ...]
        params["reply_markup"] = {"inline_keyboard": [
            [{"text": label, "callback_data": data} for label, data in buttons]]}
    return await tg("sendMessage", **params)


def remember(chat, who, text):
    """Keep the last 8 lines of each conversation for context. `who` is set
    by our code ("customer" or "us"), never taken from the message itself."""
    history_of.setdefault(chat, []).append({"from": who, "text": str(text)[:500]})
    del history_of[chat][:-8]


# ---------------------------------------------------------------------------
# Customer side
# ---------------------------------------------------------------------------

async def ask_brand(chat):
    await say(chat, "Test bench: which brand are you writing to?",
              [(brand, f"brand:{brand}") for brand in rules.FRONTLINE_BY_BRAND])


def too_fast(chat):
    """True if this chat sent more than the allowed messages in the last minute."""
    now = time.monotonic()
    times = [t for t in recent.get(chat, []) if now - t < 60] + [now]
    recent[chat] = times
    return len(times) > rules.MAX_MESSAGES_PER_MINUTE


async def handle_customer(chat, record, show_id=False):
    """Triage one customer message, answer the customer, inform the staff."""
    prefix = f"[{record.get('id')}] " if show_id else ""  # used by /replay

    # A chat that kept trying injections is restricted: no model call at all.
    if strikes.get(chat, 0) >= rules.INJECTION_STRIKES_BEFORE_BLOCK:
        print(f"ignored message from restricted chat {chat}")
        return

    await tg("sendChatAction", chat_id=chat, action="typing")
    history = list(history_of.get(chat, []))
    result = await triage_message(record, 0, openai_client, DEFAULT_MODEL, brand_facts, history)
    remember(chat, "customer", record.get("text"))

    reply = result["reply_to_customer"]
    if "injection_attempt" in result["risk_flags"]:
        strikes[chat] = strikes.get(chat, 0) + 1
        if strikes[chat] >= rules.INJECTION_STRIKES_BEFORE_BLOCK:
            reply = rules.REPLY_BLOCKED
            result["reasons"].append("repeat injection attempt, chat restricted")
            result["reply_to_customer"] = reply

    # The customer always hears back at once.
    if reply:
        await say(chat, prefix + reply)
        remember(chat, "us", reply)

    if staff_chat is None:
        await say(chat, "(no staff group yet: add this bot to a group to see the staff side)")
        return
    card = await say(staff_chat, card_text(result, record.get("text")), [("⚠️ Wrong call", "wrong")])
    if card:
        cards[card["message_id"]] = {"customer": chat, "result": result}


def card_text(result, text):
    """The staff view of one decision."""
    lines = [
        f"{ICON.get(result['action'], '⚪')} {result['action'].upper()} → {result['owner']}"
        f" · urgency {result['urgency'].upper()}",
        f"{result['id']} · {result['brand']} · confidence {result['confidence']}",
        "",
        f"Customer wrote: {text[:1200] if text else '(no text: sticker, photo, voice note or empty)'}",
    ]
    if result["summary"]:
        lines.append(f"Understood as: {result['summary']}")
    if result["intents"]:
        lines.append("Intents: " + ", ".join(i["type"] for i in result["intents"]))
    if result["entities"]:
        lines.append("Details: " + ", ".join(f"{e['type']}={e['normalized'] or e['value']}"
                                             for e in result["entities"]))
    if result["risk_flags"]:
        lines.append("Flags: " + ", ".join(result["risk_flags"]))
    lines.append("Why: " + "; ".join(result["reasons"]))
    lines.append("")
    lines.append(f"Bot told the customer: {result['reply_to_customer'] or '(nothing)'}")
    if result["human_review"]:
        lines.append("ACTION NEEDED: reply to this card to answer the customer.")
    else:
        lines.append("No action needed (for information).")
    return "\n".join(lines)


async def replay(chat):
    """Push the 25 task messages through the live path. The person who ran
    /replay plays the customer for all of them."""
    records = json.loads((HERE / "candidate_pack" / "messages.json").read_text(encoding="utf-8"))
    await say(chat, f"Replaying {len(records)} messages. Each takes about 5 seconds "
                    f"(the model call), so this runs for about 2 minutes.")
    saved, saved_strikes = history_of.pop(chat, None), strikes.pop(chat, 0)
    for number, record in enumerate(records, start=1):
        history_of.pop(chat, None)        # each task message stands alone
        strikes.pop(chat, None)
        started = time.monotonic()
        await handle_customer(chat, record, show_id=True)
        print(f"replay {number}/{len(records)} done")
        # A bot may send about 20 messages a minute to one group, so keep
        # at least 3.2 seconds between cards. The model call usually takes longer.
        await asyncio.sleep(max(0.0, 3.2 - (time.monotonic() - started)))
    history_of.pop(chat, None)
    strikes[chat] = saved_strikes
    if saved:
        history_of[chat] = saved
    await say(chat, "Replay finished.")


# ---------------------------------------------------------------------------
# Staff side
# ---------------------------------------------------------------------------

async def handle_staff_message(message):
    """A staff member replied to a card: relay their words to the customer."""
    replied_to = message.get("reply_to_message", {}).get("message_id")
    card = cards.get(replied_to)
    text = message.get("text")
    if not card or not text or text.startswith("/"):
        return
    await say(card["customer"], text)
    remember(card["customer"], "us", text)
    await say(staff_chat, f"Sent to customer by {message['from'].get('first_name', 'staff')}.")


async def handle_button(query):
    """Someone pressed a button under a message."""
    data = query.get("data", "")
    message = query.get("message", {})
    chat = message.get("chat", {}).get("id")
    name = query["from"].get("first_name", "someone")
    note = "Done"

    if data.startswith("brand:") and data[6:] in rules.FRONTLINE_BY_BRAND:
        brand_of[chat] = data[6:]
        note = f"Brand set to {brand_of[chat]}"
        await say(chat, f"You are now a customer of {brand_of[chat]}. Send any message.")
    elif data == "wrong":
        card = cards.get(message.get("message_id"))
        if card is None:
            note = "This card is no longer active (bot was restarted)."
        else:
            with CORRECTIONS.open("a", encoding="utf-8") as log:
                log.write(json.dumps({"marked_by": name, "result": card["result"]},
                                     ensure_ascii=False) + "\n")
            note = "Logged as a wrong call"
    # Telegram shows `note` as a small pop-up and stops the button's spinner.
    await tg("answerCallbackQuery", callback_query_id=query["id"], text=note)


# ---------------------------------------------------------------------------
# The main loop
# ---------------------------------------------------------------------------

async def set_staff_chat(chat):
    """Make this group the staff queue and remember it across restarts."""
    global staff_chat
    staff_chat = chat
    STAFF_FILE.write_text(str(chat))
    await say(chat, "This group is now the staff queue. Decisions will appear here as cards.")


async def handle_update(update):
    try:
        # One log line per update, so we can see what Telegram delivered.
        kind = next(key for key in update if key != "update_id")
        where = update[kind].get("chat") or update[kind].get("message", {}).get("chat", {})
        print(f"update: {kind} from {where.get('type')} chat {where.get('id')}")

        if "callback_query" in update:
            return await handle_button(update["callback_query"])

        # The bot was added to (or removed from) a chat.
        if "my_chat_member" in update:
            change = update["my_chat_member"]
            in_group = change["chat"]["type"] in ("group", "supergroup")
            joined = change["new_chat_member"]["status"] in ("member", "administrator")
            if in_group and joined and staff_chat is None:  # first group wins
                await set_staff_chat(change["chat"]["id"])
            return

        message = update.get("message")
        if not message:
            return
        chat = message["chat"]["id"]
        text = message.get("text") or message.get("caption")  # None for stickers, voice notes...

        if message["chat"]["type"] != "private":
            # The bot was already in the group before it started, so it never
            # saw the "added" event: the first group message registers the
            # group, and /staff moves the queue to the group it is typed in.
            if staff_chat is None or (text or "").startswith("/staff"):
                await set_staff_chat(chat)
            elif chat == staff_chat:
                await handle_staff_message(message)
            return

        if text in ("/start", "/brand"):
            return await ask_brand(chat)
        if text == "/replay":
            return await replay(chat)
        if chat not in brand_of:
            return await ask_brand(chat)
        if too_fast(chat):
            return await say(chat, rules.REPLY_SLOW_DOWN)  # no model call: slows down trial and error

        record = {
            "id": f"TG-{message['message_id']}",
            "brand": brand_of[chat],
            "channel": "telegram",
            # Telegram gives seconds since 1970; the model reads an ISO date better.
            "received_at": datetime.fromtimestamp(message["date"], timezone.utc).isoformat(),
            "text": text,
        }
        await handle_customer(chat, record)
    except Exception as problem:  # one bad update must not stop the bot
        print(f"update {update.get('update_id')} failed: {type(problem).__name__}: {problem}")


async def main():
    global openai_client
    if not TOKEN:
        raise SystemExit("TELEGRAM_BOT_TOKEN is missing from .env")
    openai_client = make_client()
    if openai_client is None:
        print("No OPENAI_API_KEY: every message will go to a human.")

    me = await tg("getMe")
    print(f"Running as @{me['username']}. Staff group: {staff_chat or 'not set yet'}. Ctrl+C to stop.")
    offset = None
    while True:
        # Long poll: Telegram holds the request open for up to 50 seconds
        # and answers as soon as something arrives.
        updates = await tg("getUpdates", timeout=50, offset=offset,
                           allowed_updates=["message", "callback_query", "my_chat_member"])
        if updates is None:
            await asyncio.sleep(3)  # network hiccup: wait, then try again
            continue
        for update in updates:
            offset = update["update_id"] + 1  # tells Telegram we have seen this one
            # Handle each update in the background so one slow message
            # (a model call takes a few seconds) does not block the others.
            task = asyncio.create_task(handle_update(update))
            background.add(task)
            task.add_done_callback(background.discard)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("Stopped.")
