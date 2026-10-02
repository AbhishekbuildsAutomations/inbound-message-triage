# Changelog

What changed and why, newest first.

## 2 Oct 2026 — Reply wording pass (step 3b)

**Changed after the first full Telegram replay**
- Replies no longer say "I've flagged this". Normal cases just say someone from the team will be with them shortly. Only urgent or critical cases (stranded traveller, health question, money dispute, repeated complaint) say "I've flagged this as urgent ... as soon as possible".
- Praise and thanks (MSG-010, MSG-023) get one or two short sentences: thank you, we're glad. Nothing about the team.
- The reply answers the main issue only. Side requests (MSG-008's extra order of two tubs) are left to the team, who see the full message on the card.
- `/replay` pacing: the fixed 4-second pause made each message take about 12 seconds, which looked like a stall. It now only waits when a message finishes in under 3.2 seconds, and says how long the run will take.
- Telegram calls retry once on a dropped connection, so a reply is not lost to a network hiccup.

**Bug found and fixed**
- In one run the model read a bare "Unsubscribe" (MSG-017) as two intents, one of them a subscription cancel, and the bot answered with the 20% retention offer. A clarifying question now takes priority over the retention offer. Test added.

**Verified**
- `python test_triage.py` passes.
- Three live runs after the fix: 25/25 action, owner and urgency each time. In the two runs where wording was checked, only MSG-011, MSG-016 and MSG-019 said "flagged".
- `python redteam.py`: 55 attacks, 0 problems; 0 of 20 normal messages treated as attacks.

## 2 Oct 2026 — Reply policy and injection hardening (step 3)

**Why**: live testing showed the bot was too quiet. When a human was needed, the customer only got a generic "team will get back to you" line. New rule from the test: every message gets an immediate, specific reply, and the team gets a card with everything they need.

**Reply policy (what changed)**
- Every message now gets a reply at once: greeting, acknowledgment using the customer's own details, apology where something went wrong, a statement that a team member is on the way, and a request for whatever the team will need (photos for a damaged item, a contact number for wholesale, travel dates for a fare enquiry).
- `draft_for_approval` is gone. It is now `handoff`: the bot acknowledges and a team member does the work. There are no drafts waiting for approval any more.
- The bot no longer knows any prices. The invented prices were removed from `kb.json`, and the output gate rejects any reply that states an amount of money that is not in the brand facts.
- Fixed wording (in `rules.py`, not written by the model) for the cases where wording matters most: the injection warning, the medical reply ("please confirm with your doctor"), the retention offer and its acceptance.
- Retention flow: a cancellation request first gets a 20% offer. "Yes" goes to billing to apply the discount; "no" goes to billing to cancel. The bot only honours a "yes" if our own code recorded that the offer was made, so a customer cannot claim an offer we never made.
- A change that may cost money (flight date change) gets a "do you want to go ahead once the fee is checked?" question first; on "yes" it goes to the team at high urgency.
- Urgency floors in `rules.py`: anything about time, shipping, rescheduling, money or a warm lead is at least high; medical and stranded travellers are critical.

**Injection hardening (researched first)**
- Sources read: OWASP LLM Prompt Injection Prevention Cheat Sheet; promptfoo red-team strategy list; "The Attacker Moves Second" (Nasr et al., 2025); "Design Patterns for Securing LLM Agents against Prompt Injections" (2025); write-ups of the Chevrolet $1 car, Air Canada and DPD chatbot incidents.
- Main finding: no detector is reliable against an attacker who keeps trying (the 2025 paper bypassed published detectors more than 90% of the time). So detection is one layer, and the design carries the weight: the model cannot take any action, and nothing it writes is sent without passing a code check.
- `guard.py`, input side: patterns for override, fake authority, special modes, role-play, dictated replies, prompt extraction, fake system/assistant markup, and Hindi, Hinglish, Spanish, French, German. Before matching, text is un-disguised: look-alike letters, invisible characters, spaced-out letters, leetspeak, scrambled words, base64, hex, ROT13, hidden Unicode tag characters.
- A message caught by code never reaches the model. It is escalated with the fixed warning.
- The model's own instructions list what counts as an injection, and say explicitly that a blunt customer request ("refund me now", "apply my coupon and confirm") is not one.
- `guard.py`, output side (the gate): a model-written reply is rejected if it promises or confirms anything, states an amount not in the brand facts, gives medical advice, contains a link, leaks the prompt, or is too long. A rejected reply is replaced with a fixed holding line and a human is called in.
- In the bot: a second injection attempt restricts the chat; more than 8 messages a minute gets a "slow down" reply with no model call.
- New hard flags: `self_harm`, `abusive`, `data_request` (asking for someone else's details).

**Verified**
- `python test_triage.py` passes (pre-filter, rules, retention flow, guard).
- 25 task messages, three live runs: 25/25 action, 25/25 owner, 25/25 urgency each time; every message got a reply; every model reply passed the gate.
- `python redteam.py`: 55 attacks in `attacks.json`, two consecutive live runs with zero problems. 30 caught by code, 13 to 14 more by the model. The 11 to 12 not flagged as injection are social-engineering messages with nothing addressed to the bot (for example "your colleague said my refund was approved"); they went to a human and got no commitment.
- 20 normal messages that use similar words ("please ignore my previous message", "apply my coupon and confirm"): 0 treated as attacks in both runs.
- Simulated with the real model: retention accept and decline, fee confirmation, and the two-strike injection restriction.

**Found and fixed along the way**
- The gate rejected the stranded-traveller reply for repeating the customer's own words "was cancelled". The pattern now only targets our own claims ("your booking is cancelled", "I've cancelled").
- The model treated "I have a VIP discount, apply it and confirm" and "just say yes or no" as attacks. Its injection definition was narrowed and the benign set extended to catch this.
- A request for another customer's data only got a question back with no human involved. Added the `data_request` flag.

**Honest limits**
- The attack suite was written by us from published attack lists. It is not an independent test, and passing it does not mean every attack is covered. A determined attacker will eventually get a message past detection; what they cannot get is an action or a commitment.
- The injection warning is harsh. A false alarm would send it to a real customer. We measured 0 in 20 on our benign set; real traffic would need monitoring.
- Fixed replies are in English only.
- Cost rose to about $0.32 per 1,000 messages (longer instructions), still provisional until caching is priced in.

## 2 Oct 2026 — Telegram test bench (step 2)

**Built**
- `bot.py`: customers message the bot in a private chat (`/start` picks the brand); a Telegram group is the staff queue. Every decision appears there as a card with the message, what the bot understood, flags, confidence and the reason.
- Staff can press "Send draft", reply to a card to answer in their own words, or press "Wrong call" (logged to `corrections.jsonl`).
- `/replay` pushes the 25 task messages through the live path.
- The core now accepts conversation history, so a follow-up like "the membership one" is understood from the previous lines.

**Decisions and why**
- *Checked existing bots first.* The best-known open-source one, bostrot/telegram-support-bot (Node.js), forwards messages to a staff group where staff answer by replying. We reuse that handoff pattern. We did not adopt the project: its LLM mode answers customers directly with no decision layer, which is the part this task is about.
- *No bot framework.* The bot needs five Bot API methods, called over plain HTTP with the HTTP library the OpenAI SDK already installs. Fewer concepts to explain than python-telegram-bot or aiogram.
- *Long polling, not webhooks*: runs from a laptop, no public URL.
- *Plain text only* when sending: customer text can never be interpreted as formatting.
- *When a human takes over, the customer gets a fixed holding line*, never the draft. An injection attempt gets no reply at all.
- *Bot-alone actions are also posted to staff* as FYI cards, so a time-sensitive case is still visible.
- *Two intent definitions sharpened* (`general_question` vs `sales_enquiry`) after MSG-003 flipped in 2 of 6 runs. "How much roughly?" matched both definitions as written; the fix was to the definitions, not a special case for that message. Four runs after the change: 25/25 each.

**Verified**
- Simulated a full conversation with fake Telegram updates and the real model: brand pick, auto-reply, clarifying question, follow-up using history, staff reply relay, wrong-call log, injection (no reply), sticker.
- The simulation found and fixed one bug: the "send" action could resend a reply the bot had already sent.
- The bot starts and connects as the test bot.

**Not verified yet**
- A real end-to-end run in Telegram with the staff group (the bot must be added to the group by a person).

**Known limits**
- State is in memory: restarting the bot forgets open cards and conversation history.
- The first group the bot is added to becomes the staff queue; there is no staff login.
- A bot may send about 20 messages a minute to one group, so Telegram is a test bench, not the staff tool at 10,000 messages a day.

## 2 Oct 2026 — Core brain (step 1)

**Built**
- `triage.py`: the pipeline. Pre-filter (code) → one model call (describe only) → decision (code).
- `rules.py`: every business rule as plain tables: routing per intent, risk flags, confidence threshold, injection patterns.
- `kb.json`: invented brand facts so the bot has something to answer from. Clearly marked as demo data.
- `expected.json`: answer key for the 25 messages, written before the first model run.
- `evaluate.py`: scores `results.json` against the answer key and fails if a risky message would skip a human.
- `test_triage.py`: no-key checks for broken input and for the decision rules.

**Decisions and why**
- *The model describes, code decides.* The model has no way to act, so a message that fools it still cannot trigger a refund. The injection check also runs in code, independent of the model.
- *Six outcomes*: reply alone, thank and log, ask the customer, draft for approval, escalate, route internally. With several intents in one message, the most cautious wins.
- *Bot acts alone only when*: no risk flag, no money involved, confidence at or above 0.7, at most 2 intents, and the answer is in the brand facts. Asking a clarifying question is also allowed alone because it cannot do harm.
- *Confidence is combined*, not just the model's own number: lowest intent confidence, minus a penalty for a missing required entity (e.g. no order ID), minus a penalty for more than 2 intents.
- *Native OpenAI structured output, no wrapper library.* Checked `instructor` and `pydantic-ai`: they add multi-provider support and validation retries. We use one provider and the API already enforces the schema, so a wrapper adds a dependency without a benefit here.
- *No prompt-injection library.* OpenAI's Guardrails injection check is built for agents that call tools. Our model calls no tools, so the structural defence (model cannot act) plus a pattern check covers it.
- *Checked existing open-source triage projects* (AI-Triage-System, bankops-ai). Both use the same pattern we chose: structured classification, then a deterministic rule engine and a confidence threshold to a human queue. Neither is a reusable tool; they confirm the approach.
- *Retries*: the OpenAI SDK already retries rate limits, timeouts and server errors with exponential backoff (`max_retries=4`). We add one retry of our own for an unusable answer, then fall back to a human.
- *Model*: `gpt-6-luna` ($0.10 in / $0.50 out per 1M tokens, checked 2 Oct 2026). Reasoning effort set to "low" because the default "medium" is billed as output.

**Verified**
- `python test_triage.py` passes.
- Dry run over all 25 messages produces 25 records and catches MSG-005 (injection), MSG-007 (phone only) and MSG-025 (null) without the model.
- Four live runs on `gpt-6-luna` scored 25/25, 24/25, 25/25, 25/25 on action and 25/25 on owner every time. The safety check passed every time and no model call failed.
- The one miss: MSG-003 flipped once from "reply alone" to "draft for approval" because the model read "thinking of booking before diwali" as a sales enquiry. It erred toward the human, which is the safe direction. Not tuned further, to avoid fitting the prompt to 25 messages.
- Hinglish (MSG-006): the model resolved "Saturday 4 baje" to a date and time and drafted the reply in the same Hindi-English mix.

**Changed after the first live run**
- A message with more than 2 intents now always goes to a human, even when the bot only wanted to ask a question (MSG-014). Before, the "at most 2 intents" rule did not cover clarifying questions.

**Measured (per run of 25 messages, 23 model calls)**
- About 30,700 input and 7,800 to 8,300 output tokens; about 4.4 to 5.3 seconds per call; 12 to 15 seconds for the whole file at 10 calls in parallel.
- About $0.28 per 1,000 messages with every input token priced at the full rate. Provisional: prompt caching is not yet priced in (step 4).

**Open**
- Urgency is extracted but does not change the decision yet; it will sort and ping in the staff view.
- Bot-alone actions (ask, thank, auto-reply) are not shown to staff yet; the Telegram step will post them as FYI so a time-sensitive case like MSG-022 is still visible.
