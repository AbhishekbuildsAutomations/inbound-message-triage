# Inbound Message Triage

A small service that reads inbound customer messages (WhatsApp, email, Instagram) for several brands and, for each one, decides:

- what the sender wants
- what useful details are in the message
- what happens next, who handles it, and how urgently

Every sender gets an immediate reply. A human is called in whenever the message involves risk, money, or work only a person can do.

**Read first:** [DECISION_LOG.md](DECISION_LOG.md) (one page). The run output for the 25 sample messages is in [RESULTS.md](RESULTS.md).

## How it works

The design rule is: **the model describes, code decides.** The model never takes an action.

```
message ─► 1. pre-filter (code) ─► 2. model call ─► 3. decision (code) ─► result
              broken input,           describes         routing table,
              injection scan          the message,      urgency, confidence,
                                      drafts a reply    output gate on the reply
```

1. **Pre-filter** (`triage.py`, `guard.py`): plain code. Handles null, empty, wrong-type, phone-only and emoji-only input, and scans for prompt injection, including disguised text. A message caught here never reaches the model.
2. **Model call** (`triage.py`): one call per message to `gpt-6-luna` with a strict JSON schema. It returns intents, entities, risk flags, urgency and a draft reply. Nothing else.
3. **Decision** (`triage.py`, `rules.py`): plain code looks up each intent in a routing table, applies risk flags and urgency floors, combines a confidence score, and runs the model's reply through an output gate before it may be sent.

Every business rule lives in [`rules.py`](rules.py) as plain tables. That is the file to read to answer "why did this message go there?".

### The six outcomes

| Action | Meaning | Human needed |
|---|---|---|
| `auto_reply` | The bot answers fully from the brand facts file | No |
| `thank_and_log` | Praise; the bot says thanks | No |
| `ask_customer` | The bot asks one question because nobody can act yet | No |
| `handoff` | The bot acknowledges; a team member does the work | Yes |
| `route_internal` | Not a customer (vendor, job applicant, wholesale buyer) | Yes |
| `escalate` | Risk or money; a human takes over with priority | Yes |

When one message contains several requests, the most cautious outcome wins.

### Confidence and the human rule

Each result carries a `confidence` from 0 to 1. It starts from the model's least certain intent and is lowered by things the model cannot judge about itself: a missing required detail (an order question with no order ID) and more than two requests in one message.

The bot finishes a message alone only when **all** of these hold: no risk flag, no money involved, confidence of at least 0.7, at most two intents, and the answer is in the brand facts. A clarifying question or a thank-you is also allowed alone. Everything else goes to a human, and these always do: medical questions, payment disputes, refunds, stranded travellers, legal threats, injection attempts, and requests for someone else's data.

## Setup

Needs Python 3.10 or newer.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Run it

**Without any API key** (pre-filter and routing only; the model step is skipped and those messages default to a human):

```bash
python triage.py candidate_pack/messages.json --dry-run
python test_triage.py
```

**With a key** (the full pipeline):

```bash
cp .env.example .env        # then put your OpenAI key in .env
python triage.py candidate_pack/messages.json
python evaluate.py
```

`triage.py` writes `results.json` (for programs) and `RESULTS.md` (for people). `evaluate.py` scores the run against a hand-written answer key in `expected.json` and fails if a risky message would skip a human.

### Keys you supply

| Key | Needed for | Notes |
|---|---|---|
| `OPENAI_API_KEY` | Live runs | The account needs paid access; `gpt-6-luna` is not on the free tier |
| `TELEGRAM_BOT_TOKEN` | Optional Telegram test bench | From @BotFather |

Keys go in `.env`, which is git-ignored. No key is stored in this repository.

### Example output

```
id          action          owner              urgency   conf  human  summary / reason
MSG-001     handoff         support            high      0.98  yes    The sender asks for a tracking update for their order
MSG-005     escalate        support            high      1.0   yes    Prompt injection attempt (matched: 'SYSTEM NOTICE:')
MSG-016     escalate        emergency_on_call  critical  0.99  yes    The sender reports a cancelled connection and is stranded
MSG-018     auto_reply      salon_front_desk   low       0.99  no     The sender asks whether the salon is open on Sundays.
MSG-025     ask_customer    support            normal    1.0   no     text is empty or missing
```

One full record from `results.json`:

```json
{
  "id": "MSG-018",
  "brand": "hair-studio",
  "channel": "instagram",
  "text": "hi! are you open on sundays",
  "action": "auto_reply",
  "owner": "salon_front_desk",
  "human_review": false,
  "confidence": 0.99,
  "urgency": "low",
  "reasons": ["simple, low risk and answered from brand facts"],
  "intents": [{"type": "general_question", "confidence": 0.99, "action": "auto_reply", "owner": "salon_front_desk"}],
  "risk_flags": [],
  "reply_to_customer": "Hi! Yes, we're open on Sundays from 10:00 to 20:00.",
  "reply_source": "model"
}
```

## Cost and scale (10,000 messages a day)

Measured on the 25 sample messages, 2 October 2026:

| Item | Value |
|---|---|
| Model calls | 22 of 25 messages (3 are handled by code alone) |
| Tokens per call | about 2,180 input and 330 output |
| Price (`gpt-6-luna`) | $0.10 per 1M input tokens, $0.50 per 1M output tokens |
| **Cost per 1,000 messages** | **$0.34** |
| Cost at 10,000 a day | about $3.35 a day, about $100 a month |
| Time per model call | about 4.5 seconds; 25 messages finish in about 12 seconds at 10 calls in parallel |

How the number is built: (47,998 input tokens × $0.10 + 7,167 output tokens × $0.50) ÷ 1,000,000 = $0.0084 for 25 messages, which is $0.34 per 1,000.

Assumptions:

- Real traffic looks like the sample: similar message length, and about 12% of messages need no model call.
- Every input token is billed at the full price. Most of each prompt is the same instruction block, which OpenAI bills at 10% when it is served from its prompt cache. If that block is always cached the cost falls to roughly $0.17 per 1,000. I quote the uncached figure because cache hits are not guaranteed.
- No retries. A failed call is retried, which would add cost in proportion to the failure rate (0 failures in every run so far).
- Standard processing. The Batch API is 50% cheaper but can take up to 24 hours, which is wrong for a stranded traveller.
- Price source: https://developers.openai.com/api/docs/pricing, checked 2 October 2026.

Throughput: 10,000 a day is about 7 messages a minute. The entry-level paid tier for `gpt-6-luna` allows 500 requests and 500,000 tokens a minute. The OpenAI SDK retries rate limits, timeouts and server errors with exponential backoff; the service adds one retry for an unusable answer and then falls back to a human.

## Guardrails

- **Input scan** (`guard.py`): patterns for instruction override, fake authority, role-play, dictated replies, prompt extraction and fake system markup, in English, Hindi, Hinglish, Spanish, French and German. Text is un-disguised first: look-alike letters, invisible characters, spaced-out letters, leetspeak, scrambled words, base64, hex and ROT13.
- **Output gate** (`guard.py`): a model-written reply is rejected if it promises or confirms anything, states an amount of money that is not in the brand facts, gives medical advice, contains a link, or leaks the prompt. A rejected reply is replaced by a fixed holding line and a human is called in.
- **Fixed wording** (`rules.py`): the injection warning, the medical reply and the retention offer are written by people, not by the model.

Run the attack suite (needs a key):

```bash
python redteam.py
```

It plays 55 attacks from `attacks.json` and 20 normal messages that use similar words. Latest run: no attack produced a harmful reply, and no normal message was treated as an attack. The suite was written from published attack lists, so it is a regression check, not proof that every attack is covered.

## Telegram test bench (optional)

`bot.py` puts the same pipeline behind a Telegram bot so the full loop can be tried by hand: a private chat plays the customer, and a group plays the staff queue. Each decision arrives in the group as a card; a staff member answers the customer by replying to the card.

```bash
# add TELEGRAM_BOT_TOKEN to .env, add the bot to a group as admin, then:
python bot.py
```

In the private chat: `/start` picks a brand, `/replay` pushes the 25 sample messages through the live path.

## Files

| File | What it is |
|---|---|
| `triage.py` | The pipeline and the command line |
| `rules.py` | All business rules as tables: routing, flags, urgency, fixed replies |
| `guard.py` | Injection scan and output gate |
| `kb.json` | Placeholder brand facts the bot may answer from (no prices) |
| `expected.json`, `evaluate.py` | Answer key and scorer |
| `test_triage.py` | Checks that need no key |
| `attacks.json`, `redteam.py` | Attack suite and runner |
| `bot.py` | Telegram test bench |
| `results.json`, `RESULTS.md` | Output for the 25 sample messages |
| `DECISION_LOG.md`, `CHANGELOG.md` | Decisions, and the build history |

## Known limits

- `kb.json` holds placeholder facts. The task supplied no opening hours or policies, so real ones must replace them before real use.
- The sample data has no sender or thread ID. Conversation history only exists in the Telegram bench, where the chat ID stands in for a thread.
- Attachments are mentioned in two messages but are not in the data. The service flags them for a human.
- The Telegram bench keeps everything in memory and forgets it on restart.
