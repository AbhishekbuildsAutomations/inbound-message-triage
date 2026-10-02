# Decision log

## What I chose not to build, and why

- **A second, stronger model for hard cases.** The cheap model scored 25/25 on my answer key in repeated runs, so a second model would add cost without changing an outcome. Uncertain messages go to a person instead.
- **Letting the model act.** It only describes a message and drafts a reply; code picks the action from tables in `rules.py`. That is what makes MSG-005 harmless: an injected instruction has nothing to trigger.
- **Answers about prices, fees or order status.** I was given no price list or order system, so the bot never states an amount. A wrong fee quote costs more than a slower answer.
- **A database, queue, dashboard or framework.** At 10,000 messages a day (7 a minute), one process with 10 parallel calls and the plain SDK is enough.
- **Hosted deployment.** It runs locally from the README, with or without keys. I spent that time on a Telegram test bench to try the human handoff by hand.

## Where this breaks

- **No sender or thread ID in the data.** MSG-007 and MSG-012 are only unanswerable because context is missing, and MSG-011's "third time writing" cannot be checked.
- **Injection detection is not complete.** Code and the model caught 48 to 49 of 59 attacks in my suite; the rest were social-engineering messages that went to a human or got a harmless question. A persistent attacker will get past detection. What holds is structural: no actions, and a code check on every reply.
- **The injection warning is harsh.** A false alarm sends it to a real customer. An independent review found 15 ordinary phrases my first patterns flagged; I rewrote them and now test 60 look-alike phrases, which is still a small sample.
- **The answer key is my own judgment.** 25/25 means it matches what I think is right on 25 messages. The 0.7 confidence threshold is a starting point, not tuned.
- **Attachments are invisible.** MSG-021 and MSG-024 are flagged for a person, not read.
- **A model update can shift results.** `evaluate.py` and `redteam.py` exist to catch that.

## What I would do with another day

- Connect a real order and booking lookup, so "where is my order" gets an answer.
- Add thread history from the real channels and deduplicate repeat messages.
- Log every "wrong call" a human marks and tune the threshold against it.
- Read attachments with a document model, behind the same guard.
- Re-measure cost on a week of real traffic, with prompt caching priced in.

## AI tools used

- **Claude Code** (Anthropic): research on models, pricing and injection defences; writing the code, tests and documents under my direction; running the test and attack suites. I set the design rule and the routing and reply policy, and reviewed each decision against live results.
- **OpenAI `gpt-6-luna`**: the model inside the service.
- **Telegram Bot API**: test bench for the customer and staff sides.
- **Exa web search**: documentation, existing open-source tools, published attack lists.
