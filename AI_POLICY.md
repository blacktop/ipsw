# AI Usage Policy

AI tools are welcome here as productivity tools. What is not welcome is low-effort, unverifiable output that shifts the review burden onto maintainers.

This policy applies to outside contributions to `ipsw`, including issues, discussions, and pull requests.

## Rules

- **Disclose material AI usage.** If AI materially helped with code, issue text, triage, reproduction, analysis, or PR copy, say so and name the tool. If there was no AI help, say `none` when asked.
- **The human contributor must understand the work.** You must be able to explain what the submission does, why it is correct, what evidence supports it, and what risks remain without asking the AI to explain it back to you.
- **Human review is required for AI-assisted writing.** Issues and discussions may use AI for drafting, but the final text must be reviewed, edited, and fact-checked by a human. Keep it concise and specific.
- **Human verification is required for AI-assisted code.** Do not submit AI-generated patches you have not personally reviewed and tested. You own the change.
- **Do not invent evidence.** Do not post AI-generated logs, crash output, repro steps, benchmark numbers, reverse-engineering claims, or test results unless you actually produced and verified them.
- **Low-effort AI submissions may be closed.** Maintainers may close issues or pull requests that are clearly undisclosed, spammy, unreviewed, or not grounded in real evidence.

## Disclosure Guidance

Good disclosures are short and concrete. Examples:

- `AI assistance: none`
- `AI assistance: Claude Code helped draft the PR description and suggested a refactor; I reviewed every changed line and ran task ci.`
- `AI assistance: ChatGPT helped summarize the bug report; I rewrote it, verified the repro manually, and attached the real command output.`

Bad disclosures:

- `Written with AI`
- `Cursor did most of it`
- No disclosure when AI materially contributed

## There Are Humans Here

Every issue and pull request is read by humans. Please do not hand maintainers a pile of plausible-looking AI output and expect them to separate signal from noise for you.

If you use AI well, disclose it, keep the submission grounded in evidence, and take responsibility for the result, that is fine.
