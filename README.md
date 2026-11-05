# hush-cli

The Hush Security command line interface.

## Install

From source, with Go 1.24 or later:

```bash
git clone https://github.com/hushsecurity/hush-cli && cd hush-cli && make build
```

## Sign in

```bash
hush login            # pick your organization in the browser
hush login --org acme # or name it
```

For an organization outside the default region, add `--api <your Hush API URL>`
(or set `HUSH_API_URL`).

The browser opens your organization's sign-in page; once you sign in, the CLI
keeps a refresh token in your user config folder (`hush/session.json`).
`hush logout` removes it.

## Skills

Your organization's admins assign skills to you in Hush. To install them for
your coding agents:

```bash
hush skills list             # what's assigned to you, and what's installed
hush skills show my-skill    # a skill's details and SKILL.md
hush skills sync             # install them, update them, remove unassigned ones
hush skills remove my-skill  # uninstall one; sync then leaves it out
hush skills add my-skill     # install it again
```

`hush status` shows who you're signed in as. `hush skills list --json` prints
JSON for scripts.

Skills are installed once in `~/.agents/skills`, which Codex, Cursor and most
other agents read. Claude Code gets a link to each one in `~/.claude/skills`
(a copy where links aren't allowed, e.g. Windows without developer mode).

Sync only updates or removes skills it installed itself, and leaves other
skills in those folders alone.

### Keep skills current

```bash
hush skills autosync on   # sync whenever Claude Code starts a session
hush skills autosync off
```

This adds a `SessionStart` hook to `~/.claude/settings.json` that runs
`hush skills sync --quiet`. Agents without such hooks share the same skills
folder, so they pick up what it syncs too; or run `hush skills sync` yourself.
