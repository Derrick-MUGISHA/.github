# Security notice: config-file worm (PolinRider / EtherHiding loader)

**Status (2026-11-25):** removed from every branch of every repository in this account/organization. If you cloned or pulled any of these repositories between **January and November 2026** and ran or opened it, read this page and check your machine.

## Reporting a vulnerability

Do not open a public issue. Use GitHub's **Security → Report a vulnerability** on the affected repository (private vulnerability reporting), or contact the repository owner directly.

---

## What happened

A self-spreading piece of malware hid inside JavaScript config files of our projects and spread from developer laptop to repository to the next developer. It reached **99 repositories and 434 branches** across our accounts and organizations before it was found and removed. The newest copy reached a maintainer's laptop on 2026-11-13, about 11 minutes after cloning an infected repository and opening it in VS Code.

## Who is behind it

The technique, file targets, and repository-spreading behaviour match a campaign that public researchers attribute to a **North Korea (DPRK)-linked threat actor**:

- OpenSourceMalware's dossier ["PolinRider"](https://github.com/OpenSourceMalware/PolinRider) (2026-03-07, updated 2026-04-11) attributes this config-file campaign to the DPRK, linked to the Lazarus-associated "Contagious Interview" activity. It reports that it "culminates in a new version of the DPRK Beavertail malware". It describes the same whitespace-padded loader in `postcss.config.mjs`, `tailwind.config.js` and `eslint.config.mjs`, and the same propagation artifacts (`temp_auto_push.bat`, `config.bat`) that the worm added to our `.gitignore` files.
- The Canadian Centre for Cyber Security's ["EtherHiding: The trojan in your toolchain"](https://www.cyber.gc.ca/en/news-events/etherhiding-trojan-your-toolchain) documents a closely related loader hidden in `tailwind.config.js` behind more than a thousand whitespace characters. Its later stages install the InvisibleFerret backdoor, which runs inside VS Code's own Node.js runtime.

Our samples fetch their command server from the **Ethereum** blockchain, while the reports above describe TRON, Aptos and BSC. So this is a closely related generation, not necessarily byte-identical. The GitHub accounts that pushed infected commits to our repositories were themselves **victims** whose machines or tokens were compromised, not the authors of the malware.

## How it works

1. **Hidden loader.** One line of obfuscated JavaScript is appended to a real config file (`postcss.config.mjs`, `tailwind.config.js`, `vite.config.js`, `eslint.config.*`, `babel.config.js`, `jest.config.js`, `karma.conf.js`, some route files). It sits after 100–3,000 spaces or tabs, so it is off-screen in editors and in GitHub's diff. ESM files also get `import { createRequire } from 'module'` prepended. Decoy files `init`, `ini`, `ing`, `api.js` and fake fonts (`*.lkf`) carry the same payload, and `"node init && "` / `"node api.js && "` is added to the start of `dev`, `build` and `start` scripts.
2. **It runs by itself.** The worm commits a hidden `.vscode/tasks.json` with `"runOn": "folderOpen"`, `"reveal": "never"` and `"hide": true`. It runs `node .vscode/ini` or `node public/fonts/fa-solid-*.ttf` (a fake font that is really the payload) the moment the folder is opened in VS Code. To make that file committable, the worm removes `.vscode/*` and `.env` from `.gitignore`, and it adds its own helper scripts (`config.bat`, `temp_auto_push.bat`) there so they are never committed. Separately, VS Code extensions (Tailwind CSS IntelliSense, ESLint, Jest) and dev servers (`next dev`, `vite`) execute these config files as soon as a folder is opened or a build starts. You don't need to run anything.
3. **Command server from the blockchain.** The loader reads the latest transaction of an attacker-controlled Ethereum address and decodes the server's IP address from it ("EtherHiding"). Blocking one IP does not stop it: the attacker just posts a new transaction.
4. **Backdoor.** It installs `~/.node_modules/` (`.npm-ws-runner.js`, `.npm-ws.json`, socket.io client) and appends a launcher to npm's own `lib/cli.js`. Every `npm` command, including VS Code's background TypeScript service, restarts a hidden `node -e` process that downloads encrypted code and runs it with `eval`, which gives the attacker full remote control.
5. **Theft.** The attacker installed a Python credential-stealing kit (`SecretStorage`, `pycryptodomex`, `pyzipper`, `dbus-next`) to read the system keyring and browser passwords and cookies.
6. **Spreading.** Using the victim's own git and GitHub credentials, the worm amends the payload into the latest commit of every repository it can push to and force-pushes. It keeps the original author, message and author date. It also removes `.env` and `.vscode/` from `.gitignore`, so secrets get committed.

## How to spot it

**In a repository** (run in the repo root; any output means infected):

```bash
git grep -nE '[[:space:]]{20,}(global(\[|\.)|var z ?= ?.)|[[:space:]]{100,}[^[:space:]]' -- ':!*.md' | cut -c1-120
git grep -nE 'splitLane|var NX,SX|npm-ws|M260630A' -- ':!*.md'
git grep -nE '"node (init|api\.js) &&' -- '*package.json'
git ls-files | grep -E '(^|/)(init|ini|ing|api\.js)$|\.lkf$'
git grep -nE 'folderOpen' -- '*.vscode/tasks.json'                  # hidden auto-run task
git grep -nE '^(config\.bat|temp_auto_push\.bat)' -- '*.gitignore'   # worm hides its scripts
# commits amended by the worm: author in +0200, committer in -0700/-0800
git log --all --format='%h %ai | %ci | %an | %s' | awk -F'|' '$1 ~ /\+0200 $/ && $2 ~ /-0[78]00 $/'
```

Also look for a burst of **force-pushes** to many repositories within minutes in GitHub's Activity view (`/activity` on any repo). A person doesn't push like that; the worm does.

**On a computer:**

```bash
ls -la ~/.node_modules/.npm-ws* 2>/dev/null                          # backdoor files
pgrep -af 'node -e' | grep -E 'npm-ws|require\("http"\)'             # running backdoor
f="$(npm root -g)/npm/lib/cli.js"; wc -c "$f"; grep -c 'M260630A\|npm-ws' "$f"   # trojaned npm (clean ~408 bytes, 0 matches)
python3 -m pip list --user 2>/dev/null | grep -iE 'secretstorage|pycryptodomex|pyzipper|dbus-next'
```

Indicators: command server `95.135.181.84` (ports 443/80, path `/0x/cls`); victim tags `A8-5078-1`, `8-7260`, `-11730`, `-5000`; markers `splitLane`, `var NX,SX`, `M260630A`, `global['!']`, `global.i = 'A8-`.

## If you have it

1. **Disconnect** the computer from the network. Don't run `npm`, `pnpm` or `yarn` on it.
2. **From a different, clean device**, change passwords and revoke sessions and tokens for GitHub (also delete SSH keys and personal access tokens), npm, cloud accounts (AWS etc.), email, and every account saved in the browser. Move any crypto to a new wallet. Replace every secret that was in a `.env` file.
3. **Reinstall the operating system.** The attacker could run any command, so cleaning by hand can miss things.
4. **Reclone** your repositories fresh, run the repository checks above before installing anything, and install with `npm ci --ignore-scripts` first.
5. Tell your team and anyone you share repositories with.

## How to stop it spreading

- **Protect branches:** in every repository, turn on a rule for `main` (and ideally all branches) that **blocks force-pushes** and requires pull requests. That alone stops this worm's push step.
- **2FA everywhere** (GitHub, npm), required at the organization level.
- **Short-lived, fine-grained tokens** instead of broad `repo` / `workflow` / `admin:org` tokens stored on laptops.
- **Review config-file changes with whitespace visible** (`git diff --ws-error-highlight=all`); be suspicious of any change to `postcss`, `tailwind`, `vite`, `eslint`, `next` or `babel` config files.
- **Open untrusted repositories in VS Code's Restricted Mode**, and never run take-home "coding tests" from recruiters on your main machine.
- **Keep Dependabot and secret scanning on**, and never commit `.env` files.

## What was done

- 2026-11-25: the backdoor was stopped and removed from the affected laptop, and npm was restored.
- Every infected branch in 99 repositories received a clean-up commit that removes only the malware (loader lines, decoy files, script hooks). A second commit removed the hidden VS Code auto-run tasks and restored the `.gitignore` entries the worm changed. No other content was changed; 118 files came out byte-identical to their pre-infection version.
- In repositories owned by the maintainer, history was rewritten with `git-filter-repo` so that no old commit contains the loader payload anymore. Each branch's current files are identical to the cleaned version. Where a repository's rules block force-pushes, only the clean-up commits were applied. Old commits elsewhere may still contain the payload: never check out an old commit and run it.
- Dependabot alerts were enabled on all administered repositories.
