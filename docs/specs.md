# `logos-signer-manager-module` — Reference Specification

## Purpose

`signer_manager_module` takes signature requests from any named module, shows them to a person
through the signer app, and has the account's **signer** sign. A signer is any module that
implements [`logos.signer/1`](https://github.com/logos-co/logos-signer-interface):
`keystore_module` for keys kept in files, and one module per hardware wallet. The manager holds no
keys. It reads, renders and commits to every request, computes every digest itself, hands the
digests to the account's signer, and checks every signature against the account's public material
before anyone can collect a result.

It is phase K1 of the [Shared Keystore Plan](https://claude.ai/artifact/LdbUCDJNW5Ep817xKkvtMf).
The approval API comes from `keystore_module`, with the same method names and shapes, so a
requester or an approver changes only the module it calls.

## How a request moves

1. A named module calls `request_approval` with an intent and gets a handle and a receipt.
   The manager parses the intent once, finds every signer that holds the account, and for a
   Bitcoin request reads the PSBT against the wallet's xpub. A request no holder can take is
   refused here, before anything is shown.
2. The approver (the signer app, `evm_signer_ui`) calls `pending` and `acknowledge`. It gets
   the manager's own lines, the requester's claim apart from them, the commitment to echo
   back, the signer it goes to and what that signer collects: a password, a PIN, or nothing.
   It also gets every signer holding the account, so the person can choose another with
   `choose_signer` (see [One account, several signers](#one-account-several-signers)).
   `unlocked` says an unlock covers the request, so the person approves without a password.
3. The person approves. `approve` re-derives the commitment and checks the echo. It then
   computes one digest per item and calls the signer's `sign`, passing the password only
   when one was typed:
   - EIP-155 or EIP-1559 transaction hashes, EIP-191 and EIP-712 digests, or an opaque digest
     for EVM;
   - BIP143 or BIP341 sighashes for each input of a PSBT.
4. The signer answers with signatures only. The manager checks each one before building the
   result:
   - an EVM signature must recover to the account;
   - an ECDSA or BIP340 signature must verify against the key at that input's path, derived
     from the account's xpub.

   It then builds the result itself: the signed transaction envelope, the 65-byte signature,
   or the PSBT with signatures added. A wrong password leaves the request on screen.
5. The requester collects the results with its receipt.

A signer with a device answers `sign` with a job that waits for the person. The record then
stays in `signing`, and each later call checks how the job stands:
- a confirmation settles it `approved`;
- a refusal on the device settles it `rejected`;
- a failure puts it back on screen with the reason.

## Roles and tiers

| Tier | Methods | Admits |
|---|---|---|
| A | `pending`, `acknowledge`, `choose_signer`, `approval_signers`, `approve`, `reject` | a configured **approver** (default `evm_signer_ui`) |
| B | `request_approval`, `approval_status`, `fetch_result`, `ack_result`, `cancel_approval` | any **named module**; all but the first also need the receipt |
| B | `roster` | any **named module** |
| C | `accounts`, `signers`, `caller_identity`, and for now `configure` | anyone |
| B | `request_open`, `request_unlock` | any **named module**, collecting with `fetch_result` and its receipt |
| B | `wallets`, `data_key` | any **named module**; `data_key` answers the caller's own keys only |
| — | `enroll_seed` | a configured **signer** module |
| A | `wallet_settings`, `unlock_wallet`, `unlock_progress`, `cancel_unlock`, `lock_wallets`, `set_rule`, `change_keys`, `set_names`, `create_password`, `rename_password`, `change_password`, `remove_password` | a configured **approver** |
| A and D | `access_requests`, `acknowledge_access`, `approve_access`, `reject_access` | an approver for opens (its consent), or the custodian |
| D | `open_accounts`, `unlock`, `lock` | a configured **custodian** (default `evm_keystore_ui`, the keys app) |
| — | `account_descriptors`, and `close_account` for one's own wallet | a module the wallet is open for |
| A and D | `unlocked`, `unattended_signatures` | the approver or the custodian |

Refusals are the identical `{"ok":false,"error":"not authorized"}`. The host anchor (the CLI)
is never a named module.

### `configure(config_json: String) -> String`

`{ approvers?, custodians?, signers? }` → `{ ok, approvers, custodians, signers }`. Total, as the
keystore's: a role or list the document doesn't name is held by nobody, and a malformed document
changes nothing. `signers` lists the signer modules consulted, in order; when several hold the same
account, that order breaks ties between them (see
[One account, several signers](#one-account-several-signers)). Defaults: approver `evm_signer_ui`, custodian `evm_keystore_ui`
(for the open and unlock requests to come), signers `keystore_module`, `keycard_shell_module`,
`keycard_module` and `qr_signer_module`, so a device module the person installs is consulted with
nothing to configure. The QR signer comes last, and needs no connection: a Keycard Shell's account
it shares with the Shell's USB module is signed over USB by default while the Shell is connected.
A signer that doesn't answer, such as a device module that isn't installed, offers nothing and
rests for 30 seconds. Each ask costs the transport about a second to find no module, and longer on
a loaded machine, so a resting signer isn't asked again before then, unless it announces itself
that its accounts changed. Another signer's announcement, which the keystore makes at every
import, re-reads that signer alone, and so does looking up an account no signer offers.

`configure` is ungated for now, like the keystore's, and the keystore's caveat applies: the
protection is deferred to module identity in the core. A module that names itself a signer can
refuse or stall a request, but it can't get a false signature past the checks above.

## API

| Method | Params | Returns |
|---|---|---|
| `configure` | `config_json` | `{ ok, approvers, custodians, signers }` |
| `request_approval` | `intent_json` | `{ ok, handle, receipt, state }` |
| `approval_status` | `handle, receipt` | `{ ok, state, reason? }`; `state` is `offered`, `rendered`, `signing` or `settled` |
| `fetch_result` | `handle, receipt` | `{ ok, signed: [..] }`, idempotent until `ack_result` |
| `ack_result` | `handle, receipt` | `bool` |
| `cancel_approval` | `handle, receipt` | `bool`; a signer still working is told to stop |
| `pending` | — | `{ ok, pending: [{ handle, requester, state, purpose, legs, ageMs, error? }] }` |
| `acknowledge` | `handle` | `{ ok, handle, bundle_id, requester, claim_lines, render_lines, signer, collects, account, unlocked, signers, explicit }`; `account` is what an unlock of it names |
| `choose_signer` | `handle, bundle_id, signer` | `acknowledge`'s reply, for the signer chosen |
| `approval_signers` | `handle` | `acknowledge`'s reply, as the holders stand now |
| `approve` | `handle, bundle_id, password` | `{ ok, signed_count }`, or `{ ok, state: "signing" }`, or `{ ok: false, code, error }` |
| `reject` | `handle` | `bool` |
| `accounts` | — | `{ ok, accounts: [{ id, key, family, chain?, address?, label?, signer, available }] }`, each under one holder |
| `roster` | — | `{ ok, accounts: [{ key, family, chain?, address?, path?, label?, labels?, wallet?, holders }] }`, each with every holder |
| `signers` | — | `{ ok, signers: [{ name, info? }] }` |
| `caller_identity` | — | `{ ok, kind, identity, approvers, custodians, signers }`: everything a total `configure` must repeat |
| `request_open`, `request_unlock` | `params_json` | `{ ok, handle, receipt, state }` |
| `access_requests` | — | `{ ok, requests: [{ handle, requester, kind, state, ageMs, seed }] }`; opens only, for an approver |
| `acknowledge_access` | `handle` | `{ ok, handle, requester, kind, bundle_id, lines, asked, seed }` |
| `approve_access` | `params_json` | `{ ok }`, or `{ ok: false, code, error }` |
| `reject_access` | `handle` | `bool` |
| `account_descriptors` | `group` | `{ ok, group, external, internal }` |
| `close_account` | `params_json` | `{ ok, closed }` |
| `open_accounts` | — | `{ ok, open: [{ module, group }] }` |
| `unlock` | `params_json` | `{ ok, account, expiresInMs, countLeft }` |
| `lock` | `params_json` | `{ ok, locked }` |
| `unlocked` | — | `{ ok, unlocked: [{ account, expiresInMs, countLeft, apps, confirm }] }` |
| `unattended_signatures` | — | `{ ok, signed: [{ handle, requester, account, ageMs }] }` |
| `wallets` | — | `{ ok, wallets: [{ seed, name, locked, kinds, privateName? }] }` |
| `data_key` | `params_json` | `{ ok, key, generation, seed }`, or `{ ok: false, code: "locked" }` |
| `enroll_seed` | `params_json` | `{ ok, seed, new, unlocked }` |
| `wallet_settings` | — | `{ ok, wallets: [{ seed, name, privateName?, locked, holders, device, index, generation, ways, origin?, birthday? }], passwords: [{ id, name, wallets }] }`; `device`: its holders give an unlock key |
| `unlock_wallet`, `set_rule`, `change_keys` | `params_json` | `{ ok, state: "done" }`, or `{ ok, state: "device", handle }`, or `{ ok: false, code, error }` |
| `unlock_progress` | `handle` | `{ ok, state, seed, step?, code?, error? }` |
| `cancel_unlock` | `handle` | `bool` |
| `lock_wallets` | `params_json` | `{ ok, locked }` |
| `set_names`, `rename_password`, `change_password`, `remove_password` | `params_json` | `{ ok }` |
| `create_password` | `params_json` | `{ ok, id }` |

`approve`'s `code` is the signer's: `wrong_secret` (ask again), `locked` (no password and no
unlock), `unavailable` (the signer module didn't answer, or the chosen device isn't connected). The
manager adds its own `signer_changed`: see below. The request stays on screen for all of them.
`accounts` and `roster` carry no xpub: a Bitcoin wallet's xpub shows its whole history, so the
manager does not hand it to whoever asks.

## One account, several signers

The same account can be held by several signers: the keystore, a Keycard in a reader, a Keycard
Shell over USB, a QR wallet. Each names it its own way. An EVM account is its address everywhere,
but a Bitcoin wallet is `g_…` in the keystore, `keycard-…` on a card and `qr-…` in a QR wallet. The
manager groups holders by what the account is:

- **The key:** an EVM account's lowercase address; a Bitcoin account's `btc_` and 32 hex of a
  SHA-256 over its family, chain, chain code and public key. Two xpubs of one key whose metadata
  differs, such as the parent fingerprint, are one account. A signer may list that key as the
  account's `key`; the manager checks it against the xpub.
- **Guards:** a row under the unlock keys' purpose (`m/1280263247'`), or an EVM row outside
  `m/44'/60'`, is dropped from every listing, as an edited file might put one there.
- **Ranking:** the keystore first; then connected devices, a Keycard reader before a USB device;
  then QR wallets, which need no connection; then devices that aren't connected. Within each, the
  configured signer order.
- **Names:** the first name in configured signer order, with `labels` listing them all when holders
  disagree. `wallet` is the master fingerprint any holder reports and the first wallet name a
  holder's `origin` gives.

`roster` lists every account once, with its holders ranked. Each holder is `{ signer, accountId,
kind, model, transport, presence, available, collects, showsRequest, requestKinds }`, where
`transport` is `keystore`, `reader`, `usb`, `qr` or `other`, and `presence` is `local`,
`connected`, `on_demand` (a QR wallet) or `absent`. `accounts` keeps its shape, one holder per
account, and gains `key`.

A request goes to the first holder that is ready and can take it, unless the person chooses:
- `acknowledge` lists every holder as `signers`, each with `canTake` and, when it can't, `why`: a
  bare digest or several legs on a device that shows requests, or a kind it doesn't sign.
- `choose_signer` picks one that can take it. The choice stands until changed. The request and its
  commitment don't change, so nothing needs reviewing again.
- `approval_signers` gives the same reply again after a signer's accounts change, with the default
  re-picked if nobody chose.
- At `approve`, a chosen device that isn't connected answers `unavailable`. A default that moved
  since it was shown answers `signer_changed`, and the next `approve` signs with the new one. The
  request stays on screen either way.

Only the keystore's copy of an account is ever unlocked. Signing unattended goes to the keystore,
and approving with no password needs the keystore chosen.

A device's Bitcoin wallet keeps one database key, whichever holder opens it. The keystore keeps it
under the holder that already has one, else the first device holder in configured order. So
reopening the wallet through the Shell instead of the reader finds the same key and the same
database.

### The intent

Unchanged from `keystore_module`: `{ address | group, purpose?, legs }`, with legs `tx`
(`chain_id`, `tx`: the keystore's unsigned-transaction JSON), `message` (`text`), `digest`
(`digest`, `purpose`), `typed_data` (`typed_data`) and `psbt` (`network`, `psbt`, base64). An EVM
request names `address`; a Bitcoin request names `group` and carries exactly one `psbt` leg. The
render, the commitment rules and the refusals (displayable text only, declared EIP-712 fields only,
64 KiB, four pending per requester and sixteen in all, a sixty-second sweep for offers nobody
claimed) are the keystore's. The commitment's domain tag is now `logos-signer-manager-approval-v1`.

A Bitcoin request may carry `xpub`: the wallet's, from the requester that has it open. The manager
refuses it unless it gives the wallet's roster key, uses it for this request alone wherever it reads
the account (the holders, the PSBT checks, the result), passes it to the signer in the
`SignRequest`, and forgets it once the request settles.

### A PSBT

Read as keystore_module's spike K0 read it:
- **Refused before anything is shown:**
  - an input this wallet can't sign, or one already signed;
  - a script path;
  - a native segwit input without its previous transaction, or with an amount that disagrees
    with it;
  - a sighash other than ALL, or DEFAULT for taproot;
  - a coin spent twice;
  - a network mismatch.
- **Change** is checked by deriving the key at the path the output claims.
- **The fee** is the manager's own sum.

The manager computes each input's sighash and hands the sighashes to the signer with each
input's path. It adds a signature to the PSBT only after the signature verifies. One signature
missing, or one that fails, adds none.

## Wallets and their keys

A **wallet** here is a seed, whichever signers hold it: the keystore, a Keycard, a Shell, a QR
wallet. Each module keeps its own data about a wallet encrypted with keys of its own, and the
person unlocks the wallet once per session, in the Signer app, for every module at once. The
manager holds the unlocked keys and hands each module only its own. Nothing stays unlocked past a
restart or a `lock_wallets`.

- **The unlock key** of a seed is the compressed public key at `m/1280263247'/n'`, which every
  holder of the seed gives (`unlock_key` in the signer interface). `n` is the seed's unlock index:
  0 at first, and the next one after `change_keys` with `newIndex`, as when a QR answer may have
  been photographed.
- **The seed key** is random, one per seed, with a generation. A module's key is
  `HKDF-SHA256(seed key, "logos/data/v1", module ‖ 0 ‖ scope ‖ 0 ‖ generation)`; `data_key({ seed,
  scope, generation? })` answers it to the caller, named by its identity, or `locked`. A holder
  of the seed may name it its own way, as it lists it in `seed`. A module that knows an account
  and not its seed names the `account` instead, looked up among the accounts the signers last
  listed (never asking one), and the answer names the `seed`. The current
  generation is the default; an earlier one still answers, so a module reads its old data and
  writes it again under the new key in its own time. `"profile"` instead of a seed is a key for
  data of no wallet, such as contacts: any unlocked wallet opens it.
- **Ways in.** A wallet's rule is one or more ways in, each a set of factors that must all be
  there: `device` (the unlock key, from any holder) and named passwords (`password:<id>`). Each way
  wraps the seed key under `HKDF` over its factors' keys, with XChaCha20-Poly1305 bound to the
  seed, the way and the generation. "Device only" is the default; a QR wallet that gives no unlock
  key takes a password alone. Forgetting the password of a "device and password" way loses the
  wallet's data: the person adds the wallet again.
- **Always unlocked.** A rule of one way that takes nothing, `[[]]`, leaves the wallet open from
  the moment the module starts, and Lock leaves it open: its seed key is wrapped under a key anyone
  with the files can derive, so its data is as readable as if it were stored in the clear. Modules
  keep using `data_key` unchanged. Moving it back to a protected rule gives it new keys, since the
  old one sat where anyone could read it; data under the old generation still opens through the chain.
- **Passwords** are named and shared: one can unlock several wallets. Each has a key of its own
  under its scrypt output (N = 2^17, r = 8, p = 1), so `change_password` touches no wallet, and
  `remove_password` is refused while a rule takes it. Their names show in the clear.
- **Names.** A wallet's public `name` shows while it is locked; its private name, origin and
  birthday are sealed under its seed key and show once it is unlocked.
- **Adding.** A signer calls `enroll_seed` from its add flow, while the holder's unlock key at
  index 0 is at hand, so adding never asks twice: `{ seed, kind, unlockKey?, name, origin?,
  birthday? }`, where `seed` is the signer's own name for the seed (a Keycard's key UID, a Shell's
  master key id, a QR wallet's master fingerprint, a keystore wallet's id). A new wallet is
  unlocked at once. A seed already known, by that holder or by its unlock key, gains the holder.
  Signers list a wallet's accounts, xpubs included, only while it is unlocked.
- **Unlocking.** The Signer app calls `unlock_wallet({ seed, way, holder?, secret?, passwords? })`.
  A way without the device settles at once. One with it asks the holder for the unlock key: a PIN
  session, a press on the Shell or a QR round trip. The reply is then `{ state: "device", handle }`,
  and `unlock_progress(handle)` reports `device` with its `step`, `needs_password` (the device
  answered, a password didn't: `unlock_wallet({ handle, passwords })` tries again without the
  device), `done` or `failed`. `set_rule` and `change_keys` take the same step when a new way, or
  any way, needs the device.
- **Files.** `<persistence>/unlock/seeds.json` and `passwords.json`, the directory 0700 and the
  files 0600, written atomically. They hold no key in the clear. Files the manager can't read are
  left alone, and every call answers why.
- `data_key` and `enroll_seed` answer a module that may be waiting on its own call, so they call
  out to no module.

## Opening and unlocking

A Bitcoin wallet's descriptors reach a module only once a person opens the wallet for it: in the
Signer app, an approver's consent once the wallet is unlocked, or in the keys app, the custodian's
older path with a database key from the keystore. An account stays unlocked for signing only on
terms a person chose.

- **Consent.** An approver claims an open with `acknowledge_access`, which names the wallet's
  `seed` so the app shows it beside the wallet, and approves it with `{ handle, bundle_id, group?
  }`. A locked wallet answers `code: locked` and the request stays on screen. The result is `{
  group, family, chain, network, external, internal, fingerprint, seed, origin?, birthday? }`, with
  no database key: the module takes its own from `data_key(seed, …)`. A request may name the wallet
  by `{ group, seed }` while its seed is locked and no signer lists it; it is checked once unlocked.
  An approver decides opens only, and the first app to claim a request keeps it.

- `request_open` takes `{ group, network? }` to reopen a wallet, or `{ family, network }` to let the
  person pick, create or restore one, with optional `unlock` terms and a `reason`. A network must
  belong to the wallet's chain (`main` or `test`); a request naming the wrong one is refused before
  anything is shown. It answers `{ ok, handle, receipt, state }`. Once the custodian approves,
  `fetch_result` with the receipt returns `{ ok, result: { group, family, chain, network, external,
  internal, fingerprint, databaseKey, origin, birthday, unlocked } }`, `network` being the one the
  request named, and the wallet is **open** for that module: `account_descriptors(group)`, the
  wallet's id as a plain string, answers `{ ok, group, external, internal }` to it again, and to
  nobody else. `close_account` (`{ group }`) ends that; an unlock scoped to the module alone ends
  with it.
- **Where a wallet's history starts.** `origin` is `created` when the keys app made the wallet's
  phrase for it, and `birthday` is then the day it was made: no coin can have reached it before.
  Otherwise it is `restored`, with the day the person gave as `birthday`, or `null`. A wallet core
  starts scanning at the birthday, or, for a restored wallet without one, where its family began:
  segwit's activation for `bitcoin`, taproot's for `bitcoin_taproot`. Both come from the keystore's
  record, so a wallet made before it kept them reads `restored`, with no birthday.
- `request_unlock` takes `{ account, ttlMs?, count?, apps?, confirm?, reason? }`, the terms an app
  asks for. `fetch_result` returns `{ ok, result: { account, terms, expiresInMs, countLeft } }`:
  the terms the person granted, which may differ.
- **A device account** is one any signer but the keystore offers. Its database key comes from the
  keystore's `device_database_key`, made at the first open under the password the person sets in
  the keys app, with the first day of use they give as `birthday` in `approve_access`. Every later
  open needs that password. A device signs on its own screen, so it has nothing to unlock: terms in
  the decision are refused, the app's own are not granted, and `request_unlock` for it is refused
  before anything is shown. Its `origin` is always `restored`, since a device keeps no record of
  when its seed was made. A keystore wallet's birthday was set when it was made, so a decision
  that gives one for it is refused.
- A requester has at most two open or unlock requests pending, and one nobody shows within five
  minutes settles `expired_no_ack`.
- The custodian (the keys app) works the queue with `access_requests`, `acknowledge_access` (the
  lines to show, the commitment to echo, and `asked`: the wallet or the family and network to pick
  from, and the terms the app wants), `approve_access` (`{ handle, bundle_id, group?,
  password, unlock?, birthday? }`) and `reject_access`. A wrong password answers `code: wrong_secret` and
  leaves the request on screen. The database key comes from the keystore's `database_key`, the
  unlock from its `unlock`; the manager keeps neither.
- The keys app also unlocks and locks on its own: `unlock` (`{ account, password, ttlMs?,
  count?, apps, confirm? }`) and `lock` (`{ account? }`, everything for `{}`). `unlocked` lists
  every unlock with its apps and confirmation, and `open_accounts` every open wallet.

### Terms

The keystore holds an unlocked key and enforces its **time** and **count**; the manager enforces
which **apps** it covers and whether each signature is still **confirmed**. An empty `apps` means
the module that asked. `"*"` covers any app, and only with confirmation, because without it every
module could sign. With an unlock that covers a request:

- **confirmed**: the approver approves with no password, and the keystore signs inside the unlock;
- **without asking**: the request is signed as it arrives, unseen, and settles at once;
  `signed_without_asking` announces it and `unattended_signatures` lists it.

A request from a module the unlock doesn't cover still needs the password. A keystore that answers
`locked` (its time or count ran out) ends the manager's scope too, and before it shows a request as
covered or signs one unseen, the manager checks the keystore still holds that unlock. The manager locks every account
when it starts, since the terms it kept are gone.

### Events

`approval_offered` and `approval_settled` (handle, state), `approval_progress` when a request moves
to `signing`, and `accounts_changed` (count) after a signer reports its accounts changed. For opening
and unlocking: `access_requested`, `access_settled`, `unlock_changed` (account) and
`signed_without_asking` (handle). For wallets: `wallets_changed` (seed) when one is added,
unlocked or changed, and `wallets_locked` (count). Handles and ids only: the event plane is
unauthenticated.

The manager listens to each signer's `signer_accounts_changed` and `sign_progress`, and announces
what they change as they come: a device plugged out, or a job its person ended on the device. An app
that only listens hears it without anyone calling the manager first.

## The signers

Signer modules are bound at runtime through the `signer` interface dependency
(`signer.lidl`, from `logos-signer-interface`), one binding per configured name. `keystore_module`
is also a concrete dependency, so it loads with the manager. `keycard_module`,
`keycard_shell_module` and `qr_signer_module` are optional dependencies: where installed, they load
with the manager and ahead of it, and where not, the manager loads without them. A signer that doesn't answer within
three seconds for `signer_info`, or twenty for anything else, offers nothing until asked again.

A signer that shows requests on its own screen takes them whole, one per request:
`evm_transaction` (the unsigned bytes whose keccak-256 is the signing hash), `evm_message`,
`evm_typed_data`, or `btc_psbt` (the manager's own reading of the PSBT). The request is refused before
anyone is shown it when the signer can't take it: a bare digest, a request of several legs, or a kind
the signer doesn't list. The answer is checked over the manager's own digests, as a hash signer's is.

A device signer answers `sign` with a job that waits for its person. The approval then reports
`signing` until the job ends: done, refused on the device (the request settles `rejected`), or
failed. Every signature that comes back is checked against the account before a result is built.
An answer that fails the check puts the request back on screen, saying why. The doctest drives this
with `doctests/mock-device`, a fixture behind the same interface that waits for its button and can
answer wrong on purpose.

The manager calls its signers from inside its own methods, so it runs with `concurrency: "multi"`:
each call has a worker thread, and the manager's state sits behind one lock. A call that arrives
while another waits on a signer waits for that lock on its own thread. Under the default
`"single"`, the host delivered it inside the first call's nested event loop, on the thread that
held the lock, and the manager hung.

## Build and test

```sh
cd rust-lib && cargo test --no-default-features   # the core, against the interface's mock signer
nix build                                         # the module
nix build '.#lgx'                                 # an installable package
./doctests/run.sh                                 # the round trip through logoscore
```

`tools/regtest` proves the PSBT path against a real node. BDK builds native segwit and taproot sends
from the descriptors the manager derives. The manager reads them, has the interface's mock signer sign
them, and checks every signature, and bitcoind has to accept and mine the result. Forged change has to
show as a send, and a false input amount has to be refused, or for taproot sign nothing that spends:

```sh
cd tools/regtest
BITCOIND_EXE=$(nix build nixpkgs#bitcoind --no-link --print-out-paths)/bin/bitcoind cargo run --release
```
