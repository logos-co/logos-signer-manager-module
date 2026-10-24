# logos-signer-manager-module

`signer_manager_module` takes signature requests from any named module, shows them to a person
through the signer app, and has the account's signer sign: `keystore_module` for keys kept in files,
and one module per hardware wallet, each behind
[`logos.signer/1`](https://github.com/logos-co/logos-signer-interface). It holds no keys. It reads,
renders and commits to every request, computes every digest, and checks every signature against
the account's public material before anyone can collect a result.

The approval API is `keystore_module`'s, with the same names and shapes:
- **Requesters**, any named module: `request_approval`, `approval_status`, `fetch_result`,
  `ack_result` and `cancel_approval`.
- **The approver**, the signer app: `pending`, `acknowledge`, `approve` and `reject`, and
  `choose_signer` and `approval_signers` to pick which signer holding the account signs.

A requester or an approver moving here changes only the module it calls. The results are byte for
byte what the keystore returned when it signed itself.

`accounts` lists every signer's accounts, without xpubs, each under one holder. `roster` lists each
account once with every signer that holds it, ranked: the keystore, connected devices, QR wallets,
then unplugged devices. Apps pick accounts from it. `signers` says which signer modules are
consulted. `configure` names the approvers, the custodians and the signers. Unconfigured, it consults
the keystore, then the Keycard Shell's, the Keycard's and the QR signer's modules when they are
installed. Those three are optional dependencies, so installed ones load with the manager.

Each wallet, a seed whichever signers hold it, is unlocked once per session in the Signer app, by
its device, a password, or both, as its rule says. The manager then hands each module keys of its
own for that wallet's data (`data_key`), and signers list the wallet's accounts. `wallets` lists
them, `enroll_seed` registers one a signer adds, and the Signer app keeps the rules, the named
passwords and the names (see [Wallets and their keys](docs/specs.md#wallets-and-their-keys)).

See [`docs/specs.md`](docs/specs.md) for the reference, and
[`doctests/signer-manager-runtime.test.yaml`](doctests/signer-manager-runtime.test.yaml) for the
round trip through `logoscore`.

```sh
cd rust-lib && cargo test --no-default-features
nix build
```

[`tools/regtest`](tools/regtest) signs native segwit and taproot sends through the manager and has a
regtest bitcoind accept them, once over hashes and once by a mock device handed each PSBT whole.

Licensed under MIT or Apache-2.0.

### Public account origins

`accounts` preserves the optional `origin` object supplied in a signer's
`signer_accounts` response. It contains `devices` (`kind`, `id`, `name`), an optional
`phrase` (`id`, `name`), and optional derivation `path` / source `kind`. These are
public display hints, never credentials or signing authority. Metadata is captured
with the inventory response and invalidated through existing signer account events.
Only the provider chosen by registry precedence can supply an account's origin;
duplicate addresses from other providers cannot overwrite it. Older providers may
omit it, and clients must say unknown rather than infer a phrase or device.

### Signing across connections

The signer manager shares saved public Keycard account offers between the reader and USB
Shell providers for each request. It does not copy account files: labels, wallet names and
removal continue to belong to the original saved offer. A matching, paired reader takes
priority over a USB Shell. The reader checks the seed before requesting the PIN and checks
the full master public key again after unlocking.

USB presence does not identify the card inside a Shell. On first use of each USB connection,
the user confirms the master public key. The public root is cached only in memory for that
attachment; later signatures and account exports reuse it. Removal, a changed attachment,
a link failure or module restart clears verification. On macOS, the HID path contains the
IORegistry service entry ID, detecting even a reconnect between polls; other backends also
invalidate on an observed removal or path change. Opening uses the enumerated attachment path.
The UI distinguishes an unverified connection, the verified wallet and a different wallet.
A confirmed mismatching root can advance to another connected Shell; refusal or cancellation
ends the request. Every returned signature is still checked by the signer manager against
the selected account and request before release, including if the seed changes while connected.
Active jobs remain pinned to the provider that started them, even after hotplug.

Only `signer_manager_module` may supply the optional `keycardAccount` public routing metadata
to `sign`. Legacy Shell accounts must first use “Identify wallet…” to establish their full
master key identity. No PIN or pairing data is shared between the providers.
