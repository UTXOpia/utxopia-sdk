# Changelog

## 0.1.0-alpha.4

Lets the wallet deposit path drop its OP_RETURN too.

`buildDepositPsbt` required a 73-byte `opReturnPayload` and threw without one, so
a deposit paid from the user's own BTC wallet always carried a data output — even
though the tweak flow binds the note keys through the address's tapleaf and needs
no metadata on chain. Only the faucet path could be converted.

**Changed**
- `buildDepositPsbt` — `opReturnPayload` is now optional. Omit it and the
  transaction is a plain payment: deposit output plus change, nothing else. A
  mis-sized payload is still rejected.
- `estimateDepositFee(numInputs, feeRate, inputType, hasChange, hasOpReturn?)` —
  a fifth parameter, defaulting to `true` so existing callers are unaffected.
  Without it the estimate charged for an OP_RETURN output that was never built,
  and the depositor paid the difference.

Additive: every existing caller keeps its behaviour.

## 0.1.0-alpha.3

OP_RETURN-free BTC deposits, and the key derivation that makes them recoverable.

### ⚠️ Do not use 0.1.0-alpha.2

`0.1.0-alpha.2` was published from an intermediate state. Its `createTweakDeposit`
derives a deposit address as `TapTweak(ika_key, commitment)` — a *tweak of the
custody key*. No program accepts that address, and Ika's MPC cannot sign for a
tweaked key, so **coins sent to an address derived by alpha.2 are unspendable by
anyone**. Upgrade before calling that function.

### Deposits without OP_RETURN

An exchange withdrawal form cannot attach an OP_RETURN, so a deposit that needs
one cannot be funded from an exchange. The note keys now ride in Solana
instruction data instead, bound to the deposit address itself:

```
leaf    = <sha256(npk ‖ eph)> OP_DROP <ika_xonly> OP_CHECKSIG
address = TapTweak(NUMS, tapleaf_hash(leaf))
```

Nothing on the Bitcoin side marks the transaction as a deposit — it is a plain
payment to a P2TR address. Substituting either key derives a different leaf, and
so a different address, which the funding transaction never paid.

The internal key is BIP-341's NUMS point, making the key path unspendable. That
is forced, not chosen: Ika's MPC cannot sign for a tweaked key, so an address
whose internal key were the dWallet key plus a per-deposit tweak would be
unspendable by the very custodian meant to sweep it. Script-path binding keeps
the deposit under pool custody from the moment it confirms.

**Added**
- `deriveDepositAddress(commitment, ikaXOnlyPubkey, network)` — returns the
  address plus the `leafScript` and `controlBlock` a spend needs
- `depositLeafScript(commitment, ikaXOnlyPubkey)`
- `DEPOSIT_NUMS_INTERNAL_KEY`
- `buildVerifyDepositInstructionData` (disc 25) and
  `buildVerifyDepositPermissionedInstructionData` (disc 26)
- `UTXOpiaClient.prepareTweakDeposit({ depositIndex, ikaXOnlyPubkey })`

**Changed**
- `createTweakDeposit(recipientMeta, vaultXOnlyPubkey, recovery, network)` —
  takes `recovery` and derives a script-path address. Its alpha.2 shape is gone.
- `deriveTaprootAddress` also returns `parity`, needed for a control block.
  Additive; existing callers are unaffected.

### Recoverable ephemeral keys

A deposit address commits to its ephemeral key through the tapleaf, and the key
path is unspendable — so a random ephemeral key that is later lost burns the
coins outright. Deposit ephemeral keys are now derived, never random:

```
viewingNode = sha256("utxopia:deposit-viewing-node:v1" ‖ viewingPrivKey)
eph         = sha256("utxopia:deposit-ephemeral:v1" ‖ viewingNode ‖ u32le(index))
```

Indexed off the *viewing* key rather than the master seed, so recovery can be
delegated: hand someone the node and they can rebuild every address, tapleaf and
control block — and move the BTC — without any ability to spend a note. Spending
still needs the spending key and the nullifying key, neither reachable from here.

`recovery` is required on `createTweakDeposit` on purpose. An optional safety
property is one somebody forgets, and the failure here is not a bug report.

**Added**
- `depositViewingNode(viewingPrivKey)`
- `depositEphemeralKeyPair({ viewingNode, depositIndex })`
- `type DepositRecoveryMaterial`

### Outgoing payment history

An announcement is encrypted to the recipient's viewing key and the sender
discards the ephemeral private key, so a sender could not rediscover what they
paid out — that history existed only in local storage. Indexing the ephemeral key
off a separate node makes every outgoing payment recomputable from keys alone.
Zcash calls the equivalent an outgoing viewing key.

The node is deliberately distinct from the deposit one. They authorise different
things and one must not smuggle in the other:

- deposit node → *"you can recover my BTC"*
- outgoing node → *"you can see who I paid"*

**Added**
- `outgoingViewingNode(viewingPrivKey)`
- `outgoingEphemeralKeyPair({ outgoingNode, sendIndex })`
- `findNextSendIndex(outgoingNode, seenEphemeralPubs, gapLimit = 20)` — recovers
  the next unused index from the ephemeral pubkeys already on chain. It scans
  past holes left by abandoned payments, and it is a **floor**, not the live
  counter: a payment broadcast but not yet indexed is invisible to it, so a
  sender keeping local state must take `max(localCounter, findNextSendIndex(…))`.
  Reusing an index re-derives the same ephemeral key, which against the same
  recipient means the same note commitment twice.
- `type OutgoingRecoveryMaterial`

**Changed**
- `createStealthDeposit(recipientMeta, amountSats, tokenId, outgoing?)` — the new
  parameter is optional, unlike the deposit one, because omitting it costs a
  record you cannot reconstruct rather than funds.

Change outputs and the OP_RETURN deposit helpers still use random ephemeral keys.
Change is announced to your own viewing key and is already found by scanning, so
determinism would buy a property you have; every derived key costs a counter that
must be persisted and never reused.

### Cross-implementation vectors

The address derivation exists in four places — this SDK, the Solana program, the
backend sweeper, and the e2e harness. All four are pinned to the same fixtures,
each asserted independently, because a mismatch has no loud failure mode: the
addresses simply never credit.

```
commitment  adfafc05aac733fe9509f43bd1d158c882890351c7f343634c8ef9ea42cdb505
leafHash    06b24c2fa653211557f4c8106c52ac04480606e06850fd967e87a995750a2933
outputKey   fd6a4b0b28873788b11b45d8fdf81918d82c39b0503690647791e92215bf8b59
address     bcrt1pl44ykzegsumc3vgmghv0m7qerrvzcwds2qmfqerhj85jy9dl3dvs084mpx
```

### Compatibility

Additive for existing consumers apart from `createTweakDeposit`, which was
introduced and reshaped within the alpha.2 line and has no stable prior form.
`deriveTaprootAddress`, `createStealthDeposit` and every OP_RETURN deposit helper
keep their existing behaviour.
