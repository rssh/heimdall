# Technical questions

Discrepancies and open questions to resolve with FluidTokens (upstream
`ft-bifrost-bridge`). Mirrored in
`internal-docs/bitfrost/heimdall/spec_differences.md`.

## 1. Registration linked-list: node key in datum (spec) vs NFT asset name (code)

`documentation/technical_documentation.md` §3.2 "Registration Linked-List"
(added 2026-03-03) sketches the node **datum** as carrying the ordering key:

```json
{ key              :: ByteArray        -- pool_id (ordering key)
, next             :: ByteArray | Null -- key of the next node, or null for the tail
, data             ::
    { bifrost_id_pk :: ByteArray
    , bifrost_url   :: ByteArray
    }
}
```

The implemented contracts (`onchain/validators/bitcoin/spos-registry.ak` +
`aiken_design_patterns/linked_list`, merged 2026-04-20 in M2 PR #15, confirmed
against the compiled `plutus.json` blueprint) store **no key in the datum**.
The element's key is the asset name of the registry-policy NFT held in the
UTxO (`"reg-root"` for the root, `pool_id` for nodes, empty node-key prefix),
and the datum is only:

```text
Element       = Constr(0, [ ElementData, Link ])
ElementData   = Constr(0, [ Constr(0, []) ])                            -- Root{ListRootData}
              | Constr(1, [ Constr(0, [bifrost_id_pk, bifrost_url]) ])  -- Node{RegistrationNodeData}
Link          = Constr(0, [ next_key ]) | Constr(1, [])                 -- Some key / None
```

The difference is not cosmetic. A datum is unauthenticated, mutable state:
anyone can park a UTxO at the script address with a forged `key`, and every
spend path would have to re-check "key unchanged" and "key == token name".
The asset name is minted under the registry policy (validated once, at mint),
immutable without a burn/mint the policy controls, and indexable by chain
indexers (`(policy, pool_id)` lookup). The implemented design is the stronger
one; the spec sketch describes the *logical* record, not the wire format.

Anything decoding registration datums from the spec sketch instead of the
contracts would mis-parse every element. Heimdall follows the contracts
(`src/cardano/registry.rs`, WI-002).

Related naming drift in the same section: §3.2 says the operations correspond
to `ordered.prepend` / `ordered.remove`; the implementation uses
`linked_list.insert_ascending` / `linked_list.remove`.

**Question for FluidTokens:** update §3.2 to the implemented shape (key as
NFT asset name, `Element{data, link}` datum), or is a datum-key redesign
intended? Until answered, the spec/code mismatch is tracked as a heimdall
work item blocking register_spo tx construction (WI-005).
