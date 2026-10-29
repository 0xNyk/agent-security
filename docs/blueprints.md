# Technical blueprints

These diagrams describe control flow and authority. They are kept in Mermaid so labels remain searchable and changes remain reviewable.

## Repository boundary

```mermaid
flowchart LR
    incoming[Untrusted code] --> vet[vet-incoming]
    vet -->|ADOPT| review[Human review]
    vet -->|REVIEW| review
    vet -->|REJECT| quarantine[Keep outside workspace]
    review --> work[Working repository]
    work --> tests[Offline fixture tests]
    tests --> scan[scan-repo]
    scan -->|clean within known patterns| publish[Public boundary]
    scan -->|finding| repair[Inspect or remove]
    repair --> tests
```

The publish arrow does not mean safe. It means the known-pattern gate and project tests passed.

## Scanner pipeline

```mermaid
flowchart TD
    scope[Resolve staged, full-tree, or ref scope] --> tracked[Read selected tracked files]
    tracked --> generic[Generic leak patterns]
    tracked --> dropper[Same-file dropper patterns]
    tracked --> unicode[Invisible Unicode check]
    tracked --> markers[Optional local private markers]
    generic --> verdict[Severity and allow review]
    dropper --> verdict
    unicode --> verdict
    markers --> verdict
    verdict -->|CRITICAL| fail[Fail]
    verdict -->|MAJOR| block[Fail unless explicitly downgraded]
    verdict -->|none| clean[Clean within known patterns]
```

Private markers remain outside the repository. The generic layer runs when no marker file exists and prints that limitation.

## Destructive-operation control stack

```mermaid
flowchart BT
    command[Agent or human command] --> shim[PATH shim]
    command --> hook[Supported host pre-tool hook]
    shim --> confirm[Repo-specific confirmation]
    hook --> confirm
    confirm --> github[GitHub API]
    direct[Direct REST client or unguarded binary] --> github
    github --> token[Token permissions]
    github --> org[Organization restrictions]
    github --> branch[Branch protection]
```

The shim and hook are bypassable brakes. Token, organization, and branch controls are server-side boundaries.

## Untrusted-content handling

```mermaid
flowchart LR
    fetched[Fetched or pasted content] --> tripwire[scan-content]
    tripwire --> inspect[Classify as data]
    inspect --> isolate[Limit credentials, private data, and outbound tools]
    isolate --> human{Would content-derived instructions cause an action?}
    human -->|yes| approval[Require human approval]
    human -->|no| analyze[Continue analysis]
```

Detection supports this flow but does not enforce it. The behavioral contract lives in [untrusted content](../references/untrusted-content.md).


## Research egress

```mermaid
flowchart LR
    intent[Agent intends to fetch a URL] --> classify[check-url]
    classify -->|ALLOW| fetch[Fetch]
    classify -->|REVIEW| operator{Operator names the exact URL?}
    classify -->|BLOCK| refuse[Never fetched]
    operator -->|yes| fetch
    operator -->|no| refuse
    fetch --> content[Fetched content]
    content --> tripwire[scan-content]
```

The decision happens before retrieval, from the URL string alone. `BLOCK` has no override; `REVIEW` has one, and it must name the exact URL. Whatever comes back is still untrusted data.

## Host runtime

```mermaid
flowchart TD
    gates[Gate controls: scan, vet, scan-content, check-url, guard] --> paths[See only what crosses their path]
    delivery[Lifecycle script, build step, headless worker] --> implant[Detached process]
    implant -. never crosses a gate .-> paths
    implant --> host[(Running host)]
    host --> audit[runtime-audit]
    audit --> proc[Command-line shapes]
    audit --> drift[Autostart and profile drift vs baseline]
    proc --> verdict{CRIT, WARN, BLIND, or clean}
    drift --> verdict
```

This is the one blueprint where the arrow that matters is the dotted one. A control on a path cannot see what never takes the path, so no amount of gate coverage substitutes for looking at the machine. `runtime-audit` looks at the machine — manually, at a single moment, at known command-line shapes. Schedule it, or it only ever confirms what you already suspected.

## On-disk indicators

```mermaid
flowchart TD
    publish[Compromised release, hijacked Action tag, worm loader] --> disk[(Installed, dormant)]
    disk -. not a process yet .-> runtime[runtime-audit sees nothing]
    disk --> sweep[ioc-sweep]
    list[ioc-indicators.txt] --> sweep
    sweep --> locks[Lockfiles, manifests, caches]
    sweep --> paths[Drop paths, loaders, tmp staging]
    sweep --> actions[Workflows: Action refs not SHA-pinned]
    sweep --> cfg[Repo + home agent configs vs baseline]
    locks --> verdict{findings, clean, or BLIND}
    paths --> verdict
    actions --> verdict
    cfg --> verdict
```

The blueprint is a list and a walk. Everything it knows comes from the indicator file, so
it is only as current as the last line appended, and it says so by exiting `1` on a match,
`0` on none, and `2` when it could not look.
