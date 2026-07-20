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

