# Protocol Action Style (Template)

## Purpose
Use this template to document one protocol action in a code-grounded, RFC-grounded way.

## File Naming Rule
- Put each action in its own file under `protocl-actions/`.
- Use kebab-case names, for example: `create-group-protocol.md`, `add-member-protocol.md`.

## Required Sections

### 1) Action Summary
- `Action Name`:
- `Actors`:
- `Trigger`:
- `Preconditions`:
- `Outputs`:

### 2) Flow Table (Mandatory)
Use this table format:

| Step | Details | Math Action (Equation / Primitive) | Place in Code | RFC 9420 Mapping | Status | Notes |
|---|---|---|---|---|---|---|
| 1 | What happens | `x = H(label, context, inputs...)` | `src/file.rs:line` | `Section` | `Implemented / Partial / Missing` | Any caveat |

Rules:
- `Details` must describe behavior, not intent only.
- `Math Action` is mandatory:
  - For cryptographic steps: show primitive and exact inputs.
  - For non-crypto steps: write `N/A (state transition only)`.
- `Place in Code` must be real file+line references.
- `RFC 9420 Mapping` must name relevant section(s).
- `Status` must explicitly say whether behavior is complete.

### 3) Security-Critical Material Tracking
Document each secret/key transition in a compact table:

| Material | Produced At | Consumed At | Place in Code | RFC 9420 Mapping | Notes |
|---|---|---|---|---|---|
| `path_secret` | where generated | where used | `src/file.rs:line` | `Section` | scope/lifetime |

### 4) Gaps / Suspicious Items (Mandatory)
If implementation differs from RFC, write it explicitly:

| Item | Why Suspicious | Evidence (Code) | RFC Impact | Suggested Fix |
|---|---|---|---|---|
| Example gap | Explanation | `src/file.rs:line` | What can go wrong | Next task |

### 5) Verification
- List exact commands/tests used to validate this action.
- Example:
```bash
cargo test --lib
cargo test --test ds_fetch_apply_e2e
```

### 6) Operator Notes
- Add short operational notes (what to show in demo, expected logs, failure signs).

---

## Minimal Skeleton (Copy/Paste)

```md
# <Action Name>

## Action Summary
- Action Name:
- Actors:
- Trigger:
- Preconditions:
- Outputs:

## Flow Table
| Step | Details | Math Action (Equation / Primitive) | Place in Code | RFC 9420 Mapping | Status | Notes |
|---|---|---|---|---|---|---|
| 1 |  |  |  |  |  |  |

## Security-Critical Material Tracking
| Material | Produced At | Consumed At | Place in Code | RFC 9420 Mapping | Notes |
|---|---|---|---|---|---|
|  |  |  |  |  |  |

## Gaps / Suspicious Items
| Item | Why Suspicious | Evidence (Code) | RFC Impact | Suggested Fix |
|---|---|---|---|---|
|  |  |  |  |  |

## Verification
```bash
# add exact commands
```

## Operator Notes
- 
```
