# Empire Knowledge Pack Integration

`legends-a2ui` ships an attachable `legends.knowledge-pack/v1` manifest at `knowledge/a2ui/pack.json`.

## Verification

```sh
legends-a2ui knowledge-pack --check --json
```

## Attachment

```sh
cto-legends run legends-empire -- knowledge attach <pack.json> --vault <vault-path>
```

Suggested home inside the vault: `wiki/library/legends-a2ui/a2ui`.
