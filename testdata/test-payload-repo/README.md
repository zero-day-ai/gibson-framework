# Test Payload Repository

This is a test repository for Gibson payload execution system testing.

## Structure

- `model/` - Model domain payloads (prompt injection, jailbreaks)
- `data/` - Data domain payloads (data poisoning, input validation)
- `interface/` - Interface domain payloads (API abuse, UI manipulation)
- `infrastructure/` - Infrastructure domain payloads
- `output/` - Output domain payloads
- `process/` - Process domain payloads

Each domain contains plugins with `payloads.json` files containing arrays of payload definitions.

This README should be ignored during payload discovery.