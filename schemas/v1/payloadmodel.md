# PayloadModel v1-0-0

Individual payload model.

## Required Fields

| Field | Type | Description | Constraints |
|-------|------|-------------|-------------|
| **author** | string | Payload author | minLength: 1 |
| **category** | any | Module category | - |
| **content** | string | Payload content | minLength: 1 |
| **domain** | any | Attack domain this payload belongs to | - |
| **name** | string | Payload name | minLength: 1, maxLength: 200 |

## Optional Fields

| Field | Type | Description | Constraints |
|-------|------|-------------|-------------|
| created_at | string | Timestamp when the instance was created | - |
| description | string \| null | Payload description | - |
| expected_indicators | array | Expected success indicators in response | - |
| failure_indicators | array | Indicators of payload failure/detection | - |
| id | string | Unique identifier for the model instance | - |
| license | string | Payload license | - |
| metadata | any | Payload metadata | - |
| owasp_category | null | Related OWASP category | - |
| references | array | Reference URLs or citations | - |
| safe_for_production | boolean | Whether payload is safe for production testing | - |
| severity | any | Expected severity if successful | - |
| source | string \| null | Payload source/origin | - |
| status | any | Payload status | - |
| tags | array | Payload tags | - |
| updated_at | string \| null | Timestamp when the instance was last updated | - |
| validated | boolean | Whether payload has been validated | - |
| variants | array | Payload variants (encodings, transformations) | - |
| version | string | Payload version | - |

## Examples

### Valid Payload
```json
{
  "name": "example_name",
  "category": "example_category",
  "domain": "example_domain",
  "author": "example_author",
  "content": "example_content"
}
```

## Validation

Use the provided JSON Schema to validate payloads:

```bash
# Using ajv-cli
ajv validate -s schemas/v1/payload.json -d your-payload.json

# Using Python
from gibson.utils.payload_validator import PayloadValidator
validator = PayloadValidator(version="v1")
is_valid, errors = validator.validate(your_payload)
```
