# Crypto Conditions

> Implementation of crypto-conditions

## Usage

``` js
const conditions = require('@ripple/five-bells-conditions')

// Check a condition for validity
const validationResult = conditions.validate({ ... })
// validationResult = { valid: false, errors: [ ... ]}

// Check if a fulfillment completes the condition
const result = conditions.testFulfillment({ ... }, { ... })
// result = true
```
