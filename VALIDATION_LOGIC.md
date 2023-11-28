# Validation Logic
High level summary of the different steps in the Validation logic and comparison against [geth based implementation](https://github.com/ultrasoundmoney/builder/pull/1)

# Geth Logic
1. Parse ExecutionPayload into node representation of a Block ([function call](https://github.com/ultrasoundmoney/builder/blob/aa8f1a597901f303551b21d2bbf637dea1205624/eth/block-validation/api.go#L124), [definition](https://github.com/ultrasoundmoney/builder/blob/aa8f1a597901f303551b21d2bbf637dea1205624/beacon/engine/types.go#L276)
    1.  Decode Transactions ([call](https://github.com/ultrasoundmoney/builder/blob/aa8f1a597901f303551b21d2bbf637dea1205624/beacon/engine/types.go#L282), [implementation](https://github.com/ultrasoundmoney/builder/blob/aa8f1a597901f303551b21d2bbf637dea1205624/beacon/engine/types.go#L145)
    2.  Generate Withdrawal Hash ([implementation](https://github.com/ultrasoundmoney/builder/blob/aa8f1a597901f303551b21d2bbf637dea1205624/beacon/engine/types.go#L287-L296))
    3.  Combine Payload Data with decoded transactions and withdrawal hash into Block object ([implementation](https://github.com/ultrasoundmoney/builder/blob/aa8f1a597901f303551b21d2bbf637dea1205624/beacon/engine/types.go#L306-L324)
