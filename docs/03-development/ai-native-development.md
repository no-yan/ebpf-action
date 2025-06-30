# Documentation Guidelines for AI-Native Development

## Overview

This document establishes guidelines for writing effective documentation comments in development environments where AI tools like Claude Code handle over 80% of implementation.

## Fundamental Principles

### 1. Intent-First Principle

* Document **design intent**, not **implementation details**.
* Emphasize "why" and "for what purpose" rather than "how".
* AI can read implementations but cannot infer business rationale.

### 2. Eliminate Redundancy

* Do not write obvious comments.
* Avoid including information that can be expressed through type annotations.
* Express through code whenever possible.

### 3. AI Collaboration Principle

* Provide context necessary for AI's future modifications.
* Clearly mark areas requiring human judgment.
* Warn about patterns easily misunderstood by AI.

## Guidelines by Comment Level

### Module/Package Level

```python
"""
Payment processing module

Responsibilities:
- Integration with external payment providers
- Payment state management and retry logic
- Audit logging

Design Decisions:
- Stripe prioritized, with PayPal fallback maintained (business decision, Q3 2024)
- Require idempotency_key for all API calls to ensure idempotency
- No retention of card information for PCI DSS compliance

AI Notes:
- Implement PaymentGateway interface for new payment providers
- Always use Decimal type for monetary amounts (no floats allowed)
"""
```

### Class Level

```python
class OrderProcessor:
    """
    Core logic for order processing

    Business Rules:
    - Allow partial shipments if stock insufficient (B2B only)
    - Orders over 1,000,000 JPY require manual approval
    - Cancellations allowed up to 24 hours before shipment

    State Transitions:
    PENDING -> CONFIRMED -> PROCESSING -> SHIPPED
         \\-> CANCELLED (only within 24h)

    External Dependencies:
    - InventoryService: inventory checks and reservations
    - PaymentGateway: payment processing
    - NotificationService: customer notifications (async)
    """
```

### Function/Method Level

```python
def calculate_shipping_cost(
    items: List[OrderItem],
    destination: Address,
    express: bool = False
) -> Decimal:
    """
    Calculate shipping cost

    Business Rules:
    - Remote islands incur an additional fee (+1,500 JPY)
    - Shipments over 10kg are treated as large shipments
    - Mixed frozen/refrigerated items charged at frozen rate

    Notes:
    - Rates obtained from ShippingRateTable (updated monthly)
    - When modifying via AI, always confirm latest rates
    """
    # implementation (no comments)
```

## Anti-Patterns

### ❌ Comments to Avoid

```python
# Bad example: explains implementation
def get_user(user_id: int) -> User:
    """
    Retrieve user by user ID

    Args:
        user_id: ID of the user

    Returns:
        User: user object
    """
    # Search database by user ID
    user = db.query(User).filter(User.id == user_id).first()
    # Return user
    return user
```

### ✅ Good Comments

```python
def get_user(user_id: int) -> User:
    """
    Retrieves user including deleted ones

    Note: Retained for 90 days post-GDPR deletion requests for auditing
    """
    return db.query(User).filter(User.id == user_id).first()
```

## Special Documentation Cases

### 1. Patterns Easily Misunderstood by AI

```python
# AI-WARNING: Intentional O(n²) complexity
# Reason: Dataset always under 100 items, prioritizing readability
for item in items:
    for other in items:
        if item.id != other.id:
            process_pair(item, other)
```

### 2. Temporary Workarounds

```python
# TEMP-WORKAROUND: [JIRA-1234]
# Workaround PayPal API bug (verified 2024-11-15)
# Remove after confirmed fix
if provider == "paypal":
    amount = str(int(amount * 100) / 100)
```

### 3. Performance Optimization

```python
# PERF-CRITICAL: Called 1 million times daily
# - Caching required
# - Database access forbidden
# - Must complete within 50ms
@cache(ttl=300)
def check_rate_limit(user_id: str) -> bool:
    # implementation
```

## Criteria for Inline Comments

Use inline comments only for:

1. **Complex regex or algorithms**

   ```python
   # Simplified RFC 5322 email validation
   email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
   ```

2. **Explaining magic numbers**

   ```python
   timeout = 30  # Recommended timeout by Stripe
   ```

3. **Future extension points**

   ```python
   # TODO: Extend for multilingual support
   message = "Order received"
   ```

## Comments as Metadata

### Structured Metadata Use

```python
@deprecated(since="2.0", remove_in="3.0", alternative="process_order_v2")
@performance(sla_ms=100, peak_rps=1000)
@business_critical(level="high", owner="payment-team")
def process_order(order: Order) -> Result:
    """
    Legacy order processing (no new use)

    Migration guide: docs/migration/order-v2.md
    """
```

## Checklist

Before writing documentation comments, verify:

* [ ] Does this comment include information AI cannot infer from the implementation?
* [ ] Are business rules or design decisions explained?
* [ ] Are there warnings or notes needed for future changes?
* [ ] Does it avoid repeating what is evident from the code?
* [ ] Does it provide necessary context for human reviewers?

## Continuous Improvement

* Quarterly review AI collaboration patterns
* Actively delete obsolete comments
* Update guidelines as AI capabilities improve



