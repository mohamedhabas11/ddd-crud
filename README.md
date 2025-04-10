# ddd-crud

Domain-Driven Design (DDD) CRUD project in Go.

## Problem Statement

Most CRUD projects built in Go are structured in a flat or layered architecture. As systems grow, this leads to tight coupling and low maintainability. DDD promotes clean separation of concerns and aligns code with business rules, making systems more scalable, testable, and understandable.

## Objective

Build a CRUD application in Go using Domain-Driven Design principles to demonstrate how to:

- Model business logic cleanly.
- Decouple domain, infrastructure, and interfaces.
- Promote testability and maintainability.
- Enable swappable implementations across layers (e.g., persistence, transport).

## Bounded Contexts

This project defines the following bounded contexts:

- **Identity Context**: Admins, ShopManagers, Customers.
- **Shop Management Context**: Shops, Inventories, Employees.
- **Ordering Context**: Orders, Fulfillment logic.
- **Accounting Context**: Commission logic and revenue tracking.

## Business Logic

- [ ] Admins can activate/deactivate shops.
- [ ] Admins can activate/deactivate users.
- [ ] ShopManagers can manage employees and inventories.
- [ ] ShopManagers can manage multiple shops.
- [ ] Customers can place orders.

## System Internals

- [ ] An order can be fulfilled by multiple inventories.
- [ ] Fairness strategy applied when distributing orders across shops.
- [ ] Commission logic to reward shops fulfilling inventory for others.

### Inventory Management

Enable ShopManagers to:

- View inventory status of their own shops (for restocking).
- View inventory status of other shops (for commission-based sales).

### Fairness Strategy

When a large order cannot be fulfilled by a single shop, the system:

1. Prioritizes inventory from the originating shop.
2. Selects additional items from shops in the same region with the fewest fulfilled orders.
3. Falls back to nearest available regions.

## Core DDD Concepts

- **Entities**: Business objects with identity (`User`, `Shop`, `Order`)
- **Value Objects**: Immutable descriptors (`Status`, `Email`, `Money`)
- **Aggregates**: `Shop`, `Order` (encapsulating consistency rules)
- **Repositories**: Abstractions over data persistence
- **Application Layer**: Orchestrates domain logic and use cases
- **Domain Layer**: Pure business logic
- **Infrastructure Layer**: Persistence, HTTP interfaces, etc.

## Tech Stack

- [Go](https://golang.org/)
- [GORM](https://gorm.io/) for database persistence
- [Fiber](https://gofiber.io/) or standard `net/http` for HTTP server
- Dependency injection using [Google Wire](https://github.com/google/wire) or [Uber FX](https://github.com/uber-go/fx)

