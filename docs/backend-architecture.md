
# PING Backend Architecture

## Architecture Style

PING uses a Modular Monolith architecture built with
Java, Spring Boot, and PostgreSQL.

The application is deployed as a single backend service
with one PostgreSQL database.

## Logical Modules

### 1. Identity
- User accounts and profiles
- Authentication and email verification
- Sessions and password reset
- Username management

### 2. Social
- Friend requests
- Friendships
- Friendship history and access revocation

### 3. Groups
- Group creation and membership
- Group invitations and join requests
- Ownership transfer
- Group archival

### 4. Pings
- Group and Direct Pings
- Participation and approval requests
- Capacity and deadline rules
- Ping lifecycle

### 5. Notifications
- Push device registration
- Transactional outbox
- Notification recipient eligibility
- Push delivery

### 6. Lifecycle
- Account deletion acceptance
- Cross-module deletion orchestration
- Cleanup coordination

## Module Boundaries

- Each module owns its business rules and persistence.
- Modules communicate through explicit application interfaces.
- Direct access to another module's repositories is discouraged.
- Cross-module transactions follow the agreed lock protocol.
- PostgreSQL is the source of truth.
- External push delivery happens after database commit.

## Technical Decisions

- Java + Spring Boot
- Spring Security
- PostgreSQL
- REST APIs
- Modular Monolith
- JUnit, Mockito, Testcontainers
- Docker and GitHub Actions

## Architecture Status

Physical Schema v1.1 is the implementation baseline.

ADR-009, ADR-011, and ADR-012 remain conditional.

Email reuse and data retention policies remain pending.

Shared Feed and Moments are Post-MVP.
