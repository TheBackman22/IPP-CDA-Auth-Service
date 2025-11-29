# Auth Service

IPP-CDA Authentication & Identity Management Microservice

## Overview

The Auth Service is a standalone microservice responsible for user authentication and identity management in the IPP-CDA platform. It issues and validates JWT tokens used by all other services to authenticate requests.

## Technology Stack

- **Java**: 21 (LTS with virtual threads)
- **Framework**: Spring Boot 3.2.x
- **Security**: Spring Security 6.x
- **JWT**: jjwt 0.12.x
- **Database**: PostgreSQL 15+
- **Build Tool**: Maven

## Quick Start

### Prerequisites

- Java 21 or higher
- Maven 3.9+
- PostgreSQL 15+
- Docker (optional, for containerized deployment)

### Local Development

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd auth-service
   ```

2. **Set up PostgreSQL database**
   ```bash
   createdb ippcda
   psql -d ippcda -f src/main/resources/db/migration/V1__initial_schema.sql
   ```

3. **Configure environment variables**
   ```bash
   export DB_USERNAME=postgres
   export DB_PASSWORD=postgres
   export JWT_SECRET=your-256-bit-secret-key-here-min-32-chars
   ```

4. **Run the application**
   ```bash
   mvn spring-boot:run
   ```

The service will start on `http://localhost:8081`

### Using Docker

```bash
docker build -t auth-service .
docker run -p 8081:8081 \
  -e DB_USERNAME=postgres \
  -e DB_PASSWORD=postgres \
  -e JWT_SECRET=your-secret \
  auth-service
```

## API Endpoints

### Public Endpoints

- `POST /api/v1/auth/register` - Create new user account
- `POST /api/v1/auth/login` - Authenticate and get tokens
- `POST /api/v1/auth/refresh` - Refresh access token

### Protected Endpoints

- `GET /api/v1/auth/me` - Get current user profile
- `PUT /api/v1/auth/me` - Update current user profile
- `POST /api/v1/auth/logout` - Invalidate refresh token

### Internal Endpoints

- `POST /api/v1/auth/validate` - Validate token (requires service key)

### Health Check

- `GET /actuator/health` - Service health status

## Configuration

Key configuration properties in `application.yml`:

```yaml
server:
  port: 8081

jwt:
  secret: ${JWT_SECRET}
  access-token-expiration: 3600000    # 1 hour
  refresh-token-expiration: 604800000 # 7 days

internal:
  service-key: ${INTERNAL_SERVICE_KEY}
```

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `PORT` | No | 8081 | Server port |
| `DB_USERNAME` | Yes | - | Database username |
| `DB_PASSWORD` | Yes | - | Database password |
| `JWT_SECRET` | Yes | - | Base64-encoded 256-bit secret |
| `INTERNAL_SERVICE_KEY` | Yes | - | Key for service-to-service auth |

## Testing

```bash
# Run all tests
mvn test

# Run tests with coverage
mvn test jacoco:report

# Run integration tests only
mvn test -Dtest=*IntegrationTest
```

## Project Structure

```
auth-service/
├── src/
│   ├── main/
│   │   ├── java/com/ippcda/auth/
│   │   │   ├── config/          # Configuration classes
│   │   │   ├── controller/      # REST controllers
│   │   │   ├── dto/             # Data transfer objects
│   │   │   ├── entity/          # JPA entities
│   │   │   ├── exception/       # Custom exceptions
│   │   │   ├── filter/          # Security filters
│   │   │   ├── repository/      # JPA repositories
│   │   │   ├── service/         # Business logic
│   │   │   └── validation/      # Custom validators
│   │   └── resources/
│   │       ├── application.yml
│   │       └── db/migration/    # Database migrations
│   └── test/                    # Unit and integration tests
├── Dockerfile
├── pom.xml
└── README.md
```

## Security

- Passwords are hashed using BCrypt (cost factor 12)
- JWT tokens signed with HS384 algorithm
- Refresh tokens stored as SHA-256 hashes
- Stateless authentication
- CORS configured for allowed origins

## Deployment

See [SERVICE_SPEC.md](SERVICE_SPEC.md) for detailed deployment instructions including:
- Docker configuration
- Render.com deployment
- Production checklist

## Documentation

- [Service Specification](SERVICE_SPEC.md) - Complete technical specification
- API documentation available at `/swagger-ui.html` (when enabled)

## License

Proprietary - IPP-CDA Platform
