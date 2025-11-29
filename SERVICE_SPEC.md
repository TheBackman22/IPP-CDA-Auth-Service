# Auth Service - Service Specification

*IPP-CDA Authentication & Identity Management Microservice*

---

## Table of Contents

1. [Overview](#1-overview)
2. [Responsibilities](#2-responsibilities)
3. [Technology Stack](#3-technology-stack)
4. [API Contract](#4-api-contract)
5. [Data Model](#5-data-model)
6. [Security Implementation](#6-security-implementation)
7. [Configuration](#7-configuration)
8. [Error Handling](#8-error-handling)
9. [Integration Points](#9-integration-points)
10. [Project Structure](#10-project-structure)
11. [Implementation Guide](#11-implementation-guide)
12. [Testing](#12-testing)
13. [Deployment](#13-deployment)
14. [Checklist](#14-checklist)

---

## 1. Overview

The Auth Service is a standalone microservice responsible for user authentication and identity management in the IPP-CDA platform. It issues and validates JWT tokens used by all other services to authenticate requests.

### Service Identity

| Property | Value |
|----------|-------|
| Service Name | `auth-service` |
| Default Port | `8081` |
| Context Path | `/api/v1/auth` |
| Database Schema | `auth_schema` |

### Key Metrics

| Metric | Target |
|--------|--------|
| Login latency | < 200ms |
| Token validation | < 10ms |
| Availability | 99.9% |

---

## 2. Responsibilities

### In Scope

- User registration with email/password
- User login and JWT token generation
- Access token refresh using refresh tokens
- Token validation endpoint for other services
- Password hashing and verification
- User profile retrieval and updates
- Password reset flow (optional Phase 2)

### Out of Scope

- OAuth2/Social login (future enhancement)
- Multi-factor authentication (future enhancement)
- Role-based access control beyond basic user role
- Session management (stateless JWT only)

---

## 3. Technology Stack

| Component | Technology | Version | Purpose |
|-----------|------------|---------|---------|
| Runtime | Java | 21 | LTS with virtual threads |
| Framework | Spring Boot | 3.2.x | Application framework |
| Security | Spring Security | 6.x | Authentication/authorization |
| JWT | jjwt (io.jsonwebtoken) | 0.12.x | JWT creation/validation |
| ORM | Spring Data JPA | 3.2.x | Database access |
| Database | PostgreSQL | 15+ | User persistence |
| Validation | Jakarta Validation | 3.0 | Request validation |
| Build | Maven or Gradle | Latest | Build tool |
| Testing | JUnit 5, Mockito | Latest | Unit/integration tests |

### Dependencies (pom.xml)

```xml
<dependencies>
    <!-- Spring Boot Starters -->
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-web</artifactId>
    </dependency>
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-security</artifactId>
    </dependency>
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-data-jpa</artifactId>
    </dependency>
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-validation</artifactId>
    </dependency>
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-actuator</artifactId>
    </dependency>
    
    <!-- Database -->
    <dependency>
        <groupId>org.postgresql</groupId>
        <artifactId>postgresql</artifactId>
        <scope>runtime</scope>
    </dependency>
    
    <!-- JWT -->
    <dependency>
        <groupId>io.jsonwebtoken</groupId>
        <artifactId>jjwt-api</artifactId>
        <version>0.12.5</version>
    </dependency>
    <dependency>
        <groupId>io.jsonwebtoken</groupId>
        <artifactId>jjwt-impl</artifactId>
        <version>0.12.5</version>
        <scope>runtime</scope>
    </dependency>
    <dependency>
        <groupId>io.jsonwebtoken</groupId>
        <artifactId>jjwt-jackson</artifactId>
        <version>0.12.5</version>
        <scope>runtime</scope>
    </dependency>
    
    <!-- Utilities -->
    <dependency>
        <groupId>org.projectlombok</groupId>
        <artifactId>lombok</artifactId>
        <optional>true</optional>
    </dependency>
    
    <!-- Testing -->
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-test</artifactId>
        <scope>test</scope>
    </dependency>
    <dependency>
        <groupId>org.springframework.security</groupId>
        <artifactId>spring-security-test</artifactId>
        <scope>test</scope>
    </dependency>
    <dependency>
        <groupId>org.testcontainers</groupId>
        <artifactId>postgresql</artifactId>
        <scope>test</scope>
    </dependency>
</dependencies>
```

---

## 4. API Contract

### Base URL

```
Production: https://auth.ipp-cda.example.com/api/v1/auth
Development: http://localhost:8081/api/v1/auth
```

### Endpoints Summary

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| POST | `/register` | Create new user account | No |
| POST | `/login` | Authenticate and get tokens | No |
| POST | `/refresh` | Refresh access token | No (refresh token) |
| POST | `/logout` | Invalidate refresh token | Yes |
| GET | `/me` | Get current user profile | Yes |
| PUT | `/me` | Update current user profile | Yes |
| POST | `/validate` | Validate token (internal) | Service Key |

---

### 4.1 Register User

Creates a new user account.

**Request**

```http
POST /api/v1/auth/register
Content-Type: application/json

{
    "email": "user@example.com",
    "password": "SecurePass123!",
    "displayName": "John Doe",
    "timezone": "America/Chicago"
}
```

**Validation Rules**

| Field | Rules |
|-------|-------|
| email | Required, valid email format, unique |
| password | Required, min 8 chars, 1 uppercase, 1 lowercase, 1 number |
| displayName | Optional, max 100 chars |
| timezone | Optional, valid IANA timezone, defaults to "UTC" |

**Response - Success (201 Created)**

```json
{
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "email": "user@example.com",
    "displayName": "John Doe",
    "timezone": "America/Chicago",
    "createdAt": "2025-01-15T10:30:00Z"
}
```

**Response - Validation Error (400 Bad Request)**

```json
{
    "timestamp": "2025-01-15T10:30:00Z",
    "status": 400,
    "error": "Bad Request",
    "code": "VALIDATION_ERROR",
    "message": "Validation failed",
    "path": "/api/v1/auth/register",
    "details": [
        {
            "field": "password",
            "message": "Password must contain at least one uppercase letter"
        }
    ]
}
```

**Response - Email Exists (409 Conflict)**

```json
{
    "timestamp": "2025-01-15T10:30:00Z",
    "status": 409,
    "error": "Conflict",
    "code": "EMAIL_ALREADY_EXISTS",
    "message": "An account with this email already exists",
    "path": "/api/v1/auth/register"
}
```

---

### 4.2 Login

Authenticates user and returns JWT tokens.

**Request**

```http
POST /api/v1/auth/login
Content-Type: application/json

{
    "email": "user@example.com",
    "password": "SecurePass123!"
}
```

**Response - Success (200 OK)**

```json
{
    "accessToken": "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9...",
    "refreshToken": "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9...",
    "tokenType": "Bearer",
    "expiresIn": 3600,
    "user": {
        "id": "550e8400-e29b-41d4-a716-446655440000",
        "email": "user@example.com",
        "displayName": "John Doe",
        "timezone": "America/Chicago"
    }
}
```

**Response - Invalid Credentials (401 Unauthorized)**

```json
{
    "timestamp": "2025-01-15T10:30:00Z",
    "status": 401,
    "error": "Unauthorized",
    "code": "INVALID_CREDENTIALS",
    "message": "Invalid email or password",
    "path": "/api/v1/auth/login"
}
```

---

### 4.3 Refresh Token

Obtains new access token using refresh token.

**Request**

```http
POST /api/v1/auth/refresh
Content-Type: application/json

{
    "refreshToken": "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9..."
}
```

**Response - Success (200 OK)**

```json
{
    "accessToken": "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9...",
    "tokenType": "Bearer",
    "expiresIn": 3600
}
```

**Response - Invalid/Expired Refresh Token (401 Unauthorized)**

```json
{
    "timestamp": "2025-01-15T10:30:00Z",
    "status": 401,
    "error": "Unauthorized",
    "code": "INVALID_REFRESH_TOKEN",
    "message": "Refresh token is invalid or expired",
    "path": "/api/v1/auth/refresh"
}
```

---

### 4.4 Logout

Invalidates the refresh token (blacklists it).

**Request**

```http
POST /api/v1/auth/logout
Authorization: Bearer {access_token}
Content-Type: application/json

{
    "refreshToken": "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9..."
}
```

**Response - Success (204 No Content)**

No body.

---

### 4.5 Get Current User

Returns the authenticated user's profile.

**Request**

```http
GET /api/v1/auth/me
Authorization: Bearer {access_token}
```

**Response - Success (200 OK)**

```json
{
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "email": "user@example.com",
    "displayName": "John Doe",
    "timezone": "America/Chicago",
    "createdAt": "2025-01-15T10:30:00Z",
    "updatedAt": "2025-01-15T10:30:00Z"
}
```

---

### 4.6 Update Current User

Updates the authenticated user's profile.

**Request**

```http
PUT /api/v1/auth/me
Authorization: Bearer {access_token}
Content-Type: application/json

{
    "displayName": "John D.",
    "timezone": "America/New_York"
}
```

**Response - Success (200 OK)**

```json
{
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "email": "user@example.com",
    "displayName": "John D.",
    "timezone": "America/New_York",
    "createdAt": "2025-01-15T10:30:00Z",
    "updatedAt": "2025-01-15T11:45:00Z"
}
```

---

### 4.7 Validate Token (Internal)

Internal endpoint for other services to validate tokens.

**Request**

```http
POST /api/v1/auth/validate
X-Internal-Service-Key: {service_key}
Content-Type: application/json

{
    "token": "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9..."
}
```

**Response - Valid Token (200 OK)**

```json
{
    "valid": true,
    "userId": "550e8400-e29b-41d4-a716-446655440000",
    "email": "user@example.com",
    "expiresAt": "2025-01-15T11:30:00Z"
}
```

**Response - Invalid Token (200 OK)**

```json
{
    "valid": false,
    "reason": "TOKEN_EXPIRED"
}
```

---

## 5. Data Model

### 5.1 Database Schema

```sql
-- Create schema
CREATE SCHEMA IF NOT EXISTS auth_schema;

-- Users table
CREATE TABLE auth_schema.users (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email           VARCHAR(255) NOT NULL UNIQUE,
    password_hash   VARCHAR(255) NOT NULL,
    display_name    VARCHAR(100),
    timezone        VARCHAR(50) NOT NULL DEFAULT 'UTC',
    email_verified  BOOLEAN NOT NULL DEFAULT FALSE,
    active          BOOLEAN NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Refresh tokens table (for blacklisting/tracking)
CREATE TABLE auth_schema.refresh_tokens (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID NOT NULL REFERENCES auth_schema.users(id) ON DELETE CASCADE,
    token_hash      VARCHAR(255) NOT NULL UNIQUE,
    expires_at      TIMESTAMP WITH TIME ZONE NOT NULL,
    revoked         BOOLEAN NOT NULL DEFAULT FALSE,
    revoked_at      TIMESTAMP WITH TIME ZONE,
    created_at      TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    
    CONSTRAINT fk_refresh_token_user 
        FOREIGN KEY (user_id) REFERENCES auth_schema.users(id)
);

-- Indexes
CREATE INDEX idx_users_email ON auth_schema.users(email);
CREATE INDEX idx_users_active ON auth_schema.users(active) WHERE active = true;
CREATE INDEX idx_refresh_tokens_user_id ON auth_schema.refresh_tokens(user_id);
CREATE INDEX idx_refresh_tokens_hash ON auth_schema.refresh_tokens(token_hash);
CREATE INDEX idx_refresh_tokens_expires ON auth_schema.refresh_tokens(expires_at) 
    WHERE revoked = false;

-- Updated_at trigger
CREATE OR REPLACE FUNCTION auth_schema.update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TRIGGER update_users_updated_at 
    BEFORE UPDATE ON auth_schema.users
    FOR EACH ROW EXECUTE FUNCTION auth_schema.update_updated_at_column();
```

### 5.2 JPA Entities

```java
// User.java
@Entity
@Table(name = "users", schema = "auth_schema")
@Getter @Setter
@NoArgsConstructor
public class User {
    
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;
    
    @Column(nullable = false, unique = true)
    private String email;
    
    @Column(name = "password_hash", nullable = false)
    private String passwordHash;
    
    @Column(name = "display_name", length = 100)
    private String displayName;
    
    @Column(nullable = false, length = 50)
    private String timezone = "UTC";
    
    @Column(name = "email_verified", nullable = false)
    private boolean emailVerified = false;
    
    @Column(nullable = false)
    private boolean active = true;
    
    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private OffsetDateTime createdAt;
    
    @UpdateTimestamp
    @Column(name = "updated_at", nullable = false)
    private OffsetDateTime updatedAt;
    
    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<RefreshToken> refreshTokens = new ArrayList<>();
}

// RefreshToken.java
@Entity
@Table(name = "refresh_tokens", schema = "auth_schema")
@Getter @Setter
@NoArgsConstructor
public class RefreshToken {
    
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;
    
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;
    
    @Column(name = "token_hash", nullable = false, unique = true)
    private String tokenHash;
    
    @Column(name = "expires_at", nullable = false)
    private OffsetDateTime expiresAt;
    
    @Column(nullable = false)
    private boolean revoked = false;
    
    @Column(name = "revoked_at")
    private OffsetDateTime revokedAt;
    
    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private OffsetDateTime createdAt;
}
```

### 5.3 DTOs

```java
// Request DTOs
public record RegisterRequest(
    @NotBlank @Email String email,
    @NotBlank @Size(min = 8, max = 100) @ValidPassword String password,
    @Size(max = 100) String displayName,
    @ValidTimezone String timezone
) {}

public record LoginRequest(
    @NotBlank @Email String email,
    @NotBlank String password
) {}

public record RefreshRequest(
    @NotBlank String refreshToken
) {}

public record UpdateProfileRequest(
    @Size(max = 100) String displayName,
    @ValidTimezone String timezone
) {}

public record ValidateTokenRequest(
    @NotBlank String token
) {}

// Response DTOs
public record UserResponse(
    UUID id,
    String email,
    String displayName,
    String timezone,
    OffsetDateTime createdAt,
    OffsetDateTime updatedAt
) {
    public static UserResponse from(User user) {
        return new UserResponse(
            user.getId(),
            user.getEmail(),
            user.getDisplayName(),
            user.getTimezone(),
            user.getCreatedAt(),
            user.getUpdatedAt()
        );
    }
}

public record AuthResponse(
    String accessToken,
    String refreshToken,
    String tokenType,
    long expiresIn,
    UserResponse user
) {}

public record TokenRefreshResponse(
    String accessToken,
    String tokenType,
    long expiresIn
) {}

public record TokenValidationResponse(
    boolean valid,
    UUID userId,
    String email,
    OffsetDateTime expiresAt,
    String reason
) {
    public static TokenValidationResponse valid(UUID userId, String email, OffsetDateTime expiresAt) {
        return new TokenValidationResponse(true, userId, email, expiresAt, null);
    }
    
    public static TokenValidationResponse invalid(String reason) {
        return new TokenValidationResponse(false, null, null, null, reason);
    }
}
```

---

## 6. Security Implementation

### 6.1 JWT Structure

**Access Token Claims**

```json
{
    "sub": "550e8400-e29b-41d4-a716-446655440000",
    "email": "user@example.com",
    "type": "access",
    "iat": 1705315800,
    "exp": 1705319400
}
```

**Refresh Token Claims**

```json
{
    "sub": "550e8400-e29b-41d4-a716-446655440000",
    "type": "refresh",
    "jti": "660e8400-e29b-41d4-a716-446655440001",
    "iat": 1705315800,
    "exp": 1705920600
}
```

### 6.2 JWT Service

```java
@Service
@RequiredArgsConstructor
public class JwtService {
    
    private final JwtProperties jwtProperties;
    
    private SecretKey getSigningKey() {
        byte[] keyBytes = Decoders.BASE64.decode(jwtProperties.getSecret());
        return Keys.hmacShaKeyFor(keyBytes);
    }
    
    public String generateAccessToken(User user) {
        return Jwts.builder()
            .subject(user.getId().toString())
            .claim("email", user.getEmail())
            .claim("type", "access")
            .issuedAt(new Date())
            .expiration(new Date(System.currentTimeMillis() + jwtProperties.getAccessTokenExpiration()))
            .signWith(getSigningKey())
            .compact();
    }
    
    public String generateRefreshToken(User user, UUID tokenId) {
        return Jwts.builder()
            .subject(user.getId().toString())
            .claim("type", "refresh")
            .id(tokenId.toString())
            .issuedAt(new Date())
            .expiration(new Date(System.currentTimeMillis() + jwtProperties.getRefreshTokenExpiration()))
            .signWith(getSigningKey())
            .compact();
    }
    
    public Claims parseToken(String token) {
        return Jwts.parser()
            .verifyWith(getSigningKey())
            .build()
            .parseSignedClaims(token)
            .getPayload();
    }
    
    public boolean isTokenValid(String token) {
        try {
            Claims claims = parseToken(token);
            return !claims.getExpiration().before(new Date());
        } catch (JwtException e) {
            return false;
        }
    }
    
    public UUID extractUserId(String token) {
        Claims claims = parseToken(token);
        return UUID.fromString(claims.getSubject());
    }
    
    public String extractTokenType(String token) {
        Claims claims = parseToken(token);
        return claims.get("type", String.class);
    }
}
```

### 6.3 Password Policy

```java
@Target({ElementType.FIELD})
@Retention(RetentionPolicy.RUNTIME)
@Constraint(validatedBy = PasswordValidator.class)
public @interface ValidPassword {
    String message() default "Password does not meet requirements";
    Class<?>[] groups() default {};
    Class<? extends Payload>[] payload() default {};
}

public class PasswordValidator implements ConstraintValidator<ValidPassword, String> {
    
    private static final String PASSWORD_PATTERN = 
        "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&])[A-Za-z\\d@$!%*?&]{8,}$";
    
    @Override
    public boolean isValid(String password, ConstraintValidatorContext context) {
        if (password == null) return false;
        
        List<String> violations = new ArrayList<>();
        
        if (password.length() < 8) {
            violations.add("Password must be at least 8 characters");
        }
        if (!password.matches(".*[a-z].*")) {
            violations.add("Password must contain at least one lowercase letter");
        }
        if (!password.matches(".*[A-Z].*")) {
            violations.add("Password must contain at least one uppercase letter");
        }
        if (!password.matches(".*\\d.*")) {
            violations.add("Password must contain at least one number");
        }
        
        if (!violations.isEmpty()) {
            context.disableDefaultConstraintViolation();
            violations.forEach(v -> 
                context.buildConstraintViolationWithTemplate(v).addConstraintViolation()
            );
            return false;
        }
        
        return true;
    }
}
```

### 6.4 Password Hashing

```java
@Configuration
public class SecurityBeans {
    
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(12); // Cost factor 12
    }
}
```

### 6.5 Security Configuration

```java
@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {
    
    private final JwtAuthenticationFilter jwtAuthFilter;
    
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .cors(cors -> cors.configurationSource(corsConfigurationSource()))
            .csrf(csrf -> csrf.disable())
            .sessionManagement(session -> 
                session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            )
            .authorizeHttpRequests(auth -> auth
                // Public endpoints
                .requestMatchers(HttpMethod.POST, "/api/v1/auth/register").permitAll()
                .requestMatchers(HttpMethod.POST, "/api/v1/auth/login").permitAll()
                .requestMatchers(HttpMethod.POST, "/api/v1/auth/refresh").permitAll()
                // Health check
                .requestMatchers("/actuator/health").permitAll()
                // Internal endpoint (validated by service key filter)
                .requestMatchers("/api/v1/auth/validate").permitAll()
                // All other requests require authentication
                .anyRequest().authenticated()
            )
            .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class)
            .exceptionHandling(ex -> ex
                .authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED))
            );
        
        return http.build();
    }
    
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(List.of("http://localhost:3000", "https://ipp-cda.vercel.app"));
        configuration.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        configuration.setAllowedHeaders(List.of("*"));
        configuration.setAllowCredentials(true);
        
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }
}
```

### 6.6 JWT Authentication Filter

```java
@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    
    private final JwtService jwtService;
    private final UserRepository userRepository;
    
    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain) throws ServletException, IOException {
        
        String authHeader = request.getHeader("Authorization");
        
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }
        
        String token = authHeader.substring(7);
        
        try {
            if (jwtService.isTokenValid(token) && 
                "access".equals(jwtService.extractTokenType(token))) {
                
                UUID userId = jwtService.extractUserId(token);
                
                userRepository.findById(userId)
                    .filter(User::isActive)
                    .ifPresent(user -> {
                        UsernamePasswordAuthenticationToken authToken =
                            new UsernamePasswordAuthenticationToken(
                                user, null, Collections.emptyList()
                            );
                        authToken.setDetails(
                            new WebAuthenticationDetailsSource().buildDetails(request)
                        );
                        SecurityContextHolder.getContext().setAuthentication(authToken);
                    });
            }
        } catch (Exception e) {
            // Token invalid - continue without authentication
        }
        
        filterChain.doFilter(request, response);
    }
}
```

---

## 7. Configuration

### 7.1 Application Properties

```yaml
# application.yml
spring:
  application:
    name: auth-service
  
  datasource:
    url: jdbc:postgresql://localhost:5432/ippcda
    username: ${DB_USERNAME:postgres}
    password: ${DB_PASSWORD:postgres}
    hikari:
      maximum-pool-size: ${DB_POOL_SIZE:5}
      minimum-idle: 2
      connection-timeout: 20000
  
  jpa:
    hibernate:
      ddl-auto: validate
    properties:
      hibernate:
        default_schema: auth_schema
        dialect: org.hibernate.dialect.PostgreSQLDialect
    open-in-view: false

server:
  port: ${PORT:8081}

# Custom JWT properties
jwt:
  secret: ${JWT_SECRET:your-256-bit-secret-key-here-min-32-chars}
  access-token-expiration: ${JWT_ACCESS_EXPIRATION:3600000}    # 1 hour in ms
  refresh-token-expiration: ${JWT_REFRESH_EXPIRATION:604800000} # 7 days in ms

# Internal service key
internal:
  service-key: ${INTERNAL_SERVICE_KEY:dev-service-key}

# Actuator
management:
  endpoints:
    web:
      exposure:
        include: health,info,metrics
  endpoint:
    health:
      show-details: when_authorized

# Logging
logging:
  level:
    com.ippcda.auth: DEBUG
    org.springframework.security: INFO
```

### 7.2 Configuration Properties Class

```java
@Configuration
@ConfigurationProperties(prefix = "jwt")
@Getter @Setter
public class JwtProperties {
    private String secret;
    private long accessTokenExpiration = 3600000;  // 1 hour
    private long refreshTokenExpiration = 604800000; // 7 days
}
```

### 7.3 Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `PORT` | No | 8081 | Server port |
| `DB_USERNAME` | Yes | - | Database username |
| `DB_PASSWORD` | Yes | - | Database password |
| `DATABASE_URL` | Yes (prod) | - | Full JDBC URL for production |
| `JWT_SECRET` | Yes | - | Base64-encoded 256-bit secret |
| `JWT_ACCESS_EXPIRATION` | No | 3600000 | Access token TTL (ms) |
| `JWT_REFRESH_EXPIRATION` | No | 604800000 | Refresh token TTL (ms) |
| `INTERNAL_SERVICE_KEY` | Yes | - | Key for service-to-service auth |

---

## 8. Error Handling

### 8.1 Error Response Structure

```java
public record ErrorResponse(
    OffsetDateTime timestamp,
    int status,
    String error,
    String code,
    String message,
    String path,
    List<FieldError> details
) {
    public record FieldError(String field, String message) {}
}
```

### 8.2 Error Codes

| Code | HTTP Status | Description |
|------|-------------|-------------|
| `VALIDATION_ERROR` | 400 | Request validation failed |
| `INVALID_CREDENTIALS` | 401 | Wrong email or password |
| `INVALID_TOKEN` | 401 | JWT is malformed or invalid |
| `TOKEN_EXPIRED` | 401 | JWT has expired |
| `INVALID_REFRESH_TOKEN` | 401 | Refresh token invalid/revoked |
| `AUTHENTICATION_REQUIRED` | 401 | No token provided |
| `ACCESS_DENIED` | 403 | Token valid but access denied |
| `USER_NOT_FOUND` | 404 | User does not exist |
| `EMAIL_ALREADY_EXISTS` | 409 | Email already registered |
| `USER_DISABLED` | 403 | Account is deactivated |
| `INTERNAL_ERROR` | 500 | Unexpected server error |

### 8.3 Global Exception Handler

```java
@RestControllerAdvice
@Slf4j
public class GlobalExceptionHandler {
    
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ErrorResponse> handleValidationException(
            MethodArgumentNotValidException ex, HttpServletRequest request) {
        
        List<ErrorResponse.FieldError> details = ex.getBindingResult()
            .getFieldErrors()
            .stream()
            .map(e -> new ErrorResponse.FieldError(e.getField(), e.getDefaultMessage()))
            .toList();
        
        return ResponseEntity.badRequest().body(new ErrorResponse(
            OffsetDateTime.now(),
            400,
            "Bad Request",
            "VALIDATION_ERROR",
            "Validation failed",
            request.getRequestURI(),
            details
        ));
    }
    
    @ExceptionHandler(AuthenticationException.class)
    public ResponseEntity<ErrorResponse> handleAuthException(
            AuthenticationException ex, HttpServletRequest request) {
        
        return ResponseEntity.status(401).body(new ErrorResponse(
            OffsetDateTime.now(),
            401,
            "Unauthorized",
            "INVALID_CREDENTIALS",
            ex.getMessage(),
            request.getRequestURI(),
            null
        ));
    }
    
    @ExceptionHandler(EmailAlreadyExistsException.class)
    public ResponseEntity<ErrorResponse> handleEmailExists(
            EmailAlreadyExistsException ex, HttpServletRequest request) {
        
        return ResponseEntity.status(409).body(new ErrorResponse(
            OffsetDateTime.now(),
            409,
            "Conflict",
            "EMAIL_ALREADY_EXISTS",
            ex.getMessage(),
            request.getRequestURI(),
            null
        ));
    }
    
    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorResponse> handleGenericException(
            Exception ex, HttpServletRequest request) {
        
        log.error("Unexpected error", ex);
        
        return ResponseEntity.status(500).body(new ErrorResponse(
            OffsetDateTime.now(),
            500,
            "Internal Server Error",
            "INTERNAL_ERROR",
            "An unexpected error occurred",
            request.getRequestURI(),
            null
        ));
    }
}
```

---

## 9. Integration Points

### 9.1 Consumed By

| Service | Purpose | Endpoint Used |
|---------|---------|---------------|
| Event Service | Validate user tokens | `POST /validate` |
| Data Aggregator | Validate service requests | `POST /validate` |
| Enrichment Service | Validate service requests | `POST /validate` |
| Frontend | User authentication | All public endpoints |

### 9.2 Integration Pattern

Other services validate tokens by either:

1. **Calling Auth Service** (recommended for simplicity)
   ```java
   // In Event Service
   TokenValidationResponse response = authClient.validateToken(token);
   if (!response.valid()) {
       throw new UnauthorizedException();
   }
   ```

2. **Local JWT validation** (better performance, requires shared secret)
   ```java
   // Each service has its own JwtService with the same secret
   Claims claims = jwtService.parseToken(token);
   UUID userId = UUID.fromString(claims.getSubject());
   ```

### 9.3 Service Key Validation

```java
@Component
@RequiredArgsConstructor
public class InternalServiceKeyFilter extends OncePerRequestFilter {
    
    @Value("${internal.service-key}")
    private String serviceKey;
    
    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain) throws ServletException, IOException {
        
        if (request.getRequestURI().equals("/api/v1/auth/validate")) {
            String providedKey = request.getHeader("X-Internal-Service-Key");
            
            if (!serviceKey.equals(providedKey)) {
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                response.getWriter().write("{\"error\":\"Invalid service key\"}");
                return;
            }
        }
        
        filterChain.doFilter(request, response);
    }
}
```

---

## 10. Project Structure

```
auth-service/
├── src/
│   ├── main/
│   │   ├── java/
│   │   │   └── com/
│   │   │       └── ippcda/
│   │   │           └── auth/
│   │   │               ├── AuthServiceApplication.java
│   │   │               ├── config/
│   │   │               │   ├── JwtProperties.java
│   │   │               │   ├── SecurityConfig.java
│   │   │               │   └── SecurityBeans.java
│   │   │               ├── controller/
│   │   │               │   └── AuthController.java
│   │   │               ├── dto/
│   │   │               │   ├── request/
│   │   │               │   │   ├── RegisterRequest.java
│   │   │               │   │   ├── LoginRequest.java
│   │   │               │   │   ├── RefreshRequest.java
│   │   │               │   │   ├── UpdateProfileRequest.java
│   │   │               │   │   └── ValidateTokenRequest.java
│   │   │               │   └── response/
│   │   │               │       ├── AuthResponse.java
│   │   │               │       ├── TokenRefreshResponse.java
│   │   │               │       ├── TokenValidationResponse.java
│   │   │               │       ├── UserResponse.java
│   │   │               │       └── ErrorResponse.java
│   │   │               ├── entity/
│   │   │               │   ├── User.java
│   │   │               │   └── RefreshToken.java
│   │   │               ├── exception/
│   │   │               │   ├── AuthException.java
│   │   │               │   ├── EmailAlreadyExistsException.java
│   │   │               │   ├── InvalidCredentialsException.java
│   │   │               │   ├── InvalidTokenException.java
│   │   │               │   └── GlobalExceptionHandler.java
│   │   │               ├── filter/
│   │   │               │   ├── JwtAuthenticationFilter.java
│   │   │               │   └── InternalServiceKeyFilter.java
│   │   │               ├── repository/
│   │   │               │   ├── UserRepository.java
│   │   │               │   └── RefreshTokenRepository.java
│   │   │               ├── service/
│   │   │               │   ├── AuthService.java
│   │   │               │   ├── JwtService.java
│   │   │               │   └── UserService.java
│   │   │               └── validation/
│   │   │                   ├── ValidPassword.java
│   │   │                   ├── PasswordValidator.java
│   │   │                   ├── ValidTimezone.java
│   │   │                   └── TimezoneValidator.java
│   │   └── resources/
│   │       ├── application.yml
│   │       ├── application-dev.yml
│   │       ├── application-prod.yml
│   │       └── db/
│   │           └── migration/
│   │               └── V1__initial_schema.sql
│   └── test/
│       └── java/
│           └── com/
│               └── ippcda/
│                   └── auth/
│                       ├── controller/
│                       │   └── AuthControllerTest.java
│                       ├── service/
│                       │   ├── AuthServiceTest.java
│                       │   └── JwtServiceTest.java
│                       └── integration/
│                           └── AuthIntegrationTest.java
├── Dockerfile
├── pom.xml (or build.gradle)
├── README.md
└── SERVICE_SPEC.md
```

---

## 11. Implementation Guide

### 11.1 Implementation Order

Follow this order for incremental, testable development:

1. **Project Setup**
   - Initialize Spring Boot project
   - Configure dependencies (pom.xml)
   - Set up application.yml

2. **Database Layer**
   - Create SQL migration scripts
   - Implement User entity
   - Implement UserRepository
   - Test with H2 or Testcontainers

3. **Security Foundation**
   - Implement JwtProperties
   - Implement JwtService
   - Write unit tests for JWT generation/parsing

4. **Registration Flow**
   - Implement RegisterRequest DTO with validation
   - Implement UserService.register()
   - Implement AuthController.register()
   - Test registration endpoint

5. **Login Flow**
   - Implement LoginRequest DTO
   - Implement RefreshToken entity and repository
   - Implement AuthService.login()
   - Implement AuthController.login()
   - Test login endpoint

6. **Token Refresh Flow**
   - Implement RefreshRequest DTO
   - Implement AuthService.refresh()
   - Implement AuthController.refresh()
   - Test refresh endpoint

7. **Protected Endpoints**
   - Implement JwtAuthenticationFilter
   - Configure SecurityConfig
   - Implement /me endpoints
   - Test protected endpoints

8. **Internal Validation Endpoint**
   - Implement InternalServiceKeyFilter
   - Implement /validate endpoint
   - Test with service key

9. **Error Handling**
   - Implement custom exceptions
   - Implement GlobalExceptionHandler
   - Test error scenarios

10. **Logout & Cleanup**
    - Implement logout (token revocation)
    - Add scheduled job to clean expired tokens

### 11.2 Key Implementation Notes

**Password Hashing**
```java
// Registration
String hashedPassword = passwordEncoder.encode(request.password());
user.setPasswordHash(hashedPassword);

// Login verification
if (!passwordEncoder.matches(request.password(), user.getPasswordHash())) {
    throw new InvalidCredentialsException("Invalid email or password");
}
```

**Refresh Token Storage**
```java
// Store hash, not the actual token
String tokenHash = DigestUtils.sha256Hex(refreshTokenString);
refreshToken.setTokenHash(tokenHash);

// Lookup by hash
String providedHash = DigestUtils.sha256Hex(request.refreshToken());
RefreshToken token = refreshTokenRepository.findByTokenHash(providedHash)
    .orElseThrow(() -> new InvalidTokenException("Invalid refresh token"));
```

**Getting Current User**
```java
@GetMapping("/me")
public ResponseEntity<UserResponse> getCurrentUser(@AuthenticationPrincipal User user) {
    return ResponseEntity.ok(UserResponse.from(user));
}
```

---

## 12. Testing

### 12.1 Unit Tests

```java
@ExtendWith(MockitoExtension.class)
class AuthServiceTest {
    
    @Mock
    private UserRepository userRepository;
    
    @Mock
    private RefreshTokenRepository refreshTokenRepository;
    
    @Mock
    private PasswordEncoder passwordEncoder;
    
    @Mock
    private JwtService jwtService;
    
    @InjectMocks
    private AuthService authService;
    
    @Test
    void register_withValidRequest_shouldCreateUser() {
        // Given
        RegisterRequest request = new RegisterRequest(
            "test@example.com", "Password123!", "Test User", "UTC"
        );
        when(userRepository.existsByEmail(request.email())).thenReturn(false);
        when(passwordEncoder.encode(request.password())).thenReturn("hashed");
        when(userRepository.save(any(User.class))).thenAnswer(i -> {
            User u = i.getArgument(0);
            u.setId(UUID.randomUUID());
            return u;
        });
        
        // When
        UserResponse response = authService.register(request);
        
        // Then
        assertThat(response.email()).isEqualTo("test@example.com");
        verify(userRepository).save(any(User.class));
    }
    
    @Test
    void register_withExistingEmail_shouldThrowException() {
        // Given
        RegisterRequest request = new RegisterRequest(
            "existing@example.com", "Password123!", null, null
        );
        when(userRepository.existsByEmail(request.email())).thenReturn(true);
        
        // When/Then
        assertThatThrownBy(() -> authService.register(request))
            .isInstanceOf(EmailAlreadyExistsException.class);
    }
    
    @Test
    void login_withValidCredentials_shouldReturnTokens() {
        // Given
        LoginRequest request = new LoginRequest("test@example.com", "Password123!");
        User user = createTestUser();
        
        when(userRepository.findByEmail(request.email())).thenReturn(Optional.of(user));
        when(passwordEncoder.matches(request.password(), user.getPasswordHash())).thenReturn(true);
        when(jwtService.generateAccessToken(user)).thenReturn("access-token");
        when(jwtService.generateRefreshToken(eq(user), any())).thenReturn("refresh-token");
        
        // When
        AuthResponse response = authService.login(request);
        
        // Then
        assertThat(response.accessToken()).isEqualTo("access-token");
        assertThat(response.refreshToken()).isEqualTo("refresh-token");
    }
}
```

### 12.2 Integration Tests

```java
@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT)
@Testcontainers
@AutoConfigureTestDatabase(replace = Replace.NONE)
class AuthIntegrationTest {
    
    @Container
    static PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>("postgres:15")
        .withDatabaseName("testdb")
        .withUsername("test")
        .withPassword("test");
    
    @DynamicPropertySource
    static void configureProperties(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", postgres::getJdbcUrl);
        registry.add("spring.datasource.username", postgres::getUsername);
        registry.add("spring.datasource.password", postgres::getPassword);
    }
    
    @Autowired
    private TestRestTemplate restTemplate;
    
    @Autowired
    private UserRepository userRepository;
    
    @BeforeEach
    void setUp() {
        userRepository.deleteAll();
    }
    
    @Test
    void fullAuthenticationFlow() {
        // 1. Register
        RegisterRequest registerRequest = new RegisterRequest(
            "integration@test.com", "Password123!", "Test User", "UTC"
        );
        
        ResponseEntity<UserResponse> registerResponse = restTemplate.postForEntity(
            "/api/v1/auth/register", registerRequest, UserResponse.class
        );
        
        assertThat(registerResponse.getStatusCode()).isEqualTo(HttpStatus.CREATED);
        assertThat(registerResponse.getBody().email()).isEqualTo("integration@test.com");
        
        // 2. Login
        LoginRequest loginRequest = new LoginRequest("integration@test.com", "Password123!");
        
        ResponseEntity<AuthResponse> loginResponse = restTemplate.postForEntity(
            "/api/v1/auth/login", loginRequest, AuthResponse.class
        );
        
        assertThat(loginResponse.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(loginResponse.getBody().accessToken()).isNotBlank();
        
        String accessToken = loginResponse.getBody().accessToken();
        
        // 3. Access protected endpoint
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(accessToken);
        HttpEntity<?> entity = new HttpEntity<>(headers);
        
        ResponseEntity<UserResponse> meResponse = restTemplate.exchange(
            "/api/v1/auth/me", HttpMethod.GET, entity, UserResponse.class
        );
        
        assertThat(meResponse.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(meResponse.getBody().email()).isEqualTo("integration@test.com");
    }
}
```

### 12.3 Test Coverage Targets

| Component | Target |
|-----------|--------|
| Service layer | 90% |
| Controller layer | 80% |
| Security filters | 85% |
| Overall | 80% |

---

## 13. Deployment

### 13.1 Dockerfile

```dockerfile
# Build stage
FROM eclipse-temurin:21-jdk-alpine AS build
WORKDIR /app

COPY pom.xml .
COPY src ./src

RUN apk add --no-cache maven && \
    mvn clean package -DskipTests

# Runtime stage
FROM eclipse-temurin:21-jre-alpine
WORKDIR /app

# Add non-root user
RUN addgroup -S appgroup && adduser -S appuser -G appgroup
USER appuser

COPY --from=build /app/target/auth-service-*.jar app.jar

EXPOSE 8081

HEALTHCHECK --interval=30s --timeout=3s --start-period=30s --retries=3 \
    CMD wget -q --spider http://localhost:8081/actuator/health || exit 1

ENTRYPOINT ["java", "-jar", "app.jar"]
```

### 13.2 Render Configuration

```yaml
# render.yaml (in repo root)
services:
  - type: web
    name: auth-service
    runtime: docker
    dockerfilePath: ./Dockerfile
    envVars:
      - key: SPRING_PROFILES_ACTIVE
        value: prod
      - key: DATABASE_URL
        fromDatabase:
          name: ippcda-db
          property: connectionString
      - key: JWT_SECRET
        generateValue: true
      - key: INTERNAL_SERVICE_KEY
        generateValue: true
    healthCheckPath: /actuator/health
    plan: free
```

### 13.3 Production Checklist

- [ ] JWT_SECRET is a strong, randomly generated 256-bit key
- [ ] INTERNAL_SERVICE_KEY is unique and securely stored
- [ ] Database connection pool sized for free tier (max 2)
- [ ] CORS origins configured for production domain
- [ ] Logging level set appropriately (INFO for prod)
- [ ] Health check endpoint accessible
- [ ] SSL/TLS enabled (handled by Render)

---

## 14. Checklist

### Phase 1: Setup
- [x] Create Spring Boot project with dependencies
- [x] Configure application.yml for local development
- [ ] Set up PostgreSQL locally or via Docker
- [ ] Create database schema migration

### Phase 2: Core Implementation
- [ ] Implement User entity and repository
- [ ] Implement JwtService with tests
- [ ] Implement registration endpoint with validation
- [ ] Implement login endpoint
- [ ] Implement refresh token flow
- [ ] Implement JWT authentication filter

### Phase 3: Security & Polish
- [ ] Configure Spring Security
- [ ] Implement protected /me endpoints
- [ ] Implement /validate endpoint for internal use
- [ ] Implement global exception handling
- [ ] Add request logging

### Phase 4: Testing
- [ ] Unit tests for services (>90% coverage)
- [ ] Integration tests for full flows
- [ ] Test error scenarios
- [ ] Test token expiration handling

### Phase 5: Deployment
- [ ] Create Dockerfile
- [ ] Test Docker build locally
- [ ] Configure Render deployment
- [ ] Verify health check works
- [ ] Test production deployment

---

## Document History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2025-01-XX | Initial service specification |

---

*This specification should be updated as implementation progresses and requirements evolve.*