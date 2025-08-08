# Architecture Change Request: Context-Aware URL Generation for Multi-Document Mode

## Problem Statement

The Y-Sweet relay server currently uses a static URL prefix configuration (`RELAY_SERVER_URL`) for generating client WebSocket URLs in multi-document mode. This creates a problem for Fly.io deployments where:

- **External clients** access the server via public domains through fly-relay proxy (HTTPS/WSS)
- **Internal clients** access the server via `.flycast` private network addresses (HTTP/WS)

Both client contexts need different WebSocket URLs that match their respective access patterns, but the current static configuration can only serve one context correctly.

## Proposed Architecture Change

### Core Concept
Replace static URL prefix with **context-aware URL generation** that detects the client's access pattern from HTTP request headers and generates appropriate WebSocket URLs.

### URL Generation Strategy
1. **Priority Order**: Explicit URL prefix → Context-derived URL → Fallback rejected
2. **Context Detection**: Use `Host` header to determine client access pattern
3. **Protocol Detection**: Map host patterns to appropriate schemes (HTTPS for external, HTTP for flycast)
4. **Security**: Validate hosts against allowlist to prevent header injection attacks

### Implementation Changes

#### 1. Enhanced Server Configuration
```rust
// Add to Server struct
pub allowed_hosts: Vec<AllowedHost>,

#[derive(Clone, Debug)]
pub struct AllowedHost {
    pub host: String,
    pub scheme: String, // "http" or "https"
}
```

#### 2. CLI Configuration
```rust
// Add to main.rs Serve struct
#[clap(long, env = "RELAY_SERVER_ALLOWED_HOSTS", value_delimiter = ',')]
allowed_hosts: Option<Vec<String>>,
```

#### 3. Allowlist Generation Logic
- **Explicit Configuration**: Parse full URLs with schemes from `RELAY_SERVER_ALLOWED_HOSTS`
- **Implicit Generation**: Auto-generate from `RELAY_SERVER_URL` + `{FLY_APP_NAME}.flycast`
- **Scheme Mapping**: External hosts → HTTPS/WSS, Flycast hosts → HTTP/WS

#### 4. Auth Endpoint Modification
Modify `/doc/:doc_id/auth` endpoint to:
- Validate incoming `Host` header against allowlist
- Generate context-appropriate WebSocket URLs
- Maintain backward compatibility when explicit URL prefix is set

### Configuration Examples

#### Implicit Generation (Recommended)
```bash
# Fly.io deployment - auto-generates allowlist
RELAY_SERVER_URL=https://api.mycompany.com
FLY_APP_NAME=my-relay-server

# Generated allowlist:
# - https://api.mycompany.com (external clients)
# - http://my-relay-server.flycast (internal clients)
```

#### Explicit Override
```bash
# Custom allowlist with explicit schemes
RELAY_SERVER_ALLOWED_HOSTS="https://api.mycompany.com,https://staging.mycompany.com,http://my-relay-server.flycast"
```

### Security Considerations

1. **Host Validation**: All hosts validated against explicit allowlist
2. **Scheme Enforcement**: Prevents protocol downgrade attacks
3. **Fly.io Network Trust**: Safe within Fly.io's trusted network boundary
4. **Backward Compatibility**: Existing explicit URL prefix behavior unchanged

### Benefits

1. **Dual Context Support**: External and internal clients get correct URLs automatically
2. **Zero Configuration**: Works out-of-the-box for standard Fly.io deployments
3. **Security**: Prevents host header injection via allowlist validation
4. **Flexibility**: Supports custom multi-tenant scenarios
5. **Backward Compatibility**: Existing deployments unaffected

### Impact Assessment

- **Breaking Changes**: None (additive change with fallback)
- **Performance**: Minimal (single hash map lookup per auth request)
- **Deployment**: Requires environment variable updates for custom configurations
- **Testing**: Requires validation across external/internal client scenarios

## Recommendation

**IMPLEMENT** - This architecture change solves a real deployment challenge for Fly.io multi-context access patterns while maintaining security and backward compatibility. The implicit configuration approach minimizes operational overhead while providing flexibility for custom scenarios.