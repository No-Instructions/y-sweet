# Architecture Change Request: Enable Server Token Access to File Download URLs

## Problem Statement
Currently, the `/f/:doc_id/download-url` endpoint only accepts file tokens, but not server tokens. This creates an unnecessary barrier for administrative operations where a server token holder needs to download files by hash without first generating intermediate tokens.

## Proposed Solution
Modify the file download endpoint to accept server tokens while maintaining security boundaries, by moving the file hash parameter from the token payload to the request parameters.

## Architecture Changes

### 1. Endpoint Modification
**Current**: `GET /f/:doc_id/download-url`
- Hash embedded in file token payload
- Only accepts file tokens via `verify_file_token_for_doc()`

**Proposed**: `GET /f/:doc_id/download-url?hash={file_hash}`
- Hash as query parameter
- Accepts file tokens AND server tokens

### 2. Authentication Logic Update
Modify `handle_file_download_url()` in `server.rs` to support two token types:

1. **File Token**: Current behavior - hash comes from token payload, validated via `verify_file_token_for_doc()`
2. **Server Token**: New behavior - hash comes from query parameter, validated via `verify_server_token()`

### 3. Token Verification Flow
```
1. Extract hash from query parameter (if present)
2. Try to verify as file token using verify_file_token_for_doc()
   - If successful, use hash from token payload (existing logic)
3. If file token verification fails, try server token verification
   - If successful, use hash from query parameter with full access
4. If both fail, return 401 Unauthorized
```

### 4. Security Considerations
- **Backward Compatibility**: Existing file tokens continue to work unchanged
- **Parameter Validation**: Query parameter hash must pass `validate_file_hash()`
- **Authorization**: Server tokens get full access to any file in any document
- **Hash Source**: File tokens use embedded hash, server tokens use query parameter

### 5. API Impact
- **Breaking Change**: No - existing clients continue to work
- **New Capability**: Server token holders can download files with `?hash=...` parameter
- **Documentation**: Update OpenAPI spec to reflect optional hash query parameter

## Implementation Details

### Error Handling
- If hash provided in both token and query parameter, token takes precedence
- Clear error messages distinguishing between "invalid token" vs "invalid hash parameter"

### Performance
- Minimal impact - just additional token verification attempt
- Query parameter parsing is lightweight

### Testing Requirements  
- Verify both token types work correctly
- Test backward compatibility with existing file tokens
- Validate hash parameter security (validation, injection prevention, etc.)

## Benefits
1. **Administrative Efficiency**: Server tokens can directly download files
2. **Simplified Workflows**: Eliminates intermediate token generation step
3. **Maintain Security**: No reduction in security boundaries
4. **Backward Compatible**: Zero impact on existing clients

## Alternative Considered
Adding a separate admin endpoint like `/admin/files/:doc_id/:hash/download-url` was considered but rejected because it duplicates functionality and creates API inconsistency.

## Implementation Location
- File: `crates/y-sweet/src/server.rs`
- Function: `handle_file_download_url()` (around line 1025)
- Related validation: `validate_file_hash()` in `crates/y-sweet-core/src/api_types.rs`