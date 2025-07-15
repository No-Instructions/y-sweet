# Y-Sweet Webhook Testing

This document describes how to test the webhook functionality in Y-Sweet.

## Setup

1. Set the webhook URL environment variable:
   ```bash
   export Y_SWEET_WEBHOOK_URL=https://httpbin.org/post
   ```

2. Optionally, set the timeout (default is 5000ms):
   ```bash
   export Y_SWEET_WEBHOOK_TIMEOUT_MS=10000
   ```

## Running the Server

Start the Y-Sweet server with webhook support:

```bash
cargo run --bin y-sweet -- serve --port 3000 --host 0.0.0.0
```

You should see a log message indicating the webhook dispatcher was initialized:
```
INFO y_sweet: Webhook dispatcher initialized
```

## Testing Webhook Calls

1. Create a document:
   ```bash
   curl -X POST http://localhost:3000/doc/new
   ```

2. Update the document (this will trigger a webhook):
   ```bash
   curl -X POST http://localhost:3000/d/[DOC_ID]/update \
     -H "Content-Type: application/octet-stream" \
     --data-binary @/dev/null
   ```

3. Check the webhook endpoint (if using httpbin.org) to see the received payload:
   ```json
   {
     "doc_id": "your-doc-id",
     "timestamp": "2024-01-01T00:00:00Z"
   }
   ```

## Environment Variables

- `Y_SWEET_WEBHOOK_URL`: The URL to send webhook notifications to
- `Y_SWEET_WEBHOOK_TIMEOUT_MS`: Timeout in milliseconds for webhook requests (default: 5000)

## Steel Thread Features

The current implementation includes:

1. **Basic webhook configuration** via environment variables
2. **HTTP POST requests** sent to configured URL on document updates
3. **Simple JSON payload** with document ID and timestamp
4. **Async execution** - webhook calls don't block document processing
5. **Proper error handling** with logging
6. **Timeout support** for webhook requests

## Next Steps

Future enhancements will include:
- Document ID prefix matching
- Retry logic with exponential backoff
- Circuit breaker pattern
- Webhook signature verification
- Dynamic configuration