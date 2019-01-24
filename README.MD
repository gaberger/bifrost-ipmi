




Things to do.

1. Verify session-id's of during session initialization
2. Accept session-less commands within session as long as they have a valid session-id's (section 6.12.1)
3. Check status return codes on each message
4. Check for valid sequence-no windows (section 6.12.14)
5. Check for session inactivity timeouts (section 6.12.15) typcally 60 seconds +-3

## Proxy functions

One thing we need to workout is how to bridge credentials and targets from one protocol to another. 

For IPMI, only the `username` is sent between the remote console and the managed console and is 20 bytes long. Because RAKP uses symmetric keys the client and the server must know the password. 
