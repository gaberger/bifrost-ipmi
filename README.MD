



## Tables

| Parameter | bytes | Name                         |   |
| SIDm      |     4 | Remote_Console_Session_ID    |   |
| SIDc      |     4 | BMC Session ID               |   |
| Rm        |    16 | Remote Console Random Number |   |
| Rc        |    16 | BMC Random Number            |   |
| GUIDc     |    16 | BMC GUID                     |   |
| Rolem     |     1 | Requested Privilege Level    |   |
| ULENGTHm  |     1 | User Name Length             |   |
| UNamem    |   var | User Name array              |   |


Things to do.

1. Verify session-id's of during session initialization
2. Accept session-less commands within session as long as they have a valid session-id's (section 6.12.1)
3. Check status return codes on each message
4. Check for valid sequence-no windows (section 6.12.14)
5. Check for session inactivity timeouts (section 6.12.15) typcally 60 seconds +-3

## Proxy functions

One thing we need to workout is how to bridge credentials and targets from one protocol to another. 

For IPMI, only the `username` is sent between the remote console and the managed console and is 20 bytes long. Because RAKP uses symmetric keys the client and the server must know the password. 

## Cipher Slots
;; ID   IANA    Auth Alg        Integrity Alg   Confidentiality Alg
;; 0    N/A     none            none            none
;; 1    N/A     hmac_sha1       none            none
;; 2    N/A     hmac_sha1       hmac_sha1_96    none
;; 3    N/A     hmac_sha1       hmac_sha1_96    aes_cbc_128
;; 4    N/A     hmac_sha1       hmac_sha1_96    xrc4_128
;; 5    N/A     hmac_sha1       hmac_sha1_96    xrc4_40
;; 6    N/A     hmac_md5        none            none
;; 7    N/A     hmac_md5        hmac_md5_128    none
;; 8    N/A     hmac_md5        hmac_md5_128    aes_cbc_128
;; 9    N/A     hmac_md5        hmac_md5_128    xrc4_128
;; 10   N/A     hmac_md5        hmac_md5_128    xrc4_40
;; 11   N/A     hmac_md5        md5_128         none
;; 12   N/A     hmac_md5        md5_128         aes_cbc_128
;; 13   N/A     hmac_md5        md5_128         xrc4_128
;; 14   N/A     hmac_md5        md5_128         xrc4_40
;; 15   N/A     hmac_sha256     none            none
;; 16   N/A     hmac_sha256     sha256_128      none
;; 17   N/A     hmac_sha256     sha256_128      aes_cbc_128
;; 18   N/A     hmac_sha256     sha256_128      xrc4_128
;; 19   N/A     hmac_sha256     sha256_128      xrc4_40  
