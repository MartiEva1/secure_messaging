# secure_messaging


This report describes a protocol to secure messaging, in particular it allows two entities client and server to communicate providing them:
- end-to-end encryption
- message authentication
- entity authentication

Last security service is obtained trusting a third party called C.
This protocol has three main stages:
1. PK key generation and exchange
2. Entity authentication
3. Secure communication session
