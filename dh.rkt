#lang racket
(require "ssh-openssl.rkt"
         "utils.rkt"
         "constants.rkt")

(provide  algorithm-negotiation
          do-key-exchange)
 
(define (server? x) (eq? x 'server))

(define (algorithm-negotiation io role)
  (define (negotiate sa ca)
    (for/list ([cs ca]
               [ss sa])
      (define nv (for/or ([c cs]) (if (member c ss) c #f)))
      (unless nv (error 'negotiate "failed algorithm negotiation ~a ~a" cs ss))
      nv))
  (define (build-kexinit)
    (define algorithms-openssh (list 
      (list #"diffie-hellman-group-exchange-sha256" #"diffie-hellman-group-exchange-sha1" #"diffie-hellman-group14-sha1" #"diffie-hellman-group1-sha1")
      (list #"ssh-rsa" #"ssh-dss")
      (list #"aes128-ctr" #"aes192-ctr" #"aes256-ctr" #"arcfour256" #"arcfour128" #"aes128-cbc" #"3des-cbc" #"blowfish-cbc" #"cast128-cbc" #"aes192-cbc" #"aes256-cbc" #"arcfour" #"rijndael-cbc@lysator.liu.se")
      (list #"aes128-ctr" #"aes192-ctr" #"aes256-ctr" #"arcfour256" #"arcfour128" #"aes128-cbc" #"3des-cbc" #"blowfish-cbc" #"cast128-cbc" #"aes192-cbc" #"aes256-cbc" #"arcfour" #"rijndael-cbc@lysator.liu.se")
      (list #"hmac-md5" #"hmac-sha1" #"umac-64@openssh.com" #"hmac-ripemd160" #"hmac-ripemd160@openssh.com" #"hmac-sha1-96" #"hmac-md5-96")
      (list #"hmac-md5" #"hmac-sha1" #"umac-64@openssh.com" #"hmac-ripemd160" #"hmac-ripemd160@openssh.com" #"hmac-sha1-96" #"hmac-md5-96")
      (list #"none" #"zlib@openssh.com" #"zlib")
      (list #"none" #"zlib@openssh.com" #"zlib")))
    (define algorithms (list 
      (list #"diffie-hellman-group-exchange-sha256" #"diffie-hellman-group-exchange-sha1")
      (list #"ssh-rsa")
      (list #"aes128-cbc")
      (list #"aes128-cbc")
      (list #"hmac-md5" #"hmac-sha1")
      (list #"hmac-md5" #"hmac-sha1")
      (list #"none")
      (list #"none")))
    (define pkt (bytes-append
    (bytes SSH_MSG_KEXINIT) 
    (random-bytes 16)
    (for/fold ([accum #""]) ([x algorithms])
      (bytes-append accum (build-ssh-bytes (bytes-join x #","))))
    (build-ssh-bytes #"")
    (build-ssh-bytes #"")
    (bytes 0)
    (->bytes 0)))
    (values pkt algorithms))

  (define (parse-kexinit bytes)
    (define in (open-input-bytes bytes))
    (define type (read-byte in))
    (define cookie (read-bytes 16 in))
    (define lines (for/list ([x (in-range 10)]) (read-ssh-string in)))
    (define first-kex-pkt (read-ssh-bool in))
    (define future-use (read-ssh-uint32 in))
    (for/list ([x lines]) 
      (eprintf "~a~n" x)
      (regexp-split #rx"," x)))

  (define (curry-io io)
    (values (lambda (x) (send io send-packet x)) (lambda () (send io recv-packet))))

  (define-values (send-pkt recv-pkt) (curry-io io))
  (define-values (OUR_KEX_PAYLOAD OUR_ALGORITHMS) (build-kexinit))
  (send-pkt OUR_KEX_PAYLOAD)
  (define PEER_KEX_PAYLOAD (recv-pkt))
  (define PEER_ALGORITHMS  (parse-kexinit PEER_KEX_PAYLOAD))
  (define-values (SERVER_KEX_PAYLOAD SERVER_ALGORITHMS CLIENT_KEX_PAYLOAD CLIENT_ALGORITHMS)
    (if (server? role) 
      (values OUR_KEX_PAYLOAD OUR_ALGORITHMS PEER_KEX_PAYLOAD PEER_ALGORITHMS)
      (values PEER_KEX_PAYLOAD PEER_ALGORITHMS OUR_KEX_PAYLOAD OUR_ALGORITHMS)))
  (cons CLIENT_KEX_PAYLOAD (cons SERVER_KEX_PAYLOAD (negotiate SERVER_ALGORITHMS CLIENT_ALGORITHMS))))

(define (do-key-exchange io handshake algorithms role)
  (match-define (list client-kex-payload server-kex-payload kex-alg pub-priv-alg client-sym server-sym client-hmac server-hmac client-comp server-comp) algorithms)

  (define kex-length-requirement (max 8 (cipher-length client-sym) (cipher-length server-sym) (hmac-size client-hmac) (hmac-size server-hmac)))
  (define (diffie-hellman-exchange-hash hasher->bin group-info cpub spub ssh-shared-secret public-host-key-blob)
    (match-define (list client-version server-version) handshake)
    (match-define (list client-kex-payload server-kex-payload kex-alg pub-priv-alg client-sym server-sym client-hmac server-hmac client-comp server-comp) algorithms)
    (define (chomprn x) (regexp-replace "\r$" (regexp-replace "\n$" (regexp-replace "\r\n$" x "") "") ""))
    (hasher->bin
      (build-ssh-bytes (chomprn client-version))
      (build-ssh-bytes (chomprn server-version))
      (build-ssh-bytes client-kex-payload)
      (build-ssh-bytes server-kex-payload)
      (build-ssh-bytes public-host-key-blob)
      group-info
      cpub
      spub
      ssh-shared-secret))

  (define (client-diffie-hellman hasher->bin sshp sshg init-id reply-id group-info)
    (define-values (dh cpub) (DiffieHellman-get-public-key sshp sshg kex-length-requirement))
    (sendp io init-id cpub)

    (define-values (host-key-buf server-pub sig-buf) (recvp io reply-id "sXs"))
    (define-values (server-key-type server-key-e server-key-n) (parse/bs host-key-buf "sss"))
    (define-values (sig-type sig) (parse/bs sig-buf "ss"))
    (define-values (ssh-shared-secret) (DiffieHellman-get-shared-secret/C dh server-pub))

    (define exchange-hash (diffie-hellman-exchange-hash hasher->bin group-info cpub server-pub ssh-shared-secret host-key-buf))
    (define rc (sha1-rsa-verify/sha1/e_n exchange-hash server-key-e server-key-n sig))
    (unless rc (error "a"))
    (init-streams exchange-hash ssh-shared-secret hasher->bin))

  (define (server-diffie-hellman hasher->bin sshp sshg init-id reply-id group-info)
    (define-values (cpub) (recvp io init-id "X"))              ;  S <- C
    (define-values (spub ssh-shared-secret) (DiffieHellman-get-shared-secret/S sshp sshg cpub kex-length-requirement))
    (define public-host-key-blob (ssh-host-public-file->blob "/home/tewk/.ssh/rktsshhost.pub"))

    (define exchange-hash (diffie-hellman-exchange-hash hasher->bin group-info cpub spub ssh-shared-secret public-host-key-blob))
    (define signature (sha1-rsa-sign/fn "/home/tewk/.ssh/rktsshhost" exchange-hash))
    (sendp io reply-id
      (build-ssh-bytes public-host-key-blob)
      spub
      (build-ssh-bytes (bytes-append (build-ssh-bytes #"ssh-rsa") (build-ssh-bytes signature))))
    (init-streams exchange-hash ssh-shared-secret hasher->bin))

  (define (client-group-exchange)
    (sendp io SSH_MSG_KEX_DH_GEX_REQUEST (->bytes 1024) (->bytes 1024) (->bytes 8192))
    (define-values (sshp sshg) (recvp io SSH_MSG_KEX_DH_GEX_GROUP "XX"))
    (values 1024 1024 8192 sshp sshg))

  (define (server-group-exchange)
    (define-values (bmin bm bmax) (recvp io SSH_MSG_KEX_DH_GEX_REQUEST "iii")) ;  S <- C
    (sendp io SSH_MSG_KEX_DH_GEX_GROUP sshp14 sshg14)                          ;  S -> C
    (values bmin bm bmax sshp14 sshg14))

  (define (group-exchange hasher->bin)
    (define-values (bmin bm bmax sshp sshg) (if (server? role) (server-group-exchange) (client-group-exchange)))
    ((if (server? role) server-diffie-hellman client-diffie-hellman)
         hasher->bin sshp sshg SSH_MSG_KEX_DH_GEX_INIT SSH_MSG_KEX_DH_GEX_REPLY (bytes-append (->bytes bmin) (->bytes bm) (->bytes bmax) sshp sshg)))

  (define (exchange sshp sshg)
    ((if (server? role) server-diffie-hellman client-diffie-hellman) sha1->bin sshp sshg SSH_MSG_KEXDH_INIT SSH_MSG_KEXDH_REPLY #""))

  (define sshp14 (build-ssh-bytes (hex-bytes->bytes (bytes-append
    #"00FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    #"29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    #"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    #"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    #"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    #"C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    #"83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    #"670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    #"E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    #"DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    #"15728E5A8AACAA68FFFFFFFFFFFFFFFF"))))
  (define sshg14 (build-ssh-bytes (bytes 2)))
  (define sshp1 (build-ssh-bytes (hex-bytes->bytes (bytes-append
      #"00FFFFFFFFFFFFFFFFC90FDAA22168C234"
      #"C4C6628B80DC1CD129024E088A67CC74"
      #"020BBEA63B139B22514A08798E3404DD"
      #"EF9519B3CD3A431B302B0A6DF25F1437"
      #"4FE1356D6D51C245E485B576625E7EC6"
      #"F44C42E9A637ED6B0BFF5CB6F406B7ED"
      #"EE386BFB5A899FA5AE9F24117C4B1FE6"
      #"49286651ECE65381FFFFFFFFFFFFFFFF"))))
  (define sshg1 (build-ssh-bytes (bytes 2)))

  (define (init-streams exchange-hash ssh-shared-secret hasher->bin)
    (sendp io SSH_MSG_NEWKEYS)
    (unless (recv/assert io SSH_MSG_NEWKEYS) (error "Expected SSH_MSG_NEWKEYS"))

    (define session-id (send io get-session-id exchange-hash))

    (define (gen k) (hasher->bin ssh-shared-secret exchange-hash k session-id))
    (define-values (C->S S->C) (send io get-CS-SC))
    (send C->S init client-sym client-hmac (gen #"A") (gen #"C") (gen #"E"))
    (send S->C init server-sym server-hmac (gen #"B") (gen #"D") (gen #"F"))

    exchange-hash)

  (match kex-alg
    [#"diffie-hellman-group-exchange-sha256" (group-exchange sha256->bin)]
    [#"diffie-hellman-group-exchange-sha1"   (group-exchange sha1->bin)]
    [#"diffie-hellman-group14-sha1"          (exchange sshp14 sshg14)]
    [#"diffie-hellman-group1-sha1"           (exchange sshp1 sshg1)]
    [else (error (format "key exchange algorithm ~a not supported" kex-alg))]))
  

