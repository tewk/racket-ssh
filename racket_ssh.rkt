#lang racket
(require "ssh_openssl.rkt")

(define (->bytes x)
  (cond [(string? x) (string->bytes/locale x)]
        [(bytes? x) x]
        [(number? x) (integer->integer-bytes x 4 #f #t)]))

(define (build-ssh-bytes data)
  (define byte-data (->bytes data))
  (bytes-append
    (->bytes (bytes-length byte-data))
    byte-data))

(define (read-ssh-string in)
  (define len (integer-bytes->integer (read-bytes 4 in) #f #t))
  (define data (read-bytes len in))
;  (eprintf "SSHSTR: ~a~n" len)
  data)

(define (read-ssh-bool in) (if (= 0 (read-byte in)) #f #t))
(define (read-ssh-uint32 in) (integer-bytes->integer (read-bytes 4 in) #f #t))
(define (random-bytes cnt) (apply bytes (for/list ([x (in-range cnt)]) (random 256))))

(define (build-kexinit)
  (bytes-append
  (bytes SSH_MSG_KEXINIT) 
  (random-bytes 16)
  (build-ssh-bytes #"diffie-hellman-group-exchange-sha256,diffie-hellman-group-exchange-sha1,diffie-hellman-group14-sha1,diffie-hellman-group1-sha1")
  ;(build-ssh-bytes #"diffie-hellman-group1-sha1")
  (build-ssh-bytes #"ssh-rsa,ssh-dss")
;  (build-ssh-bytes #"aes128-ctr,aes192-ctr,aes256-ctr,arcfour256,arcfour128,aes128-cbc,3des-cbc,blowfish-cbc,cast128-cbc,aes192-cbc,aes256-cbc,arcfour,rijndael-cbc@lysator.liu.se")
;  (build-ssh-bytes #"aes128-ctr,aes192-ctr,aes256-ctr,arcfour256,arcfour128,aes128-cbc,3des-cbc,blowfish-cbc,cast128-cbc,aes192-cbc,aes256-cbc,arcfour,rijndael-cbc@lysator.liu.se")
  (build-ssh-bytes #"aes128-cbc")
  (build-ssh-bytes #"aes128-cbc")
  (build-ssh-bytes #"hmac-md5,hmac-sha1,umac-64@openssh.com,hmac-ripemd160,hmac-ripemd160@openssh.com,hmac-sha1-96,hmac-md5-96")
  (build-ssh-bytes #"hmac-md5,hmac-sha1,umac-64@openssh.com,hmac-ripemd160,hmac-ripemd160@openssh.com,hmac-sha1-96,hmac-md5-96")
  (build-ssh-bytes #"none,zlib@openssh.com,zlib")
  (build-ssh-bytes #"none,zlib@openssh.com,zlib")
  (build-ssh-bytes #"")
  (build-ssh-bytes #"")
  (bytes 0)
  (integer->integer-bytes 0 4 #t)))

(define (parse-kexinit bytes)
  (define in (open-input-bytes bytes))
  (define type (read-byte in))
  (define cookie (read-bytes 16 in))
  (define lines (for/list ([x (in-range 9)]) (read-ssh-string in)))
  (define r1 (read-ssh-string in))
  (define first-kex-pkt (read-ssh-bool in))
  (define future-use (read-ssh-uint32 in))
  (eprintf "KEXINIT PACKET: ~a ~a ~a~n" type (bytes->hex-string cookie) first-kex-pkt)
  (for ([x lines]) (eprintf "~a~n" x)))
;      byte         SSH_MSG_KEXINIT
;      byte[16]     cookie (random bytes)
;      name-list    kex_algorithms
;      name-list    server_host_key_algorithms
;      name-list    encryption_algorithms_client_to_server
;      name-list    encryption_algorithms_server_to_client
;      name-list    mac_algorithms_client_to_server
;      name-list    mac_algorithms_server_to_client
;      name-list    compression_algorithms_client_to_server
;      name-list    compression_algorithms_server_to_client
;      name-list    languages_client_to_server
;      name-list    languages_server_to_client
;      boolean      first_kex_packet_follows
;      uint32       0 (reserved for future extension)

(define (parse-dh-reply bytes)
  (define in (open-input-bytes bytes))
  (define type (read-byte in))
  (define s1 (read-ssh-string in))
  (define s2 (read-ssh-string in))
  (define s3 (read-ssh-string in))
  (printf "~a\n~a\n~a\n" s1 s2 s3))

(define (parse-dh-group-exch-req bytes)
  (define in (open-input-bytes bytes))
  (define type (read-byte in))
  (values (read-ssh-uint32 in)
          (read-ssh-uint32 in)
          (read-ssh-uint32 in)))

(define (parse-dh-group-exch-reply bytes)
  (define in (open-input-bytes bytes))
  (define type (read-byte in))
  (values (read-ssh-string in)
          (read-ssh-string in)))

(define (parse-dh-group-exch-init bytes)
  (define in (open-input-bytes bytes))
  (define type (read-byte in))
  (read-ssh-string in))

(define (parse-dh-group-exch-gex-reply bytes)
  (define in (open-input-bytes bytes))
  (define type (read-byte in))
  (define host-key- (read-ssh-string in))
  (define in2 (open-input-bytes host-key-))
  (define host-key (read-ssh-string in2))
  (define host-key-cert (read-ssh-string in2))
  (define server-pub (read-ssh-string in))
  (define sigbuf (read-ssh-string in))
  (define in3 (open-input-bytes sigbuf))
  (define sig-type (read-ssh-string in3))
  (define sig (read-ssh-string in3))
  (values host-key host-key-cert server-pub sig-type sig))

(define SSH_MSG_DISCONNECT                       1) 
(define SSH_MSG_IGNORE                           2) 
(define SSH_MSG_UNIMPLEMENTED                    3) 
(define SSH_MSG_DEBUG                            4) 
(define SSH_MSG_SERVICE_REQUEST                  5) 
(define SSH_MSG_SERVICE_ACCEPT                   6) 
(define SSH_MSG_KEXINIT                         20) 
(define SSH_MSG_NEWKEYS                         21) 
(define KEXDH_INIT                              30) 
(define KEXDH_REPLY                             31) 
(define KEXDH_GEX_GROUP    31)
(define KEXDH_GEX_INIT     32)
(define KEXDH_GEX_REPLY    33)
(define KEXDH_GEX_REQUEST  34)
(define SSH_MSG_USERAUTH_REQUEST                50) 
(define SSH_MSG_USERAUTH_FAILURE                51) 
(define SSH_MSG_USERAUTH_SUCCESS                52) 
(define SSH_MSG_USERAUTH_BANNER                 53) 
(define SSH_MSG_GLOBAL_REQUEST                  80) 
(define SSH_MSG_REQUEST_SUCCESS                 81) 
(define SSH_MSG_REQUEST_FAILURE                 82) 
(define SSH_MSG_CHANNEL_OPEN                    90) 
(define SSH_MSG_CHANNEL_OPEN_CONFIRMATION       91) 
(define SSH_MSG_CHANNEL_OPEN_FAILURE            92) 
(define SSH_MSG_CHANNEL_WINDOW_ADJUST           93) 
(define SSH_MSG_CHANNEL_DATA                    94) 
(define SSH_MSG_CHANNEL_EXTENDED_DATA           95) 
(define SSH_MSG_CHANNEL_EOF                     96) 
(define SSH_MSG_CHANNEL_CLOSE                   97) 
(define SSH_MSG_CHANNEL_REQUEST                 98) 
(define SSH_MSG_CHANNEL_SUCCESS                 99) 
(define SSH_MSG_CHANNEL_FAILURE                100) 

(define (dbuffer data)
  (write data)
  (newline)
  (write (apply bytes-append (for/list ([x (in-bytes data)])
                               (case x
                                 [(10 13) (bytes x)]
                                 [else (bytes x 32)]))))
  (newline)
  (write (string->bytes/locale (bytes->hex-string data)))
  (newline))
(define (say x) (printf "~a~n" x) x)

(define ssh-transport
  (class object%
    (init-field (in null)
                (out null))
    (field (cipher-in (make-cipher)))
    (field (cipher-out (make-cipher)))
    (field (hmac-in (make-hmac)))
    (field (hmac-out (make-hmac)))
    (field (hmac #f))
    (field (hmaclen 16))
    (field (cipher-block-size 16))
    (field (shared-secret null))
    (field (sendIV null))
    (field (recvIV null))
    (field (sendInteg null))
    (field (recvInteg null))
    (field (sentcnt 0))
    (field (recvcnt 0))

    (define/public (hmac-on shared-secret session_id EIV EEC EInteg DIV DEC DInteg)
      (set! sendIV EIV)
      (set! recvIV DIV)
      (set! sendInteg EInteg)
      (set! recvInteg DInteg)
      (encrypt-init cipher-out "aes-128" EEC EIV)
      (decrypt-init cipher-in  "aes-128" DEC DIV)
      (hmac-init hmac-out "md5" EInteg)
      (hmac-init hmac-in  "md5" DInteg)
      (set! hmac #t))

    (define/public (send-raw-bytes x)
      (write-bytes x out)
      (flush-output out))
    ;  (set! sentcnt (+ sentcnt 1)))

    (define (updateIV ivv)
      (lambda (iv)
        (set! ivv (let* ([b (bytes-append ivv iv)]
                         [bl (bytes-length b)])
                    (subbytes b (- bl cipher-block-size) bl)))))

    (define updateSentIV (updateIV sendIV))
    (define updateRecvIV (updateIV sendIV))

    (define (build-packet buffer)
      (define buf (->bytes buffer))
      (define blen (bytes-length buf))
      (define initial-total-len (+ 4 1 blen))
      (define ipadding-len (- 8 (modulo initial-total-len 8)))
      (define padding-len (if (ipadding-len . < . 4) (+ ipadding-len 8) ipadding-len))
      (define packet-length (+ 1 blen padding-len))
      (define type (bytes-ref buffer 0))
      (eprintf "SENT PKT: type ~a pktlen: ~a padding ~a datalen ~a\n" type packet-length padding-len blen)
      ;(eprintf "~a\n" (bytes->hex-string buf))
      (bytes-append
        (integer->integer-bytes packet-length 4 #f #t)
        (bytes padding-len)
        buf
        (random-bytes padding-len)))

    (define/public (parse-packet buffer)
      (define in (open-input-bytes buffer))
      (define packet-len (integer-bytes->integer (read-bytes 4 in) #f #t))
      (define padding-len (read-byte in))
      (define data-len (- packet-len 1 padding-len))
      (define data (read-bytes data-len in))
      (define padding (read-bytes padding-len in))
      (define type (bytes-ref data 0))
      (eprintf "RECV PKT: type ~a pktlen: ~a padding ~a datalen ~a~n" type packet-len padding-len data-len)
      ;(eprintf "~a\n" (bytes->hex-string data))
      (when (= type 1)
        (define in (open-input-bytes data))
        (define type (read-byte in))
        (define ec (read-ssh-uint32 in))
        (define s1 (read-ssh-string in))
        (define s2 (read-ssh-string in))
        (printf "SSH_CLOSE_CONNECTION ~a desc: ~a langtag: ~a\n" ec s1 s2))
      data)

    (define/public (recv-parse-packet) (parse-packet (recv-packet)))
    (define/public (recv-packet)
      (begin0
      (if hmac
        (let* ([prefix-size (max 4 16)]
               [enc-prefix (read-bytes (max 4 16) in)]
               [prefix (decrypt-begin cipher-in enc-prefix recvIV)]
               [packet-len (integer-bytes->integer (subbytes prefix 0 4) #f #t)]
               [enc-rest (read-bytes (- packet-len 12) in)]
               [rest (decrypt-rest cipher-in enc-rest)]
               [hmac (read-bytes hmaclen in)]
               [pkt (bytes-append prefix rest)]
               [comp-hmac (hmacit hmac-in (bytes-append recvInteg (->bytes (add1 recvcnt)) rest))])
         (printf "ENC RECV ~a ~a ~a\n" packet-len (bytes->hex-string enc-prefix) (bytes->hex-string enc-rest))
         (printf "ENC RECV ~a ~a ~a\n" packet-len (bytes->hex-string prefix) (bytes->hex-string rest))
          (if (bytes=? hmac comp-hmac)
            pkt
            (begin 
              (printf "HMAC DOESNT MATCH TH ~a MI ~a\n" (bytes->hex-string hmac) (bytes->hex-string comp-hmac))
              (printf "~a ~a\n" prefix rest)
              pkt)))
        (let* ([prefix-size 4]
               [prefix (read-bytes prefix-size in)]
               [packet-len (integer-bytes->integer prefix #f #t)]
               [rest (read-bytes packet-len in)]
               [pkt (bytes-append prefix rest)])
          pkt))
      (set! recvcnt (+ recvcnt 1))))

    (define/public (send-build-packet buffer) (send-packet (build-packet buffer)))
    (define/public (send-packet pkt)
      (if hmac
        (let ([b (hmacit hmac-out (bytes-append sendInteg (->bytes sentcnt) pkt))])
          (printf "MD5 ~a ~a\n" sentcnt (bytes->hex-string b))
          (write-bytes (encrypt-all cipher-out pkt sendIV) out)
          (write-bytes b out)
          (updateSentIV pkt))
        (write-bytes pkt out))
      (flush-output out)
      (set! sentcnt (+ sentcnt 1)))

    (super-new)))

(define ssh
  (class object%
    (init-field (host "localhost") (port 2224))
    (field (io null))
    (define/public (send-buffer x)
      (send io send-build-packet x))
    (define/public (send-raw x)
      (send io send-raw-bytes x))
    (define/public (recv-packet)
      (send io recv-parse-packet))
    (define/public (connect host port)
      (define-values (in out) (tcp-connect "localhost" 2224))
      (set! io (new ssh-transport (in in) (out out)))


      (define SERVER_VERSION (read-line in))
      (printf "SERVER: ~a\n" SERVER_VERSION)
      (define CLIENT_VERSION #"SSH-2.0-RacketSSH_0.1p0 Racket5.0\r\n")
      (send-raw CLIENT_VERSION)

      (define CLIENT_KEX_PAYLOAD (build-kexinit))
      (send-buffer CLIENT_KEX_PAYLOAD)
      (define SERVER_KEX_PAYLOAD (recv-packet))
      (parse-kexinit SERVER_KEX_PAYLOAD)

      ;DH-GROUP_EXECH
      (let ([b (bytes-append (bytes KEXDH_GEX_REQUEST) (->bytes 1024) (->bytes 1024) (->bytes 8192))])
        ;(printf "~a\n" (bytes->hex-string b))
        (send-buffer b))
      (let-values ([(pbs gbs) (parse-dh-group-exch-reply (recv-packet))])
        (printf "P ~a~nG ~a~n" (bytes->hex-string pbs) (bytes->hex-string gbs))
        (let-values ([(dh pub) (DiffieHellman-get-public-key pbs gbs 20)])
          (let ([b (bytes-append (bytes KEXDH_GEX_INIT) pub)])
           ;(printf "~a\n" (bytes->hex-string b))
           (send-buffer b))
          (let-values ([(s-host-key s-sig server-pub-key sigtype sig) (parse-dh-group-exch-gex-reply (recv-packet))])
            (let-values ([(shared-secret) (DiffieHellman-get-shared-secret dh server-pub-key)])
            (printf "~a~n" (bytes->hex-string (recv-packet)))
            (send-buffer (bytes SSH_MSG_NEWKEYS))))))
    
;IV (sha256->bin shared-secret #"A" session_id) 
;EC (sha256->bin shared-secret #"C" session_id) 
;Integ (sha256->bin shared-secret #"E" session_id) 

      (send io hmac-on))
 
    (super-new)))

(define (hex-bytes->bytes bstr)
  (let* ([len (bytes-length bstr)]
         [bstr2l (/ len 2)]
         [bstr2 (make-bytes bstr2l)]
         [digit
          (lambda (v)
            (if (v . <= . (char->integer #\9))
                (- v (char->integer #\0))
            (if (v . <= . (char->integer #\F))
                (+ (- v (char->integer #\A)) 10)
                (+ (- v (char->integer #\a)) 10))))])
    (for ([i (in-range bstr2l)])
      (let ([c1 (bytes-ref bstr (* 2 i))]
            [c2 (bytes-ref bstr (+ (* 2 i) 1))])
        ;(printf "~a ~a ~a ~a\n" c1 c2 (digit c1) (digit c2))
        (bytes-set! bstr2 i (bitwise-ior (arithmetic-shift (digit c1) 4)
                                         (digit c2)))))
    bstr2))

(define sshd
  (class object%
    (init-field (host "localhost") (port 22))
    (field (io null))
    (define/public (send-buffer x) (send io send-build-packet x))
    (define/public (send-raw x)    (send io send-raw-bytes x))
    (define/public (recv-packet)   (send io recv-parse-packet))
    (define/public (listen)
      (define-values (in out) (tcp-accept (tcp-listen 2222 4 #t)))
      (set! io (new ssh-transport (in in) (out out)))
      (define SERVER_VERSION #"SSH-2.0-RacketSSH_0.1p0 Racket5.0\r\n")
      (send-raw SERVER_VERSION)
      (define CLIENT_VERSION (read-line in))
      (printf "CLIENT: ~a\n" CLIENT_VERSION)

      (define SERVER_KEX_PAYLOAD (build-kexinit))
      (send-buffer SERVER_KEX_PAYLOAD)
      (define CLIENT_KEX_PAYLOAD (recv-packet))
      (parse-kexinit CLIENT_KEX_PAYLOAD)

      (define p (hex-bytes->bytes (bytes-append
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
#"15728E5A8AACAA68FFFFFFFFFFFFFFFF")))
      (define g (bytes 2))
      (define sshp (build-ssh-bytes p))
      (define sshg (build-ssh-bytes g))
      (define public-host-key-blob (ssh-host-public-file->blob "/home/tewk/.ssh/rktsshhost.pub"))
      (define (chomprn x) (regexp-replace "\r$" (regexp-replace "\n$" (regexp-replace "\r\n$" x "") "") ""))
      (define-values (bmin bm bmax) (parse-dh-group-exch-req (recv-packet)))
      (send-buffer (bytes-append (bytes KEXDH_GEX_GROUP) sshp sshg))
      (define-values (client-e) (parse-dh-group-exch-init (recv-packet)))
      (define-values (dh pub shared-secret) (DiffieHellmanGroup14-get-shared-secret client-e))
      (define ssh-shared-secret (build-ssh-bin shared-secret))
  ;    (printf "E   ~a ~a~n" (bytes-length client-e) (bytes->hex-string client-e))
  ;    (printf "PUB ~a~n" (bytes->hex-string pub))
  ;    (printf "SS  ~a~n" (bytes->hex-string ssh-shared-secret))
      (define exchange-hash 
        (sha256->bin 
          (build-ssh-bytes (chomprn CLIENT_VERSION)) 
          (build-ssh-bytes (chomprn SERVER_VERSION))
          (build-ssh-bytes CLIENT_KEX_PAYLOAD)
          (build-ssh-bytes SERVER_KEX_PAYLOAD)
          (build-ssh-bytes public-host-key-blob)
          (->bytes bmin) (->bytes bm) (->bytes bmax) 
          sshp 
          sshg 
          (build-ssh-bytes client-e)
          pub
          ssh-shared-secret))
      (define signature (sha1-rsa-signature/fn "/home/tewk/.ssh/rktsshhost" exchange-hash))
      (send-buffer (bytes-append 
        (bytes KEXDH_GEX_REPLY) 
        (build-ssh-bytes public-host-key-blob)
        pub
        (build-ssh-bytes (bytes-append (build-ssh-bytes #"ssh-rsa") (build-ssh-bytes signature)))))



      (printf "CLIENT SSH_MSG_NEWKEYS ~a~n" (bytes->hex-string (recv-packet)))
      (define session_id exchange-hash)
      (define DIV (sha256->bin ssh-shared-secret exchange-hash #"A" session_id))
      (define DEC (sha256->bin ssh-shared-secret exchange-hash #"C" session_id))
      (define DInteg (sha256->bin ssh-shared-secret exchange-hash #"E" session_id))
      (define EIV (sha256->bin ssh-shared-secret exchange-hash #"B" session_id))
      (define EEC (sha256->bin ssh-shared-secret exchange-hash #"D" session_id))
      (define EInteg (sha256->bin ssh-shared-secret exchange-hash #"F" session_id))
      (send-buffer (bytes SSH_MSG_NEWKEYS))
      (send io hmac-on shared-secret session_id EIV EEC EInteg DIV DEC DInteg)

      (printf "~a\n" (read-ssh-string (open-input-bytes (recv-packet)))))
    (super-new)))

(match (current-command-line-arguments)
  [(vector) (send (new ssh (host "localhost") (port 22)) connect "localhost" 2224)]
  [(vector "s") (send (new sshd (host "localhost") (port 22)) listen)])
