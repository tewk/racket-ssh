#lang racket/base
(require "openssl.rkt"
         "ssh-utils.rkt"
         openssl/sha1
         racket/port
         net/base64
         ffi/unsafe
         (for-syntax racket/base))

(provide MD5-it
         DiffieHellman-get-public-key
         DiffieHellman-get-shared-secret/C
         DiffieHellman-get-shared-secret/S
         sha1->hex
         sha1->bin
         sha256->hex
         sha256->bin
         fn->EVP_PKEY-private
         sha1-rsa-signature
         sha1-rsa-signature/fn
         sha1-rsa-verify/bin
         ssh-host-public-file->blob
         bytes->hex-string)

(define (sha1-rsa-signature/fn fn b)
  (let ([db (make-bytes EVP_MAX_MD_SIZE)]
        [dl EVP_MAX_MD_SIZE]
        [ctx (EVP_MD_CTX_create)])
    (EVP_DigestInit ctx (EVP_sha1))
    (EVP_DigestUpdate ctx b (bytes-length b))
    (EVP_DigestFinal ctx db dl)
    (define digest (subbytes db 0 20))
    (define pk (fn->RSAPrivateKey fn))
    (define sl (RSA_size pk))
    (define sb (make-bytes sl))
    (RSA_sign NID_sha1 digest (bytes-length digest) sb sl pk)
    (subbytes sb 0 sl)))

(define (sha1-rsa-verify/bin b key sig)
  (define pk (bin->RSAPublicKey key))
  (RSA_verify NID_sha1 b (bytes-length b) sig (bytes-length sig) key))

(define (sha1-rsa-signature b key)
  (let ([digest (make-bytes EVP_MAX_MD_SIZE)]
        [dl EVP_MAX_MD_SIZE]
        [ctx (EVP_MD_CTX_create)])
    (EVP_DigestInit ctx (EVP_sha1))
    (EVP_DigestUpdate ctx b (bytes-length b))
    (EVP_SignFinal ctx digest dl key)
    (subbytes digest 0 dl)))

(define (bin->EVP_PKEY-private bin)
  (define bio #f)
  (dynamic-wind
    (lambda () (set! bio (BIO_new_mem_buf bin (bytes-length bin))))
    (lambda () (PEM_read_bio_PrivateKey bio #f #f #f))
    (lambda () (BIO_free bio))))

(define (fn->EVP_PKEY-private fn)
  (define bio #f)
  (dynamic-wind
    (lambda () (set! bio (BIO_new_file (->bytes fn) #"r")))
    ``(lambda () (PEM_read_bio_PrivateKey bio #f #f #f))
    (lambda () (BIO_free bio))))

(define (fn->RSAPrivateKey fn)
  (define bio #f)
  (dynamic-wind
    (lambda () (set! bio (BIO_new_file (->bytes fn) #"r")))
    (lambda () (PEM_read_bio_RSAPrivateKey bio #f #f #f))
    (lambda () (BIO_free bio))))

(define (bin->RSAPublicKey bin)
  (define bio #f)
  (dynamic-wind
    (lambda () (set! bio (BIO_new_mem_buf bin (bytes-length bin))))
    (lambda () (PEM_read_bio_RSAPublicKey bio #f #f #f))
    (lambda () (BIO_free bio))))

(define (sha1->hex . lst)
  (bytes->hex-string (apply sha1->bin lst)))
(define (sha1->bin . lst)
  (let ([ctx (malloc 256)]
        [tmp (make-bytes 4096)]
        [result (make-bytes SHA1_DIGEST_LENGTH)])
    (SHA1_Init ctx)
    (for ([x lst]) (SHA1_Update ctx x (bytes-length x)))
    (SHA1_Final result ctx)
    result))

(define (sha256->hex . lst)
  (bytes->hex-string (apply sha256->bin lst)))
(define (sha256->bin . lst)
  (let ([ctx (malloc 256)]
        [tmp (make-bytes 4096)]
        [result (make-bytes SHA256_DIGEST_LENGTH)])
    (SHA256_Init ctx)
    (for ([x lst]) 
      (SHA256_Update ctx x (bytes-length x)))
    (SHA256_Final result ctx)
    result))

(define (build-ssh-bin b)
  (define bl (bytes-length b))
  (if (not (= 0 (bitwise-and #x80 (bytes-ref b 0))))
    (bytes-append (->bytes (+ bl 1)) (bytes 0) b)
    (bytes-append (->bytes bl) b)))

(define (build-ssh-bn bn)
  (define b (make-bytes (BN_num_bytes bn) 0))
  (define bl (BN_bn2bin bn b))
  (build-ssh-bin (subbytes b 0 bl)))

(define (sshbytes->string x) 
  (subbytes x
            (if (= (bytes-ref x 4) 0) 5 4) 
            (bytes-length x)))

(define (DiffieHellman-get-public-key _pbs _gbs)
  (define pbs (sshbytes->string _pbs))
  (define gbs (sshbytes->string _gbs))
  (define dh (DH_new))
  (define p (BN_new))
  (define g (BN_new))

  (set-DH-p! dh (BN_bin2bn pbs (bytes-length pbs) p))
  (set-DH-g! dh (BN_bin2bn gbs (bytes-length gbs) g))
  (DiffieHellmanGenerateKey dh (* 20 8))
  (values dh (build-ssh-bn (DH-pub_key dh))))

(define (MD5-it d)
  (define r (make-bytes 16 0))
  (MD5 d (bytes-length d) r)
  r)

(define (DiffieHellman-get-shared-secret/C dh _peer-public-key)
  (define peer-public-key (sshbytes->string _peer-public-key))
  (define peer-key (BN_new))
  (BN_bin2bn peer-public-key (bytes-length peer-public-key) peer-key)
  (define shared-secret (make-bytes (DH_size dh)))
  (DH_compute_key shared-secret peer-key dh)
  (build-ssh-bin shared-secret))

(define (DiffieHellman-get-shared-secret/S pbs gbs peer-public-key)
  (define-values (dh pub_key) (DiffieHellman-get-public-key pbs gbs))
  (define ssh-shared-secret (DiffieHellman-get-shared-secret/C dh peer-public-key))
  (values pub_key ssh-shared-secret))

(define (DiffieHellmanGenerateKey dh bits-needed)
  (define pbits (BN_num_bits (DH-p dh)))
  (define bits-needed*2 (* 2 bits-needed))
  ;(printf "~a ~a ~a\n" bits-needed bits-needed*2 pbits)
  (when (bits-needed . > . (/ 2147483647 2))
    (eprintf "DiffieHellmanGenerateKey group too bi: ~a (2*bits-needed ~a)\n" pbits bits-needed*2))
  (when (bits-needed*2 . >= . pbits)
    (eprintf "DiffieHellmanGenerateKey group too small: (p bits ~a) <= (2*bits-needed ~a) \n" pbits bits-needed*2))

  (let loop ()
    ;(when (not (DH-priv_key dh))
    ;  (BN_clear_free (DH-priv_key dh)))
    (set-DH-priv_key! dh (BN_new))
    (when (= 0 (BN_rand (DH-priv_key dh) bits-needed*2 0 0))
      (eprintf "dh_gen_key: BN_rand failed"))
    (when (= 0 (DH_generate_key dh))
      (eprintf "DH_generate_key failed"))
    (if (not (DiffieHellmanPubIsValid dh (DH-pub_key dh) "desc"))
      (loop)
      #t)))

(define-syntax-rule (with-BN ([a b]...) body ...)
  (let* ([a null] ...)
    (dynamic-wind
      (lambda ()
        (set! a b) ...)
      (lambda ()
        body ...)
      (lambda ()
        (BN_clear_free a) ...))))

(define-syntax-rule (for/sum ([a b]...) body ...)
  (for/fold ([sum 0]) ([a b]...)
    (+ sum (begin body ...)))) 

(define (DiffieHellmanPubIsValid dh pub desc)
 (with-BN ([tmp (BN_new)])
  ;(printf "publ ") (BNp (DH-pub_key dh))
  ;(printf "priv ") (BNp (DH-priv_key dh))
  ;(printf "p    ") (BNp (DH-p dh))
  (BN_sub tmp (DH-p dh) (BN_value_one))
  ;(printf "p-1  ") (BNp tmp)
  ;(printf "cmp pub tmp ~a\n" (BN_cmp pub tmp))
  (cond 
   [(not (zero? (BN-neg pub))) (eprintf "~a pub is negative" desc) #f]
   [(not (= 1 (BN_cmp pub (BN_value_one)))) (eprintf "~a pub is <= 1" desc) #f]
   [(or (zero? (BN_sub tmp (DH-p dh) (BN_value_one)))
        (not (= -1 (BN_cmp pub tmp))))
        (eprintf "invalid public DH value: >= p-1\n")
        (eprintf "~a ~a ~a\n" (DH-p dh) pub (BN_cmp pub tmp))
        (BNp (DH-p dh))
        (BNp tmp)
        (BNp pub)
        #f]
  [else
    (define pbits (BN_num_bits (DH-p dh)))
    (define pub-bits-set (for/sum ([i (in-range pbits)]) (BN_is_bit_set pub i)))
    ;(eprintf "bits set ~a/~a\n" pub-bits-set pbits)
    (if (pub-bits-set . > . 1)
      #t
      (begin
        (eprintf "invalid public DH value (~a/~a)\n" pub-bits-set pbits)
        #f))])))

(define-syntax-rule (define/provide (n a ...) b ...)
  (begin
    (provide n)
    (define (n a ...) b ...)
    ))

(define name->cipher
  (make-hash (list (cons #"aes128-cbc" EVP_aes_128_cbc))))

(define (ssh-name->cipher ssh-name)
  (hash-ref name->cipher ssh-name 
    (lambda () (error (format "Cipher ~a not found" ssh-name)))))
  
(define name->hmac
  (make-hash (list (cons #"hmac-md5" EVP_md5)
                   (cons #"hmac-sha1" EVP_sha1))))

(define (ssh-name->hmac ssh-name)
  (hash-ref name->hmac ssh-name 
    (lambda () (error (format "HMAC ~a not found" ssh-name)))))
  
(define/provide (make-cipher)
  (define c (EVP_CIPHER_CTX_new))
  (EVP_CIPHER_CTX_init c)
  c)

(define/provide (make-hmac)
  (define c (malloc 240))
  (HMAC_CTX_init c)
  c)

(define/provide (hmac-init hcntx ssh-name key)
  (define evp ((ssh-name->hmac ssh-name)))
  (define size (EVP_MD_size evp))
  (define block_size (EVP_MD_block_size evp))
  (define rc (HMAC_Init_ex hcntx (subbytes key 0 size) size evp #f))
  (values rc size block_size))

(define/provide (hmacit hcntx data)
  (define result (make-bytes EVP_MAX_MD_SIZE))
  (HMAC_Init_ex hcntx #f 0 #f #f)
  (HMAC_Update hcntx data (bytes-length data))
  (define rl (HMAC_Final hcntx result))
  result)

(define/provide (cipher-init ccntx ssh-name ec iv en/de)
  (define rc (EVP_CipherInit_ex ccntx ((ssh-name->cipher ssh-name)) #f ec iv en/de))
  (EVP_CIPHER_CTX_set_padding ccntx 0)
  (values rc (EVP_CIPHER_CTX_block_size ccntx) (EVP_CIPHER_CTX_key_length ccntx) (EVP_CIPHER_CTX_iv_length ccntx)))

(define/provide (decrypt-begin ccntx buffer iv)
  (define bl (bytes-length buffer))
  (define rl (+ bl 16))
  (define result (make-bytes rl))
  (define resultlen rl)
  (EVP_CipherInit_ex ccntx #f #f #f iv 0)
  (define-values (r rlo) (EVP_CipherUpdate ccntx result buffer bl))
  (subbytes result 0 rlo))

(define/provide (decrypt-rest ccntx buffer)
  (define bl (bytes-length buffer))
  (define rl (+ bl 16))
  (define result (make-bytes rl))
  (define result2 (make-bytes 32))
  (define-values (r rlo) (EVP_CipherUpdate ccntx result buffer bl))
  (define-values (r2 rlo2) (EVP_CipherFinal_ex ccntx result2))
  (bytes-append (subbytes result 0 rlo)
                (subbytes result2 0 rlo2)))

(define/provide (encrypt-all ccntx buffer iv)
  (define bl (bytes-length buffer))
  (define rl (+ bl 16))
  (define result (make-bytes rl))
  (define result2 (make-bytes 16))
  (EVP_CipherInit_ex ccntx #f #f #f iv 1)
  (define-values (r rlo) (EVP_CipherUpdate ccntx result buffer bl))
  (define-values (r2 rlo2) (EVP_CipherFinal_ex ccntx result2))
  (bytes-append (subbytes result 0 rlo)
                (subbytes result2 0 rlo2)))

(define (ssh-host-public-file->blob fn)
  (define b64 (call-with-input-file fn port->bytes))
  (base64-decode (regexp-replace #px"\\S+\\s+(\\S+)\\s+\\S+" b64 #"\\1")))
