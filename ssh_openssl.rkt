#lang racket/base
(require "openssl.rkt"
         openssl/sha1
         racket/port
         net/base64
         ffi/unsafe
         (for-syntax racket/base))

(provide MD5-it
         DiffieHellmanGroup1-get-public-key
         DiffieHellman-get-public-key
         DiffieHellman-get-shared-secret
         DiffieHellmanGroup14-get-shared-secret
         sha1->hex
         sha1->bin
         sha256->hex
         sha256->bin
         build-ssh-bn
         build-ssh-bin
         fn->EVP_PKEY-private
         sha1-rsa-signature
         sha1-rsa-signature/fn
         ssh-host-public-file->blob
         bytes->hex-string)

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
  (define result (make-bytes 16))
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
