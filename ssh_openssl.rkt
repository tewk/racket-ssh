#lang racket/base
(require "openssl.rkt"
         openssl/sha1
         racket/port
         net/base64
         (for-syntax racket/base))

(provide MD5-it
         DiffieHellmanGroup1-get-public-key
         DiffieHellman-get-public-key
         DiffieHellman-get-shared-secret
         DiffieHellmanGroup14-get-shared-secret
         sha256->hex
         sha256->bin
         build-ssh-bn
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
  #hash(("aes-128" . 'KKEVP_aes_128_cbc)))

(define (ssh-name->cipher ssh-name)
  (hash-ref name->cipher ssh-name 
    (lambda () (error (format "Cipher ~a not found" ssh-name)))))
  
  
(define/provide (make-cipher)
  (define c (EVP_CIPHER_CTX_new))
  (EVP_CIPHER_CTX_init c)
  c)

(define/provide (encrypt-init ccntx ssh-name ec iv)
  (EVP_EncryptInit_ex ccntx (EVP_aes_128_cbc) #f ec iv))
(define/provide (decrypt-init ccntx ssh-name ec iv)
  (EVP_DecryptInit_ex ccntx (EVP_aes_128_cbc) #f ec iv))

(define/provide (decrypt-begin ccntx buffer iv)
  (define bl (bytes-length buffer))
  (define rl (+ bl 16))
  (define result (make-bytes rl))
  (define resultlen rl)
  (EVP_DecryptInit_ex ccntx #f #f #f iv)
  (define r (EVP_DecryptUpdate ccntx result resultlen buffer bl))
  (printf "DB ~a ~a ~a ~a ~a\n" r (bytes->hex-string result) resultlen (bytes->hex-string buffer) bl)
  (subbytes result 0 resultlen))

(define/provide (decrypt-rest ccntx buffer)
  (define bl (bytes-length buffer))
  (define rl (+ bl 16))
  (define result (make-bytes rl))
  (define resultlen rl)
  (define result2 (make-bytes 16))
  (define resultlen2 16)
  (EVP_DecryptUpdate ccntx result resultlen buffer bl)
  (EVP_DecryptFinal_ex ccntx result resultlen)
  (bytes-append (subbytes result 0 resultlen)
                (subbytes result2 0 resultlen2)))


(define/provide (encrypt-all ccntx buffer iv)
  (define bl (bytes-length buffer))
  (define rl (+ bl 16))
  (define result (make-bytes rl))
  (define resultlen rl)
  (define result2 (make-bytes 16))
  (define resultlen2 16)
  (EVP_EncryptInit_ex ccntx #f #f #f iv)
  (EVP_EncryptUpdate ccntx result resultlen buffer bl)
  (EVP_EncryptFinal_ex ccntx result resultlen)
  (bytes-append (subbytes result 0 resultlen)
                (subbytes result2 0 resultlen2)))


(define (ssh-host-public-file->blob fn)
  (define b64 (call-with-input-file fn port->bytes))
  (base64-decode (regexp-replace #px"\\S+\\s+(\\S+)\\s+\\S+" b64 #"\\1")))

