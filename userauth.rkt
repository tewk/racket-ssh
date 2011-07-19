#lang racket
(require "utils.rkt")
(require "constants.rkt")
(require "ssh-openssl.rkt")

(provide do-client-user-auth
         do-server-user-auth)

(define (do-client-user-auth io)
  (sendp io SSH_MSG_SERVICE_REQUEST "ssh-userauth")
  (unless (recv/assert io SSH_MSG_SERVICE_ACCEPT "ssh-userauth")
    (error 'do-client-user-auth "BAD USER AUTH SERVICE REQUEST"))

  (sendp io SSH_MSG_USERAUTH_REQUEST "tewk" "ssh-conenction" "publickey" #f "ssh-rsa" "boo")
  (recv/assert io SSH_MSG_USERAUTH_PK_OK "ssh-rsa" "boo")
  (sendp io SSH_MSG_USERAUTH_REQUEST "tewk" "ssh-connection" "publickey" #t "ssh-rsa" "boo" "boos")
  (recv/assert io SSH_MSG_USERAUTH_SUCCESS))


(define (auth-failure io others)
  (sendp io SSH_MSG_USERAUTH_FAILURE others))
(define (auth-success io)
  (sendp io SSH_MSG_USERAUTH_SUCCESS))

(define (parse-auth-request io sessionid)
  (define in (open-input-bytes (send io recv-packet)))
  (define-values (pktid user serv type) (parse in "bsss"))
  (cond 
    [(bytes=? type #"publickey")
      (define-values (bool algo keyy) (parse in "Bss"))
      (if bool 
        (let ([sign (read-ssh-string in)])
          (define-values (key-alg key1 key2) (parse/bs keyy "sss"))
          (define-values (sig-alg sig) (parse/bs sign "ss"))
          (define local-sig (unparse "sbsssBss" sessionid SSH_MSG_USERAUTH_REQUEST user serv type bool algo keyy))
          (define rc (sha1-rsa-verify/sha1/e_n local-sig key1 key2 sig))
          (if (= rc 1)
            (auth-success io)
            (auth-failure io "publickey")))
        (let ()
          (sendp io SSH_MSG_USERAUTH_PK_OK (->sshb algo keyy))
          (parse-auth-request io sessionid)))]
    [(bytes=? type #"none") (auth-failure io "publickey")]
    [(bytes=? type #"password")
      (define-values (bool pass) (parse in "Bs"))
      (if (equal? pass #"BOGUSBOGUS")
          (auth-success io)
          (auth-failure io ""))]))

(define (do-server-user-auth io sessionid)
  (recv/assert io SSH_MSG_SERVICE_REQUEST "ssh-userauth")
  (sendp io SSH_MSG_SERVICE_ACCEPT "ssh-userauth")
  (parse-auth-request io sessionid))

