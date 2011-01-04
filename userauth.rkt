#lang racket
(require "ssh-utils.rkt")
(require "ssh-msg-ids.rkt")
(require "ssh_openssl.rkt")

(provide do-client-user-auth
         do-server-user-auth)

(define (do-client-user-auth io)
  (sendp io SSH_MSG_SERVICE_REQUEST #"ssh-userauth")
  (unless (recv/assert io SSH_MSG_SERVICE_ACCEPT #"ssh-userauth")
    (error 'do-client-user-auth "BAD USER AUTH SERVICE REQUEST"))

  (sendp io SSH_MSG_USERAUTH_REQUEST "tewk" "SERVICE" "publickey" #f "rsa" "boo")
  (recv/assert io SSH_MSG_USERAUTH_PK_OK "rsa" "boo")
  (sendp io SSH_MSG_USERAUTH_REQUEST "tewk" "SERVICE" "publickey" #t "rsa" "boo" "boos")
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
          (define local-sig (bytes-append (->sshb sessionid)
                              (bytes SSH_MSG_USERAUTH_REQUEST)
                              (->sshb user serv type bool algo keyy)))
          (if (equal? sign local-sig)
            (auth-success io)
            (auth-failure io "publickey")))
        (let ()
          (printf "~a ~a ~a ~a ~a ~a\n~a\n" pktid user serv type bool algo (bytes->hex-string keyy))
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
  (sendp io SSH_MSG_SERVICE_ACCEPT #"ssh-userauth")
  (parse-auth-request io sessionid))

