(ns ipmi-aleph.datastructures
  (:require [gloss.core :refer :all]
            [gloss.io :refer :all]
            [byte-streams :as bs]
            [clojure.string :as str]))

(def status-codes {})

(defcodec network-function-codes
  (enum :byte
        {:chassis-request       0x00
         :chassis-response      0x01
         :bridge-request        0x02
         :bridge-response       0x03
         :ser-request           0x04
         :ser-response          0x05
         :app-request           0x06
         :app-response          0x07
         :firmware-transfer-req 0x08
         :firmware-transfer-rsp 0x09
         :storage-req           0x0A
         :storage-rsp           0x0B
         :transport-req         0x0C
         :transport-rsp         0x0D}))

(defcodec ipmi-payload-types
  (enum :byte
        {:ipmi-message          0x00
         :sol                   0x01
         :oem-explicit          0x02
         :rmcp-open-session-req 0x10
         :rmcp-open-session-rsp 0x11
         :rakp-message-1        0x12
         :rakp-message-2        0x13
         :rakp-message-3        0x14
         :rakp-message-4        0x15}))

(defcodec rakp-auth-algo
  (enum :byte
        {:none        0x00
         :hmac-sha1   0x01
         :hmac-md5    0x02
         :hmac-sha256 0x03}))

(defcodec integrity-algo
  (enum :byte
        {:none            0x00
         :hmac-sha1-96    0x01
         :hmac-md5-128    0x02
         :md5-128         0x03
         :hmac-sha256-128 0x04}))

(defcodec encryption-algo
  (enum :byte
        {:none        0x00
         :aes-cbc-128 0x01
         :xrc4-128    0x02
         :xrc4-40     0x03}))

(defcodec -payload identity)

(defcodec aec-cbc-encryption
  (ordered-map
   :confidentiality-header (repeat 16 :byte)
   :payload -payload
   :pad :byte))

(defcodec ipmi-rmcp-session
  (ordered-map
   :auth-type (bit-map
               :reserved 4
               :authentication 4)
   :sess-seq (repeat 4 :ubyte)
   :sess-id (repeat 4 :ubyte)
   :message-length :ubyte))

(defcodec ipmi-rmcp+-session
  (ordered-map
   :authentication-type :ubyte
   :payload-type (bit-map :encryption 1
                          :authenticated 1
                          :payload-type 6)
   :session-id (repeat 4 :ubyte)
   :session-sequence (repeat 4 :ubyte)))

(def IPMB (compile-frame
           (ordered-map
            :target-address :ubyte
            :app-request (bit-map :net-fun 6
                                  :target-LUN 2)
            :header-checksum :ubyte
            :source-address :ubyte
            :source-LUN (bit-map :sequence 6
                                 :source-LUN 2)
            :command :ubyte)))

(defn RMCP [f] (compile-frame
                (ordered-map :version :ubyte ; 0x06
                             :reserved :ubyte ; 0x00
                             :sequence :ubyte
                             :type (bit-map :messagermcp-ack 1
                                            :reserverd 2
                                            :class 5) ; need lookup
                             ;:ipmi-1-5 IPMI-1-5
                             :payload f
                             ;:ipmb IPMB
                                        ;:payload f
)))

(defcodec payload-type (bit-map :encryption 1
                                :authenticated 1
                                :payload-type 6))

(defcodec myheader
  (ordered-map :first :ubyte
               :second :ubyte))

(defcodec detail {:body :ubyte})
(defcodec none {:none :ubyte})

(defn lookup-codec [code]
  (cond
    (= (:second code) 0) detail
    (= (:second code) 1) detail
    :else none))

(defcodec l1
  (header
   myheader
   #(lookup-codec %)
   (fn [b]
     (:header b))))

;(bs/print-bytes (encode l1 :first 0x00 :second 0x00 :body 0x00))
;(decode l1 (byte-array [0x00 1 0x03]))

;; (defcodec mac-addr (compile-frame (repeat 6 :ubyte)
;;                                   (fn [s]
;;                                     (map
;;                                      #(Integer/parseInt % 16)
;;                                      (str/split s  #":")))
;;                                   (fn [b]
;;                                     (apply str (interpose ":" (map #(Integer/toString % 16) b)))))
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; (defcodec ether-type                                                                                     ;;
;;   (enum :uint16                                                                                          ;;
;;         {                                                                                                ;;
;;          :ARP           0x0806                                                                           ;;
;;          :RARP          0x8035                                                                           ;;
;;          :IPV4          0x0800                                                                           ;;
;;          :LLDP          0x88CC                                                                           ;;
;;          :BSN           0x8942                                                                           ;;
;;          :VLAN-UNTAGGED 0xffff                                                                           ;;
;;          :IPV6          0x86dd                                                                           ;;
;;          }                                                                                               ;;
;;         ))                                                                                               ;;
;;                                                                                                          ;;
;; (defcodec ip-addr (compile-frame (repeat 4 :ubyte)                                                       ;;
;;                                  (fn [s]                                                                 ;;
;;                                    (map                                                                  ;;
;;                                     #(Integer/parseInt %)                                                ;;
;;                                     (str/split s  #"\.")))                                               ;;
;;                                  (fn [b]                                                                 ;;
;;                                    (apply str (interpose "."  b)))))                                     ;;
;;                                                                                                          ;;
;; (defcodec ethernet-header                                                                                ;;
;;   (ordered-map                                                                                           ;;
;;    :destination mac-addr                                                                                 ;;
;;    :source mac-addr                                                                                      ;;
;;    :ether-type ether-type                                                                                ;;
;;    ))                                                                                                    ;;
;;                                                                                                          ;;
;;                                                                                                          ;;
;; (defcodec arp                                                                                            ;;
;;   (ordered-map                                                                                           ;;
;;    ;; :header       ethernet-header                                                                      ;;
;;    :hw-type      :ubyte                                                                                  ;;
;;    :proto-type   :ubyte                                                                                  ;;
;;    :hw-size      :ubyte                                                                                  ;;
;;    :proto-size   :ubyte                                                                                  ;;
;;    :opcode       :ubyte                                                                                  ;;
;;    :sender-mac   mac-addr                                                                                ;;
;;    :sender-ip    ip-addr                                                                                 ;;
;;    :target-mac   mac-addr                                                                                ;;
;;    :target-ip    ip-addr                                                                                 ;;
;;    ))                                                                                                    ;;
;;                                                                                                          ;;
;; (defcodec ip-frame-demo                                                                                  ;;
;;   (ordered-map                                                                                           ;;
;;    :message (repeated :ubyte :prefix :none)                                                              ;;
;;    ))                                                                                                    ;;
;;                                                                                                          ;;
;;                                                                                                          ;;
;; (defn return-ip-codec                                                                                    ;;
;;   [hd]                                                                                                   ;;
;;   (cond                                                                                                  ;;
;;     (=  (:ether-type hd)  :ARP)                   arp                                                    ;;
;;     (=  (:ether-type hd)  :IPV4)                  ip-frame-demo                                          ;;
;;     (=  (:ether-type hd)  :IPV6)                  ip-frame-demo                                          ;;
;;     :else  arp ))                                                                                        ;;
;;                                                                                                          ;;
;; (defcodec ip                                                                                             ;;
;;   (header                                                                                                ;;
;;    ethernet-header                                                                                       ;;
;;    #(return-ip-codec %)                                                                                  ;;
;;    #(% :header)                                                                                          ;;
;;    ))                                                                                                    ;;
;;                                                                                                          ;;
;;                                                                                                          ;;
;;                                                                                                          ;;
;; (defcodec aaa {:first :ubyte :second :ubyte})                                                            ;;
;; (defcodec bbb (enum :ubyte                                                                               ;;
;;                     {:one 1                                                                              ;;
;;                      :two 2}))                                                                           ;;
;;                                                                                                          ;;
;; (defcodec body1 {:third :ubyte})                                                                         ;;
;; (defcodec body2 {:fourth :ubyte})                                                                        ;;
;;                                                                                                          ;;
;;                                                                                                          ;;
;;                                                                                                          ;;
;; (defn b->h [body]                                                                                        ;;
;;   (println "In Body")                                                                                    ;;
;;   (println body)                                                                                         ;;
;;   (get                                                                                                   ;;
;;    {:one 0x00                                                                                            ;;
;;     :two 0x00}                                                                                           ;;
;;    (first body))                                                                                         ;;
;;   )                                                                                                      ;;
;;                                                                                                          ;;
;; (defn h->b [hd]                                                                                          ;;
;;   (println "In header")                                                                                  ;;
;;   (println hd)                                                                                           ;;
;;   (condp = (:second hd)                                                                                  ;;
;;     0x00 body1                                                                                           ;;
;;     0x01 body2))                                                                                         ;;
;;                                                                                                          ;;
;;                                                                                                          ;;
;; (defcodec main                                                                                           ;;
;;   (header                                                                                                ;;
;;    aaa                                                                                                   ;;
;;    #(h->b %)                                                                                             ;;
;;    #(b->h %)))                                                                                           ;;
;;                                                                                                          ;;
;; ;(bs/print-bytes (encode main {:first 0x00 :second 0x00 :third 0x00 }))                                  ;;
;; (let [h->b (fn [head]                                                                                    ;;
;;              (println head)                                                                              ;;
;;              (case head                                                                                  ;;
;;                "CMD" (compile-frame ["CMD" (string :utf-8 :delimiters ["\r\n"])])                        ;;
;;                "TERM" (compile-frame ["TERM"])))                                                         ;;
;;       b->h (fn [body] (first body))                                                                      ;;
;;       cmd->delim (fn [cmd] (if (= cmd "TERM") ["\r\n"] [" "]))                                           ;;
;;       codec (compile-frame (header (string :utf-8 :delimiters [" " "\r\n"] :value->delimiter cmd->delim) ;;
;;                                    h->b b->h))                                                           ;;
;;       cmd (encode codec ["CMD" "TOKEN"])                                                                 ;;
;;       term (encode codec ["TERM"])]                                                                      ;;
;;   (= (buf->string cmd) "CMD TOKEN\r\n")                                                                  ;;
;;   (= (buf->string term) "TERM\r\n"))                                                                     ;;
;;                                                                                                          ;;
;; (defn build-merge-header-with-data                                                                       ;;
;;   "Build a function that takes a header and returns a compiled                                           ;;
;;   frame (using `frame-fn`) that post-processes the frame to merge the                                    ;;
;;   header and the data."                                                                                  ;;
;;   [frame-fn]                                                                                             ;;
;;   (fn [h]                                                                                                ;;
;;     (compile-frame                                                                                       ;;
;;      (frame-fn h)                                                                                        ;;
;;      identity                                                                                            ;;
;;      (fn [data]                                                                                          ;;
;;        (merge h data)))))                                                                                ;;




;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;



; (defcodec tag                                                                                                          ;;
;   (enum :byte                                                                                                          ;;
;         {:auth-request 0                                                                                               ;;
;          :session-request 1}))                                                                                         ;;
;                                                                                                                        ;;
; (defcodec auth-request                                                                                                 ;;
;   {
;    :type :auth-request                                                                                                 ;;
;    :payload (compile-frame {:a :byte})})                                                                              ;;
;                                                                                                                        ;;
; (defcodec session-request                                                                                              ;;
;   {                                                                                                        ;;
;    :type :session-request                                                                                              ;;
;    :payload (compile-frame {:b :byte})})                                                                               ;;
;                                                                                                                        ;;
; (defcodec main                                                                                                         ;;
;   (header                                                                                                              ;;
;    tag                                                                                                                 ;;
;    {:auth-request auth-request                                                                                         ;;
;     :session-request session-request}                                                                                  ;;
;    :type))                                                                                                             ;;
;                                                                                                                        ;;
; (defcodec packetheader                                                                                                 ;;
;   (ordered-map                                                                                                         ;;
;    :source :byte                                                                                                       ;;
;    :destination :byte                                                                                                  ;;
;    :payload main))                                                                                                     ;;
; ;;
; (def auth-map {:source 0 :destination 0 :payload {:type :auth-request :payload {:a 0x01}}})    ;;
; (def sess-map {:source 0 :destination 0 :payload {:type :session-request :payload {:b 0x01}}})    ;;
; (bs/print-bytes (encode packetheader {:source 0 :destination 0 :payload {:type :session-request :payload {:b 0x01}}})) ;;
; (decode packetheader (byte-array [0 0 0 0]))                                                                           ;;
; (decode packetheader (byte-array [0 0 1 1]))                                                                        ;;

; (decode packetheader (encode packetheader auth-map )
; (decode packetheader (encode packetheader sess-map ))

