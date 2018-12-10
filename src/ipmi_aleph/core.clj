(ns ipmi-aleph.core
  (:require [aleph.udp :as udp]
            [byte-streams :as bs]
            [manifold.deferred :as d]
            [manifold.stream :as s]
            [buddy.core.crypto :as crypto]
            [buddy.core.nonce :as nonce]
            [buddy.core.codecs :as codecs]
            [gloss.io :refer [decode encode]]
            [ipmi-aleph.codec :refer :all]
            [ipmi-aleph.handlers :as h]))

(def server-port 623)

(defn send-ipmi-init!
  [s host port  message]
  (s/put! s {:host    host
             :port    port
             :message message}))

(defn encr []
  (let [eng   (crypto/block-cipher :twofish :cbc)
        iv16  (nonce/random-nonce 16)
        key32 (nonce/random-nonce 32)
        data  (codecs/hex->bytes "000000000000000000000000000000AA")]
    (crypto/init! eng {:key key32 :iv iv16 :op :encrypt})
    (crypto/process-block! eng data)))

(defn get-and-set!
  "An atomic operation which returns the previous value, and sets it to `new-val`."
  [a new-val]
  (let [old-val @a]
    (if (compare-and-set! a old-val new-val)
      old-val
      (recur a new-val))))

(defn parse-ipmi-packet-callback
  [{:keys [sender message]}]
  (let [message (decode rmcp-header message)
        message-tag (get-in message [:class :message-type :message-tag])]
    (h/presence-pong message-tag)))

(defn start-udp-server
  []
  (println "Starting Server on port " server-port)
  (let [accumulator   (atom {})
        server-socket @(udp/socket {:port server-port})]
    (->> server-socket
         (s/map parse-ipmi-packet-callback)
         (s/consume (fn [response]
                      (s/put! server-socket (encode rmcp-header response)))))
  server-socket))

     ;(s/put! client-socket
    ;{
    ; :port server-port
    ;:message (str metric ":" value)}))
    ; (s/put! (presence-pong))
    ;     (bs/print-bytes)
    ;     (s/consume #(prn 'message! %))
    ;     )
         ;(s/consume
          ;(fn [[metric value]]
           ; (swap! accumulator update metric #(+ (or % 0) value)))))
    ;; If `stream` is closed, close the associated socket.
    ;(s/on-drained stream #(s/close! server-socket))
    ;#_stream




;server-socket))



;(def server (start-udp-server))
;(send-ipmi-init! (client-socket))
;@(s/take! server)
;(s/close! server)

