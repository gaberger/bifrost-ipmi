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
            [ipmi-aleph.handlers :as h]
            [clojure.string :as str]
            [taoensso.timbre :as log]
            [taoensso.timbre.appenders.core :as appenders]))

(log/refer-timbre)
(log/merge-config! {:appenders {:println {:enabled? true}}})
#_(log/merge-config!
   {:appenders
    {:spit (appenders/spit-appender {:fname (str/join [*ns* ".log"])})}})

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
  (log/debug "Starting Server")
  (let [accumulator   (atom {})
        server-socket @(udp/socket {:port server-port
                                        ;:socket-address (java.net.InetSocketAddress/createUnresolved "192.168.100.141" server-port)
                                    })]
    (->> server-socket
         #_(s/map parse-ipmi-packet-callback)
         #_(s/consume (fn [response]
                        (s/put! server-socket (encode rmcp-header response))))
         (s/consume (fn [payload]
                      (log/debug "Got payload " payload)
                      (let [sender (:sender payload)
                            address (-> (.getAddress sender) (.getHostAddress))
                            port (.getPort sender)
                            message (decode rmcp-header (:message payload))
                            message-tag (get-in message [:rmcp-class :asf-payload :asf-message-header :message-tag])]
                        (log/debug "Sending UDP request to host: " address "on port: " port)
                        (s/put! server-socket {:host address
                                               :port port
                                               :message (encode rmcp-header (h/presence-pong message-tag))})))))
    server-socket))



;(s/on-drained stream #(s/close! server-socket))




;server-socket))



;(def server (start-udp-server))
;(s/close! server)
;(send-ipmi-init! (client-socket))
;@(s/take! server)

