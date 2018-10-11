(ns ipmi-aleph.core
  (:require [aleph.udp :as udp]
            [byte-streams :as bs]
            [gloss.core :refer [bit-map compile-frame defcodec]]
            [gloss.core.codecs :refer [ordered-map]]
            [gloss.io :refer [decode encode encode-to-stream contiguous]]
            [manifold.deferred :as d]
            [manifold.stream :as s])
  (:import (java.net InetSocketAddress
                     SocketAddress
                     Inet4Address)))

(def server-port 1002)
(def server-address  (InetSocketAddress. "100.67.141.16" 623))

(defn client-socket []
  @(udp/socket {:port 10002}))

                                        ;(def ipmi-init-bytes (byte-array (map (comp byte) [06 00 FF 07 00 00 00 00 00 00 00 00 00 09 20 18 c8 81 00 38 8E 04])))


(def host "100.67.141.16")

(defcodec RMCP (ordered-map :version :ubyte
                            :reserved :ubyte
                            :sequence :ubyte
                            :type :ubyte
                            :auth-type :ubyte
                            :sess-seq :uint32
                            :sess-id :uint32
                            :length :ubyte
                            :target-address :ubyte
                            :network-function :ubyte
                            :header-checksum :ubyte
                            :source-address :ubyte
                            :source-LUN :ubyte
                            :command :ubyte
                            :compatibility :ubyte
                            :priv-level :ubyte
                            :data-checksum :ubyte))

(def host "100.67.141.16")

(defn send-ipmi-init!
  [s host port  message]
  (s/put! s {:host host
             :port port
             :message (encode RMCP {:version 0x6
                                    :reserved 0x0
                                    :sequence 0xFF
                                    :type 0x7
                                    :auth-type 0x0
                                    :sess-seq 0x0
                                    :sess-id 0x0
                                    :length 9x0
                                    :target-address 0x20
                                    :network-function 0x18
                                    :header-checksum 0xc8
                                    :source-address 0x81
                                    :source-LUN 0x00
                                    :command 0x38
                                    :compatibility 0x8e
                                    :priv-level 0x04
                                    :data-checksum 0xb5})}))



(defn start-udp-server
  []
  (let [accumulator   (atom {})
        server-socket @(udp/socket {:port server-port})
        ;; Once a second, take all the values that have accumulated, `put!` them out, and
        ;; clear the accumulator.
        metric-stream (s/periodically 1000 #(get-and-set! accumulator {}))]
    ;; Listens on a socket, parses each incoming message, and increments the appropriate metric.
    (->> server-socket
         (bs/print-bytes)
         #_(s/consume)
         #_(fn [[metric value]])
         #_(swap! accumulator update metric #(+ (or % 0) value)))
    ;; If `metric-stream` is closed, close the associated socket.
    (s/on-drained metric-stream #(s/close! server-socket))
    metric-stream))

;(def server (start-udp-server))
;(send-ipmi-init! (client-socket))
;@(s/take! server)
;(s/close! server)


