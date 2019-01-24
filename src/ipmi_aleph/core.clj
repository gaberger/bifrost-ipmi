(ns ipmi-aleph.core
  (:require [aleph.udp :as udp]
            [manifold.stream :as s]
            [manifold.deferred :as d]
            [buddy.core.crypto :as crypto]
            [buddy.core.nonce :as nonce]
            [buddy.core.codecs :as codecs]
            [gloss.io :refer [decode encode]]
            [byte-streams :as bs]
            [automat.core :as a]
            [automat.viz :refer [view]]
            [ipmi-aleph.codec :as c :refer [compile-codec rmcp-decode rmcp-header]]
            [ipmi-aleph.handlers :as h]
            [ipmi-aleph.utils :as u]
            [ipmi-aleph.state-machine :refer [ipmi-fsm ipmi-handler get-session-state udp-session fsm-state]]
            [clojure.string :as str]
            [taoensso.timbre :as log]
            [taoensso.timbre.appenders.core :as appenders]))

(log/refer-timbre)
(log/merge-config! {:appenders {:println {:enabled? true}}})
;(log/merge-config!
;   {:appenders
;    {:spit (appenders/spit-appender {:fname (str/join [*ns* ".log"])})}})

(defn fsm []
  (let [fsm (a/compile ipmi-fsm ipmi-handler)]
    (partial a/advance fsm)))


(defn message-handler  [adv message]
  (let [fsm-state-var (if-not (nil? @fsm-state) @fsm-state nil)
        peer (get-session-state message)
        auth-codec (if-not (nil? fsm-state-var)
                     (if (-> fsm-state-var (contains? :session-auth))
                       (-> (u/get-session-auth (fsm-state-var :session-auth)) :auth-codec)
                       nil)
                     nil)
        compiled-codec (if (nil? auth-codec)
                                 rmcp-header
                                 (compile-codec (log/spy auth-codec)))
        decoder (partial decode compiled-codec)
        decoded (try
                  (decoder (log/spy (:message message)))
                  (catch Exception e
                    (do
                      (log/error "Caught decoding error:" (.getMessage e))
                      {})))
        m (merge peer decoded)
        new-fsm-state  (let [fsm-state (try
                                         (adv fsm-state-var m)
                                         (catch Exception e
                                           (do
                                             (log/error "State Machine Error " (.getMessage e))
                                             fsm-state-var)))]
                         (condp = (:value fsm-state)
                           nil fsm-state-var
                           fsm-state))]
    (log/debug "STATE-INDEX " (:state-index new-fsm-state))
    (log/debug "STATE-ACCEPT " (:accepted? new-fsm-state))
    (reset! fsm-state new-fsm-state)))

(defn start-consumer
  [server-socket]
  (let [fsm (fsm)]
    (->> server-socket
         (s/consume #(message-handler fsm %)))))

(defn send-message [socket host port message]
  (s/put! socket {:host host, :port port, :message message}))

(defn start-udp-server
  [port]
  (log/info "Starting Server on port " port)
  (let [server-socket @(udp/socket {:port port})]
    server-socket))

(defn start-server [port]
  (let [server-socket (start-udp-server port)]
    (swap! udp-session assoc :socket server-socket)
    (reset! fsm-state {})
    (start-consumer server-socket)
    (future
      (Thread/sleep 200000)
      (s/close! server-socket)
      (println "closed socket"))
    server-socket))


;; (defn my-consume [f stream]
;;   (let [fsm (fsm)]
;;     (d/loop []
;;       (d/chain (s/take! stream ::drained)
;;              ;; if we got a message, run it through `f`
;;              (fn [msg]
;;                (if (identical? ::drained msg)
;;                  ::drained
;;                  (f fsm msg)))
;;              (fn [result]
;;                (when-not (identical? ::drained result)
;;                  (d/recur)))))))

;; (defn -main []
;;   (let [server-socket @(udp/socket {:port 623})]
;;     (swap! udp-session assoc :stream server-socket)
;;     (log/info "Starting Server on port " 623)
;;     (->> server-socket
;;          (my-consume message-handler))
;;   (future
;;     (while true
;;       (Thread/sleep 1000)))
;;   ))


(defn -main []
  (let [server-socket (start-udp-server 623)]
    (swap! udp-session assoc :socket server-socket)
    (start-consumer server-socket)
    (future
      (while true
        (Thread/sleep 1000)))))

(defn close-session [udp-session]
  (s/close! (:socket udp-session)))

;(send-message (:socket udp-server) "localhost" 623 (byte-array (:rmcp-ping rmcp-payloads)))

; (def s (fsm))
; (-> nil  
;  (s (c/rmcp-decode (byte-array (:rmcp-ping p/rmcp-payloads))))
;  (s (c/rmcp-decode (byte-array (:rmcp-ping p/rmcp-payloads)))))

; (def data {:socket :foobar
;            :address "0:0:0:0:0:0:0:1", 
;            :peer-port 62126, 
;            :version 6, 
;            :reserved 0, :sequence 255, 
;            :rmcp-class {:asf-payload {:iana-enterprise-number 4542, :asf-message-header 
;                                       {:asf-message-type 128, :message-tag 114, 
;                                        :reserved 0, :data-length 0}}, :type :asf-session}})
; (encode c/rmcp-header (h/rmcp-rakp-4-response-msg))
; (require '[ipmi-aleph.test-payloads :refer :all])
; (c/rmcp-decode (byte-array (:rmcp-rakp-4 rmcp-payloads)))

; (h/rmcp-rakp-4-response-msg)
