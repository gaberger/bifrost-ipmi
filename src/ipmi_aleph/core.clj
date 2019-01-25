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
            [ipmi-aleph.codec :as c :refer [compile-codec rmcp-header]]
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
                         ;;(compile-codec)
                                 rmcp-header
                                 (compile-codec auth-codec))
        decoder (partial decode compiled-codec)
        decoded (try
                  (decoder (:message message))
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



(defn -main []
  (let [server-socket (start-udp-server 623)]
    (swap! udp-session assoc :socket server-socket)
    (start-consumer server-socket)
    (future
      (while true
        (Thread/sleep 1000)))))

(defn close-session [udp-session]
  (s/close! (:socket udp-session)))


