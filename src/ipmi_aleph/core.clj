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
            [manifold.deferred :as d]
            [automat.viz :refer [view]]
            [ipmi-aleph.codec :as c :refer [compile-codec]]
            [ipmi-aleph.handlers :as h]
            [ipmi-aleph.state-machine :refer [bind-fsm ipmi-fsm ipmi-handler get-session-state server-socket fsm-state]]
            [clojure.string :as str]
            [taoensso.timbre :as log]
            [taoensso.timbre.appenders.core :as appenders])
   (:import [java.net InetSocketAddress]))

(log/refer-timbre)
(log/merge-config! {:appenders {:println {:enabled? true}}})
;(log/merge-config!
;   {:appenders 
;    {:spit (appenders/spit-appender {:fname (str/join [*ns* ".log"])})}})

;; Design issues
;; Should session-less messages be in their own FSM?
;; Each IPMI "session" should run till completion given we are not supporting any interactive capability
;; Only rmcpping doesn't follow state-machine.. Lets carve it out seperately.
;; for each peer [ip:port] process it's own fsm.
;; 


(defn message-handler  [adv message]
  (let [fsm-state-var (if-not (nil? @fsm-state) @fsm-state nil)
        peer          (get-session-state message)
        auth          (-> fsm-state-var :value :authentication-payload c/authentication-codec :codec)
        _              (log/debug "Auth Codec " auth)
        compiled-codec (compile-codec auth)
        decoder        (partial decode compiled-codec)
        decoded        (try
                         (decoder (:message message))
                         (catch Exception e
                           (do
                             (log/error "Caught decoding error:" (.getMessage e) (codecs/bytes->hex (:message  message)))
                             {})))
        m              (merge peer decoded)
        new-fsm-state  (let [fsm-state (try
                                         (adv fsm-state-var m)
                                         (catch Exception e
                                           (do
                                             (log/error "State Machine Error " (.getMessage e) "FSM State " fsm-state-var "Input " m)
                                             fsm-state-var)))]
                         (condp = (:value fsm-state)
                           nil fsm-state-var
                           fsm-state))]
    (log/debug "STATE-INDEX " (:state-index new-fsm-state) " STATE-ACCEPT " (:accepted? new-fsm-state))
    (reset! fsm-state new-fsm-state)))

(defn start-consumer
  [server-socket]
  (let [fsm (bind-fsm)]
    (future
      (->> server-socket
          (s/consume #(message-handler fsm %))))))

(defn send-message [socket host port message]
  (s/put! socket {:host host, :port port, :message message}))

(defn start-udp-server
  [port]
  (if-not (log/spy (some-> @server-socket  s/closed? not))
    (do
      (log/info "Starting Server")
      (reset! server-socket @(udp/socket {:port port :epoll? true})))
    (do
      (log/error "Port in use")
      false)
    ))

(defn close-session []
  (s/close! @server-socket))


(defn start-server [port]
    (when (start-udp-server port)
      (do
         (reset! fsm-state {})
          (start-consumer  @server-socket)
        (future
          (Thread/sleep 300000)
          (close-session)
          (println "closed socket")))))

(defn -main [host port]
    (when (start-udp-server 623)
      (do
        (reset! fsm-state {})
        (start-consumer  @server-socket)
    (future
      (while true
        (Thread/sleep 1000))))))


