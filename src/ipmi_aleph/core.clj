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
            [automat.core :refer [advance]]
            [overtone.at-at :as at]
            [ipmi-aleph.codec :as c :refer [compile-codec]]
            [ipmi-aleph.handlers :as h]
            [ipmi-aleph.state-machine :refer [bind-fsm ipmi-fsm ipmi-handler get-session-state server-socket]]
            [clojure.string :as str]
            [clojure.core.async :refer [chan close! pub sub >!! <! <!! go-loop unsub-all timeout alt! alts!! thread]]
            [taoensso.timbre :as log]
            [taoensso.timbre.appenders.core :as appenders])
  (:import [java.net InetSocketAddress]
           [java.util.concurrent Executors]
           [java.util Date TimerTask Timer]
           [java.time Duration Instant]))

(log/refer-timbre)
(log/merge-config! {:appenders {:println {:enabled? true
                                          :async? true
                                          :min-level :info}}})
;(log/merge-config!
;   {:appenders 
;    {:spit (appenders/spit-appender {:fname (str/join [*ns* ".log"])})}})

;; Design issues
;; Should session-less messages be in their own FSM?
;; Each IPMI "session" should run till completion given we are not supporting any interactive capability
;; Only rmcpping doesn't follow state-machine.. Lets carve it out seperately.
;; for each peer [ip:port] process it's own fsm.
;; 

(defonce task-pool (at/mk-pool))
(def peer-set (atom #{}))
(def chan-map (atom {}))

(declare reset-peer)

(defn task-set [f time-in-ms]
    (at/every time-in-ms f task-pool)
  )

(defn clean-peer-set []
  (for [[k v] @chan-map
        :let [h (if (empty? (:state v)) k nil)]
        :when (not (nil? h))]
    (swap! peer-set #(disj % h))))

(defn clean-chan-map []
  (for [[k v] @chan-map
        :let [h (if (empty? (:state v)) k nil)]
        :when (not (nil? h))]
    (swap! chan-map dissoc k)))

(defn reaper []
    (log/info "Running Reaper on collection count " (count @chan-map))
    (clean-peer-set)
    (clean-chan-map)
    (for [[k v]     @chan-map
          :let  [n (.toInstant (java.util.Date.))
                 t (log/spy (.toInstant (:created-at v)))
                 duration (.toMinutes (Duration/between t n))
                 _ (log/info "--Duration--" duration)]
          :when (> duration 1)]
      (reset-peer k)))

(defn reset-peer [hash]
  (log/info "Closing session for " hash)
  (swap! chan-map dissoc hash)
  (swap! peer-set #(disj % hash)))

(defn channel-sub-listener [pub hash]
  (log/debug "Channel sub listener " pub hash)
  (let [c (chan)]
    (sub pub hash c)
    (go-loop []
      (let [{:keys [router message]} (<! c)
            fsm                      (bind-fsm)
            fsm-state                (log/spy (-> (get @chan-map hash) :state))
            auth                     (log/spy (-> fsm-state :value :authentication-payload c/authentication-codec :codec))
            _                        (log/debug "Using Authentication Codec " auth)
            compiled-codec           (compile-codec auth)
            decoder                  (partial decode compiled-codec)
            host-map                 (-> (get @chan-map hash) :host-map)
            decoded                  (try
                                       (decoder (:message message))
                                       (catch Exception e
                                         (do
                                           (log/error "Caught decoding error:" (.getMessage e) (codecs/bytes->hex (:message  message)))
                                           {})))
            m                        (merge host-map decoded)
            new-fsm-state            (let [s (try
                                               (fsm fsm-state m)
                                               (catch Exception e
                                                 (do
                                                   (log/error "State Machine Error " (.getMessage e)
                                                              "FSM State " fsm-state "Input " m)
                                                   (reset-peer hash))))]
                                       (condp = (:value s)
                                         nil fsm-state
                                         s))
            complete?                (-> new-fsm-state :accepted? true?)]

        (swap! chan-map assoc-in [hash :state] new-fsm-state)
        (if complete?
          (do
            (swap! chan-map dissoc hash)
            (swap! peer-set #(disj % hash))
            (log/info "Completion State:" complete?  "Queued Requests " (count @chan-map) (count @peer-set))))
        (recur)))))

(defn message-handler  [message]
  (let [host-map (get-session-state message)
        h (-> (hash host-map) str)]
    (if (nil? (some #{h} @peer-set))
      (let [input-chan (chan)
            pub        (pub input-chan :router)]
        (swap! peer-set conj h)
        (swap! chan-map conj {h {:channel input-chan
                                 :created-at (Date.)
                                 :pub pub
                                 :host-map host-map
                                 :state  {}}})
        (log/debug "Update channel map " h input-chan)
        (channel-sub-listener pub h)
        (if nil?
          (>!! input-chan {:router  h
                           :message message})
          (log/error "Channel is blocked or closed")))
      (let [chan (-> (get @chan-map h) :channel)]
        (log/debug "Found session " h " channel " chan)
        (if true
          (>!! chan {:router  h
                     :message message})
          (log/error "Channel is blocked or closed"))))))

(defn start-consumer
  [server-socket]
  (let [fsm (bind-fsm)]
    (future
      (->> server-socket
           (s/consume #(message-handler %))))))

(defn start-udp-server
  [port]
  (if-not (log/spy (some-> @server-socket  s/closed? not))
    (do
      (log/info "Starting Server")
      (reset! server-socket @(udp/socket {:port port :epoll? true})))
    (do
      (log/error "Port in use")
      false)))

(defn stop-server []
  (s/close! @server-socket))

(defn start-server [port]
  (when (start-udp-server port)
    (let [reaper (task-set #(reaper) 10000)]
      (reset! peer-set #{})
      (reset! chan-map {})
      (start-consumer  @server-socket)
      (future
        (Thread/sleep 600000)
        (at/stop reaper)
        (stop-server)
        (println "closed socket")))))

(defn -main [port]
  (log/info "Starting Server on Port " port)
  (when (start-udp-server  (Integer. port))
    (do
      (start-consumer  @server-socket)
      (future
        (while true
          (Thread/sleep
           1000))))))




