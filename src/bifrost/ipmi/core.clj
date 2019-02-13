(ns bifrost.ipmi.core
  (:require [aleph.udp :as udp]
            [manifold.stream :as s]
            [gloss.io :refer [decode encode]]
            [buddy.core.codecs :as codecs]
            [byte-streams :as bs]
            [bifrost.ipmi.utils :refer [safe]]
            [bifrost.ipmi.codec :as c :refer [compile-codec]]
            [bifrost.ipmi.registrar :refer [registration-db register-user add-packet-driver]]
            [bifrost.ipmi.state-machine :refer [server-socket bind-fsm ipmi-fsm ipmi-handler get-session-state]]
            [clojure.string :as str]
            [clojure.core.async :refer [chan close! pub sub >!! <! <!! go-loop unsub-all timeout alt! alts!! thread]]
            [taoensso.timbre :as log]
            [taoensso.timbre.appenders.core :as appenders]
            [jvm-alloc-rate-meter.core :as ameter])
  (:import [java.net InetSocketAddress]
           [java.util.concurrent Executors]
           [java.util Date TimerTask Timer]
           [java.time Duration Instant]))

(log/refer-timbre)
(log/merge-config! {:appenders {:println {:enabled? true
                                          :async? true
                                          :min-level :debug}}})
;(log/merge-config!
;   {:appenders 
;    {:spit (appenders/spit-appender {:fname (str/join [*ns* ".log"])})}})

;; Design issues
;; Should session-less messages be in their own FSM?
;; Each IPMI "session" should run till completion given we are not supporting any interactive capability
;; Only rmcpping doesn't follow state-machine.. Lets carve it out seperately.
;; for each peer [ip:port] process it's own fsm.
;; 

(defn start-stop-meter []
   (ameter/start-alloc-rate-meter #(println "Rate is:" (/ % 1e6) "MB/sec")))

(def dump-registrar @registration-db)

(defn stop-log []
  (log/merge-config! {:appenders {:println {:enabled? false}
                                          :async? true
                                          :min-level :info}}))

(defn debug-log []
  (log/merge-config! {:appenders {:println {:enabled? true}
                                  :async? true
                                  :min-level :debug}}))
(defn info-log []
  (log/merge-config! {:appenders {:println {:enabled? true}
                                  :async? true
                                  :min-level :debug}}))

(defonce app-state (atom {:peer-set #{}
                          :chan-map {}}))

(def input-chan (chan))
(def publisher  (pub input-chan :router))

(defn reset-app-state []
  (reset! app-state  {:peer-set #{}
                      :chan-map {}}))

(defn upsert-chan [host-hash chan-map]
  (letfn [(add-chan-map
            [ks & opts]
            (let [peer-set (update-in ks [:peer-set] conj (first opts))
                  chan-map (assoc-in peer-set [:chan-map (first opts)] (fnext opts))]
              chan-map))]
    (swap! app-state #(add-chan-map % host-hash chan-map))))

(defn delete-chan [host-hash]
  (letfn [(del-chan-map
            [ks & opts]
            (let  [peer-set (update-in ks [:peer-set] #(disj % (first opts)))
                   chan-map (update-in peer-set [:chan-map] dissoc (first opts))]
              chan-map))]
    (swap! app-state #(del-chan-map % host-hash))))

(defn channel-exists? [h]
  (let [peer-set (get-in @app-state [:peer-set])]
    (some #{h} peer-set)))

(defn get-peers []
  (get-in @app-state [:peer-set] #{}))

(defn count-peer []
  (count (get-in @app-state [:peer-set])))

(defn get-chan-map []
  (get-in @app-state [:chan-map] {}))

(defn update-chan-map-state [h state]
  (swap! app-state assoc-in [:chan-map h :state] state))

(defn get-chan-map-state [h]
  (get-in @app-state [:chan-map h :state] {}))

(defn get-chan-map-host-map [h]
  (get-in @app-state [:chan-map h :host-map] {}))

(declare reset-peer)

(defn dump-app-state []
     (for [[k v] (get-chan-map)
           :let  [n (.toInstant (java.util.Date.))
                  t (.toInstant (:created-at v))
                  duration (.toMillis (Duration/between t n))]]
       {:hash k :duration duration}))

(defn run-reaper []
  (log/info "Running Reaper on collection count " (count-peer))
  (safe
   (for [[k v] (get-chan-map)
         :let  [n (.toInstant (java.util.Date.))
                t (.toInstant (:created-at v))
                duration (.toMillis (Duration/between t n))
                _ (log/debug {:hash k :duration duration})]
         :when (> duration 30000)]
     (reset-peer k))))

(defn reset-peer [hash]
  (log/info "Closing session for " hash)
  (delete-chan hash))

(defn channel-sub-listener [hash]
  (log/debug "Channel sub listener " hash)
  (let [c (chan)]
    (sub publisher hash c)
    (go-loop []
      (let [{:keys [router message]} (<! c)
            fsm                      (bind-fsm)
            fsm-state                (get-chan-map-state  hash)
            auth                     (-> fsm-state :value :authentication-payload c/authentication-codec :codec)
            compiled-codec           (compile-codec auth)
            decoder                  (partial decode compiled-codec)
            host-map                 (get-chan-map-host-map hash)
            _                        (log/debug  "Packet In Channel" (-> message
                                                                         :message
                                                                         bs/to-byte-array
                                                                         codecs/bytes->hex))
            decoded                  (try
                                       (decoder (:message message))
                                       (catch Exception e
                                         (throw (ex-info "Decoding error" {:error (.getMessage e)
                                                                           :data (codecs/bytes->hex (:message message))}))
                                         {}))
            m                        (merge host-map decoded)
            new-fsm-state            (let [s (try
                                               (fsm fsm-state m)
                                               (catch Exception e
                                                 (throw (ex-info "State Machine Error" {:error (.getMessage e)}))))]
                                       (condp = (:value s)
                                         nil fsm-state
                                         s))
            complete?                (-> new-fsm-state :accepted? true?)]

        (update-chan-map-state hash new-fsm-state)
        (if complete?
          (do
            (delete-chan hash)
            (log/info "Completion State:" complete?  "Queued Requests " (count-peer))))
        (recur)))))

(defn message-handler  [message]
  (let [host-map (get-session-state message)
        h        (hash host-map)]
    (log/debug  "Packet In" (-> message
                                :message
                                bs/to-byte-array
                                codecs/bytes->hex))
    (if (nil? (channel-exists? h))
      (do
        (channel-sub-listener h)
        (log/debug "Create session " h)
        (upsert-chan h  {:created-at (Date.)
                         :host-map   host-map
                         :login-state {:auth 0
                                       :integ 0
                                       :conf 0}
                         :state      {}})
        (>!! input-chan {:router  h
                         :message message}))
                                        ;(log/error "Channel is blocked or closed")))
      (do
        (log/debug "Found session " h)
        (>!! input-chan {:router  h
                         :message message})))))
                                        ; (log/error "Channel is blocked or closed"))))))


(defn start-consumer [server-socket]
  (future
    (->> server-socket
         (s/consume #(message-handler %)))))

(defn start-udp-server
  [port]
  (if-not (some-> @server-socket  s/closed? not)
    (do
      (reset! server-socket @(udp/socket {:port port :epoll? true})))
    (do
      (log/error "Port in use")
      false)))

(defn start-reaper [time-to-recur]
  (future
    (loop []
      (run-reaper)
      (Thread/sleep time-to-recur)
      (recur))))
        

(defn stop-server []
  (safe (s/close! @server-socket))
  (shutdown-agents))


(defn start-server []
  (log/info "Starting Server on Port " 623)
  (log/merge-config! {:appenders {:println {:enabled? true
                                            :async? true
                                            :min-level :debug}}})
  (if-not (empty? @registration-db)
    (when (start-udp-server 623)
        (reset-app-state)
        (start-consumer  @server-socket)
        (start-reaper 10000)
        (future
          (Thread/sleep 600000)
          (stop-server)
          (println "closed socket"))))
  (log/error "Please register users first"))

;;TODO Make sure to check fore registrations

(defn -main [port]
  (log/info "Starting Server on Port " port)
  (when (start-udp-server  (Integer. port))
    (let []
      (start-consumer  @server-socket)
      (start-reaper 10000)
      #_(future
         (while true
           (Thread/sleep
            1000)))
      (future))))
