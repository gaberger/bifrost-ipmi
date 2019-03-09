(ns bifrost.ipmi.core
  (:require [aleph.udp :as udp]
            [manifold.stream :as s]
            [gloss.io :refer [decode encode]]
            [buddy.core.codecs :as codecs]
            [byte-streams :as bs]
            [bifrost.ipmi.application-state :refer :all]
            [bifrost.ipmi.utils :refer [safe]]
            [bifrost.ipmi.codec :as c]
            [bifrost.ipmi.registrar :as r]
            [bifrost.ipmi.state-machine :as state]
            [bifrost.ipmi.decode :as decode]
            [bifrost.ipmi.config :as config]
            [clojure.string :as str]
            [clojure.core.async :as async]
            [integrant.core :as ig]
            [taoensso.timbre :as log]
            [taoensso.timbre.appenders.core :as appenders]
            [jvm-alloc-rate-meter.core :as ameter]
            [bifrost.ipmi.server :as server]
            [automat.core :as a])
  (:import [java.net InetSocketAddress]
           [java.util Date TimerTask Timer]
           [java.time Duration Instant]))

(log/refer-timbre)
(log/merge-config! {:appenders {:println {:enabled? true
                                          :async? true
                                          :min-level :debug}}})
(def config (config/server-config (state/bind-server-fsm)))


;(log/merge-config!
;   {:appenders
;    {:spit (appenders/spit-appender {:fname (str/join [*ns* ".log"])})}})

;; Design issues
;; Each IPMI "session" should run till completion given we are not supporting any interactive capability
;; Only rmcpping doesn't follow state-machine.. Lets carve it out seperately.


(defn start-stop-meter []
  (ameter/start-alloc-rate-meter #(println "Rate is:" (/ % 1e6) "MB/sec")))

(def dump-registrar (deref r/registration-db))

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

(defn run-reaper []
  (log/info "Running Reaper on collection count " (state/count-peer))
  (doall
   (for [[k v] (state/get-chan-map)
         :let  [n (.toInstant (java.util.Date.))
                t (.toInstant (:created-at v))
                duration (.toMillis (Duration/between t n))
                _ (log/debug {:hash k :duration duration})]
         :when (> duration 30000)]
     (server/reset-peer k))))

#_(defn server-handler  [message]
  (let [host-map (state/get-session-state message)
        h        (hash host-map)]
    (log/debug  "Packet In" (-> message
                                :message
                                bs/to-byte-array
                                codecs/bytes->hex) "Port" (:port host-map))
    (when-not (state/channel-exists? h)
      (do
        (log/debug "Creating subscriber for topic " h)
        (state/upsert-chan h  {:created-at  (Date.)
                               :host-map    host-map
                               :fsm         (state/bind-server-fsm)
                               :login-state {:auth  0
                                             :integ 0
                                             :conf  0}
                               :state       {}})
        (thread
          (server/read-processor h))))
    (log/debug "Publish message on topic " h)
    (server/publish  {:router h
                      :message       message})))

;(defn proxy-handler [message]
;  (let [host-map (state/get-session-state message)
;        h (hash host-map)
;        fsm (state/bind-client-fsm)
;        codec (c/compile-codec h)];

;    (->> (decode-message codec message)
;         (a/advance nil fsm fsm-state)
;         (update-fsm-state)
;         (send-message))

;    ))
;(send-message {:type :get-channel-auth-cap-req :input input :seq seq})


(defn close-channels []
  (async/close! (:command-channel config))
  (async/close! (:decode-channel config)))

(defn start-command-processor []
  (async/pipe (:decode-channel @config) (:command-channel @config))
  (async/thread
    (loop []
      (when-some [command (async/<!! (:command-channel @config))]
        (log/debug "got command" command)))
    (recur)))


(defn start-server-consumer [server-socket]
  (->> server-socket
       (s/consume #(async/put! (:decode-channel @config) %))))

#_(defn start-proxy-consumer [server-socket]
  (->> server-socket
       (s/consume #(proxy-handler %))))

(defn start-udp-server
  [port]
  (if-not (some-> (deref state/server-socket)  s/closed? not)
    (do
      (reset! state/server-socket @(udp/socket {:port port :epoll? true}))
      (dosync (alter app-state assoc :server-port port)))
    (do
      (log/error "Port in use")
      false)))

(defn start-reaper [time-to-recur]
  (async/thread
    (loop []
      (run-reaper)
      (Thread/sleep time-to-recur)
      (recur))))

(defn stop-server []
  (safe (s/close! @state/server-socket)))

(defn start-server
  [& args]
  (if-let [{:keys [mode port]} (first args)]
    (condp = mode
      :server (if-not (empty? @r/registration-db)
                  (when (start-udp-server (or port 623))
                    (do
                      (log/info "Starting Server on Port " (or port 623))
                      (start-server-consumer  @state/server-socket)))
                  (log/error "Please register users first"))
      :proxy (do
               (log/info "Starting proxy on Port" (or port 1623))))
    (println "Must provide a port and a mode")))

;;TODO Make sure to check for registrations


(defn -main [port]
  (log/info "Starting Server on Port " (or port 623))
  (when (start-udp-server  (Integer. (or port 623)))
    (let []
      (start-server-consumer  @state/server-socket)
      (start-reaper 60000)
      (future
        (while true
          (Thread/sleep
           1000))))))
