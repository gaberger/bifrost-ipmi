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
            [bifrost.ipmi.decode :as decode]
            [bifrost.ipmi.config :as config]
            [bifrost.ipmi.messages :as messages]
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
#_(def config (config/server-config (state/bind-server-fsm)))

#_(def config (config/server-config (state/bind-server-fsm)))

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
  (log/info "Running Reaper on collection count " (count-peer))
  (doall
   (for [[k v] (get-chan-map)
         :let  [n (.toInstant (java.util.Date.))
                t (.toInstant (:created-at v))
                duration (.toMillis (Duration/between t n))
                _ (log/debug {:hash k :duration duration})]
         :when (> duration 30000)]
     (reset-peer k))))

(def input-chan (async/chan))
(def publisher (async/pub input-chan :host-map))

(defn create-processor
  [hostmap]
  (log/debug "read processor input" hostmap)
  (let [decoder (decode/make-server-decoder)
        subscriber (async/chan)]
    (async/sub publisher hostmap decoder)
    #_(async/pipe subscriber decoder)
    (async/thread
      (loop []
        (when-some [msg (async/<!! subscriber)]
          (log/debug "found message" msg))
        (recur)))))

(defn server-handler  [udp-message]
  (let [host-map (decode/get-session-state udp-message)
        h        (hash host-map)]
    (log/debug  "Packet In" (-> udp-message
                                :message
                                bs/to-byte-array
                                codecs/bytes->hex) "Port" (:port host-map))
    (when-not (channel-exists? h)
      (do
        (log/debug "Creating subscriber for topic " h)
        (upsert-chan h  {:created-at  (Date.)
                               :host-map    host-map
                               :state       {}})
        (create-processor h)
        (async/put! input-chan {:host-map h
                                :message udp-message})))
    (log/debug "Publish message on topic " h)
    (async/put! input-chan   {:host-map h
                              :message  udp-message})))

(defn start-server-consumer [server-socket]
  (->> server-socket
       (s/consume #(server-handler %))))

(defn run-command-loop [command-chan]
  (async/go-loop []
    (when-some [command (async/<! command-chan)]
      (log/debug "Received Command" command)
      (recur))))

(defn start-udp-server
  [port]
  (if-not (some-> (deref messages/server-socket)  s/closed? not)
    (do
      (reset! messages/server-socket @(udp/socket {:port port :epoll? true}))
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
  (safe (s/close! @messages/server-socket)))

(defn start-server
  [& args]
  (if-let [{:keys [port]} (first args)]
    (if-not (empty? @r/registration-db)
      (when (start-udp-server (or port 623))
        (do
          (log/info "Starting Server on Port " (or port 623))
          (let [stream (start-server-consumer @messages/server-socket)]
            (log/debug "Stream" stream))))
      (log/error "Please register users first"))
    (println "Must provide a port")))

;;TODO Make sure to check for registrations


#_(defn -main [port]
    (log/info "Starting Server on Port " (or port 623))
    (when (start-udp-server  (Integer. (or port 623)))
      (let []
        (start-server-consumer  @state/server-socket)
        (start-reaper 60000)
        (future
          (while true
            (Thread/sleep
             1000))))))
