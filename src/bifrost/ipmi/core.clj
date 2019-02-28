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
            [clojure.string :as str]
            [clojure.core.async :as async :refer :all]
            [taoensso.timbre :as log]
            [taoensso.timbre.appenders.core :as appenders]
            [jvm-alloc-rate-meter.core :as ameter]
            [bifrost.ipmi.server :as server])
  (:import [java.net InetSocketAddress]
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


;; (defn asf-ping-handler [hash]
;;   (let [output-chan (chan)]
;;     (sub publisher :ping output-chan)
;;     (go-loop []
;;       (let [{:keys [message]} (<! output-chan)
;;             compiled-codec (compile-codec)
;;             decoder (partial decode compiled-codec)
;;             host-map (get-chan-map-host-map hash)
;;             decoded (safe (decoder (:message message)))
;;             message-tag  (get-in decoded [:rmcp-class
;;                                           :asf-payload
;;                                           :asf-message-header
;;                                           :message-tag])]

;;         (send-message {:type :asf-ping :input message :message-tag message-tag})))))





(defn publish [data]
  (try (go (>! server/input-chan data))
       (catch Exception e
         (throw (ex-info "Exception during publish" {:error (.getMessage e)})))
       (finally data)))

(defn message-handler  [message]
  (let [host-map (state/get-session-state message)
        h        (hash host-map)]
    (log/debug  "Packet In" (-> message
                                :message
                                bs/to-byte-array
                                codecs/bytes->hex))
    (when-not (state/channel-exists? h)
      (do
        (log/debug "Creating subscriber for topic " h)
        (thread
            (server/read-processor h)
          )

        (state/upsert-chan h  {:created-at  (Date.)
                               :host-map    host-map
                               :fsm         (state/bind-server-fsm)
                               :login-state {:auth  0
                                             :integ 0
                                             :conf  0}
                               :state       {}})))
    (log/debug "Publish message on topic " h)
    (publish  {:router  h
               :role    :server
               :message message})))

(defn start-consumer [server-socket]
  (->> server-socket
       (s/consume #(message-handler %))))

(defn start-udp-server
  [port]
  (if-not (some-> (deref state/server-socket)  s/closed? not)
    (do
      (reset! state/server-socket @(udp/socket {:port port :epoll? true})))
    (do
      (log/error "Port in use")
      false)))

(defn start-reaper [time-to-recur]
  (go-loop []
    (run-reaper)
    (Thread/sleep time-to-recur)
    (recur)))

(defn stop-server []
  (safe (s/close! @state/server-socket)))

(defn start-server
  ([port]
   (log/info "Starting Server on Port " 623)
   (if-not (empty? @r/registration-db)
     (when (start-udp-server port)
       (do
         (reset-app-state)
         (start-consumer  @state/server-socket)
         #_(start-reaper 60000)
         #_(future
             (Thread/sleep 120000)
             (stop-server)
             (println "closed socket"))))
     (log/error "Please register users first")))
  ([]
   (start-server 623)))

;;TODO Make sure to check fore registrations

(defn -main [port]
  (log/info "Starting Server on Port " port)
  (when (start-udp-server  (Integer. port))
    (let []
      (start-consumer  @state/server-socket)
      (start-reaper 60000)
      (future
        (while true
          (Thread/sleep
           1000))))))
