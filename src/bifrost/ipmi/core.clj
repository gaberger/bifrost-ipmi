(ns bifrost.ipmi.core
  (:require [aleph.udp :as udp]
            [manifold.stream :as s]
            [gloss.io :refer [decode encode]]
            [buddy.core.codecs :as codecs]
            [byte-streams :as bs]
            [bifrost.ipmi.application-state :refer :all]
            [bifrost.ipmi.utils :refer [safe]]
            [bifrost.ipmi.codec :as c :refer [decode-message compile-codec get-login-state get-authentication-codec]]
            [bifrost.ipmi.registrar :refer [registration-db register-user add-packet-driver]]
            [bifrost.ipmi.state-machine :refer [send-message server-socket bind-fsm ipmi-fsm
                                                ipmi-handler mock-handler get-session-state]]
            [clojure.string :as str]
            [clojure.core.async :refer [go dropping-buffer sliding-buffer chan close! pub sub >!! <! <!! >!
                                        go-loop unsub-all timeout alt! alts!! thread]]
            [taoensso.timbre :as log]
            [taoensso.timbre.appenders.core :as appenders]
            [jvm-alloc-rate-meter.core :as ameter])
  (:import [java.net InetSocketAddress]
           [java.util Date TimerTask Timer]
           [java.time Duration Instant]))

(log/refer-timbre)
(log/merge-config! {:appenders {:println {:enabled? true
                                          :async? false
                                          :min-level :debug}}})

;(log/merge-config!
;   {:appenders
;    {:spit (appenders/spit-appender {:fname (str/join [*ns* ".log"])})}})

;; Design issues
;; Each IPMI "session" should run till completion given we are not supporting any interactive capability
;; Only rmcpping doesn't follow state-machine.. Lets carve it out seperately.

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
    (-> (some #{h} peer-set) boolean)))

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
  (doall
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

(def input-chan (chan))
(def publisher (pub input-chan :router))


(defn process-message [fsm fsm-state message]
  (log/debug "State Machine Process Message")
  (let [new-fsm-state (try (fsm fsm-state message)
                           (catch IllegalArgumentException e
                             (log/error (ex-info "State Machine Error"
                                                 {:error     (.getMessage e)
                                                  :message   message
                                                  :fsm-state fsm-state}))
                             fsm-state))]
    #_(condp = (:value ret)
        nil fsm-state
        ret)
    (log/debug "FSM-State "  new-fsm-state)
    new-fsm-state))

(defn channel-sub-listener [t]
  (let [reader (chan)]
    (sub publisher t reader)
    (try
      (go-loop []
        (let [{:keys [router message]} (<! reader)
              _                        (log/debug  "Packet In Channel" (-> message
                                                                           :message
                                                                           bs/to-byte-array
                                                                           codecs/bytes->hex))
              fsm                      (bind-fsm)
              fsm-state                (get-chan-map-state router)
              login-state              (get-login-state router)
              auth                     (get-authentication-codec router)

              compiled-codec (compile-codec router)
              decoder        (partial decode compiled-codec)
              host-map       (get-session-state message)]

          (if-let [decoded (decode-message compiled-codec message)]
            (let [m             (merge {:hash router} host-map decoded)
                  new-fsm-state (process-message fsm fsm-state m)
                  complete?     (-> new-fsm-state :accepted? true?)]
              (update-chan-map-state router new-fsm-state)
              (when complete?
                (delete-chan hash))
              (log/info "Completion State:" complete?  "Queued Requests " (count-peer)))
            #_(delete-chan hash))
          (recur)))
      (catch Exception e (ex-data e)))))

(defn publish [data]
  (try (go (>! input-chan data))
       (catch Exception e (ex-info "Exception during publish" {:error (.getMessage e)}))
       (finally data)))

(defn message-handler  [message]
  (let [host-map   (get-session-state message)
        h          (hash host-map)]
    (log/debug  "Packet In" (-> message
                                :message
                                bs/to-byte-array
                                codecs/bytes->hex))
    (log/debug "APP-STATE" @app-state)

    (when-not (log/spy (channel-exists? h))
      (do
        (log/debug "Creating subscriber for topic " h)
        (thread
          (try
            (channel-sub-listener h)
            (catch Exception e (ex-data e))))

        (upsert-chan h  {:created-at (Date.)
                         :host-map    host-map
                         :login-state {:auth  0
                                       :integ 0
                                       :conf  0}
                         :state       {}})))
    (log/debug "Publish message on topic " h)
    (publish  {:router  h
               :message message})))

(defn start-consumer [server-socket]
  (->> server-socket
       (s/consume #(message-handler %))))

(defn start-udp-server
  [port]
  (if-not (some-> @server-socket  s/closed? not)
    (do
      (reset! server-socket @(udp/socket {:port port :epoll? true})))
    (do
      (log/error "Port in use")
      false)))

(defn start-reaper [time-to-recur]
  (go-loop []
    (run-reaper)
    (Thread/sleep time-to-recur)
    (recur)))

(defn stop-server []
  (safe (s/close! @server-socket)))

(defn start-server
  ([port]
   (log/info "Starting Server on Port " 623)
   (if-not (empty? @registration-db)
     (when (start-udp-server port)
       (do
         (reset-app-state)
         (start-consumer  @server-socket)
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
      (start-consumer  @server-socket)
      ;(start-reaper 120000)
      (future
        (while true
          (Thread/sleep
           1000))))))
