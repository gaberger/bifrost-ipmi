(ns ipmi-aleph.core
  (:require [aleph.udp :as udp]
            [byte-streams :as bs]
            [manifold.deferred :as d]
            [manifold.stream :as s]
            [buddy.core.crypto :as crypto]
            [buddy.core.nonce :as nonce]
            [buddy.core.codecs :as codecs]
            [gloss.io :refer [decode encode]]
            [automat.core :as a]
            [ipmi-aleph.codec :refer :all]
            [ipmi-aleph.state-machine :as fsm]
            [ipmi-aleph.handlers :as h]
            [clojure.string :as str]
            [clojure.core.async :refer [thread]]
            [taoensso.timbre :as log]
            [taoensso.timbre.appenders.core :as appenders]))

(log/refer-timbre)
(log/merge-config! {:appenders {:println {:enabled? true}}})
;(log/merge-config!
;   {:appenders
;    {:spit (appenders/spit-appender {:fname (str/join [*ns* ".log"])})}})

(def server-port 623)

#_(defn send-ipmi-init!
    [s host port  message]
    (s/put! s {:host    host
               :port    port
               :message message}))

(defn encr []
  (let [eng   (crypto/block-cipher :twofish :cbc)
        iv16  (nonce/random-nonce 16)
        key32 (nonce/random-nonce 32)
        data  (codecs/hex->bytes "000000000000000000000000000000AA")]
    (crypto/init! eng {:key key32 :iv iv16 :op :encrypt})
    (crypto/process-block! eng data)))

(defn get-and-set!
  "An atomic operation which returns the previous value, and sets it to `new-val`."
  [a new-val]
  (let [old-val @a]
    (if (compare-and-set! a old-val new-val)
      old-val
      (recur a new-val))))

;(defn parse-ipmi-packet-callback
;  [{:keys [sender message]}]
;  (let [message (decode rmcp-header message)
;        message-tag (get-in message [:class :message-type :message-tag])]
;    (h/presence-pong message-tag)))

(defn send-pong [session message-tag]
  (let [server-socket (get session :socket)
        host (get session :address)
        port (get session :peer-port)]
    (s/put! server-socket {:host host
                           :port port
                           :message (encode rmcp-header (h/presence-pong-msg message-tag))})))

(defn fsm []
  (let [fsm [(a/$ :init)
             (a/or
              [:asf-ping (a/$ :asf-ping)]
              [:open-session-request (a/$ :open-session-request)])]
        compiled-fsm (a/compile fsm
                                {:signal #(:type (get-message-type %))
                                 :reducers {:init (fn [state _] (assoc state :last-message []))
                                            :open-session-request (fn [state input]
                                                                    :open-session-request)
                                            :asf-ping (fn [state input]
                                                        (let [message-tag (get-in input [:rmcp-class
                                                                                         :asf-payload
                                                                                         :asf-message-header
                                                                                         :message-tag])
                                                              message-type (conj {} (get-message-type input))
                                                              message (assoc message-type :message-tag message-tag)]
                                                          (update-in state [:last-message] conj message)
                                                          (send-pong input message-tag)))
                                            :asf-pong (fn [state input]
                                                        (let [message-tag (get-in input [:rmcp-class
                                                                                         :asf-payload
                                                                                         :asf-message-header
                                                                                         :message-tag])
                                                              message-type (conj {} (get-message-type input))
                                                              message (assoc message-type :message-tag message-tag)]
                                                          (update-in state [:last-message] conj message)))}})
       ; _ (automat.viz/view compiled-fsm)
        adv (partial a/advance compiled-fsm)]
    adv))

(defn process-message [m]
  (let [parsed-message (decode rmcp-header m)]
    (clojure.pprint/pprint parsed-message)
    (clojure.pprint/pprint
     (a/find ipmi-aleph.state-machine/fsm nil parsed-message))))

      ;(fsm/adv parsed-message)
                                    ; message-tag (get-in message [:rmcp-class :asf-payload :asf-message-header :message-tag])]
                                    ;(log/debug "Sending UDP request to host: " address "on port: " port "for message-tag " message-tag)
                                    ;(s/put! server-socket {:host address :port port :message (encode rmcp-header (h/presence-pong message-tag))})))

(def udp-session (atom {}))

(defn message-handler [server-state payload]
  (log/debug server-state payload)
  (let [myfsm (fsm)
        sender (:sender payload)
        address (-> (.getAddress sender) (.getHostAddress))
        port (.getPort sender)
        message (:message payload)
        server-state  (conj server-state {:address address :peer-port port})
        decoded  (try (rmcp-decode message)
                      (catch Exception e (str "caught exception: " (.getMessage e))))
        session-state (merge server-state decoded)
        _ (swap! udp-session conj session-state)
        fsm-state (myfsm nil session-state)]
    (clojure.pprint/pprint @udp-session)))

(defn start-consumer
  [server-state]
  (let [udp-socket (:socket server-state)]
    (->> udp-socket
         (s/consume #(message-handler server-state %)))))

(defn send-message [socket host port message]
  (s/put! socket {:host host, :port port, :message message}))

(defn start-udp-server
  [port]
  (log/info "Starting Server on port " port)
  (let [server-socket @(udp/socket {:port port})
        server-state (assoc {} :socket server-socket)]
    server-state))

(defn start-server []
  (let [udp-server (start-udp-server 1001)
        _ (start-consumer udp-server)]
    udp-server
    #_(thread
        (Thread/sleep 25000)
        (s/close! (:socket udp-server)))))

;(s/close! (:socket @session))

(defn close []
  (s/close! (:socket udp-server)))
