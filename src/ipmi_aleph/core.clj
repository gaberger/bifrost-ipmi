(ns ipmi-aleph.core
  (:require [aleph.udp :as udp]
            [manifold.stream :as s]
            [buddy.core.crypto :as crypto]
            [buddy.core.nonce :as nonce]
            [buddy.core.codecs :as codecs]
            [gloss.io :refer [decode encode]]
            [automat.core :as a]
            [ipmi-aleph.codec :as c]
            [ipmi-aleph.handlers :as h]
            [clojure.string :as str]
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
; TODO Refactor these with a lookup
(defn send-pong [session message-tag]
  (let [server-socket (get session :socket)
        host (get session :address)
        port (get session :peer-port)]
    (s/put! server-socket {:host host
                           :port port
                           :message (encode c/rmcp-header (h/presence-pong-msg message-tag))})))

(defn send-auth-cap-response [session]
  (let [server-socket (get session :socket)
        host (get session :address)
        port (get session :peer-port)]
    (s/put! server-socket {:host host
                           :port port
                           :message (encode c/rmcp-header (h/auth-capabilities-response-msg))})))

(defn send-open-session-response [session]
  (let [server-socket (get session :socket)
        host (get session :address)
        port (get session :peer-port)]
    (s/put! server-socket {:host host
                           :port port
                           :message (encode c/rmcp-header (h/rmcp-open-session-response-msg))})))

(defn fsm []
  (let [fsm [(a/$ :init)
             (a/or
              [:asf-ping (a/$ :asf-ping)]
              [:get-channel-auth-cap-req (a/$ :get-channel-auth-cap-req)
               :open-session-request (a/$ :open-session-request)])]
        compiled-fsm (a/compile fsm
                                {:signal #(:type (c/get-message-type %))
                                 :reducers {:init (fn [state _] (assoc state :last-message []))
                                            :get-channel-auth-cap-req (fn [state input]
                                                                        (log/debug "Auth Capabilities Request")
                                                                        (let [message (conj {} (c/get-message-type input))]
                                                                          (update-in state [:last-message] conj message)
                                                                          (send-auth-cap-response input)
                                                                          state))
                                            :open-session-request (fn [state input]
                                                                    (log/debug "Open Session Request")
                                                                    (let [message (conj {} (c/get-message-type input))]
                                                                      (update-in state [:last-message] conj message)
                                                                      (send-open-session-response input)
                                                                      state))
                                            :asf-ping (fn [state input]
                                                        (let [message-tag (get-in input [:rmcp-class
                                                                                         :asf-payload
                                                                                         :asf-message-header
                                                                                         :message-tag])
                                                              message-type (conj {} (c/get-message-type input))
                                                              message (assoc message-type :message-tag message-tag)]
                                                          (update-in state [:last-message] conj message)
                                                          (send-pong input message-tag)))}})
       ; _ (automat.viz/view compiled-fsm)
        adv (partial a/advance compiled-fsm)]
    adv))

(def udp-session (atom {}))

(defn message-handler [server-state payload]
  (log/debug server-state payload)
  (let [myfsm (fsm)
        fsm-state (if-not (empty? @udp-session) @udp-session nil)
        sender (:sender payload)
        address (-> (.getAddress sender) (.getHostAddress))
        port (.getPort sender)
        message (:message payload)
        server-state  (conj server-state {:address address :peer-port port})
        decoded  (try (c/rmcp-decode message)
                      (catch Exception e (str "caught decoding exception: " (.getMessage e))))
        _     (log/debug (c/get-message-type decoded))
        session-state (merge server-state decoded)
        new-fsm-state (myfsm fsm-state session-state)]
    (swap! udp-session conj new-fsm-state)))

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

(defn start-server [port]
  (let [udp-server (start-udp-server port)
        _ (start-consumer udp-server)]
    (future
      (Thread/sleep 25000)
      (s/close! (:socket udp-server))
      (println "closed socket"))
    udp-server))

;(send-message (:socket udp-server) "localhost" 623 (byte-array (:open-session-request rmcp-payloads)))

;(send-message (:socket udp-server) "localhost" 623 (byte-array (:rmcp-ping rmcp-payloads)))
