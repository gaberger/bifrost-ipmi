(ns ipmi-aleph.core
  (:require [aleph.udp :as udp]
            [manifold.stream :as s]
            [buddy.core.crypto :as crypto]
            [buddy.core.nonce :as nonce]
            [buddy.core.codecs :as codecs]
            [gloss.io :refer [decode encode]]
            [byte-streams :as bs]
            [automat.core :as a]
            [automat.viz :refer [view]]
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
(def udp-session (atom {}))

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
                           :message (encode c/rmcp-header (h/rmcp-open-session-response-msg 0 0))})))

(defn send-rakp-2-response [session]
  (let [server-socket (get session :socket)
        host (get session :address)
        port (get session :peer-port)]
    (s/put! server-socket {:host host
                           :port port
                           :message (encode c/rmcp-header (h/rmcp-rakp-2-response-msg))})))

(defn send-rakp-4-response [session]
  (let [server-socket (get session :socket)
        host (get session :address)
        port (get session :peer-port)]
    (s/put! server-socket {:host host
                           :port port
                           :message (encode c/rmcp-header (h/rmcp-rakp-4-response-msg))})))

(defn fsm []
  (let [fsm [(a/$ :init)
             (a/or
              (a/+
               [:asf-ping (a/$ :asf-ping)])
              [:get-channel-auth-cap-req (a/$ :get-channel-auth-cap-req)
               :open-session-request (a/$ :open-session-request)
               :rmcp-rakp-1 (a/$ :rmcp-rakp-1)
               :rmcp-rakp-3 (a/$ :rmcp-rakp-3)])]
              ;  :set-session-priv-level #_(a/$ :set-session-priv-level)])]

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
                                            :rmcp-rakp-1 (fn [state input]
                                                           (log/debug "RAKP-1 Request")
                                                           (let [message (conj {} (c/get-message-type input))
                                                                 state (update-in state [:last-message] conj message)]
                                                             (send-rakp-2-response input)
                                                             state))
                                            :rmcp-rakp-3 (fn [state input]
                                                           (log/debug "RAKP-3 Request")
                                                           (let [message (conj {} (c/get-message-type input))
                                                                 state (update-in state [:last-message] conj message)]
                                                             (send-rakp-4-response input)
                                                             state))
                                            ; :set-session-priv-level (fn [state input]
                                            ;                           (log/debug "Set Session Priv level")
                                            ;                           (let [message (conj {} (c/get-message-type input))
                                            ;                                 state (update-in state [:last-message] conj message)]
                                            ;                              state))
                                            :asf-ping (fn [state input]
                                                        (let [message-tag (get-in input [:rmcp-class
                                                                                         :asf-payload
                                                                                         :asf-message-header
                                                                                         :message-tag])
                                                              message-type (conj {} (c/get-message-type input))
                                                              message (assoc message-type :message-tag message-tag)
                                                              state (update-in state [:last-message] conj message)]
                                                          (send-pong input message-tag)
                                                          state))}})

        

        ;_ (automat.viz/view compiled-fsm)
        adv (partial a/advance compiled-fsm)]
    adv))


(defn message-handler [server-state payload]
  (let [myfsm (fsm)
        fsm-state (if-not (empty? @udp-session) @udp-session nil)
        sender (:sender payload)
        address (-> (.getAddress sender) (.getHostAddress))
        port (.getPort sender)
        message (:message payload)
        server-state  (conj server-state {:address address :peer-port port})
        _ (log/debug "DUMP BYTES" (bs/print-bytes message))
        decoded  (try (c/rmcp-decode message)
                      (catch Exception e (str "caught decoding exception: " (.getMessage e))))
        _ (log/debug "Decoded: " decoded)
        session-state (merge server-state decoded)
        new-fsm-state (myfsm fsm-state session-state)]
    (reset! udp-session new-fsm-state)))

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
      (Thread/sleep 30000)
      (s/close! (:socket udp-server))
      (println "closed socket"))
    udp-server))

;(send-message (:socket udp-server) "localhost" 623 (byte-array (:open-session-request rmcp-payloads)))

;(send-message (:socket udp-server) "localhost" 623 (byte-array (:rmcp-ping rmcp-payloads)))

; (def s (fsm))
; (-> nil  
;  (s (c/rmcp-decode (byte-array (:rmcp-ping p/rmcp-payloads))))
;  (s (c/rmcp-decode (byte-array (:rmcp-ping p/rmcp-payloads)))))

; (def data {:socket :foobar
;            :address "0:0:0:0:0:0:0:1", 
;            :peer-port 62126, 
;            :version 6, 
;            :reserved 0, :sequence 255, 
;            :rmcp-class {:asf-payload {:iana-enterprise-number 4542, :asf-message-header 
;                                       {:asf-message-type 128, :message-tag 114, 
;                                        :reserved 0, :data-length 0}}, :type :asf-session}})
; (encode c/rmcp-header (h/rmcp-rakp-4-response-msg))
; (require '[ipmi-aleph.test-payloads :refer :all])
; (c/rmcp-decode (byte-array (:rmcp-rakp-4 rmcp-payloads)))

; (h/rmcp-rakp-4-response-msg)