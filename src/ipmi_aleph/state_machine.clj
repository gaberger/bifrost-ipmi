(ns ipmi-aleph.state-machine
  (:require
   [automat.viz :refer [view]]
   [automat.core :as a]
   [gloss.io :refer [encode decode]]
   [ipmi-aleph.codec :as c]
   [ipmi-aleph.packet :as p]
   [ipmi-aleph.crypto :refer [calc-sha1-key calc-rakp-1 calc-rakp-3 calc-rakp-4-sidm calc-rakp-4-sik]]
   [manifold.stream :as s]
   [ipmi-aleph.handlers :as h]
   [taoensso.timbre :as log]
   [clj-uuid :as uuid]
   [buddy.core.codecs :as codecs]
   [buddy.core.bytes :as bytes]
   [byte-streams :as bs]))

(def udp-session (atom {}))
(def fsm-state   (atom {}))

(declare ipmi-fsm)
(declare ipmi-handler)

(defn bind-fsm []
  (partial a/advance (a/compile ipmi-fsm ipmi-handler)))


;; (add-watch fsm-state :watcher
;;            (fn [key atom old-state new-state]
;;              (prn "-- Atom Changed --")
;;              (prn "key" key)
;;              (prn "atom" atom)
;;              (prn "old-state" old-state)
;;              (prn "new-state" new-state)))


(defn get-session-state [msg]
  (let [sender (:sender msg)
        address (-> (.getAddress sender) (.getHostAddress))
        port (.getPort sender)]
    {:host address :port port}))

(defn send-udp [session message]
  (let [server-socket (get @udp-session :socket)
        host (get session :host)
        port (get session :port)]
    (log/debug "Sending Message to host:" host " port:" port)
    (log/debug  "Bytes" (-> message
                            bs/to-byte-array
                            codecs/bytes->hex))
    (s/put! server-socket {:host host
                           :port port
                           :message message})))

(defmulti send-message :type)
(defmethod send-message :chassis-status [m]
  (log/info "Sending Status Chassis Response: ")
  (let [{:keys [input sid]} m
        message             (h/chassis-status-response-msg sid)
        codec               (c/compile-codec)
        ipmi-encode         (partial encode codec)
        encoded-message     (ipmi-encode message)]
    (log/debug message)
    (send-udp input encoded-message)))

(defmethod send-message :device-id-req [m]
  (log/info "Sending Device ID  Response: ")
  (let [{:keys [input sid]} m
        message             (h/device-id-response-msg sid)
        codec               (c/compile-codec)
        ipmi-encode         (partial encode codec)
        encoded-message     (ipmi-encode message)]
    (log/debug message)
    (send-udp input encoded-message)))

(defmethod send-message :chassis-reset [m]
  (log/info "Sending Chassis Reset Response")
  (let [{:keys [input sid seq]} m
        message                 (h/chassis-reset-response-msg sid seq)
        codec                   (c/compile-codec)
        ipmi-encode             (partial encode codec)
        encoded-message         (ipmi-encode message)]
    (log/debug message)
    (send-udp input encoded-message)))

(defmethod send-message :get-channel-auth-cap-req [m]
  (log/info "Sending Chassis Auth Capability Response")
  (let [{:keys [input]} m
        message         (h/auth-capabilities-response-msg)
        codec           (c/compile-codec)
        ipmi-encode     (partial encode codec)
        encoded-message (ipmi-encode message)]
    (log/debug message)
    (send-udp input encoded-message)))

(defmethod send-message :open-session-request [m]
  (log/info "Sending Open Session Response ")
  (let [{:keys [input sidm sidc a i c]} m
        message                         (h/rmcp-open-session-response-msg sidc sidm a i c)
        codec                           (c/compile-codec)
        ipmi-encode                     (partial encode codec)
        encoded-message                 (ipmi-encode message)]
    (log/debug message)
    (send-udp input encoded-message)))

(defmethod send-message :rmcp-rakp-1 [m]
  (log/info "Sending RAKP1 Response")
  (let [{:keys [input]} m
        message         (h/rmcp-rakp-2-response-msg m)
        auth            (get m :auth)
        codec           (if (nil? auth)
                          (c/compile-codec)
                          (c/compile-codec auth))
        ipmi-encode     (partial encode codec)
        encoded-message (ipmi-encode message)]
    ;(log/debug "RAKP-2" (-> encoded-message (bs/to-byte-array) (codecs/bytes->hex)))`
    (send-udp input encoded-message)))

(defmethod send-message :rmcp-rakp-4 [m]
  (log/info "Sending RAKP4 Response")
  (let [{:keys [input sidm]} m
        message              (h/rmcp-rakp-4-response-msg m)
        auth                 (get m :auth)
        codec                (if (nil? auth)
                               (c/compile-codec)
                               (c/compile-codec auth))
        ipmi-encode          (partial encode codec)
        encoded-message       (ipmi-encode message)]
    (log/debug message)
    (send-udp input encoded-message)))

(defmethod send-message :session-priv-level [m]
  (log/info "Sending Session Privi Level Response")
  (let [{:keys [input sid]} m
        message             (h/set-session-priv-level-rsp-msg sid)
        codec               (c/compile-codec)
        ipmi-encode         (partial encode codec)
        encoded-message     (ipmi-encode message)]
    (log/debug message)
    (send-udp input encoded-message)))

(defmethod send-message :rmcp-close-session [m]
  (log/info "Sending Session Close Response")
  (let [{:keys [input sid seq]} m
        message                 (h/rmcp-close-response-msg sid seq)
        codec                   (c/compile-codec)
        ipmi-encode             (partial encode codec)
        encoded-message         (ipmi-encode message)]
    (log/debug message)
    (send-udp input encoded-message)))

(defmethod send-message :asf-ping [m]
  (log/info "Sending Ping Response")
  (let [{:keys [input message-tag]} m
        message                     (h/presence-pong-msg message-tag)
        codec                       (c/compile-codec)
        ipmi-encode                 (partial encode codec)
        encoded-message             (ipmi-encode message)]
    (log/debug message)
    (send-udp input encoded-message)))

(defn send-rmcp-ack [session seq-no]
  (log/info "Sending rmcp-ack " seq-no)
  (let [message         (h/rmcp-ack seq-no)
        codec           (c/compile-codec)
        ipmi-encode     (partial encode codec)
        encoded-message (ipmi-encode message)]
    (send-message session encoded-message)))

(def ipmi-fsm
  [(a/* (a/$ :init)
        (a/or
         [:asf-ping (a/$ :asf-ping)]
         (a/*
          [:get-channel-auth-cap-req (a/$ :get-channel-auth-cap-req)
           :open-session-request (a/$ :open-session-request)
           :rmcp-rakp-1 (a/$ :rmcp-rakp-1)
           :rmcp-rakp-3 (a/$ :rmcp-rakp-3)]
          (a/* (a/or
                [:chassis-status-req (a/$ :chassis-status)]
                [:chassis-reset-req (a/$ :chassis-reset)]
                [:device-id-req (a/$ :device-id-req)]
                [:set-session-prv-level-req (a/$ :session-priv-level)]))
          [:rmcp-close-session-req (a/$ :rmcp-close-session)])))])

(def ipmi-fsm-sample
  [(a/or (a/* [:Z])
         (a/or (a/* [:A :B :C]
                    (a/or [:D] [:E] [:F])
                    [:G])))])

(def ipmi-handler
  {:signal   #(:type  (log/spy (c/get-message-type %)))
   :reducers {:init                     (fn [state _] (assoc state :last-message []))
              :chassis-status           (fn [state input]
                                          (log/debug "Chassis Status Request")
                                          (let [message (conj {} (c/get-message-type input))
                                                state   (update-in state [:last-message] conj message)
                                                sid     (get state :sidm)]
                                            (send-message {:type :chassis-status :input input :sid sid})
                                            state))
              :device-id-req            (fn [state input]
                                          (log/debug "Device ID Request")
                                          (let [message (conj {} (c/get-message-type input))
                                                state   (update-in state [:last-message] conj message)
                                                sid     (get state :sidm)]
                                            (send-message {:type :device-id-req :input input :sid sid})
                                            state))
              :chassis-reset            (fn [state input]
                                          (log/debug "Chassis Reset Request -->" input)
                                          (let [message (conj {} (c/get-message-type input))
                                                state   (update-in state [:last-message] conj message)
                                                sid     (get state :sidm)
                                                seq     (get-in input [:rmcp-class :ipmi-session-payload :ipmi-2-0-payload :session-seq] 0)]
                                            (send-message {:type :chassis-reset :input input :sid sid :seq seq})
                                        ;(reboot-device [device api-key])
                                            state))
              :get-channel-auth-cap-req (fn [state input]
                                          (let [message (conj {} (c/get-message-type input))
                                                state   (update-in state [:last-message] conj message)]
                                            (log/debug "Auth Capabilities Request")
                                            (send-message {:type :get-channel-auth-cap-req :input input})
                                            state))
              :open-session-request     (fn [state input]
                                          (log/debug "Open Session Request ")
                                          (let [message (conj {} (c/get-message-type input))
                                                a       (get-in input [:rmcp-class :ipmi-session-payload
                                                                       :ipmi-2-0-payload :authentication-payload
                                                                       :algo
                                                                       :algorithm])
                                                i       (get-in input [:rmcp-class :ipmi-session-payload
                                                                       :ipmi-2-0-payload :integrity-payload
                                                                       :algo
                                                                       :algorithm])
                                                c       (get-in  input [:rmcp-class :ipmi-session-payload
                                                                        :ipmi-2-0-payload :confidentiality-payload
                                                                        :algo :algorithm])
                                                sidm    (get-in input [:rmcp-class :ipmi-session-payload
                                                                       :ipmi-2-0-payload
                                                                       :remote-session-id])
                                                sidc    (rand-int (.pow (BigInteger. "2") 16))
                                                rolem   (get-in input [:rmcp-class :ipmi-session-payload
                                                                       :ipmi-2-0-payload :privilege-level
                                                                       :max-priv-level])
                                                state   (-> state
                                                            (update-in [:last-message] conj message)
                                                            (merge {:sidc                    sidc
                                                                    :sidm                    sidm
                                                                    :priv-level              rolem
                                                                    :authentication-payload  a
                                                                    :confidentiality-payload c
                                                                    :integrity-payload       i}))
                                                m       {:type :open-session-request :input input :sidc sidc :sidm sidm :a a :i i :c c}]
                                            (log/debug "Open Session Request " m)
                                        ; TODO Need selector for auth, ident, conf types
                                            (send-message m)
                                            state))
              :rmcp-rakp-1              (fn [state input]
                                          (log/debug "RAKP-1 Request")
                                          (log/debug "DEBUG STATE" state)
                                          (let [message (conj {} (c/get-message-type input))
                                                rm      (get-in input [:rmcp-class :ipmi-session-payload
                                                                       :ipmi-2-0-payload :remote-console-random-number])
                                                unamem  (get-in input [:rmcp-class :ipmi-session-payload
                                                                       :ipmi-2-0-payload :user-name])
                                                sidc    (get state :sidc)
                                                sidm    (get state :sidm)
                                                rolem   (:priv-level state)

                                                auth       (-> (get c/authentication-codec (:authentication-payload state))
                                                               :codec)
                                                rc         (vec (take 16 (repeatedly #(rand-int 16))))
                                                guidc      (vec (uuid/as-byte-array (uuid/v4)))
                                                rakp2-hmac (if (= :rmcp-rakp-hmac-sha1 auth)
                                                             (vec (calc-rakp-1 {:rm    rm   :rc   rc   :guidc  guidc
                                                                                :sidc  sidc :sidm sidm :unamem unamem
                                                                                :rolem rolem}))
                                                             nil)
                                                m          {:type       :rmcp-rakp-1
                                                            :input      input
                                                            :sidc       sidc
                                                            :rc         rc
                                                            :unamem     unamem
                                                            :rm         rm
                                                            :sidm       sidm
                                                            :guidc      guidc
                                                            :rakp2-hmac rakp2-hmac
                                                            :auth       auth}
                                                state      (-> state
                                                               (update-in [:last-message] conj message)
                                                               (merge (select-keys  m [:sidc :sidm :rm :rc :guidc :unamem :rolem])))]
                                            (log/debug "RAKP 1" m)
                                            (send-message m)
                                            state))
              :rmcp-rakp-3 (fn [state input]
                             (log/debug "RAKP-3 Request " state)
                             (let [message (conj {} (c/get-message-type input))
                                   auth      (-> (get c/authentication-codec (:authentication-payload state))
                                                 :codec)
                                   unamem    (get state :unamem)
                                   sidc      (get state :sidc)
                                   sidm      (get state :sidm)
                                   guidc     (get state :guidc)
                                   rolem     (get state :priv-level)
                                   rm        (get state :rm)
                                   rc        (get state :rc)
                                   sidm-hmac (if (= :rmcp-rakp-hmac-sha1 auth)
                                               (let [kec       (get-in input [:rmcp-class :ipmi-session-payload
                                                                              :ipmi-2-0-payload :key-exchange-code])
                                                     sidc-hmac (calc-rakp-3 {:sidm   sidm :rc rc :rolem rolem :unamem unamem})
                                                     sik-hmac  (calc-rakp-4-sik {:rm rm :rc rc :rolem rolem :unamem unamem})
                                                     sidm-hmac (calc-rakp-4-sidm {:rm  rm :sidc sidc :guidc guidc :sik sik-hmac})]

                                                 ;(assert (= kec sidc-hmac))
                                                 sidm-hmac)
                                               nil)

                                   state     (-> state
                                                 (update-in [:last-message] conj message)
                                                 (merge {:sidm-hmac sidm-hmac}))
                                   m         {:type :rmcp-rakp-4 :auth auth :input input :sidm sidm :sidm-hmac sidm-hmac}]
                               (log/debug "RAKP 4 " m)
                               (send-message m)
                               state))
              :session-priv-level (fn [state input]
                                    (log/debug "Set Session Priv Level")
                                    (let [message (conj {} (c/get-message-type input))
                                          sid     (get state :sidm)
                                          seq     (get-in input [:rmcp-class :ipmi-session-payload :ipmi-2-0-payload :session-seq] 0)
                                          state   (-> state
                                                      (update-in [:last-message] conj message)
                                                      (assoc :seq seq))]
                                      (send-message {:type :session-priv-level :input input :sid sid})
                                      state))
              :asf-ping           (fn [state input]
                                    (log/debug "ASF PING")
                                    (let [message-tag  (get-in input [:rmcp-class
                                                                      :asf-payload
                                                                      :asf-message-header
                                                                      :message-tag])
                                          message-type (conj {} (c/get-message-type input))
                                          message      (assoc message-type :message-tag message-tag)]
                                      (send-message {:type :asf-ping :input input :message-tag message-tag})
                                      state))
              :rmcp-close-session (fn [state input]
                                    (log/debug "Session Closing " state)
                                    (let [sid (get state :sidm)
                                          seq (get-in input [:rmcp-class :ipmi-session-payload :ipmi-2-0-payload :session-seq] 0)]
                                      (send-message {:type :rmcp-close-session :input input :sid sid :seq seq})
                                      state))}})

(defn view-fsm []
  (automat.viz/view (a/compile ipmi-fsm ipmi-handler)))

(defn view-fsm-sample []
  (automat.viz/view (a/compile ipmi-fsm-sample ipmi-handler)))
