(ns bifrost.ipmi.state-machine
  (:require
   [automat.viz :refer [view]]
   [automat.core :as a]
   [gloss.io :refer [encode decode]]
   [bifrost.ipmi.codec :as c]
   [bifrost.ipmi.crypto :refer [calc-sha1-key calc-rakp-1 calc-rakp-3 calc-rakp-4-sidm calc-rakp-4-sik]]
   [bifrost.ipmi.registrar :refer :all]
   [bifrost.ipmi.utils :refer [safe]]
   [manifold.stream :as s]
   [bifrost.ipmi.handlers :as h]
   [taoensso.timbre :as log]
   [clj-uuid :as uuid]
   [buddy.core.codecs :as codecs]
   [buddy.core.bytes :as bytes]
   [byte-streams :as bs]))

(def server-socket (atom nil))

(declare ipmi-fsm)
(declare ipmi-handler)

(defn bind-fsm []
  (partial a/advance (a/compile ipmi-fsm ipmi-handler)))


;; (add-watch session-atom :watcher
;;            (fn [key atom old-state new-state]
;;              (log/debug "-- Atom Changed -- key" key " atom" atom " old-state" old-state " new-state" new-state)))


(defn get-session-state [msg]
  (let [sender (:sender msg)
        address (-> (.getAddress sender) (.getHostAddress))
        port (.getPort sender)]
    {:host address :port port}))

(defn send-udp [session message]
  (let [host (get session :host)
        port (get session :port)
        bytes (-> message bs/to-byte-array)]
    (assert (not (nil? host)) "Host cannon be nil")
    (log/debug "Sending Message to host:" host " port:" port)
    (log/debug  "Bytes" (-> message
                            bs/to-byte-array
                            codecs/bytes->hex))
    (s/put! @server-socket {:host    host
                            :port    port
                            :message bytes})))

(defmulti send-message :type)
(defmethod send-message :error-response [m]
  (log/info "Sending Error Response: ")
  (let [{:keys [input]} m
        message             (log/spy (h/error-response-msg m))
        codec               (c/compile-codec)
        ipmi-encode         (partial encode codec)
        encoded-message     (safe (ipmi-encode message))]
    (safe (send-udp input encoded-message))))

(defmulti send-message :type)
(defmethod send-message :chassis-status [m]
  (log/info "Sending Status Chassis Response: ")
  (let [{:keys [input sid]} m
        message             (h/chassis-status-response-msg m)
        codec               (c/compile-codec)
        ipmi-encode         (partial encode codec)
        encoded-message     (safe (ipmi-encode message))]
    (safe (send-udp input encoded-message))))

(defmethod send-message :device-id-req [m]
  (log/info "Sending Device ID  Response: ")
  (let [{:keys [input sid]} m
        message             (h/device-id-response-msg m)
        codec               (c/compile-codec)
        ipmi-encode         (partial encode codec)
        encoded-message     (safe (ipmi-encode message))]
    (safe (send-udp input encoded-message))))

(defmethod send-message :chassis-reset [m]
  (log/info "Sending Chassis Reset Response")
  (let [{:keys [input]} m
        message                 (log/spy (h/chassis-reset-response-msg m))
        codec                   (c/compile-codec)
        ipmi-encode             (partial encode codec)
        encoded-message         (safe (ipmi-encode message))]
    (safe (send-udp input encoded-message))))

(defmethod send-message :get-channel-auth-cap-req [m]
  (log/info "Sending Chassis Auth Capability Response")
  (let [{:keys [input]} m
        message         (h/auth-capabilities-response-msg m)
        codec           (c/compile-codec)
        ipmi-encode     (partial encode codec)
        encoded-message (safe (ipmi-encode message))]
    (safe (send-udp input encoded-message))))

(defmethod send-message :open-session-request [m]
  (log/info "Sending Open Session Response ")
  (let [{:keys [input]} m
        message                         (log/spy (h/rmcp-open-session-response-msg m))
        codec                           (c/compile-codec)
        ipmi-encode                     (partial encode codec)
        encoded-message                 (safe (ipmi-encode message))]
    (safe (send-udp input encoded-message))))

(defmethod send-message :rmcp-rakp-2 [m]
  (log/info "Sending RAKP2")
  (let [{:keys [input]} m
        message         (h/rmcp-rakp-2-response-msg m)
        auth            (get m :auth)
        codec           (if (nil? auth)
                          (c/compile-codec)
                          (c/compile-codec auth))
        ipmi-encode     (partial encode codec)
        encoded-message (try
                          (safe (ipmi-encode message))
                          (catch Exception e
                            (log/error "Error encoding message input:" m "message:" message)))]
    (safe (send-udp input encoded-message))))

(defmethod send-message :rmcp-rakp-4 [m]
  (log/info "Sending RAKP4")
  (let [{:keys [input sidm]} m
        message              (h/rmcp-rakp-4-response-msg m)
        auth                 (get m :auth)
        codec                (c/compile-codec auth)
        ipmi-encode          (partial encode codec)
        encoded-message      (safe (ipmi-encode message))]
    (safe (send-udp input encoded-message))))

(defmethod send-message :session-priv-level [m]
  (log/info "Sending Session Priv Level Response")
  (let [{:keys [input sid]} m
        message             (h/set-session-priv-level-rsp-msg m)
        codec               (c/compile-codec)
        ipmi-encode         (partial encode codec)
        encoded-message     (safe (ipmi-encode message))]
    (safe (send-udp input encoded-message))))

(defmethod send-message :rmcp-close-session [m]
  (log/info "Sending Session Close Response")
  (let [{:keys [input sid seq]} m
        message                 (h/rmcp-close-response-msg m)
        codec                   (c/compile-codec)
        ipmi-encode             (partial encode codec)
        encoded-message         (safe (ipmi-encode message))]
    (safe (send-udp input encoded-message))))

(defmethod send-message :asf-ping [m]
  (log/info "Sending Ping Response")
  (let [{:keys [input message-tag]} m
        message                     (h/presence-pong-msg message-tag)
        codec                       (c/compile-codec)
        ipmi-encode                 (partial encode codec)
        encoded-message             (safe (ipmi-encode message))]
    (safe (send-udp input encoded-message))))

(defmethod send-message :hpm-capabilities-req [m]
  (log/info "Sending HPM Capabilities Response")
  (let [{:keys [input]} m
        message         (h/hpm-capabilities-msg m)
        codec           (c/compile-codec)
        ipmi-encode     (partial encode codec)
        encoded-message (safe (ipmi-encode message))]
    (safe (send-udp input encoded-message))))

(defmethod send-message :picmg-properties-req [m]
  (log/info "Sending PICMG Properties Response")
  (let [{:keys [input]} m
        message         (h/picmg-response-msg m)
        codec           (c/compile-codec)
        ipmi-encode     (partial encode codec)
        encoded-message (safe (ipmi-encode message))]
    (safe (send-udp input encoded-message))))

(defmethod send-message :vso-capabilities-req [m]
  (log/info "Sending VSO Capabilities Response")
  (let [{:keys [input]} m
        message         (h/vso-response-msg m)
        codec           (c/compile-codec)
        ipmi-encode     (partial encode codec)
        encoded-message (safe (ipmi-encode message))]
    (safe (send-udp input encoded-message))))

(defn send-rmcp-ack [session seq-no]
  (log/info "Sending rmcp-ack " seq-no)
  (let [message         (h/rmcp-ack seq-no)
        codec           (c/compile-codec)
        ipmi-encode     (partial encode codec)
        encoded-message (safe (ipmi-encode message))]
    (send-message session encoded-message)))

(def ipmi-fsm
  [(a/* (a/$ :init)
        (a/*
         [:get-channel-auth-cap-req (a/$ :get-channel-auth-cap-req)
          :open-session-request (a/$ :open-session-request)
          :rmcp-rakp-1 (a/$ :rmcp-rakp-1)
          :rmcp-rakp-3 (a/$ :rmcp-rakp-3)]
         (a/* (a/or
               [:chassis-status-req (a/$ :chassis-status)]
               [:chassis-reset-req (a/$ :chassis-reset)]
               [:device-id-req (a/$ :device-id-req)]
               [:hpm-capabilities-req (a/$ :hpm-capabilities-req)]
               [:picmg-properties-req (a/$ :picmg-properties-req)]
               [:vso-capabilities-req (a/$ :vso-capabilities-req)]
               [:set-session-prv-level-req (a/$ :session-priv-level)])))
        [:rmcp-close-session-req (a/$ :rmcp-close-session)])])


;;TODO create schemas for send-message input to test handlers


(def ipmi-handler
  {:signal   #(:type  (c/get-message-type %))
   :reducers {:init                 (fn [state _]
                                      (assoc state :last-message []))
              :hpm-capabilities-req (fn [state input]
                                      (log/info "HPM Capabilities")
                                      (log/debug "Incoming " input)
                                      (let [message         (c/get-message-type input)
                                            seq             (get-in input [:rmcp-class :ipmi-session-payload :ipmi-2-0-payload :session-seq] 0)
                                            seq-no          (get-in input [:rmcp-class :ipmi-session-payload :ipmi-2-0-payload :source-lun :seq-no])
                                            sa              (get-in input [:rmcp-class :ipmi-session-payload :ipmi-2-0-payload :source-address] 0)
                                            ta              (get-in input [:rmcp-class :ipmi-session-payload :ipmi-2-0-payload :target-address] 0)
                                            hsum            (get-in input [:rmcp-class :ipmi-session-payload :ipmi-2-0-payload :header-checksum] 0)
                                            sl              (get-in input [:rmcp-class :ipmi-session-payload :ipmi-2-0-payload :source-lun] 0)
                                            completion-code 0xC1
                                            c               (:command message)
                                            f               (:response message)]
                                        ;ta  | nf |  hcsum | sa | slun | c   | cc | csum
                                        (send-message {:type     :error-response
                                                       :input    input
                                                       :sid      (get state :sidm)
                                                       :seq      seq
                                                       :ta       0x81
                                                       :function f
                                                       :hcsum    0xcb
                                                       :sa       0x81
                                                       :seq-no   seq-no
                                                       :sl       0x08
                                                       :command  c
                                                       :status   0xC1
                                                       :csum     0x17}))
                                      state)
              :picmg-properties-req (fn [state input]
                                      (log/info "PICMG Properties")
                                      (log/debug "Incoming " input)
                                      (let [message         (c/get-message-type input)
                                            seq             (get-in input [:rmcp-class :ipmi-session-payload :ipmi-2-0-payload :session-seq] 0)
                                            seq-no          (get-in input [:rmcp-class :ipmi-session-payload :ipmi-2-0-payload :source-lun :seq-no])
                                            sa              (get-in input [:rmcp-class :ipmi-session-payload :ipmi-2-0-payload :source-address] 0)
                                            ta              (get-in input [:rmcp-class :ipmi-session-payload :ipmi-2-0-payload :target-address] 0)
                                            hsum            (get-in input [:rmcp-class :ipmi-session-payload :ipmi-2-0-payload :header-checksum] 0)
                                            sl              (get-in input [:rmcp-class :ipmi-session-payload :ipmi-2-0-payload :source-lun] 0)
                                            completion-code 0xC1
                                            c               (:command message)
                                            f               (:response message)]
                                        ;ta  | nf |  hcsum | sa | slun | c   | cc | csum
                                        (send-message {:type     :error-response   :input input
                                                       :sid      (get state :sidm) :seq   seq
                                                       :ta       0x81
                                                       :function f
                                                       :hcsum    0xcb
                                                       :sa       0x81
                                                       :seq-no   seq-no
                                                       :sl       0x10
                                                       :command  c
                                                       :status   0xC1
                                                       :csum     0x17}))
                                      state)
              :vso-capabilities-req (fn [state input]
                                      (log/info "VSO Capabilities")
                                      (log/debug "Incoming " input)
                                      (let [message (c/get-message-type input)
                                            seq     (get-in input [:rmcp-class :ipmi-session-payload :ipmi-2-0-payload :session-seq] 0)
                                            seq-no  (get-in input [:rmcp-class :ipmi-session-payload :ipmi-2-0-payload :source-lun :seq-no])
                                            sa      (get-in input [:rmcp-class :ipmi-session-payload :ipmi-2-0-payload :source-address] 0)
                                            ta      (get-in input [:rmcp-class :ipmi-session-payload :ipmi-2-0-payload :target-address] 0)
                                            c       (:command message)
                                            f       (:response message)]
                                        (send-message {:type     :error-response
                                                       :input    input :sid    (get state :sidm)
                                                       :sa   sa :ta ta :seq seq :command c :seq-no seq-no
                                                       :function f     :status 0    :csum 204}))
                                      state)

              :chassis-status           (fn [state input]
                                          (log/info "Chassis Status Request")
                                          (let [message (conj {} (c/get-message-type input))
                                                state   (update-in state [:last-message] conj message)
                                                sid     (get state :sidm)
                                                seq-no  (get-in input [:rmcp-class :ipmi-session-payload
                                                                       :ipmi-2-0-payload :source-lun :seq-no])]
                                            (send-message {:type :chassis-status :input input :sid sid :seq-no seq-no})
                                            state))
              :device-id-req            (fn [state input]
                                          (log/info "Device ID Request")
                                          (let [message (conj {} (c/get-message-type input))
                                                state   (update-in state [:last-message] conj message)
                                                sid     (get state :sidm)
                                                seq-no  (get-in input [:rmcp-class :ipmi-session-payload :ipmi-2-0-payload :source-lun :seq-no])]
                                            (send-message {:type :device-id-req :input input :sid sid :seq-no seq-no})
                                            state))
              :chassis-reset            (fn [state input]
                                          (log/info "Chassis Reset Request")
                                          (let [message (conj {} (c/get-message-type input))
                                                state   (update-in state [:last-message] conj message)
                                                sid     (get state :sidm)
                                                seq     (get-in input [:rmcp-class :ipmi-session-payload :ipmi-2-0-payload :session-seq] 0)
                                                seq-no  (get-in input [:rmcp-class :ipmi-session-payload :ipmi-2-0-payload  :source-lun :seq-no])
                                                unamem  (get state :unamem)]
                                            (if-not (nil? (log/spy (get-driver-device-id (keyword unamem))))
                                              (do
                                                (safe (reboot-server {:driver :packet :user-key (keyword unamem)}))
                                                (send-message {:type :chassis-reset :input input :sid sid :seq seq :seq-no seq-no :status 0}))
                                              (send-message {:type :chassis-reset :input input :sid sid :seq seq :seq-no seq-no :status 0x12}))
                                            state))
              :get-channel-auth-cap-req (fn [state input]
                                          (log/info "Auth Capabilities Request")
                                          (let [message (conj {} (c/get-message-type input))
                                                state   (update-in state [:last-message] conj message)]

                                            (send-message {:type :get-channel-auth-cap-req :input input})
                                            state))
              :open-session-request (fn [state input]
                                      (log/info "Open Session Request ")
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
                                                                :rolem                   rolem
                                                                :authentication-payload  a
                                                                :confidentiality-payload c
                                                                :integrity-payload       i}))
                                            m       {:type  :open-session-request
                                                     :input input :sidc sidc
                                                     :sidm  sidm  :a    a :i i :c c}]
                                        ; TODO Need selector for auth, ident, conf types
                                        (send-message m)
                                        state))
              :rmcp-rakp-1          (fn [state input]
                                      (log/info "RAKP-1 Request")
                                      (let [message (conj {} (c/get-message-type input))
                                            rm      (get-in input [:rmcp-class :ipmi-session-payload
                                                                   :ipmi-2-0-payload :remote-console-random-number])
                                            unamem  (get-in input [:rmcp-class :ipmi-session-payload
                                                                   :ipmi-2-0-payload :user-name])
                                            rolem   (get-in input [:rmcp-class :ipmi-session-payload
                                                                   :ipmi-2-0-payload :requested-max-priv-level
                                                                   :requested-max-priv-level])
                                            sidc    (get state :sidc)
                                            sidm    (get state :sidm)
                                            auth    (-> (get c/authentication-codec (:authentication-payload state))
                                                        :codec)
                                            rc      (vec (take 16 (repeatedly #(rand-int 16))))
                                            uid     (lookup-password-key unamem)
                                            guid    (get-device-id-bytes unamem)]

                                        (if-not (nil? (lookup-userid unamem))
                                          (let [rakp2-hmac (when (= :rmcp-rakp-hmac-sha1 auth)
                                                             (vec (calc-rakp-1 {:rm    rm    :rc   rc   :guidc  guid
                                                                                :sidc  sidc  :sidm sidm :unamem unamem
                                                                                :rolem rolem :uid  uid})))
                                                m          {:type       :rmcp-rakp-2
                                                            :input      input
                                                            :sidc       sidc
                                                            :rc         rc
                                                            :unamem     unamem
                                                            :rm         rm
                                                            :status     0x00
                                                            :sidm       sidm
                                                            :guidc      guid
                                                            :rakp2-hmac rakp2-hmac
                                                            :auth       auth}
                                                state      (-> state
                                                               (update-in [:last-message] conj message)
                                                               (merge (select-keys  m [:sidc :sidm :rm :rc
                                                                                       :guidc :unamem :rolem])))]
                                            (send-message m)
                                            state)
                                          (let [m {:type       :rmcp-rakp-2
                                                   :input      input
                                                   :auth       auth
                                                   :rc         rc
                                                   :sidm       sidm
                                                   :status     0x0D ;; TODO enum error codes
                                                   :guidc      guid
                                                   :rakp2-hmac [0]}]
                                            (log/error (format "User %s  Not Found.." unamem))
                                            (send-message m) state))))

              :rmcp-rakp-3 (fn [state input]
                             (log/info "RAKP-3 Request ")
                             (let [message (conj {} (c/get-message-type input))
                                   auth    (-> (get c/authentication-codec (:authentication-payload state))
                                               :codec)
                                   unamem  (get state :unamem)
                                   uid     (lookup-password-key unamem)
                                   guid    (get-device-id-bytes unamem)
                                   sidc    (get state :sidc)
                                   sidm    (get state :sidm)
                                   rolem   (get state :rolem)
                                   rm      (get state :rm)
                                   rc      (get state :rc)

                                   sidm-hmac-96 (if (= :rmcp-rakp-hmac-sha1 auth)
                                                  (let [kec          (get-in input [:rmcp-class :ipmi-session-payload
                                                                                    :ipmi-2-0-payload :key-exchange-code])
                                                        sidc-hmac    (calc-rakp-3 {:sidm sidm :rc rc :rolem rolem :unamem unamem :uid uid})
                                                        sik-hmac     (calc-rakp-4-sik {:rm rm :rc rc :rolem rolem :unamem unamem :uid uid})
                                                        _            (comment "Need to truncate sidm-hmac to 96bits")
                                                        sidm-hmac    (calc-rakp-4-sidm {:rm rm :sidc sidc :guidc guid :sik sik-hmac :uid uid})
                                                        sidm-hmac-96 (-> sidm-hmac (bytes/slice 0 12))]

                                        ;(assert (= kec sidc-hmac))
                                                    (vec sidm-hmac-96))
                                                  nil)
                                   state (-> state
                                             (update-in [:last-message] conj message)
                                             (merge {:sidm-hmac sidm-hmac-96}))
                                   m     {:type :rmcp-rakp-4 :auth auth :input input :sidm sidm :sidm-hmac sidm-hmac-96}]
                               (send-message m)
                               state))
              :session-priv-level (fn [state input]
                                    (log/info "Set Session Priv Level")
                                    (let [message (conj {} (c/get-message-type input))
                                          sid     (get state :sidm)
                                          seq     (get-in input [:rmcp-class :ipmi-session-payload :ipmi-2-0-payload :session-seq] 0)
                                          seq-no  (get-in input [:rmcp-class :ipmi-session-payload :ipmi-2-0-payload :source-lun :seq-no])
                                          state   (-> state
                                                      (update-in [:last-message] conj message)
                                                      (assoc :seq seq))]
                                      (send-message {:type :session-priv-level :input input :sid sid :seq-no seq-no})
                                      state))
              :asf-ping           (fn [state input]
                                    (log/info "ASF PING")
                                    (let [message-tag  (get-in input [:rmcp-class
                                                                      :asf-payload
                                                                      :asf-message-header
                                                                      :message-tag])
                                          message-type (conj {} (c/get-message-type input))
                                          message      (assoc message-type :message-tag message-tag)]
                                      (send-message {:type :asf-ping :input input :message-tag message-tag})
                                      state))
              :rmcp-close-session (fn [state input]
                                    (log/info "Session Closing ")
                                    (let [message (conj {} (c/get-message-type input))
                                          sid     (get state :sidm)
                                          seq     (get-in input [:rmcp-class :ipmi-session-payload :ipmi-2-0-payload :session-seq] 0)
                                          seq-no  (get-in input [:rmcp-class :ipmi-session-payload :ipmi-2-0-payload :source-lun :seq-no])
                                          state   (-> state
                                                      (update-in [:last-message] conj message)
                                                      (assoc :seq seq))]
                                      (send-message {:type :rmcp-close-session :input input :sid sid :seq seq :seq-no seq-no})
                                      state))}})

(defn view-fsm []
  (automat.viz/view (a/compile ipmi-fsm ipmi-handler)))
