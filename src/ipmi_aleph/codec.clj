(ns ipmi-aleph.codec
  (:require [gloss.core :refer [defcodec compile-frame bit-map
                                ordered-map header finite-frame
                                string enum]]
            [clojure.string :as str]
            [clojure.datafy :as d]
            [clojure.walk :as w]
            [gloss.io :refer [decode]]
            [taoensso.timbre :as log]
            [taoensso.timbre.appenders.core :as appenders]))

(defn build-merge-header-with-data
  "Build a function that takes a header and returns a compiled
  frame (using `frame-fn`) that post-processes the frame to merge the
  header and the data."
  [frame-fn]
  (fn [h]
    (compile-frame
     (frame-fn h)
     identity
     (fn [data]
       (merge h data)))))

;TODO
(def command-completion-codes
  (comment "Page 44"))

(defn get-message-type [m]
  (if (-> (:rmcp-class m) (contains? :asf-payload))
    (let [message-type  (get-in m [:rmcp-class :asf-payload :asf-message-header :asf-message-type])
          selector (condp = message-type
                     128  {:type :asf-ping :message message-type}
                     64 {:type :asf-pong :message message-type})]
      (log/debug "State-Selector:" selector)
      selector)
    (let [selector (condp = (-> (get-in m [:rmcp-class :ipmi-session-payload]) keys first)
                     :ipmi-1-5-payload  (let [response? (contains? (get-in m [:rmcp-class
                                                                              :ipmi-session-payload
                                                                              :ipmi-1-5-payload
                                                                              :ipmb-payload])
                                                                   :command-completion-code)
                                              message-type (get-in m [:rmcp-class
                                                                      :ipmi-session-payload
                                                                      :ipmi-1-5-payload
                                                                      :ipmb-payload
                                                                      :command])]
                                          (if response?
                                            (condp = message-type
                                              0x38 {:type :get-channel-auth-cap-rsp :message 56})
                                            (condp = message-type
                                              0x38 {:type :get-channel-auth-cap-req :message 56})))
                     :ipmi-2-0-payload (let [function (get-in m [:rmcp-class
                                                                 :ipmi-session-payload
                                                                 :ipmi-2-0-payload
                                                                 :network-function
                                                                 :function] nil)
                                             payload-type (get-in m [:rmcp-class
                                                                     :ipmi-session-payload
                                                                     :ipmi-2-0-payload
                                                                     :payload-type
                                                                     :type])
                                             command (get-in m [:rmcp-class
                                                                :ipmi-session-payload
                                                                :ipmi-2-0-payload
                                                                :command] nil)]
                                         (condp = payload-type
                                           16 {:type :open-session-request :payload-type 16}
                                           18 {:type :rmcp-rakp-1 :payload-type 18}
                                           19 {:type :rmcp-rakp-2 :payload-type 19}
                                           20 {:type :rmcp-rakp-3 :payload-type 20}
                                           21 {:type :rmcp-rakp-4 :payload-type 21}
                                           0 (condp = function
                                               0 (condp = command
                                                   1 {:type :chassis-status-req :command 1}
                                                   2 {:type :chassis-reset-req :command 2})
                                               1 (condp = command
                                                   1 {:type :chassis-status-rsp :command 1})
                                               6 (condp = command
                                                   1 {:type :device-id-req :command 1}
                                                   59 {:type :set-session-prv-level-req :command 59}
                                                   60 {:type :rmcp-close-session-req :command 60})
                                               7 (condp = command
                                                   1 {:type :device-id-rsp :command 1}
                                                   59 {:type :set-session-prv-level-rsp :command 59}
                                                   60 {:type :rmcp-close-session :command 60})))))]
      selector)))



(def authentication-codec
  {0x00 {:name :RAKP-none
         :auth nil
         :size 0
         :optional false}
   0x01 {:name :RAKP-HMAC-SHA1
         :auth :hmac-sha1
         :size 20
         :optional false}
   0x02 {:name :RAKP-HMAC-MD5
         :auth :hmac-md5
         :size 16
         :optional true}
   0x03 {:name :RAKP-HMAC-SHA256
         :auth :hmac-sha256
         :size 64
         :optional true}})

(defcodec channel-auth-cap-req
  (ordered-map
   :version-compatibility
   (bit-map :version-compatibility 1
            :reserved              3
            :channel               4)
   :privilege-level
   (bit-map :reserved        4
            :privilege-level 4)
   :checksum :ubyte))

(defcodec chassis-status-req
  {:checksum :ubyte})

(defcodec device-id-req
  {:checksum :ubyte})

(defcodec chassis-status-rsp
  (ordered-map
   :completion-code :ubyte
   :power-state (bit-map
                 :reserved 1
                 :power-restore-policy 2
                 :power-control-fault 1
                 :power-fault 1
                 :interlock 1
                 :overload 1
                 :power-on? 1)
   :last-power-event (bit-map
                      :reserved 3
                      :last-power-on-state-via-ipmi 1
                      :last-power-down-state-power-fault 1
                      :last-power-down-state-interlock-activated 1
                      :last-power-down-state-overloaded 1
                      :last-power-down-ac-failed 1)
   :misc-chassis-state (bit-map
                        :reserved 1
                        :chassis-identify-command-state-info-supported 1
                        :chassis-identify-state-supported 2
                        :cooling-fan-fault-detect 1
                        :drive-fault 1
                        :front-panel-lockout 1
                        :chassis-intrusion-active 1)
   :checksum :ubyte))


(defcodec chassis-control-req
  (ordered-map
   :control (bit-map :reserved 4
                     :chassis-control 4)
   :checksum :ubyte))

(defcodec device-id-rsp
  (ordered-map
   :command-completion-code :ubyte
   :device-id :ubyte
   :device-revision (bit-map :provides-sdr 1
                             :reserved 3
                             :device-revision 4)
   :device-availability (bit-map :operation 1
                                 :major-firmware-revision 7)
   :major-firmware-revision :ubyte
   :ipmi-version :ubyte
   :additional-device-support (bit-map :chassis 1
                                       :bridge 1
                                       :event-generator 1
                                       :event-receiver 1
                                       :fru-invetory 1
                                       :sel 1
                                       :sdr-repository 1
                                       :sensor 1)
   :manufacturer-id (repeat 3 :ubyte)
   :product-id :uint16-le
   :auxiliary-firmware :uint32-le
   :checksum :ubyte))

(defcodec channel-auth-cap-rsp
  (ordered-map
   :command-completion-code :ubyte
   :channel (bit-map :reserved 4
                     :channel-num 4)
   :version-compatibility (bit-map :version-compatibility 1
                                   :reserved              1
                                   :oem-proprietary-auth  1
                                   :password-key          1
                                   :reserved              1
                                   :md5-support           1
                                   :md2-support           1
                                   :no-auth-support       1)
   :auth-compatibility (bit-map    :reserved              2
                                   :key-generation        1
                                   :per-message-auth      1
                                   :user-level-auth       1
                                   :non-null-user-names   1
                                   :null-user-names       1
                                   :anonymous-login-enabled 1)
   :supported-connections (bit-map :reserved                6
                                   :ipmi-2-0                1
                                   :ipmi-1-5                1)
   :oem-id (repeat 3 :ubyte)
   :oem-aux-data :ubyte
   :checksum     :ubyte))

(defcodec open-session-request
  (ordered-map   :type :ubyte
                 :reserved (repeat 2 :ubyte)
                 :length :ubyte
                 :algo (bit-map :reserved 2
                                :algorithm 6)
                 :reserved (repeat 3 :ubyte)))

;; Should be 32 bytes
(defcodec rmcp-open-session-request
  (ordered-map
   :message-tag :ubyte
   :privilege-level (bit-map :reserved 4
                             :max-priv-level 4)
   :reserved :uint16
   :remote-session-id :uint32-le
   :authentication-payload open-session-request
   :integrity-payload open-session-request
   :confidentiality-payload open-session-request))

(defcodec rmcp-open-session-response
  (ordered-map
   :message-tag :ubyte
   :status-code :ubyte
   :privilege-level (bit-map :reserved 4
                             :max-priv-level 4)
   :reserved :ubyte
   :remote-session-id :uint32-le
   :managed-system-session-id :int32-le

   :authentication-payload open-session-request
   :integrity-payload open-session-request
   :confidentiality-payload open-session-request))

(defcodec ipmb-header
  (ordered-map
   :target-address :ubyte
   :network-function (bit-map :function 6
                              :target-lun 2)
   :header-checksum :ubyte
   :source-address :ubyte
   :source-lun :ubyte))

(defcodec ipmb-body
  (ordered-map
   :command :ubyte))

(defcodec set-session-priv-level-req
  (ordered-map
   :requested-priv-level (bit-map :reserved 4
                                  :requested-priv-level 4)
   :checksum :ubyte))

(defcodec set-session-priv-level-rsp
  (ordered-map
   :completion-code :ubyte
   :privilege-level  (bit-map :reserved 4
                              :priv-level 4)
   :checksum :ubyte))

(defcodec rmcp-close-session-req
  (ordered-map
   :session-id :uint32-le
   :checksum :ubyte))

(defcodec rmcp-close-session-rsp
  (ordered-map
   :completion-code :ubyte
   :checksum :ubyte))

(defn get-application-command-request-codec [h]
  (condp = (:command h)
    0x01 device-id-req
    0x38 channel-auth-cap-req
    0x3c rmcp-close-session-req
    0x3b set-session-priv-level-req))

(defn get-application-command-response-codec [h]
  (condp = (:command h)
    0x01 device-id-rsp
    0x38 channel-auth-cap-rsp
    0x3c rmcp-close-session-rsp
    0x3b set-session-priv-level-rsp))

;TODO FIX
(defn get-chassis-command-request-codec [h]
  (condp = (:command h)
    0x01 chassis-status-req
    0x02 chassis-control-req))

(defn get-chassis-command-response-codec [h]
  (condp = (:command h)
    0x01 chassis-status-rsp))

(defcodec ipmb-application-request-message
  (header ipmb-body
          (build-merge-header-with-data
           #(get-application-command-request-codec %))
          (fn [b]
            b)))

(defcodec ipmb-application-response-message
  (header ipmb-body
          (build-merge-header-with-data
           #(get-application-command-response-codec %))
          (fn [b]
            b)))

(defcodec ipmb-chassis-request-message
  (header ipmb-body
          (build-merge-header-with-data
           #(get-chassis-command-request-codec %))
          (fn [b]
            b)))

(defcodec ipmb-chassis-response-message
  (header ipmb-body
          (build-merge-header-with-data
           #(get-chassis-command-response-codec %))
          (fn [b]
            b)))

(defn get-network-function-codec
  " Provides the codec determined by the NetFN attribute"
  [h]
  (comment "Page 41")
  (condp = (get-in h [:network-function :function])
    0 ipmb-chassis-request-message
    1 ipmb-chassis-response-message
    6 ipmb-application-request-message
    7 ipmb-application-response-message))

(defcodec ipmb-message
  (header ipmb-header
          (build-merge-header-with-data
           #(get-network-function-codec %))
          (fn [b]
            b)))

(comment "Page 123")
(defcodec ipmi-1-5-session
  {:type :ipmi-1-5-session
   :ipmi-1-5-payload (compile-frame
                      (ordered-map
                       :session-seq :int32-le
                       :session-id  :int32-le
                       :message-length :ubyte
                       :ipmb-payload ipmb-message))})


;(defcodec key-exchange
;  (ordered-map
;   :key-exchange-code )


(defcodec rmcp-plus-rakp-1
  (ordered-map
   :message-tag :ubyte
   :reserved1 (repeat 3 :ubyte)
   :managed-system-session-id :int32-le
   :remote-console-random-number (repeat 16 :ubyte)
   :requested-max-priv-level (bit-map :reserved 3
                                      :user-lookup 1
                                      :requested-max-priv-level 4)
   :reserved2 (repeat 2 :ubyte)
   :user-name (finite-frame :ubyte (string :ascii))))

(defcodec rmcp-plus-rakp-2
  (ordered-map
   :message-tag :ubyte
   :status-code :ubyte
   :reserved (repeat 2 :ubyte)
   :remote-session-console-id :uint32-le
   :managed-system-random-number (repeat 16 :ubyte)
   :managed-system-guid (repeat 16 :ubyte)))

(defcodec rmcp-plus-rakp-3
  (ordered-map
   :message-tag :ubyte
   :status-code :ubyte
   :reserved (repeat 2 :ubyte)
   :managed-system-session-id :uint32-le))

(defcodec rmcp-plus-rakp-4
  (ordered-map
   :message-tag :ubyte
   :status-code :ubyte
   :reserved (repeat 2 :ubyte)
   :managed-console-session-id :uint32-le))

(defn get-rmcp-payload-type [h]
  (comment "Page 157")
  (condp = (get-in h [:payload-type :type])
    0x00 ipmb-message
    0x10 rmcp-open-session-request
    0x11 rmcp-open-session-response
    0x12 rmcp-plus-rakp-1
    0x13 rmcp-plus-rakp-2
    0x14 rmcp-plus-rakp-3
    0x15 rmcp-plus-rakp-4))

(defcodec rmcp-message-type
  (bit-map :encrypted? 1
           :authenticated? 1
           :type 6))

(defcodec rmcp-plus-header
  (ordered-map
   :payload-type rmcp-message-type
   :session-id :uint32-le
   :session-seq :uint32-le
   :message-length :uint16-le))

(defcodec ipmi-2-0-session
  {:type :ipmi-2-0-session
   :ipmi-2-0-payload (compile-frame (header rmcp-plus-header
                                            (build-merge-header-with-data
                                             #(get-rmcp-payload-type %))
                                            (fn [b]
                                              b)))})
(defcodec authentication-type
  (enum :ubyte {:ipmi-1-5-session 0x00
                :ipmi-2-0-session 0x06}))

(defcodec asf-presence-ping
  (ordered-map :message-tag :ubyte
               :reserved :ubyte
               :data-length :ubyte))

(defcodec asf-presence-pong
  (ordered-map
   :message-tag :ubyte
   :reserved1 :ubyte
   :data-length :ubyte
   :oem-iana-number :uint32
   :oem-defined :uint32
   :supported-entities :ubyte
   :supported-interactions :ubyte
   :reserved2 (repeat 6 :ubyte)))

(defn get-asf-message-type [h]
  (condp = (:asf-message-type h)
    0x40 asf-presence-pong
    0x80 asf-presence-ping))

(defcodec asf-message-type
  {:asf-message-type :ubyte})

(defcodec asf-message-header
  (header asf-message-type
          (build-merge-header-with-data
           #(get-asf-message-type %))
          (fn [b]
            b)))

(defcodec asf-session
  {:type :asf-session
   :asf-payload (compile-frame (ordered-map
                                :iana-enterprise-number :uint32
                                :asf-message-header asf-message-header))})
(defcodec rmcp-ack
  {:type :rmcp-ack})

(defcodec ipmi-session
  {:type                 :ipmi-session
   :ipmi-session-payload (compile-frame
                          (header
                           authentication-type
                           {:ipmi-1-5-session ipmi-1-5-session
                            :ipmi-2-0-session ipmi-2-0-session}
                           :type))})

(defcodec class-of-message
  (enum :ubyte {:asf-session  0x06
                :ipmi-session 0x07
                :rmcp-ack     0x86}))

(defcodec rmcp-class-header
  (header
   class-of-message
   {:asf-session  asf-session
    :ipmi-session ipmi-session
    :rmcp-ack     rmcp-ack}
   :type))

(defcodec rmcp-header
  (ordered-map :version :ubyte ; 0x06
               :reserved :ubyte ; 0x00
               :sequence :ubyte
               :rmcp-class rmcp-class-header))

(def rmcp-decode (partial decode rmcp-header))
