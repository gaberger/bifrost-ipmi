(ns bifrost.ipmi.codec
  (:require [bifrost.ipmi.utils :refer [transform-padding]]
            [bifrost.ipmi.application-state :refer :all]
            [gloss.core :refer [defcodec compile-frame bit-map
                                ordered-map header finite-frame
                                string enum repeated]]
            [gloss.io :refer [decode to-buf-seq]]
            [byte-streams :as bs]
            [bifrost.ipmi.crypto :refer [decrypt encrypt  calc-integrity-96]]
            [gloss.core.structure :refer [convert-map convert-sequence]]
            [gloss.core.protocols :refer [reader? compose-callback Reader Writer read-bytes write-bytes sizeof]]
            [gloss.data.primitives :refer [primitive-codecs]]
            [clojure.walk :refer [postwalk-replace]]
            [clojure.string :as str]
            [taoensso.timbre :as log]
            [buddy.core.nonce :as nonce]
            [gloss.io :as i]
            [buddy.core.codecs :as codecs]))

(defn get-sik [h]
  (get-in @app-state [:chan-map h :sik]))

(defn get-login-state [h]
  (get-in @app-state [:chan-map h :login-state] {}))

(defn get-fsm [h]
  (get-in @app-state [:chan-map h :fsm] {}))


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

(defn- compile-frame-enc- [f]
  (cond
    (map? f) (convert-map (zipmap (keys f) (map compile-frame-enc- (vals f))))
    (sequential? f) (convert-sequence (map compile-frame-enc- f))
    :else f))

(defn compile-frame-enc
  ([frame]
   (if (reader? frame)
     frame
     (->> frame
          (postwalk-replace primitive-codecs)
          compile-frame-enc-)))
  ([frame pre-encoder pre-decoder post-decoder]
   (let [codec (compile-frame-enc frame)
         read-codec (compose-callback
                     codec
                     (fn [x b]
                       [true (post-decoder x) b]))]
     (reify
       Reader
       (read-bytes [_ b]
         (read-bytes read-codec (pre-decoder b)))
       Writer
       (sizeof [_]
         (sizeof codec))
       (write-bytes [_ buf v]
          (write-bytes codec buf (pre-encoder v)))))))


;TODO


(def command-completion-codes
  (comment "Page 44"))

(def authentication-codec
  {0 {:name :RAKP-none
      :size 0
      :optional false
      :codec :rmcp-rakp}
   1 {:name :RAKP-HMAC-SHA1
      :size 20
      :optional false
      :codec :rmcp-rakp-hmac-sha1}
   2 {:name :RAKP-HMAC-MD5
      :size 16
      :optional true
      :codec :rmcp-rakp-hmac-md5}
   3 {:name :RAKP-HMAC-SHA256
      :size 64
      :optional true
      :codec :rmcp-rakp-hmac-sha256}})

(def integrity-codec
  {0 {:name :RAKP-none
      :size 0
      :optional false
      :codec :rmcp-rakp-1-none-integrity}
   1 {:name :RAKP-HMAC-SHA1-96
      :size 0
      :optional false
      :codec :rmcp-rakp-1-hmac-sha1-96-integrity}
   2 {:name :RAKP-HMAC-MD5-128
      :size 0
      :optional true
      :codec :rmcp-rakp-1-hmac-md5-128-integrity}
   3 {:name :RAKP-MD5-128
      :size 0
      :optional true
      :codec :rmcp-rakp-1-md5-128-integrity}})

(def confidentiality-codec
  {0 {:name :RAKP-none
      :size 0
      :pad 0
      :optional false
      :codec :rmcp-rakp-1-none-confidentiality}
   1 {:name :RAKP-AES-CBC-128
      :size 0
      :pad 0
      :optional false
      :codec :rmcp-rakp-1-aes-cbc-128-confidentiality}
   2 {:name :XRC4-128
      :size 0
      :pad 0
      :optional true
      :codec :rmcp-rakp-1-xrc4-128-confidentiality}
   3 {:name :RAKP-XRC4-40
      :size 0
      :pad 0
      :optional true
      :codec :rmcp-rakp-1-xrc4-40-confidentiality}})

(defn get-confidentiality-codec [h]
  (let [conf (get confidentiality-codec
                  (-> (get-login-state h) :conf)
                  {:codec :rmcp-rakp-1-none-confidentiality})]
    (:codec conf)))

(defn get-authentication-codec [h]
  (let [auth (get authentication-codec
                  (-> (get-login-state h) :auth) {:codec :rmcp-rakp})]
    (:codec auth)))

(defn get-message-type [m]
  (let [type
        (if (= (:rmcp-payload m) :error)
          {:type :error}
          (if (-> (:rmcp-class m) (contains? :asf-payload))
            (let [message-type (get-in m [:rmcp-class :asf-payload :asf-message-header :asf-message-type])
                  selector     (condp = message-type
                                 128 {:type :asf-ping :message message-type}
                                 64  {:type :asf-pong :message message-type}
                                 {:type :error :message message-type})]
              selector)
            (let [key      (-> (get-in m [:rmcp-class :ipmi-session-payload]) keys first)
                  selector (condp = key
                             :ipmi-1-5-payload (let [function (get-in m [:rmcp-class
                                                                         :ipmi-session-payload
                                                                         :ipmi-1-5-payload
                                                                         :ipmb-payload
                                                                         :network-function
                                                                         :function])
                                                     command  (get-in m [:rmcp-class
                                                                         :ipmi-session-payload
                                                                         :ipmi-1-5-payload
                                                                         :ipmb-payload
                                                                         :command])]
                                                 (condp = command
                                                   0x38 (condp = function
                                                          6 {:type :get-channel-auth-cap-req :command 56 :function 6}
                                                          7 {:type :get-channel-auth-cap-req :command 56 :function 7}
                                                          {:type :error :command command :function function})))
                             :ipmi-2-0-payload (let [session        (get-in m [:rmcp-class :ipmi-session-payload :ipmi-2-0-payload])
                                                     function       (get-in session [:network-function
                                                                                     :function] nil)
                                                     payload-type   (get-in session [:payload-type :type] nil)
                                                     command        (get-in session [:command] nil)
                                                     signature      (get-in session [:signature] nil)
                                                     authenticated? (get-in session [:payload-type :authenticated?] false)
                                                     encrypted?     (get-in session [:payload-type :encrypted?] false)]

                                                 (condp = payload-type
                                                   16 {:type         :open-session-request
                                                       :payload-type 16
                                                       :a?           authenticated?
                                                       :e?           encrypted?}
                                                   17 {:type         :open-session-response
                                                       :payload-type 17
                                                       :a?           authenticated?
                                                       :e?           encrypted?}
                                                   18 {:type :rmcp-rakp-1 :payload-type 18
                                                       :a?   authenticated?
                                                       :e?   encrypted?}
                                                   19 {:type :rmcp-rakp-2 :payload-type 19
                                                       :a?   authenticated?
                                                       :e?   encrypted?}
                                                   20 {:type :rmcp-rakp-3 :payload-type 20
                                                       :a?   authenticated?
                                                       :e?   encrypted?}
                                                   21 {:type :rmcp-rakp-4 :payload-type 21
                                                       :a?   authenticated?
                                                       :e?   encrypted?}
                                                   0  (condp = function
                                                        0  (condp = command
                                                             1 {:type     :chassis-status-req
                                                                :command  1
                                                                :function 0
                                                                :a?       authenticated?
                                                                :e?       encrypted?}
                                                             2 {:type     :chassis-reset-req
                                                                :command  2
                                                                :function 0
                                                                :a?       authenticated?
                                                                :e?       encrypted?})
                                                        1  (condp = command
                                                             1 {:type     :chassis-status-rsp
                                                                :command  1
                                                                :function 1
                                                                :a?       authenticated?
                                                                :e?       encrypted?}
                                                             2 {:type     :chassis-reset-rsp
                                                                :command  2
                                                                :function 2
                                                                :a?       authenticated?
                                                                :e?       encrypted?})
                                                        6  (condp = command
                                                             1  {:type     :device-id-req
                                                                 :command  1
                                                                 :function 6
                                                                 :a?       authenticated?
                                                                 :e?       encrypted?}
                                                             59 {:type     :set-session-prv-level-req
                                                                 :command  59
                                                                 :function 6
                                                                 :a?       authenticated?
                                                                 :e?       encrypted?}
                                                             60 {:type     :rmcp-close-session-req
                                                                 :command  60
                                                                 :function 6
                                                                 :a?       authenticated?
                                                                 :e?       encrypted?})
                                                        7  (condp = command
                                                             1  {:type     :device-id-rsp
                                                                 :command  1
                                                                 :function 7
                                                                 :a?       authenticated?
                                                                 :e?       encrypted?}
                                                             59 {:type     :set-session-prv-level-rsp
                                                                 :command  59
                                                                 :function 7
                                                                 :a?       authenticated?
                                                                 :e?       encrypted?}
                                                             60 {:type     :rmcp-close-session
                                                                 :command  60
                                                                 :function 7
                                                                 :a?       authenticated?
                                                                 :e?       encrypted?})
                                                        44 (condp = command
                                                             0  (condp = signature
                                                                  0 {:type      :picmg-properties-req
                                                                     :command   0
                                                                     :function  44
                                                                     :response  45
                                                                     :signature 0
                                                                     :a?        authenticated?
                                                                     :e?        encrypted?}
                                                                  3 {:type      :vso-capabilities-req
                                                                     :command   0
                                                                     :function  44
                                                                     :response  45
                                                                     :signature 3
                                                                     :a?        authenticated?
                                                                     :e?        encrypted?})
                                                             62 {:type     :hpm-capabilities-req
                                                                 :command  62
                                                                 :function 44
                                                                 :response 45
                                                                 :a?       authenticated?
                                                                 :e?       encrypted?})
                                                        45 (condp = command
                                                             0  (condp = signature
                                                                  0 {:type      :picmg-properties-rsp
                                                                     :command   0
                                                                     :function  45
                                                                     :signature 0
                                                                     :a?        authenticated?
                                                                     :e?        encrypted?}
                                                                  3 {:type      :vso-capabilities-rsp
                                                                     :command   0
                                                                     :function  45
                                                                     :signature 3
                                                                     :a?        authenticated?
                                                                     :e?        encrypted?})
                                                             62 {:type     :hpm-capabilities-req
                                                                 :command  62
                                                                 :function 45
                                                                 :a?       authenticated?
                                                                 :e?       encrypted?}))
                                                   {:type     :error :payload payload-type
                                                    :command  command
                                                    :function function}))
                             {:type     :error
                              :selector key})]

              selector)))]
    (log/debug "Get Message Type: " type)
    type))

(def padding-codec
  (compile-frame-enc :ubyte
                     identity
                     transform-padding
                     identity))

(defn decode-aes-payload [b]
  (let [codec (compile-frame (ordered-map
                              :iv (repeat 16 :ubyte)
                              :data (repeat 16 :ubyte)))
        decoded (decode codec (byte-array b))]
    decoded))

(declare router-key)

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
   :message-length :uint16-le
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
   :message-length :uint16-le
   :message-tag :ubyte
   :status-code :ubyte
   :privilege-level (bit-map :reserved 4
                             :max-priv-level 4)
   :reserved :ubyte
   :remote-session-id :uint32-le
   :managed-system-session-id :uint32-le

   :authentication-payload open-session-request
   :integrity-payload open-session-request
   :confidentiality-payload open-session-request))

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

(defcodec default-rsp-codec
  (ordered-map
   :command-completion-code :ubyte
   :checksum :ubyte))

(defcodec chassis-control-rsp
  (ordered-map
   :command-completion-code :ubyte
   :checksum :ubyte))

(defcodec picmg-properties-req
  (ordered-map
   :checksum :ubyte))

(defcodec picmg-properties-rsp
  (ordered-map
   :command-completion-code :ubyte
   :checksum :ubyte))

(defcodec hpm-capabilities-req
  (ordered-map
   :signature :ubyte
   :data :ubyte
   :checksum :ubyte))

(defcodec hpm-capabilities-rsp
  (ordered-map
   :command-completion-code :ubyte
   :checksum :ubyte))

(defcodec vso-capabilities-req
  (ordered-map
   :checksum :ubyte))

(defcodec vso-capabilities-rsp
  (ordered-map
   :command-completion-code :ubyte
   :checksum :ubyte))

(defn get-picmg-signature-request-codec [h]
  (condp = (:signature h)
    0x0 picmg-properties-req
    0x3 vso-capabilities-req))

#_(defn get-picmg-signature-response-codec [h]
    (condp = (:signature h)
      0x0 picmg-properties-rsp
      0x3 vso-capabilities-rsp))

(defn get-picmg-signature-response-codec [h]
  picmg-properties-rsp)

(defcodec picmg-header
  {:signature :ubyte})

(defcodec ipmb-picmg-message-req
  (header picmg-header
          (build-merge-header-with-data
           #(get-picmg-signature-request-codec %))
          (fn [b]
            b)))

(defcodec ipmb-picmg-message-rsp
  default-rsp-codec)

#_(header picmg-header
          (build-merge-header-with-data
           #(get-picmg-signature-response-codec %))
          (fn [b]
            b))

(defcodec ipmb-header
  (ordered-map
   :target-address :ubyte
   :network-function (bit-map :function 6
                              :target-lun 2)
   :header-checksum :ubyte
   :source-address :ubyte
   :source-lun (bit-map
                :seq-no 6
                :source-lun 2)))

(defcodec ipmb-header-1
  (ordered-map
   :message-length :uint16-le
   :target-address :ubyte
   :network-function (bit-map :function 6
                              :target-lun 2)
   :header-checksum :ubyte
   :source-address :ubyte
   :source-lun (bit-map
                :seq-no 6
                :source-lun 2)))

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
    0x01 chassis-status-rsp
    0x02 chassis-control-rsp))

(defn get-group-extensions-command-request-codec [h]
  (condp = (:command h)
    0x00 ipmb-picmg-message-req
    0x3e hpm-capabilities-req))

(defn get-group-extensions-command-response-codec [h]
  (condp = (:command h)
    0x00 default-rsp-codec
    0x3e default-rsp-codec))

;; (defn get-oem-extensions-command-request-codec [h]
;;   (condp = (:command h)
;;     0x0 picmg-properties-req
;;     0x3 vso-capabilities-req))

;; (defn get-oem-extensions-command-response-codec [h]
;;   (condp = (:command h)
;;     0x0 picmg-properties-rsp
;;     0x3 vso-capabilities-rsp))

(defcodec ipmb-body
  (ordered-map
   :command :ubyte))

(defcodec ipmb-group-extension-body
  (ordered-map
   :command :ubyte))
                                        ;  :signature :ubyte))

(defcodec ipmb-group-extensions-request-message
  (header ipmb-group-extension-body
          (build-merge-header-with-data
           #(get-group-extensions-command-request-codec %))
          (fn [b]
            b)))

(defcodec ipmb-group-extensions-response-message
  (header ipmb-group-extension-body
          (build-merge-header-with-data
           #(get-group-extensions-command-response-codec %))
          (fn [b]
            b)))
;; (defcodec ipmb-oem-extensions-request-message
;;   (header ipmb-body
;;           (build-merge-header-with-data
;;            #(get-oem-extensions-command-request-codec %))
;;           (fn [b]
;;             b)))

;; (defcodec ipmb-oem-extensions-response-message
;;   (header ipmb-body
;;           (build-merge-header-with-data
;;            #(get-oem-extensions-command-response-codec %))
;;           (fn [b]
;;             b)))

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

(defn get-network-function-codec
  " Provides the codec determined by the NetFN attribute"
  [h]
  (comment "Page 41")
  (condp = (get-in h [:network-function :function])
    0 ipmb-chassis-request-message
    1 ipmb-chassis-response-message
    6 ipmb-application-request-message
    7 ipmb-application-response-message
    44 ipmb-group-extensions-request-message
    45 ipmb-group-extensions-response-message))



;; RAKP Encodings


(defcodec rmcp-plus-rakp-1
  (ordered-map
   :message-length :uint16-le
   :message-tag :ubyte
   :reserved1 (repeat 3 :ubyte)
   :managed-system-session-id :uint32-le
   :remote-console-random-number (repeat 16 :ubyte)
   :requested-max-priv-level (bit-map :reserved 3
                                      :user-lookup 1
                                      :requested-max-priv-level 4)
   :reserved2 (repeat 2 :ubyte)
   :user-name (finite-frame :ubyte (string :ascii))))

(defcodec rmcp-plus-rakp-2
  (ordered-map
   :message-length :uint16-le
   :message-tag :ubyte
   :status-code :ubyte
   :reserved (repeat 2 :ubyte)
   :remote-session-console-id :uint32-le
   :managed-system-random-number (repeat 16 :ubyte)
   :managed-system-guid (repeat 16 :ubyte)))

(defcodec rmcp-plus-rakp-3
  (ordered-map
   :message-length :uint16-le
   :message-tag :ubyte
   :status-code :ubyte
   :reserved (repeat 2 :ubyte)
   :managed-system-session-id :uint32-be))

(defcodec rmcp-plus-rakp-4
  (ordered-map
   :message-length :uint16-le
   :message-tag :ubyte
   :status-code :ubyte
   :reserved (repeat 2 :ubyte)
   :managed-console-session-id :uint32-le))

;; Cipher 1

(defcodec rmcp-plus-rakp-2-hmac-sha1
  (ordered-map
   :message-length :uint16-le
   :message-tag :ubyte
   :status-code :ubyte
   :reserved (repeat 2 :ubyte)
   :remote-session-console-id :uint32-le
   :managed-system-random-number (repeat 16 :ubyte)
   :managed-system-guid (repeat 16 :ubyte)
   :key-exchange-code (repeat 20 :ubyte)))

(defcodec rmcp-plus-rakp-3-hmac-sha1
  (ordered-map
   :message-length :uint16-le
   :message-tag :ubyte
   :status-code :ubyte
   :reserved (repeat 2 :ubyte)
   :managed-system-session-id :uint32-le
   :key-exchange-code (repeat 20 :ubyte)))

(defcodec rmcp-plus-rakp-4-hmac-sha1
  (ordered-map
   :message-length :uint16-le
   :message-tag :ubyte
   :status-code :ubyte
   :reserved (repeat 2 :ubyte)
   :managed-console-session-id :uint32-le
   :integrity-check (repeat 12 :ubyte)))

(defcodec rmcp-message-type
  (bit-map :encrypted? 1
           :authenticated? 1
           :type 6))

(comment "Changing to support encryption")
(defcodec rmcp-plus-header
  (ordered-map
   :payload-type rmcp-message-type
   :session-id :uint32-le
   :session-seq :uint32-le))
   ;:message-length :uint16-le

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
   :asf-payload (compile-frame-enc (ordered-map
                                    :iana-enterprise-number :uint32
                                    :asf-message-header asf-message-header))})
(defcodec rmcp-ack
  {:type :rmcp-ack})

(defn compile-codec
  [router-key]
  (log/debug "Compile with key" router-key)
  (let [ipmb-message (compile-frame-enc
                      (header ipmb-header-1
                              (build-merge-header-with-data
                               #(get-network-function-codec  %))
                              (fn [b]
                                b))
                      identity
                      identity
                      identity)
        aes-payload  (compile-frame-enc
                      (repeated :ubyte
                                :prefix :uint16-le)
                      identity
                      (fn [b]
                        b)
                      decode-aes-payload)

        aes-post-decoder (fn [a]
                           (let [iv         (get-in a [:payload :iv])
                                 data       (get-in a [:payload :data])
                                 sik        (get-sik router-key)
                                 decrypted  (decrypt sik iv data)
                                 decrypted' (-> decrypted bs/to-byte-array to-buf-seq)
                                 decoded    (i/decode (compile-frame-enc
                                                       (header ipmb-header
                                                               (build-merge-header-with-data
                                                                #(get-network-function-codec %))
                                                               (fn [b]
                                                                 b))
                                                       identity
                                                       identity
                                                       identity) decrypted' false)]
                             (assoc-in a [:aes-decoded-payload] decoded)))
        aes-pre-encoder  (fn [b]
                           (let [session-id     (get b :session-id)
                                 session-seq    (get b :session-seq)
                                 auth-type      0x06
                                 payload        (apply dissoc b [:session-id :session-seq :payload-type])
                                 payload-buffer (-> (i/contiguous (i/encode ipmb-message payload)) bs/to-byte-array)
                                ; _              (log/debug "pre-encode payload" (-> payload-buffer codecs/bytes->hex))
                                 payload'       (nnext payload-buffer)
                                 iv             (-> (nonce/random-nonce 16) vec)
                                 sik            (get-sik router-key)
                                 encrypted      (-> (encrypt sik iv payload') vec)
                                 iv+data        (-> (conj iv encrypted) flatten vec)
                                 _              (log/debug "iv+data"
                                                           (-> iv+data byte-array codecs/bytes->hex)
                                                           "count" (count iv+data))
                                 message-length (-> (i/encode (compile-frame :uint16) (count iv+data)) bs/to-byte-array vec)
                                 ipmi-session      (ordered-map
                                                    :rmcp :ubyte
                                                    :message-type :ubyte
                                                    :session-id :uint32-le
                                                    :session-seq :uint32-le)
                                 aes-session-codec (ordered-map
                                                    :ipmi-session ipmi-session
                                                    :iv+data  (repeated :ubyte
                                                                          :prefix :uint16-le)
                                                    :padding (repeat 2 :ubyte)
                                                    :padding-length :ubyte
                                                    :rmcp :ubyte)
                                 auth-code         {:ipmi-session   {:rmcp        06
                                                                     :message-type 0xC0
                                                                     :session-id  session-id
                                                                     :session-seq session-seq}
                                                    :iv+data         iv+data
                                                    :padding        [0xff 0xff]
                                                    :padding-length 2
                                                    :rmcp           7}
                                 auth-code-data    (-> (i/encode (compile-frame aes-session-codec) auth-code) bs/to-byte-array)
                                 integrity         (calc-integrity-96 sik auth-code-data)
                                 _                 (log/debug "iv+data?" (-> iv+data byte-array codecs/bytes->hex))
                                 aes-payload       {:iv+data        iv+data
                                                    :padding        [0xff 0xff]
                                                    :padding-length 2
                                                    :rmcp           7
                                                    :auth-code      integrity}]
                             aes-payload))
        aes-encode-codec (compile-frame-enc
                          (ordered-map
                           :iv+data  (repeated :ubyte
                                               :prefix :uint16-le)
                           :padding (repeat 2 :ubyte)
                           :padding-length :ubyte
                           :rmcp :ubyte
                           :auth-code (repeat 12 :ubyte))
                          aes-pre-encoder
                          identity
                          identity)
        aes-decode-codec (compile-frame-enc
                          (ordered-map
                           :payload aes-payload
                           :pad padding-codec
                           :rcmp :ubyte
                           :auth-code (repeat 12 :ubyte))
                          identity
                          identity
                          aes-post-decoder)
        grpl             (fn [{:keys [payload-type auth conf] :as b}]
                           (let [t              (get-in payload-type [:payload-type :type])
                                 f              (get-in payload-type [:network-function :function])]
                             (condp = t
                               0x00 (condp = conf
                                      :rmcp-rakp-1-aes-cbc-128-confidentiality (if (nil? f)
                                                                                 aes-decode-codec
                                                                                 aes-encode-codec)
                                      ipmb-message)
                               0x10 rmcp-open-session-request
                               0x11 rmcp-open-session-response
                               0x12 rmcp-plus-rakp-1
                               0x13 (condp = auth
                                      :rmcp-rakp-hmac-sha1 rmcp-plus-rakp-2-hmac-sha1
                                      rmcp-plus-rakp-2)
                               0x14 (condp = auth
                                      :rmcp-rakp-hmac-sha1 rmcp-plus-rakp-3-hmac-sha1
                                      rmcp-plus-rakp-3)
                               0x15 (condp = auth
                                      :rmcp-rakp-hmac-sha1 rmcp-plus-rakp-4-hmac-sha1
                                      rmcp-plus-rakp-4))))

        authentication-type (compile-frame (enum :ubyte
                                                 {:ipmi-1-5-session 0x00
                                                  :ipmi-2-0-session 0x06}))

        ipmi-1-5-session (let [ipmb-message (compile-frame
                                             (header ipmb-header
                                                     (build-merge-header-with-data
                                                      #(get-network-function-codec %))
                                                     (fn [b]
                                                       b)))]
                           (compile-frame
                            {:type             :ipmi-1-5-session
                             :ipmi-1-5-payload (compile-frame
                                                (ordered-map
                                                 :session-seq :int32-le
                                                 :session-id  :int32-le
                                                 :message-length :ubyte
                                                 :ipmb-payload ipmb-message))}))
        ipmi-2-0-session (compile-frame-enc
                          {:type             :ipmi-2-0-session
                           :ipmi-2-0-payload (compile-frame-enc
                                              (header rmcp-plus-header
                                                      (build-merge-header-with-data
                                                       #(grpl {:payload-type %
                                                               :auth         (get-authentication-codec router-key)
                                                               :conf         (get-confidentiality-codec router-key)}))
                                                      (fn [b]
                                                        b)))})
        asf-session      (compile-frame
                          {:type        :asf-session
                           :asf-payload (ordered-map
                                         :iana-enterprise-number :uint32
                                         :asf-message-header asf-message-header)})

        ipmi-session      (compile-frame
                           {:type                 :ipmi-session
                            :ipmi-session-payload (compile-frame
                                                   (header
                                                    authentication-type
                                                    {:ipmi-1-5-session ipmi-1-5-session
                                                     :ipmi-2-0-session ipmi-2-0-session}
                                                    :type))})
        class-of-message  (enum :ubyte {:asf-session  0x06
                                        :ipmi-session 0x07
                                        :rmcp-ack     0x86})
        rmcp-class-header (header
                           class-of-message
                           {:asf-session  asf-session
                            :ipmi-session ipmi-session
                            :rmcp-ack     rmcp-ack}
                           :type)
        rmcp-header       (ordered-map :version :ubyte ; 0x06
                                       :reserved :ubyte ; 0x00
                                       :sequence :ubyte
                                       :rmcp-class rmcp-class-header)]
    (compile-frame-enc
     rmcp-header)))

(defn decode-message [codec message]
  (log/debug "Decode Message" (into [] message))
  (let [decoded (try
                  (i/decode codec (:message message) false)
                  (catch Exception e
                    (throw (ex-info "Decoder exception"
                                    {:error (.getMessage e)
                                     :message (:message message)}))
                    nil))
        _ (log/debug "Intermediate Decode Payload" decoded)
        aes-payload? (contains?
                      (get-in decoded [:rmcp-class :ipmi-session-payload :ipmi-2-0-payload])
                      :aes-decoded-payload)
        message (if aes-payload?
                  (let [aes-payload (get-in decoded [:rmcp-class
                                                     :ipmi-session-payload
                                                     :ipmi-2-0-payload
                                                     :aes-decoded-payload])]
                    (-> (update-in decoded [:rmcp-class :ipmi-session-payload :ipmi-2-0-payload] merge aes-payload)
                        (update-in  [:rmcp-class
                                     :ipmi-session-payload
                                     :ipmi-2-0-payload]
                                    dissoc :aes-decoded-payload)))
                  decoded)]
                   ;; TODO need to respond with an error message here
    (log/debug "Decoded Message " message)
    message))

(defn encode-message [encoder message]
  (log/debug "Encode Message " message)
  (let [encode-payload (try
                         (encoder message)
                         (catch Exception e
                           (log/error (ex-info "Encoder exception" {:error (.getMessage e)}))))]
        ;encoded (try
        ;           (encoder message)
        ;           (catch Exception e
        ;             (log/error (ex-info "Encoder exception"
        ;                                 {:error (.getMessage e)}))
        ;             false))]
        ;;aes-payload? (contains?
        ;;              (get-in encoded [:rmcp-class :ipmi-session-payload :ipmi-2-0-payload])
        ;;              :aes-decoded-payload)
        ;;message (if aes-payload?
    #_(let [aes-payload (get-in decoded [:rmcp-class
                                         :ipmi-session-payload
                                         :ipmi-2-0-payload
                                         :aes-decoded-payload])]
        (-> (update-in decoded [:rmcp-class :ipmi-session-payload :ipmi-2-0-payload] merge aes-payload)
            (update-in  [:rmcp-class
                         :ipmi-session-payload
                         :ipmi-2-0-payload]
                        dissoc :aes-decoded-payload)))

                   ;; TODO need to respond with an error message here
    (log/debug "Encoded Message " message)
    message))

