(ns bifrost.ipmi.codec-test
  (:require [clojure.test :refer :all]
            [mockery.core :refer [with-mocks]]
            [gloss.io :as i]
            [bifrost.ipmi.test-payloads :refer [rmcp-payloads rmcp-payloads-cipher-1 error-payloads]]
            [bifrost.ipmi.codec :refer [compile-codec get-message-type]]
            [byte-streams :as bs]))

;; (deftest test-rmcp-ack
;;   (testing "ack"
;;     (let [codec (compile-codec)
;;           decode (partial i/decode codec)]
;;       (is (=  {:version 6, :reserved 0, :sequence 255, :rmcp-class  {:type :rmcp-ack}}
;;               (decode (byte-array (:rmcp-ack rmcp-payloads))))))))


(deftest test-error-payloads
  (testing "RAKP-2"
    (let [codec (compile-codec :rmcp-rakp-hmac-sha1)
          decode (partial i/decode codec)
          encode (partial i/encode codec)
          payload (encode (decode (byte-array (:rmcp-rakp-2 error-payloads))))]
      (is (= {:version 6,
              :reserved 0,
              :sequence 255,
              :rmcp-class
              {:ipmi-session-payload
               {:ipmi-2-0-payload
                {:session-id 0,
                 :session-seq 0,
                 :payload-type
                 {:encrypted? false, :authenticated? false, :type 19},
                 :managed-system-random-number
                 [226 199 138 253 50 30 193 15 74 180 202 18 153 69 37 59],
                 :status-code 18,
                 :message-tag 0,
                 :key-exchange-code
                 [219
                  28
                  37
                  137
                  157
                  123
                  88
                  139
                  214
                  17
                  13
                  117
                  157
                  146
                  215
                  107
                  254
                  115
                  250
                  233],
                 :reserved [0 0],
                 :message-length 60,
                 :managed-system-guid
                 [161 35 69 103 137 171 205 239 161 35 69 103 137 171 205 239],
                 :remote-session-console-id 2695013284},
                :type :ipmi-2-0-session},
               :type :ipmi-session}}
             (decode payload))))))

(deftest  test-rmcp-presence
  (testing "Test PING"
    (let [codec (compile-codec)
          decode (partial i/decode codec)
          encode (partial i/encode codec)
          payload (encode  (decode (byte-array (:rmcp-ping rmcp-payloads))))]
      (is (= {:version 6,
              :reserved 0,
              :sequence 255,
              :rmcp-class
              {:asf-payload
               {:iana-enterprise-number 4542,
                :asf-message-header
                {:asf-message-type 128,
                 :message-tag 196,
                 :reserved 0,
                 :data-length 0}},
               :type :asf-session}}
             (decode payload)))))
  (testing "Test PONG"
    (let [codec (compile-codec)
          decode (partial i/decode codec)
          encode (partial i/encode codec)
          payload (encode (decode (byte-array (:rmcp-pong rmcp-payloads))))]
      (is (=   {:version 6,
                :reserved 0,
                :sequence 255,
                :rmcp-class
                {:asf-payload
                 {:iana-enterprise-number 4542,
                  :asf-message-header
                  {:asf-message-type 64,
                   :reserved2 [0 0 0 0 0 0],
                   :data-length 16,
                   :oem-defined 0,
                   :supported-interactions 0,
                   :message-tag 196,
                   :reserved1 0,
                   :oem-iana-number 4542,
                   :supported-entities 129}},
                 :type :asf-session}}
               (decode payload))))))

(deftest  test-rakp
  (testing "RAKP1 encoding"
    (let [codec  (compile-codec)
          decode (partial i/decode codec)
          encode (partial i/encode codec)
          rakp1  (encode  (decode (byte-array (rmcp-payloads :rmcp-rakp-1))))]
      (is (=  {:version  6,
               :reserved 0,
               :sequence 255,
               :rmcp-class
               {:ipmi-session-payload
                {:ipmi-2-0-payload
                 {:session-id                0
                  :session-seq               0
                  :reserved2                 [0 0],
                  :payload-type              {:encrypted? false, :authenticated? false, :type 18},
                  :remote-console-random-number
                  [207 101 36 153 230 186 137 68 79 143 233 101 74 214 188 76],
                  :user-name                 "admin",
                  :requested-max-priv-level
                  {:reserved 0, :user-lookup true, :requested-max-priv-level 4},
                  :message-tag               0,
                  :managed-system-session-id 0,
                  :reserved1                 [0 0 0],
                  :message-length            33},
                 :type :ipmi-2-0-session},
                :type :ipmi-session}}
              (decode rakp1)))))
  (testing "RAKP2 encoding"
    (let [codec  (compile-codec)
          decode (partial i/decode codec)
          encode (partial i/encode codec)
          rakp2  (encode (decode (byte-array (rmcp-payloads :rmcp-rakp-2))))]
      (is (= {:reserved   0
              :rmcp-class {:ipmi-session-payload
                           {:ipmi-2-0-payload
                            {:managed-system-guid          [161 35 69 103 137 171 205 239 161 35 69 103 137 171 205 239]
                             :managed-system-random-number [44 136 83 174 184 62 221 169 8 213 171 112 135 146 119 101]
                             :message-length               40
                             :message-tag                  0
                             :payload-type                 {:authenticated? false
                                                            :encrypted?     false
                                                            :type           19}
                             :remote-session-console-id    2695013284
                             :reserved                     [0
                                                            0]
                             :session-id                   0
                             :session-seq                  0
                             :status-code                  0}
                            :type :ipmi-2-0-session}
                           :type :ipmi-session}
              :sequence   255
              :version    6}
             (decode rakp2)))))
  (testing "RAKP3 encoding"
    (let [codec  (compile-codec)
          decode (partial i/decode codec)
          encode (partial i/encode codec)
          rakp3  (encode (decode (byte-array (rmcp-payloads :rmcp-rakp-3))))]
      (is (= {:version  6,
              :reserved 0,
              :sequence 255,
              :rmcp-class
              {:ipmi-session-payload
               {:ipmi-2-0-payload
                {:payload-type              {:encrypted? false, :authenticated? false, :type 20},
                 :session-seq               0,
                 :session-id                0,
                 :message-length            8,
                 :message-tag               0,
                 :status-code               0,
                 :reserved                  [0 0],
                 :managed-system-session-id 0},
                :type :ipmi-2-0-session},
               :type :ipmi-session}}
             (decode rakp3))))))

(deftest rakp-3-sha1-hmac
  (testing "RAKP3 encoding rakp sha1-hmac"
    (let [codec  (compile-codec :rmcp-rakp-hmac-sha1)
          decode (partial i/decode codec)
          encode (partial i/encode codec)
          rakp3  (encode (decode (byte-array (rmcp-payloads-cipher-1 :rmcp-rakp-3))))]
      (is (= {:version  6,
              :reserved 0,
              :sequence 255,
              :rmcp-class
              {:ipmi-session-payload
               {:ipmi-2-0-payload
                {:payload-type              {:encrypted? false, :authenticated? false, :type 20},
                 :session-seq               0,
                 :session-id                0,
                 :message-length            28,
                 :message-tag               0,
                 :status-code               0,
                 :reserved                  [0 0]
                 :key-exchange-code         [89 113 128 245 253 51 88 93 58 222 92 171 175 52 164 252 243 248 175 101],
                 :managed-system-session-id 16362},
                :type :ipmi-2-0-session},
               :type :ipmi-session}}
             (decode rakp3))))))

(deftest rakp-4
  (testing "RAKP4 Cipher 0"
    (let [codec  (compile-codec)
          decode (partial i/decode codec)
          encode (partial i/encode codec)
          rakp4  (encode (decode (byte-array (rmcp-payloads :rmcp-rakp-4))))]
      (is (= {:version 6,
              :reserved 0,
              :sequence 255,
              :rmcp-class
              {:ipmi-session-payload
               {:ipmi-2-0-payload
                {:payload-type {:encrypted? false, :authenticated? false, :type 21},
                 :session-id 0,
                 :session-seq 0,
                 :message-length 8,
                 :message-tag 0,
                 :status-code 0,
                 :reserved [0 0],
                 :managed-console-session-id 2695013284},
                :type :ipmi-2-0-session},
               :type :ipmi-session}}
             (decode rakp4)))))
  (testing "RAKP4 encoding rakp sha1-hmac"
    (let [codec  (compile-codec :rmcp-rakp-hmac-sha1)
          decode (partial i/decode codec)
          encode (partial i/encode codec)
          rakp4  (encode (decode (byte-array (rmcp-payloads-cipher-1 :rmcp-rakp-4))))]
      (is (=     {:version 6,
                  :reserved 0,
                  :sequence 255,
                  :rmcp-class
                  {:ipmi-session-payload
                   {:ipmi-2-0-payload
                    {:session-id 0,
                     :session-seq 0,
                     :payload-type {:encrypted? false, :authenticated? false, :type 21},
                     :managed-console-session-id 2695013284,
                     :status-code 0,
                     :message-tag 0,
                     :integrity-check [139 192 24 45 154 158 82 139 18 244 192 119],
                     :reserved [0 0],
                     :message-length 20},
                    :type :ipmi-2-0-session},
                   :type :ipmi-session}}
                 (decode rakp4))))))

(deftest test-open-close-session
  (testing "open session request"
    (let [codec (compile-codec)
          decode (partial i/decode codec)
          encode (partial i/encode codec)
          request (encode (decode (byte-array (rmcp-payloads :open-session-request))))]
      (is (=  {:version 6,
               :reserved 0,
               :sequence 255,
               :rmcp-class
               {:ipmi-session-payload
                {:ipmi-2-0-payload
                 {:session-id 0,
                  :session-seq 0,
                  :payload-type {:encrypted? false, :authenticated? false, :type 16},
                  :authentication-payload
                  {:type 0,
                   :reserved [0 0 0],
                   :length 8,
                   :algo {:reserved 0, :algorithm 0}},
                  :integrity-payload
                  {:type 1,
                   :reserved [0 0 0],
                   :length 8,
                   :algo {:reserved 0, :algorithm 0}},
                  :remote-session-id 2695013284,
                  :message-tag 0,
                  :reserved 0,
                  :message-length 32,
                  :confidentiality-payload
                  {:type 2,
                   :reserved [0 0 0],
                   :length 8,
                   :algo {:reserved 0, :algorithm 0}},
                  :privilege-level {:reserved 0, :max-priv-level 0}},
                 :type :ipmi-2-0-session},
                :type :ipmi-session}}
              (decode request)))))
  (testing "open session response"
    (let [codec (compile-codec)
          decode (partial i/decode codec)
          encode (partial i/encode codec)
          response (encode (decode (byte-array (rmcp-payloads :open-session-response))))]
      (is (= {:version 6,
              :reserved 0,
              :sequence 255,
              :rmcp-class
              {:ipmi-session-payload
               {:ipmi-2-0-payload
                {:session-id 0,
                 :session-seq 0,
                 :payload-type {:encrypted? false, :authenticated? false, :type 17},
                 :authentication-payload
                 {:type 0,
                  :reserved [0 0 0],
                  :length 8,
                  :algo {:reserved 0, :algorithm 0}},
                 :integrity-payload
                 {:type 1,
                  :reserved [0 0 0],
                  :length 8,
                  :algo {:reserved 0, :algorithm 0}},
                 :status-code 0,
                 :remote-session-id 2695013284,,
                 :message-tag 0,
                 :managed-system-session-id 1154,
                 :reserved 0,
                 :message-length 36,
                 :confidentiality-payload
                 {:type 2,
                  :reserved [0 0 0],
                  :length 8,
                  :algo {:reserved 0, :algorithm 0}},
                 :privilege-level {:reserved 0, :max-priv-level 0}},
                :type :ipmi-2-0-session},
               :type :ipmi-session}}
             (decode response)))))
  (testing "close session request"
    (let [codec (compile-codec)
          decode (partial i/decode codec)
          encode (partial i/encode codec)
          payload (encode  (decode (byte-array (:rmcp-close-session-req rmcp-payloads))))]
      (is (=     {:version 6,
                  :reserved 0,
                  :sequence 255,
                  :rmcp-class
                  {:ipmi-session-payload
                   {:ipmi-2-0-payload
                    {:session-id 898,
                     :session-seq 9,
                     :payload-type {:encrypted? false, :authenticated? false, :type 0},
                     :command 60,
                     :source-lun 28,
                     :source-address 129,
                     :checksum 162,
                     :header-checksum 200,
                     :target-address 32,
                     :network-function {:function 6, :target-lun 0},
                     :message-length 11},
                    :type :ipmi-2-0-session},
                   :type :ipmi-session}}
                 (decode payload)))))
  (testing "close session response"
    (let [codec (compile-codec)
          decode (partial i/decode codec)
          encode (partial i/encode codec)
          payload (encode  (decode (byte-array (:rmcp-close-session-rsp rmcp-payloads))))]
      (is (=     {:version 6,
                  :reserved 0,
                  :sequence 255,
                  :rmcp-class
                  {:ipmi-session-payload
                   {:ipmi-2-0-payload
                    {:session-id 2695013284,
                     :session-seq 7,
                     :payload-type {:encrypted? false, :authenticated? false, :type 0},
                     :command 60,
                     :source-lun 28,
                     :source-address 32,
                     :checksum 136,
                     :header-checksum 99,
                     :target-address 129,
                     :network-function {:function 7, :target-lun 0},
                     :completion-code 0,
                     :message-length 8},
                    :type :ipmi-2-0-session},
                   :type :ipmi-session}}
                 (decode payload))))))

(deftest  test-channel-authentication
  (testing "Get Channel Auth Cap Request"
    (let [codec (compile-codec)
          decode (partial i/decode codec)
          encode (partial i/encode codec)
          request (encode  (decode (byte-array (rmcp-payloads :get-channel-auth-cap-req))))]
      (is (= {:version 6,
              :reserved 0,
              :sequence 255,
              :rmcp-class
              {:ipmi-session-payload
               {:ipmi-1-5-payload
                {:session-seq 0
                 :session-id 0
                 :message-length 9,
                 :ipmb-payload
                 {:version-compatibility
                  {:version-compatibility true, :reserved 0, :channel 14},
                  :command 56,
                  :source-lun 0,
                  :source-address 129,
                  :checksum 181,
                  :header-checksum 200,
                  :target-address 32,
                  :network-function {:function 6, :target-lun 0},
                  :privilege-level {:reserved 0, :privilege-level 4}}},
                :type :ipmi-1-5-session},
               :type :ipmi-session}}
             (decode request false)))))
  (testing "Get Channel Auth Cap Response"
    (let [codec (compile-codec)
          decode (partial i/decode codec)
          encode (partial i/encode codec)
          response (encode (decode (byte-array (rmcp-payloads :get-channel-auth-cap-rsp))))]
      (is (=   {:version 6,
                :reserved 0,
                :sequence 255,
                :rmcp-class
                {:ipmi-session-payload
                 {:ipmi-1-5-payload
                  {:session-seq 0
                   :session-id 0
                   :message-length 16,
                   :ipmb-payload
                   {:oem-id [0 0 0],
                    :oem-aux-data 0,
                    :auth-compatibility
                    {:reserved 0,
                     :key-generation false,
                     :per-message-auth false,
                     :user-level-auth false,
                     :non-null-user-names true,
                     :null-user-names false,
                     :anonymous-login-enabled false},
                    :version-compatibility
                    {:version-compatibility true,
                     :reserved false,
                     :oem-proprietary-auth false,
                     :password-key true,
                     :md5-support true,
                     :md2-support true,
                     :no-auth-support true},
                    :command 56,
                    :channel {:reserved 0, :channel-num 1},
                    :source-lun 0,
                    :source-address 32,
                    :supported-connections
                    {:reserved 0, :ipmi-2-0 true, :ipmi-1-5 true},
                    :checksum 9,
                    :header-checksum 99,
                    :target-address 129,
                    :network-function {:function 7, :target-lun 0},
                    :command-completion-code 0}},
                  :type :ipmi-1-5-session},
                 :type :ipmi-session}}
               (decode response false))))))

(deftest  test-privilege-level_request
  (testing "Set Session Priv Level Request"
    (let [codec (compile-codec)
          decode (partial i/decode codec)
          encode (partial i/encode codec)
          payload (encode (decode (byte-array (rmcp-payloads :set-sess-prv-level-req))))]
      (is (=       {:version 6,
                    :reserved 0,
                    :sequence 255,
                    :rmcp-class
                    {:ipmi-session-payload
                     {:ipmi-2-0-payload
                      {:session-id 898,
                       :session-seq 3,
                       :requested-priv-level {:reserved 0, :requested-priv-level 4},
                       :payload-type {:encrypted? false, :authenticated? false, :type 0},
                       :command 59,
                       :source-lun 4,
                       :source-address 129,
                       :checksum 60,
                       :header-checksum 200,
                       :target-address 32,
                       :network-function {:function 6, :target-lun 0},
                       :message-length 8},
                      :type :ipmi-2-0-session},
                     :type :ipmi-session}}
                   (decode payload))))
    (testing "Set Session Priv Level Response"
      (let [codec (compile-codec)
            decode (partial i/decode codec)
            encode (partial i/encode codec)
            payload (encode (decode (byte-array (rmcp-payloads :set-sess-prv-level-rsp))))]
        (is (=      {:version 6,
                     :reserved 0,
                     :sequence 255,
                     :rmcp-class
                     {:ipmi-session-payload
                      {:ipmi-2-0-payload
                       {:session-id 2695013284,
                        :session-seq 1,
                        :payload-type {:encrypted? false, :authenticated? false, :type 0},
                        :command 59,
                        :source-lun 4,
                        :source-address 32,
                        :checksum 157,
                        :header-checksum 99,
                        :target-address 129,
                        :network-function {:function 7, :target-lun 0},
                        :completion-code 0,
                        :message-length 9,
                        :privilege-level {:reserved 0, :priv-level 4}},
                       :type :ipmi-2-0-session},
                      :type :ipmi-session}}
                    (decode payload)))))))

(deftest  test-chassis-command
  (testing "Get Chassis Status Request"
    (let [codec (compile-codec)
          decode (partial i/decode codec)
          encode (partial i/encode codec)
          payload (encode (decode (byte-array (rmcp-payloads :chassis-status-req))))]
      (is (=    {:version 6,
                 :reserved 0,
                 :sequence 255,
                 :rmcp-class
                 {:ipmi-session-payload
                  {:ipmi-2-0-payload
                   {:session-id 0,
                    :session-seq 21,
                    :payload-type {:encrypted? false, :authenticated? false, :type 0},
                    :command 1,
                    :source-lun 24,
                    :source-address 129,
                    :checksum 102,
                    :header-checksum 224,
                    :target-address 32,
                    :network-function {:function 0, :target-lun 0},
                    :message-length 8},
                   :type :ipmi-2-0-session},
                  :type :ipmi-session}}
                (decode payload)))))
  (testing "Get Chassis Status Response"
    (let [codec (compile-codec)
          decode (partial i/decode codec)
          encode (partial i/encode codec)
          payload (encode  (decode (byte-array (rmcp-payloads :chassis-status-rsp))))]
      (is (=  {:version 6,
               :reserved 0,
               :sequence 255,
               :rmcp-class
               {:ipmi-session-payload
                {:ipmi-2-0-payload
                 {:session-id 2695013284,
                  :session-seq 6,
                  :payload-type {:encrypted? false, :authenticated? false, :type 0},
                  :power-state
                  {:reserved false,
                   :power-restore-policy 0,
                   :power-control-fault false,
                   :power-fault false,
                   :interlock false,
                   :overload false,
                   :power-on? true},
                  :last-power-event
                  {:reserved 0,
                   :last-power-on-state-via-ipmi false,
                   :last-power-down-state-power-fault false,
                   :last-power-down-state-interlock-activated false,
                   :last-power-down-state-overloaded false,
                   :last-power-down-ac-failed false},
                  :command 1,
                  :source-lun 24,
                  :source-address 32,
                  :misc-chassis-state
                  {:reserved false,
                   :chassis-identify-command-state-info-supported false,
                   :chassis-identify-state-supported 0,
                   :cooling-fan-fault-detect false,
                   :drive-fault false,
                   :front-panel-lockout false,
                   :chassis-intrusion-active false},
                  :checksum 198,
                  :header-checksum 123,
                  :target-address 129,
                  :network-function {:function 1, :target-lun 0},
                  :completion-code 0,
                  :message-length 11},
                 :type :ipmi-2-0-session},
                :type :ipmi-session}}
              (decode payload))))))

(deftest  chassis-reset
  (testing "chassis-reset-req"
    (let [codec (compile-codec)
          decode (partial i/decode codec)
          encode (partial i/encode codec)
          payload  (:chassis-reset-req rmcp-payloads)
          result (encode  (decode (byte-array payload)))]
      (is (=  {:version 6,
               :reserved 0,
               :sequence 255,
               :rmcp-class
               {:ipmi-session-payload
                {:ipmi-2-0-payload
                 {:session-id 0,
                  :session-seq 21,
                  :payload-type {:encrypted? false, :authenticated? false, :type 0},
                  :command 2,
                  :source-lun 24,
                  :source-address 129,
                  :checksum 98,
                  :control {:reserved 0, :chassis-control 3},
                  :header-checksum 224,
                  :target-address 32,
                  :network-function {:function 0, :target-lun 0},
                  :message-length 8},
                 :type :ipmi-2-0-session},
                :type :ipmi-session}}
              (decode result)))))
  (testing "Chassis Reset Response"
    (let [codec (compile-codec)
          decode (partial i/decode codec)
          encode (partial i/encode codec)
          payload (encode (decode (byte-array (:chassis-reset-rsp rmcp-payloads))))]
      (is (=  {:version 6,
               :reserved 0,
               :sequence 255,
               :rmcp-class
               {:ipmi-session-payload
                {:ipmi-2-0-payload
                 {:session-id 2695013284,
                  :session-seq 6,
                  :payload-type {:encrypted? false, :authenticated? false, :type 0},
                  :command 2,
                  :source-lun 24,
                  :source-address 32,
                  :checksum 198,
                  :header-checksum 123,
                  :target-address 129,
                  :network-function {:function 1, :target-lun 0},
                  :message-length 8,
                  :command-completion-code 0},
                 :type :ipmi-2-0-session},
                :type :ipmi-session}}
              (decode payload))))))

(deftest  test-device-id
  (testing "device-id-request"
    (let [codec  (compile-codec)
          decode (partial i/decode codec)
          encode (partial i/encode codec)
          result (encode (decode (byte-array (:device-id-req rmcp-payloads))))]
      (is (= {:version  6,
              :reserved 0,
              :sequence 255,
              :rmcp-class
              {:ipmi-session-payload
               {:ipmi-2-0-payload
                {:session-id       898,
                 :session-seq      5,
                 :payload-type     {:encrypted? false, :authenticated? false, :type 0},
                 :command          1,
                 :source-lun       12,
                 :source-address   129,
                 :checksum         114,
                 :header-checksum  200,
                 :target-address   32,
                 :network-function {:function 6, :target-lun 0},
                 :message-length   7},
                :type :ipmi-2-0-session},
               :type :ipmi-session}}
             (decode result)))))
  (testing "device-id-response"
    (let [codec   (compile-codec)
          decode (partial i/decode codec)
          encode (partial i/encode codec)
          result (encode (decode (byte-array (:device-id-rsp rmcp-payloads))))]
      (is (=  {:version  6,
               :reserved 0,
               :sequence 255,
               :rmcp-class
               {:ipmi-session-payload
                {:ipmi-2-0-payload
                 {:session-id              2695013284,
                  :major-firmware-revision 8,
                  :session-seq             3,
                  :payload-type            {:encrypted? false, :authenticated? false, :type 0},
                  :device-id               0,
                  :additional-device-support
                  {:chassis         true,
                   :bridge          false,
                   :event-generator false,
                   :event-receiver  true,
                   :fru-invetory    true,
                   :sel             true,
                   :sdr-repository  true,
                   :sensor          true},
                  :device-revision
                  {:provides-sdr false, :reserved 0, :device-revision 3},
                  :command                 1,
                  :source-lun              12,
                  :auxiliary-firmware      0,
                  :source-address          32,
                  :manufacturer-id         [145 18 0],
                  :checksum                106,
                  :header-checksum         99,
                  :target-address          129,
                  :network-function        {:function 7, :target-lun 0},
                  :message-length          23,
                  :command-completion-code 0,
                  :product-id              3842,
                  :ipmi-version            2,
                  :device-availability
                  {:operation false, :major-firmware-revision 9}},
                 :type :ipmi-2-0-session},
                :type :ipmi-session}}
              (decode result))))))

(deftest group-extensions-test
  (testing "hpm properties request"
    (let [codec   (compile-codec)
          decode  (partial i/decode codec)
          encode  (partial i/encode codec)
          payload (encode (decode (byte-array (rmcp-payloads :hpm-capabilities-req))))]
      (is (= {:version  6,
              :reserved 0,
              :sequence 255,
              :rmcp-class
              {:ipmi-session-payload
               {:ipmi-2-0-payload
                {:session-id       9868,
                 :session-seq      4,
                 :payload-type     {:encrypted? false, :authenticated? false, :type 0},
                 :signature        0,
                 :command          62,
                 :source-lun       8,
                 :source-address   129,
                 :checksum         55,
                 :header-checksum  48,
                 :target-address   32,
                 :network-function {:function 44, :target-lun 0},
                 :message-length   9,
                 :data             2},
                :type :ipmi-2-0-session},
               :type :ipmi-session}}
             (decode payload)))))
  (testing "hpm properties response"
    (let [codec   (compile-codec)
          decode  (partial i/decode codec)
          encode  (partial i/encode codec)
          payload (encode (decode (byte-array (rmcp-payloads :hpm-capabilities-rsp))))]
      (is (=  {:version  6,
               :reserved 0,
               :sequence 255,
               :rmcp-class
               {:ipmi-session-payload
                {:ipmi-2-0-payload
                 {:session-id              2695013284,
                  :session-seq             2,
                  :payload-type            {:encrypted? false, :authenticated? false, :type 0},
                  :command                 62,
                  :source-lun              8,
                  :source-address          32,
                  :checksum                217,
                  :header-checksum         203,
                  :target-address          129,
                  :network-function        {:function 45, :target-lun 0},
                  :message-length          8,
                  :command-completion-code 193},
                 :type :ipmi-2-0-session},
                :type :ipmi-session}}
              (decode payload)))))
  (testing "vso capabilities req"
    (let [codec   (compile-codec)
          decode  (partial i/decode codec)
          encode  (partial i/encode codec)
          payload (encode (decode (byte-array (rmcp-payloads :vso-capabilities-req))))]
      (is (bs/compare-bytes
           payload
           (byte-array (rmcp-payloads :vso-capabilities-req))))
      (is (=     {:version 6,
                  :reserved 0,
                  :sequence 255,
                  :rmcp-class
                  {:ipmi-session-payload
                   {:ipmi-2-0-payload
                    {:session-id 9868,
                     :session-seq 13,
                     :payload-type {:encrypted? false, :authenticated? false, :type 0},
                     :signature 3,
                     :command 0,
                     :source-lun 20,
                     :source-address 129,
                     :checksum 104,
                     :header-checksum 48,
                     :target-address 32,
                     :network-function {:function 44, :target-lun 0},
                     :message-length 8},
                    :type :ipmi-2-0-session},
                   :type :ipmi-session}}
                 (decode payload)))))
  (testing "picmg properties"
    (let [codec   (compile-codec)
          decode  (partial i/decode codec)
          encode  (partial i/encode codec)
          payload (encode (decode (byte-array (rmcp-payloads :picmg-properties-req))))]
      (is (bs/compare-bytes
           payload
           (byte-array (rmcp-payloads :picmg-properties-req))))
      (is (=   {:version 6,
                :reserved 0,
                :sequence 255,
                :rmcp-class
                {:ipmi-session-payload
                 {:ipmi-2-0-payload
                  {:session-id 130,
                   :session-seq 6,
                   :payload-type {:encrypted? false, :authenticated? false, :type 0},
                   :signature 0,
                   :command 0,
                   :source-lun 16,
                   :source-address 129,
                   :checksum 111,
                   :header-checksum 48,
                   :target-address 32,
                   :network-function {:function 44, :target-lun 0},
                   :message-length 8},
                  :type :ipmi-2-0-session},
                 :type :ipmi-session}}
               (decode payload))))))

(def ipmi-decode (partial i/decode (compile-codec)))

(deftest test-message-select
  (testing "RMCP Message Type"
    (is (=  {:type :asf-ping, :message 128}
            (get-message-type (ipmi-decode (byte-array (:rmcp-ping
                                                        rmcp-payloads)))))))
  (testing "Device ID Request"
    (is (= {:type :device-id-req :command 1}
           (get-message-type (ipmi-decode (byte-array (:device-id-req rmcp-payloads)))))))

  (testing "Device ID Response"
    (is (= {:type :device-id-rsp :command 1}
           (get-message-type (ipmi-decode (byte-array (:device-id-rsp rmcp-payloads)))))))

  (testing "IPMI Capabilities"
    (is (= {:message 56, :type :get-channel-auth-cap-req}
           (get-message-type (ipmi-decode (byte-array (:get-channel-auth-cap-req rmcp-payloads)))))))
  (testing "IPMI Open Session"
    (is (= {:type :open-session-request :payload-type 16}
           (get-message-type (ipmi-decode (byte-array (:open-session-request rmcp-payloads)))))))

  (testing "IPMI RAKP 1"
    (is (= {:payload-type 18, :type :rmcp-rakp-1}
           (get-message-type (ipmi-decode (byte-array (:rmcp-rakp-1
                                                       rmcp-payloads)))))))
  (testing "IPMI RAKP 2"
    (is (= {:payload-type 19, :type :rmcp-rakp-2}
           (get-message-type (ipmi-decode (byte-array (:rmcp-rakp-2
                                                       rmcp-payloads)))))))
  (testing "IPMI RAKP 3"
    (is (= {:payload-type 20, :type :rmcp-rakp-3}
           (get-message-type (ipmi-decode (byte-array (:rmcp-rakp-3
                                                       rmcp-payloads)))))))
  (testing "IPMI RAKP 4"
    (is (= {:payload-type 21, :type :rmcp-rakp-4}
           (get-message-type (ipmi-decode (byte-array (:rmcp-rakp-4
                                                       rmcp-payloads)))))))
  (testing "Set Session Perms"
    (is (=  {:type :set-session-prv-level-req, :command 59}
            (get-message-type (ipmi-decode (byte-array (:set-sess-prv-level-req
                                                        rmcp-payloads)))))))
  (testing "Close Session Request"
    (is (=   {:type :rmcp-close-session-req, :command 60}
             (get-message-type (ipmi-decode (byte-array (:rmcp-close-session-req
                                                         rmcp-payloads)))))))
  (testing "Chassis Request"
    (is (=  {:type :chassis-status-req, :command 1}
            (get-message-type (ipmi-decode (byte-array (:chassis-status-req
                                                        rmcp-payloads)))))))
  (testing "Chassis Reset"
    (is (=  {:type :chassis-reset-req, :command 2}
            (get-message-type (ipmi-decode (byte-array (:chassis-reset-req
                                                        rmcp-payloads)))))))
  (testing "HPM Capabilities"
    (is (=  {:type :hpm-capabilities-req, :command 62}
            (get-message-type (ipmi-decode (byte-array (:hpm-capabilities-req
                                                        rmcp-payloads)))))))
  (testing "VSO Capabilities"
    (is (=  {:type :vso-capabilities-req, :signature 3}
            (get-message-type (ipmi-decode (byte-array (:vso-capabilities-req
                                                        rmcp-payloads)) false)))))
  (testing "PICMG Properties")
  (is (= {:type :picmg-properties-req, :signature 0}
         (get-message-type (ipmi-decode (byte-array (:picmg-properties-req
                                                     rmcp-payloads)) false)))))

                                        ; (deftest test-set-priv-level
; (deftest test-set-priv-level
;   (testing "Test set priv level"
;     (let [payload (encode rmcp-header (ipmi-decode (byte-array (:set-session-priv-level rmcp-payloads))))]
;       (is (= {}
;              (ipmi-decode payload false))))))

