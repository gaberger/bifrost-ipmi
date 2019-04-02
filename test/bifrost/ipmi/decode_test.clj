(ns bifrost.ipmi.decode-test
  (:require [bifrost.ipmi.decode :as sut]
            [bifrost.ipmi.utils :as u]
            [byte-streams :as bs]
            [buddy.core.codecs :as codecs]
            [clojure.test :refer :all]))

(deftest test-decode-message
  (let [b-array (u/create-rmcp-stream "cipher-0.hex")
        res     (mapv #(sut/decode-message {} %) b-array)]
    (is (=   [{:version 6,
               :reserved 0,
               :sequence 255,
               :rmcp-class
               {:ipmi-session-payload
                {:ipmi-1-5-payload
                 {:session-seq 0,
                  :session-id 0,
                  :message-length 9,
                  :ipmb-payload
                  {:version-compatibility
                   {:version-compatibility true, :reserved 0, :channel 14},
                   :command 56,
                   :source-lun {:seq-no 0, :source-lun 0},
                   :source-address 129,
                   :checksum 181,
                   :header-checksum 200,
                   :target-address 32,
                   :network-function {:function 6, :target-lun 0},
                   :privilege-level {:reserved 0, :privilege-level 4}}},
                 :type :ipmi-1-5-session},
                :type :ipmi-session}}
              {:version 6,
               :reserved 0,
               :sequence 255,
               :rmcp-class
               {:ipmi-session-payload
                {:ipmi-1-5-payload
                 {:session-seq 0,
                  :session-id 0,
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
                   :source-lun {:seq-no 0, :source-lun 0},
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
              {:version 6,
               :reserved 0,
               :sequence 255,
               :rmcp-class
               {:ipmi-session-payload
                {:ipmi-2-0-payload
                 {:session-id 0,
                  :session-seq 0,
                  :payload-type
                  {:encrypted? false, :authenticated? false, :type 16},
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
              {:version 6,
               :reserved 0,
               :sequence 255,
               :rmcp-class
               {:ipmi-session-payload
                {:ipmi-2-0-payload
                 {:session-id 0,
                  :session-seq 0,
                  :payload-type
                  {:encrypted? false, :authenticated? false, :type 17},
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
                  :remote-session-id 2695013284,
                  :message-tag 0,
                  :managed-system-session-id 1410,
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
              {:version 6,
               :reserved 0,
               :sequence 255,
               :rmcp-class
               {:ipmi-session-payload
                {:ipmi-2-0-payload
                 {:session-id 0,
                  :session-seq 0,
                  :reserved2 [0 0],
                  :payload-type
                  {:encrypted? false, :authenticated? false, :type 18},
                  :remote-console-random-number
                  [130 240 106 5 2 196 62 41 251 20 164 150 238 33 47 72],
                  :user-name "ADMIN",
                  :requested-max-priv-level
                  {:reserved 0, :user-lookup true, :requested-max-priv-level 4},
                  :message-tag 0,
                  :managed-system-session-id 1410,
                  :reserved1 [0 0 0],
                  :message-length 33},
                 :type :ipmi-2-0-session},
                :type :ipmi-session}}
              {:version 6,
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
                  [190 155 123 179 146 211 139 71 34 32 89 0 96 12 126 164],
                  :status-code 0,
                  :message-tag 0,
                  :reserved [0 0],
                  :message-length 40,
                  :managed-system-guid
                  [161 35 69 103 137 171 205 239 161 35 69 103 137 171 205 239],
                  :remote-session-console-id 2695013284},
                 :type :ipmi-2-0-session},
                :type :ipmi-session}}
              {:version 6,
               :reserved 0,
               :sequence 255,
               :rmcp-class
               {:ipmi-session-payload
                {:ipmi-2-0-payload
                 {:payload-type
                  {:encrypted? false, :authenticated? false, :type 20},
                  :session-id 0,
                  :session-seq 0,
                  :message-length 8,
                  :message-tag 0,
                  :status-code 0,
                  :reserved [0 0],
                  :managed-system-session-id 2181365760},
                 :type :ipmi-2-0-session},
                :type :ipmi-session}}
              {:version 6,
               :reserved 0,
               :sequence 255,
               :rmcp-class
               {:ipmi-session-payload
                {:ipmi-2-0-payload
                 {:payload-type
                  {:encrypted? false, :authenticated? false, :type 21},
                  :session-id 0,
                  :session-seq 0,
                  :message-length 8,
                  :message-tag 0,
                  :status-code 0,
                  :reserved [0 0],
                  :managed-console-session-id 2695013284},
                 :type :ipmi-2-0-session},
                :type :ipmi-session}}
              {:version 6,
               :reserved 0,
               :sequence 255,
               :rmcp-class
               {:ipmi-session-payload
                {:ipmi-2-0-payload
                 {:session-id 1410,
                  :session-seq 3,
                  :requested-priv-level {:reserved 0, :requested-priv-level 4},
                  :payload-type {:encrypted? false, :authenticated? false, :type 0},
                  :command 59,
                  :source-lun {:seq-no 1, :source-lun 0},
                  :source-address 129,
                  :checksum 60,
                  :header-checksum 200,
                  :target-address 32,
                  :network-function {:function 6, :target-lun 0},
                  :message-length 8},
                 :type :ipmi-2-0-session},
                :type :ipmi-session}}
              {:version 6,
               :reserved 0,
               :sequence 255,
               :rmcp-class
               {:ipmi-session-payload
                {:ipmi-2-0-payload
                 {:session-id 2695013284,
                  :session-seq 1,
                  :payload-type {:encrypted? false, :authenticated? false, :type 0},
                  :command 59,
                  :source-lun {:seq-no 1, :source-lun 0},
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
              {:version 6,
               :reserved 0,
               :sequence 255,
               :rmcp-class
               {:ipmi-session-payload
                {:ipmi-2-0-payload
                 {:session-id 1410,
                  :session-seq 4,
                  :payload-type {:encrypted? false, :authenticated? false, :type 0},
                  :signature 0,
                  :command 62,
                  :source-lun {:seq-no 2, :source-lun 0},
                  :source-address 129,
                  :checksum 55,
                  :header-checksum 48,
                  :target-address 32,
                  :network-function {:function 44, :target-lun 0},
                  :message-length 9,
                  :data 2},
                 :type :ipmi-2-0-session},
                :type :ipmi-session}}
              {:version 6,
               :reserved 0,
               :sequence 255,
               :rmcp-class
               {:ipmi-session-payload
                {:ipmi-2-0-payload
                 {:session-id 2695013284,
                  :session-seq 2,
                  :payload-type {:encrypted? false, :authenticated? false, :type 0},
                  :command 62,
                  :source-lun {:seq-no 2, :source-lun 0},
                  :source-address 32,
                  :checksum 217,
                  :header-checksum 203,
                  :target-address 129,
                  :network-function {:function 45, :target-lun 0},
                  :message-length 8,
                  :command-completion-code 193},
                 :type :ipmi-2-0-session},
                :type :ipmi-session}}
              {:version 6,
               :reserved 0,
               :sequence 255,
               :rmcp-class
               {:ipmi-session-payload
                {:ipmi-2-0-payload
                 {:session-id 1410,
                  :session-seq 5,
                  :payload-type {:encrypted? false, :authenticated? false, :type 0},
                  :command 1,
                  :source-lun {:seq-no 3, :source-lun 0},
                  :source-address 129,
                  :checksum 114,
                  :header-checksum 200,
                  :target-address 32,
                  :network-function {:function 6, :target-lun 0},
                  :message-length 7},
                 :type :ipmi-2-0-session},
                :type :ipmi-session}}
              {:version 6,
               :reserved 0,
               :sequence 255,
               :rmcp-class
               {:ipmi-session-payload
                {:ipmi-2-0-payload
                 {:session-id 2695013284,
                  :major-firmware-revision 8,
                  :session-seq 3,
                  :payload-type {:encrypted? false, :authenticated? false, :type 0},
                  :device-id 0,
                  :additional-device-support
                  {:chassis true,
                   :bridge false,
                   :event-generator false,
                   :event-receiver true,
                   :fru-invetory true,
                   :sel true,
                   :sdr-repository true,
                   :sensor true},
                  :device-revision
                  {:provides-sdr false, :reserved 0, :device-revision 3},
                  :command 1,
                  :source-lun {:seq-no 3, :source-lun 0},
                  :auxiliary-firmware 0,
                  :source-address 32,
                  :manufacturer-id [145 18 0],
                  :checksum 106,
                  :header-checksum 99,
                  :target-address 129,
                  :network-function {:function 7, :target-lun 0},
                  :message-length 23,
                  :command-completion-code 0,
                  :product-id 3842,
                  :ipmi-version 2,
                  :device-availability
                  {:operation false, :major-firmware-revision 9}},
                 :type :ipmi-2-0-session},
                :type :ipmi-session}}
              {:version 6,
               :reserved 0,
               :sequence 255,
               :rmcp-class
               {:ipmi-session-payload
                {:ipmi-2-0-payload
                 {:session-id 1410,
                  :session-seq 6,
                  :payload-type {:encrypted? false, :authenticated? false, :type 0},
                  :signature 0,
                  :command 0,
                  :source-lun {:seq-no 4, :source-lun 0},
                  :source-address 129,
                  :checksum 111,
                  :header-checksum 48,
                  :target-address 32,
                  :network-function {:function 44, :target-lun 0},
                  :message-length 8},
                 :type :ipmi-2-0-session},
                :type :ipmi-session}}
              {:version 6,
               :reserved 0,
               :sequence 255,
               :rmcp-class
               {:ipmi-session-payload
                {:ipmi-2-0-payload
                 {:session-id 2695013284,
                  :session-seq 4,
                  :payload-type {:encrypted? false, :authenticated? false, :type 0},
                  :command 0,
                  :source-lun {:seq-no 4, :source-lun 0},
                  :source-address 32,
                  :checksum 15,
                  :header-checksum 203,
                  :target-address 129,
                  :network-function {:function 45, :target-lun 0},
                  :message-length 8,
                  :command-completion-code 193},
                 :type :ipmi-2-0-session},
                :type :ipmi-session}}
              {:version 6,
               :reserved 0,
               :sequence 255,
               :rmcp-class
               {:ipmi-session-payload
                {:ipmi-2-0-payload
                 {:session-id 1410,
                  :session-seq 7,
                  :payload-type {:encrypted? false, :authenticated? false, :type 0},
                  :signature 3,
                  :command 0,
                  :source-lun {:seq-no 5, :source-lun 0},
                  :source-address 129,
                  :checksum 104,
                  :header-checksum 48,
                  :target-address 32,
                  :network-function {:function 44, :target-lun 0},
                  :message-length 8},
                 :type :ipmi-2-0-session},
                :type :ipmi-session}}
              {:version 6,
               :reserved 0,
               :sequence 255,
               :rmcp-class
               {:ipmi-session-payload
                {:ipmi-2-0-payload
                 {:session-id 2695013284,
                  :session-seq 5,
                  :payload-type {:encrypted? false, :authenticated? false, :type 0},
                  :command 0,
                  :source-lun {:seq-no 5, :source-lun 0},
                  :source-address 32,
                  :checksum 11,
                  :header-checksum 203,
                  :target-address 129,
                  :network-function {:function 45, :target-lun 0},
                  :message-length 8,
                  :command-completion-code 193},
                 :type :ipmi-2-0-session},
                :type :ipmi-session}}
              {:version 6,
               :reserved 0,
               :sequence 255,
               :rmcp-class
               {:ipmi-session-payload
                {:ipmi-2-0-payload
                 {:session-id 1410,
                  :session-seq 8,
                  :payload-type {:encrypted? false, :authenticated? false, :type 0},
                  :command 1,
                  :source-lun {:seq-no 6, :source-lun 0},
                  :source-address 129,
                  :checksum 102,
                  :header-checksum 224,
                  :target-address 32,
                  :network-function {:function 0, :target-lun 0},
                  :message-length 7},
                 :type :ipmi-2-0-session},
                :type :ipmi-session}}
              {:version 6,
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
                  :source-lun {:seq-no 6, :source-lun 0},
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
              {:version 6,
               :reserved 0,
               :sequence 255,
               :rmcp-class
               {:ipmi-session-payload
                {:ipmi-2-0-payload
                 {:session-id 1410,
                  :session-seq 9,
                  :payload-type {:encrypted? false, :authenticated? false, :type 0},
                  :command 60,
                  :source-lun {:seq-no 7, :source-lun 0},
                  :source-address 129,
                  :checksum 160,
                  :header-checksum 200,
                  :target-address 32,
                  :network-function {:function 6, :target-lun 0},
                  :message-length 11},
                 :type :ipmi-2-0-session},
                :type :ipmi-session}}
              {:version 6,
               :reserved 0,
               :sequence 255,
               :rmcp-class
               {:ipmi-session-payload
                {:ipmi-2-0-payload
                 {:session-id 2695013284,
                  :session-seq 7,
                  :payload-type {:encrypted? false, :authenticated? false, :type 0},
                  :command 60,
                  :source-lun {:seq-no 7, :source-lun 0},
                  :source-address 32,
                  :checksum 136,
                  :header-checksum 99,
                  :target-address 129,
                  :network-function {:function 7, :target-lun 0},
                  :completion-code 0,
                  :message-length 8},
                 :type :ipmi-2-0-session},
                :type :ipmi-session}}]
             res))))

(deftest test-decoder-message-cipher-1
  (let [b-array (u/create-rmcp-stream "cipher-1.hex")
        res     (mapv #(sut/decode-message {:auth-codec :rmcp-rakp-hmac-sha1} %) b-array)]
    (is (= [{:version 6,
             :reserved 0,
             :sequence 255,
             :rmcp-class
             {:ipmi-session-payload
              {:ipmi-1-5-payload
               {:session-seq 0,
                :session-id 0,
                :message-length 9,
                :ipmb-payload
                {:version-compatibility
                 {:version-compatibility true, :reserved 0, :channel 14},
                 :command 56,
                 :source-lun {:seq-no 0, :source-lun 0},
                 :source-address 129,
                 :checksum 181,
                 :header-checksum 200,
                 :target-address 32,
                 :network-function {:function 6, :target-lun 0},
                 :privilege-level {:reserved 0, :privilege-level 4}}},
               :type :ipmi-1-5-session},
              :type :ipmi-session}}
            {:version 6,
             :reserved 0,
             :sequence 255,
             :rmcp-class
             {:ipmi-session-payload
              {:ipmi-1-5-payload
               {:session-seq 0,
                :session-id 0,
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
                 :source-lun {:seq-no 0, :source-lun 0},
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
            {:version 6,
             :reserved 0,
             :sequence 255,
             :rmcp-class
             {:ipmi-session-payload
              {:ipmi-2-0-payload
               {:session-id 0,
                :session-seq 0,
                :payload-type
                {:encrypted? false, :authenticated? false, :type 16},
                :authentication-payload
                {:type 0,
                 :reserved [0 0 0],
                 :length 8,
                 :algo {:reserved 0, :algorithm 1}},
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
            {:version 6,
             :reserved 0,
             :sequence 255,
             :rmcp-class
             {:ipmi-session-payload
              {:ipmi-2-0-payload
               {:session-id 0,
                :session-seq 0,
                :payload-type
                {:encrypted? false, :authenticated? false, :type 17},
                :authentication-payload
                {:type 0,
                 :reserved [0 0 0],
                 :length 8,
                 :algo {:reserved 0, :algorithm 1}},
                :integrity-payload
                {:type 1,
                 :reserved [0 0 0],
                 :length 8,
                 :algo {:reserved 0, :algorithm 0}},
                :status-code 0,
                :remote-session-id 2695013284,
                :message-tag 0,
                :managed-system-session-id 1538,
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
            {:version 6,
             :reserved 0,
             :sequence 255,
             :rmcp-class
             {:ipmi-session-payload
              {:ipmi-2-0-payload
               {:session-id 0,
                :session-seq 0,
                :reserved2 [0 0],
                :payload-type
                {:encrypted? false, :authenticated? false, :type 18},
                :remote-console-random-number
                [164 231 102 247 225 127 193 98 185 10 4 8 103 202 9 52],
                :user-name "ADMIN",
                :requested-max-priv-level
                {:reserved 0, :user-lookup true, :requested-max-priv-level 4},
                :message-tag 0,
                :managed-system-session-id 1538,
                :reserved1 [0 0 0],
                :message-length 33},
               :type :ipmi-2-0-session},
              :type :ipmi-session}}
            {:version 6,
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
                [46 249 59 34 227 127 139 138 25 88 247 44 92 1 149 190],
                :status-code 0,
                :message-tag 0,
                :key-exchange-code
                [51
                 242
                 67
                 67
                 115
                 183
                 118
                 204
                 13
                 176
                 6
                 225
                 76
                 210
                 171
                 87
                 184
                 61
                 91
                 154],
                :reserved [0 0],
                :message-length 60,
                :managed-system-guid
                [161 35 69 103 137 171 205 239 161 35 69 103 137 171 205 239],
                :remote-session-console-id 2695013284},
               :type :ipmi-2-0-session},
              :type :ipmi-session}}
            {:version 6,
             :reserved 0,
             :sequence 255,
             :rmcp-class
             {:ipmi-session-payload
              {:ipmi-2-0-payload
               {:session-id 0,
                :session-seq 0,
                :payload-type
                {:encrypted? false, :authenticated? false, :type 20},
                :status-code 0,
                :message-tag 0,
                :managed-system-session-id 1538,
                :key-exchange-code
                [104
                 62
                 161
                 62
                 29
                 3
                 43
                 191
                 40
                 12
                 221
                 71
                 57
                 213
                 81
                 102
                 95
                 131
                 134
                 182],
                :reserved [0 0],
                :message-length 28},
               :type :ipmi-2-0-session},
              :type :ipmi-session}}
            {:version 6,
             :reserved 0,
             :sequence 255,
             :rmcp-class
             {:ipmi-session-payload
              {:ipmi-2-0-payload
               {:session-id 0,
                :session-seq 0,
                :payload-type
                {:encrypted? false, :authenticated? false, :type 21},
                :managed-console-session-id 2695013284,
                :status-code 0,
                :message-tag 0,
                :integrity-check [60 167 143 56 206 109 104 44 80 38 191 136],
                :reserved [0 0],
                :message-length 20},
               :type :ipmi-2-0-session},
              :type :ipmi-session}}
            {:version 6,
             :reserved 0,
             :sequence 255,
             :rmcp-class
             {:ipmi-session-payload
              {:ipmi-2-0-payload
               {:session-id 1538,
                :session-seq 3,
                :requested-priv-level {:reserved 0, :requested-priv-level 4},
                :payload-type {:encrypted? false, :authenticated? false, :type 0},
                :command 59,
                :source-lun {:seq-no 1, :source-lun 0},
                :source-address 129,
                :checksum 60,
                :header-checksum 200,
                :target-address 32,
                :network-function {:function 6, :target-lun 0},
                :message-length 8},
               :type :ipmi-2-0-session},
              :type :ipmi-session}}
            {:version 6,
             :reserved 0,
             :sequence 255,
             :rmcp-class
             {:ipmi-session-payload
              {:ipmi-2-0-payload
               {:session-id 2695013284,
                :session-seq 1,
                :payload-type {:encrypted? false, :authenticated? false, :type 0},
                :command 59,
                :source-lun {:seq-no 1, :source-lun 0},
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
            {:version 6,
             :reserved 0,
             :sequence 255,
             :rmcp-class
             {:ipmi-session-payload
              {:ipmi-2-0-payload
               {:session-id 1538,
                :session-seq 4,
                :payload-type {:encrypted? false, :authenticated? false, :type 0},
                :signature 0,
                :command 62,
                :source-lun {:seq-no 2, :source-lun 0},
                :source-address 129,
                :checksum 55,
                :header-checksum 48,
                :target-address 32,
                :network-function {:function 44, :target-lun 0},
                :message-length 9,
                :data 2},
               :type :ipmi-2-0-session},
              :type :ipmi-session}}
            {:version 6,
             :reserved 0,
             :sequence 255,
             :rmcp-class
             {:ipmi-session-payload
              {:ipmi-2-0-payload
               {:session-id 2695013284,
                :session-seq 2,
                :payload-type {:encrypted? false, :authenticated? false, :type 0},
                :command 62,
                :source-lun {:seq-no 2, :source-lun 0},
                :source-address 32,
                :checksum 217,
                :header-checksum 203,
                :target-address 129,
                :network-function {:function 45, :target-lun 0},
                :message-length 8,
                :command-completion-code 193},
               :type :ipmi-2-0-session},
              :type :ipmi-session}}
            {:version 6,
             :reserved 0,
             :sequence 255,
             :rmcp-class
             {:ipmi-session-payload
              {:ipmi-2-0-payload
               {:session-id 1538,
                :session-seq 5,
                :payload-type {:encrypted? false, :authenticated? false, :type 0},
                :command 1,
                :source-lun {:seq-no 3, :source-lun 0},
                :source-address 129,
                :checksum 114,
                :header-checksum 200,
                :target-address 32,
                :network-function {:function 6, :target-lun 0},
                :message-length 7},
               :type :ipmi-2-0-session},
              :type :ipmi-session}}
            {:version 6,
             :reserved 0,
             :sequence 255,
             :rmcp-class
             {:ipmi-session-payload
              {:ipmi-2-0-payload
               {:session-id 2695013284,
                :major-firmware-revision 8,
                :session-seq 3,
                :payload-type {:encrypted? false, :authenticated? false, :type 0},
                :device-id 0,
                :additional-device-support
                {:chassis true,
                 :bridge false,
                 :event-generator false,
                 :event-receiver true,
                 :fru-invetory true,
                 :sel true,
                 :sdr-repository true,
                 :sensor true},
                :device-revision
                {:provides-sdr false, :reserved 0, :device-revision 3},
                :command 1,
                :source-lun {:seq-no 3, :source-lun 0},
                :auxiliary-firmware 0,
                :source-address 32,
                :manufacturer-id [145 18 0],
                :checksum 106,
                :header-checksum 99,
                :target-address 129,
                :network-function {:function 7, :target-lun 0},
                :message-length 23,
                :command-completion-code 0,
                :product-id 3842,
                :ipmi-version 2,
                :device-availability
                {:operation false, :major-firmware-revision 9}},
               :type :ipmi-2-0-session},
              :type :ipmi-session}}
            {:version 6,
             :reserved 0,
             :sequence 255,
             :rmcp-class
             {:ipmi-session-payload
              {:ipmi-2-0-payload
               {:session-id 1538,
                :session-seq 6,
                :payload-type {:encrypted? false, :authenticated? false, :type 0},
                :signature 0,
                :command 0,
                :source-lun {:seq-no 4, :source-lun 0},
                :source-address 129,
                :checksum 111,
                :header-checksum 48,
                :target-address 32,
                :network-function {:function 44, :target-lun 0},
                :message-length 8},
               :type :ipmi-2-0-session},
              :type :ipmi-session}}
            {:version 6,
             :reserved 0,
             :sequence 255,
             :rmcp-class
             {:ipmi-session-payload
              {:ipmi-2-0-payload
               {:session-id 2695013284,
                :session-seq 4,
                :payload-type {:encrypted? false, :authenticated? false, :type 0},
                :command 0,
                :source-lun {:seq-no 4, :source-lun 0},
                :source-address 32,
                :checksum 15,
                :header-checksum 203,
                :target-address 129,
                :network-function {:function 45, :target-lun 0},
                :message-length 8,
                :command-completion-code 193},
               :type :ipmi-2-0-session},
              :type :ipmi-session}}
            {:version 6,
             :reserved 0,
             :sequence 255,
             :rmcp-class
             {:ipmi-session-payload
              {:ipmi-2-0-payload
               {:session-id 1538,
                :session-seq 7,
                :payload-type {:encrypted? false, :authenticated? false, :type 0},
                :signature 3,
                :command 0,
                :source-lun {:seq-no 5, :source-lun 0},
                :source-address 129,
                :checksum 104,
                :header-checksum 48,
                :target-address 32,
                :network-function {:function 44, :target-lun 0},
                :message-length 8},
               :type :ipmi-2-0-session},
              :type :ipmi-session}}
            {:version 6,
             :reserved 0,
             :sequence 255,
             :rmcp-class
             {:ipmi-session-payload
              {:ipmi-2-0-payload
               {:session-id 2695013284,
                :session-seq 5,
                :payload-type {:encrypted? false, :authenticated? false, :type 0},
                :command 0,
                :source-lun {:seq-no 5, :source-lun 0},
                :source-address 32,
                :checksum 11,
                :header-checksum 203,
                :target-address 129,
                :network-function {:function 45, :target-lun 0},
                :message-length 8,
                :command-completion-code 193},
               :type :ipmi-2-0-session},
              :type :ipmi-session}}
            {:version 6,
             :reserved 0,
             :sequence 255,
             :rmcp-class
             {:ipmi-session-payload
              {:ipmi-2-0-payload
               {:session-id 1538,
                :session-seq 8,
                :payload-type {:encrypted? false, :authenticated? false, :type 0},
                :command 1,
                :source-lun {:seq-no 6, :source-lun 0},
                :source-address 129,
                :checksum 102,
                :header-checksum 224,
                :target-address 32,
                :network-function {:function 0, :target-lun 0},
                :message-length 7},
               :type :ipmi-2-0-session},
              :type :ipmi-session}}
            {:version 6,
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
                :source-lun {:seq-no 6, :source-lun 0},
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
            {:version 6,
             :reserved 0,
             :sequence 255,
             :rmcp-class
             {:ipmi-session-payload
              {:ipmi-2-0-payload
               {:session-id 1538,
                :session-seq 9,
                :payload-type {:encrypted? false, :authenticated? false, :type 0},
                :command 60,
                :source-lun {:seq-no 7, :source-lun 0},
                :source-address 129,
                :checksum 31,
                :header-checksum 200,
                :target-address 32,
                :network-function {:function 6, :target-lun 0},
                :message-length 11},
               :type :ipmi-2-0-session},
              :type :ipmi-session}}
            {:version 6,
             :reserved 0,
             :sequence 255,
             :rmcp-class
             {:ipmi-session-payload
              {:ipmi-2-0-payload
               {:session-id 2695013284,
                :session-seq 7,
                :payload-type {:encrypted? false, :authenticated? false, :type 0},
                :command 60,
                :source-lun {:seq-no 7, :source-lun 0},
                :source-address 32,
                :checksum 136,
                :header-checksum 99,
                :target-address 129,
                :network-function {:function 7, :target-lun 0},
                :completion-code 0,
                :message-length 8},
               :type :ipmi-2-0-session},
              :type :ipmi-session}}]
           res))))

(deftest test-decoder-cipher-0
  (let [b-array (u/create-rmcp-stream "cipher-1.hex")
        res     (mapv #(sut/decode {} %) b-array)]
    (is (= [{:type :get-channel-auth-cap-req, :command 56, :function 6}
            {:type :get-channel-auth-cap-rsp, :command 56, :function 7}
            {:payload-type 16,
             :integ-codec  :rmcp-rakp-1-none-integrity,
             :a?           false,
             :type         :open-session-request,
             :e?           false,
             :c            0,
             :auth-codec   :rmcp-rakp-hmac-sha1,
             :remote-sid   2695013284,
             :rolem        0,
             :conf-codec   :rmcp-rakp-1-none-confidentiality,
             :i            0,
             :a            1}
            {:type         :open-session-response,
             :payload-type 17,
             :server-sid   1538,
             :remote-sid   2695013284,
             :rolem        0,
             :auth-codec   :rmcp-rakp-hmac-sha1,
             :integ-codec  :rmcp-rakp-1-none-integrity,
             :conf-codec   :rmcp-rakp-1-none-confidentiality}
            {:type         :rmcp-rakp-1,
             :payload-type 18,
             :a?           false,
             :e?           false,
             :unamem       "ADMIN",
             :remote-rn    [164 231 102 247 225 127 193 98 185 10 4 8 103 202 9 52]}
            {:type :error, :selector nil}
            {:type :error, :selector nil}
            {:type :error, :selector nil}
            {:type           :set-session-prv-level-req,
             :command        59,
             :function       6,
             :seq-no         1,
             :session-seq-no 3,
             :a?             false,
             :e?             false}
            {:type     :set-session-prv-level-rsp,
             :command  59,
             :function 7,
             :seq-no   1,
             :a?       false,
             :e?       false}
            {:type     :hpm-capabilities-req,
             :command  62,
             :function 44,
             :seq-no   2,
             :response 45,
             :a?       false,
             :e?       false}
            {:type     :hpm-capabilities-rsp,
             :command  62,
             :function 45,
             :seq-no   2,
             :a?       false,
             :e?       false}
            {:type           :device-id-req,
             :command        1,
             :function       6,
             :seq-no         3,
             :session-seq-no 5,
             :a?             false,
             :e?             false}
            {:type     :device-id-rsp,
             :command  1,
             :function 7,
             :seq-no   3,
             :a?       false,
             :e?       false}
            {:response    45,
             :session-seq 6,
             :signature   0,
             :a?          false,
             :command     0,
             :type        :picmg-properties-req,
             :e?          false,
             :function    44,
             :seq-no      4}
            {:type :picmg-properties-rsp, :function 45, :command 0}
            {:type      :vso-capabilities-req,
             :command   0,
             :function  44,
             :seq-no    5,
             :response  45,
             :signature 3,
             :a?        false,
             :e?        false}
            {:type :picmg-properties-rsp, :function 45, :command 0}
            {:type           :chassis-status-req,
             :command        1,
             :function       0,
             :seq-no         6,
             :session-seq-no 8,
             :a?             false,
             :e?             false}
            {:type           :chassis-status-rsp,
             :command        1,
             :function       1,
             :seq-no         6,
             :session-seq-no 6,
             :a?             false,
             :e?             false}
            {:type           :rmcp-close-session-req,
             :command        60,
             :function       6,
             :seq-no         7,
             :session-seq-no 9,
             :a?             false,
             :e?             false,
             :session-seq    9}
            {:type     :rmcp-close-session-rsp,
             :command  60,
             :function 7,
             :seq-no   7,
             :a?       false,
             :e?       false}]
           res))))

(deftest test-decoder-cipher-3
  (let [b-array (take 8 (u/create-rmcp-stream "cipher-3.hex"))
        res     (mapv #(sut/decode {:auth-codec :rmcp-rakp-hmac-sha1
                                    :conf-codec :rmcp-rakp-1-aes-cbc-128-confidentiality} %) b-array)]
    (is (=       [{:type :get-channel-auth-cap-req, :command 56, :function 6}          
           {:type :get-channel-auth-cap-rsp, :command 56, :function 7}
           {:payload-type 16,
            :integ-codec :rmcp-rakp-1-hmac-sha1-96-integrity,
            :a? false,
            :type :open-session-request,
            :e? false,
            :c 1,
            :auth-codec :rmcp-rakp-hmac-sha1,
            :remote-sid 2695013284,
            :rolem 0,
            :conf-codec :rmcp-rakp-1-aes-cbc-128-confidentiality,
            :i 1,
            :a 1}
           {:type :open-session-response,
            :payload-type 17,
            :server-sid 1794,
            :remote-sid 2695013284,
            :rolem 0,
            :auth-codec :rmcp-rakp-hmac-sha1,
            :integ-codec :rmcp-rakp-1-hmac-sha1-96-integrity,
            :conf-codec :rmcp-rakp-1-aes-cbc-128-confidentiality}
           {:type :rmcp-rakp-1,
            :payload-type 18,
            :a? false,
            :e? false,
            :unamem "ADMIN",
            :remote-rn
            [65 69 218 159 110 213 102 167 0 0 238 14 229 117 167 176]}
           {:type :rmcp-rakp-2,
            :payload-type 19,
            :server-guid
            [161 35 69 103 137 171 205 239 161 35 69 103 137 171 205 239],
            :server-rn [74 123 83 211 243 11 250 190 126 105 53 3 214 148 24 69],
            :server-kec [162 180 109 108 70 7 197 189 102 53 109 71 174 121 173 122 141 139 100 129],
            :a? false,
            :e? false}
           {:type :rmcp-rakp-3,
            :payload-type 20,
            :a? false,
            :e? false,
            :remote-kec
            [255 197 199 229 30 50 81 233 18 34 86 94 11 61 254 242 146 211 251 226]}
           {:type :rmcp-rakp-4, :payload-type 21, :a? false, :e? false}]
      res))))
