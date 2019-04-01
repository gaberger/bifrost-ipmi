(ns bifrost.ipmi.server-state-machine-test
  (:require [clojure.test :refer :all]
            [bifrost.ipmi.codec :refer [compile-codec] :as c]
            [bifrost.ipmi.server-state-machine :refer [bind-server-fsm]]
            [gloss.io :refer [encode contiguous] :as i]
            [bifrost.ipmi.utils :refer [safe] :as u]
            [bifrost.ipmi.test-payloads :refer :all]
            [bifrost.ipmi.registrar :refer [reboot-server]]
            [bifrost.ipmi.decode :refer [decode-message]]
            [bifrost.ipmi.handlers :as h]
            [bifrost.ipmi.server-state-machine :as state]
            [automat.core :as a]
            [clojure.core.async :as async]
            [mockery.core :refer [with-mock with-mocks]]
            [clj-uuid :as uuid]
            [bifrost.ipmi.decode :as decode]
            [taoensso.timbre :as log]
            [buddy.core.codecs :as codecs]
            [byte-streams :as bs]))

(defn mock-send-message [f]
  (with-mock _
    {:target :bifrost.ipmi.messages/send-message
     :return true
     :side-effect #(log/debug "Mock: send-message")}
    (f)))

(defn mock-send-udp [f]
  (with-mock _
    {:target :bifrost.ipmi.messages/send-udp
     :return true
     :side-effect #(log/debug "Mock: send-udp")}
    (f)))

(defn mock-get-session [f]
  (with-mock _
    {:target  :bifrost.ipmi.decode/get-session-state
     :return  {:host "127.0.0.1" :port 54123}
     :side-effect #(log/debug "Mock: get-session-state")}
    (f)))

(defn mock-packet-reset [f]
  (with-mock _
    {:target  :bifrost.ipmi.registrar/reboot-server
     :return  true
     :side-effect #(log/debug "Mock: Reboot")}
    (f)))

(defn mock-lookup-password-key [f]
  (with-mock _
    {:target  :bifrost.ipmi.registrar/lookup-password-key
     :return  "ADMIN"
     :side-effect #(log/debug "lookup password")}
    (f)))

(defn mock-lookup-userid [f]
  (with-mock _
    {:target  :bifrost.ipmi.registrar/lookup-userid
     :return  true
     :side-effect #(log/debug "Mock: lookup userid")}
    (f)))

(defn mock-get-driver-device-id [f]
  (with-mock _
    {:target  :bifrost.ipmi.registrar/get-driver-device-id
     :return  true
     :side-effect #(log/debug "Mock: get-driver-device-id")}
    (f)))

(use-fixtures
  :each
  mock-send-udp
  mock-send-message
  mock-get-session
  mock-packet-reset
  mock-lookup-password-key
  mock-lookup-userid
  mock-get-driver-device-id)

(deftest test-server-state-machine-cipher-0
  (testing "Test Server Stream Cipher 0"
    (let [command-chan (async/chan)
          decode-chan  (decode/make-server-decoder)]
      (async/pipe decode-chan command-chan)
      (async/onto-chan decode-chan (map #(assoc {} :host-map 1234 :message {:message %}) (u/create-rmcp-server-stream "cipher-0.hex")))
      (let [retval (async/<!! (async/into [] command-chan))
            r      (mapv #(update-in % [:state] (fn [s] (apply dissoc s [:server-rn :server-sid]))) retval)]
        (is (=  [{:type :command,
                  :state
                  {:server-guid [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0],
                   :remote-rn [130 240 106 5 2 196 62 41 251 20 164 150 238 33 47 72],
                   :auth-codec :rmcp-rakp,
                   :remote-sid 2695013284,
                   :rolem nil,
                   :conf-codec :rmcp-rakp-1-none-confidentiality,
                   :unamem "ADMIN"},
                  :message
                  {:a? false,
                   :command 1,
                   :type :chassis-status-req,
                   :e? false,
                   :port 54123,
                   :function 0,
                   :host "127.0.0.1",
                   :seq-no 6,
                   :session-seq-no 8}}]
                r))))))

(deftest test-server-cipher-1
  (testing "Test Server Stream Cipher 1"
    (with-mocks
      [server-rn {:target      :bifrost.ipmi.server-state-machine/create-server-rn!
                  :return      [0x2e 0xf9 0x3b 0x22 0xe3 0x7f 0x8b 0x8a 0x19 0x58 0xf7 0x2c 0x5c 0x01 0x95 0xbe]
                  :side-effect #(log/debug "Mock: create-server-rn")}
       server-guid {:target      :bifrost.ipmi.registrar/get-device-guid-bytes
                    :return      [161 35 69 103 137 171 205 239 161 35 69 103 137 171 205 239]
                    :side-effect #(log/debug "Mock: Calling get-device-id")}
       server-sid {:target :bifrost.ipmi.server-state-machine/create-server-sid!
                   :return 1538}]
      (let  [command-chan (async/chan)
             decode-chan  (decode/make-server-decoder)]
        (async/pipe decode-chan command-chan)
        (async/onto-chan decode-chan (map #(assoc {} :host-map 1234 :message {:message %})
                                          (u/create-rmcp-server-stream "cipher-1.hex")))
        (let [retval (async/<!! (async/into [] command-chan))
              ret    (first (mapv #(update-in % [:state] (fn [s] (apply dissoc s [:server-rn :server-sid]))) retval))
              sik    (vec (get-in ret [:state :sik]))]
          (is (=  [-19 -12 -61 48 -19 -12 -28 -46 -98 -22 -33 113 75 -39 -36 38 -48 -19 58 95]
                  sik)))))))

(deftest test-server-cipher-3
  (testing "Test Server Stream Cipher 3"
    (with-mocks
      [server-rn {:target      :bifrost.ipmi.server-state-machine/create-server-rn!
                  :return      [0x4a 0x7b 0x53 0xd3 0xf3 0x0b 0xfa 0xbe 0x7e 0x69 0x35 0x03 0xd6 0x94 0x18 0x45]
                  :side-effect #(log/debug "Mock: create-server-rn")}
       server-guid {:target      :bifrost.ipmi.registrar/get-device-guid-bytes
                    :return      [161 35 69 103 137 171 205 239 161 35 69 103 137 171 205 239]
                    :side-effect #(log/debug "Mock: Calling get-device-id")}
       server-sid {:target :bifrost.ipmi.server-state-machine/create-server-sid!
                   :return 1538}]
      (let  [command-chan (async/chan)
             decode-chan  (decode/make-server-decoder)]
        (async/pipe decode-chan command-chan)
        (async/onto-chan decode-chan (map #(assoc {} :host-map 1234 :message {:message %})
                                          (u/create-rmcp-server-stream "cipher-3.hex")))
        (let [retval (async/<!! (async/into [] command-chan))
              return (mapv #(update-in % [:state] (fn [s] (apply dissoc s [:server-rn :server-sid]))) retval)]
          (is (=    [{:type :command,
                      :state
                      {:server-guid
                       [161 35 69 103 137 171 205 239 161 35 69 103 137 171 205 239],
                       :sik
                       [90 -49 49 -112 0 92 8 33 42 -109 -98 -103 -127 -22 26 -111 -47 -12 -74 -63],
                       :remote-rn
                       [65 69 218 159 110 213 102 167 0 0 238 14 229 117 167 176],
                       :auth-codec :rmcp-rakp-hmac-sha1,
                       :remote-sid 2695013284,
                       :rolem nil,
                       :conf-codec :rmcp-rakp-1-aes-cbc-128-confidentiality,
                       :sidm-hmac [-32 -126 88 111 14 -88 69 -30 -111 -89 -22 -43],
                       :unamem "ADMIN"},
                      :message
                      {:a? true,
                       :command 1,
                       :type :chassis-status-req,
                       :e? true,
                       :port 54123,
                       :function 0,
                       :host "127.0.0.1",
                       :seq-no 6,
                       :session-seq-no 8}}]
                    return)))))))

(deftest test-client-state-machine-cipher-0
  (testing "Test Client Stream Cipher 0"
    (let [command-chan (async/chan)
          decode-chan  (decode/make-client-decoder)]
      (async/pipe decode-chan command-chan)
      (async/onto-chan decode-chan (map #(assoc {} :host-map 1234 :message {:message %}) (u/create-rmcp-client-stream "cipher-0.hex")))
      (let [retval (async/<!! (async/into [] command-chan))
            r      (mapv #(update-in % [:state] (fn [s] (apply dissoc s [:server-rn :server-sid]))) retval)]
        (is (=     [{:type :command,
                     :state
                     {:server-guid
                      [161 35 69 103 137 171 205 239 161 35 69 103 137 171 205 239],
                      :integ-codec :rmcp-rakp-1-none-integrity,
                      :auth-codec :rmcp-rakp,
                      :server-rn
                      [190 155 123 179 146 211 139 71 34 32 89 0 96 12 126 164],
                      :remote-sid 2695013284,
                      :seq 0,
                      :server-sid 1410,
                      :rolem 0,
                      :conf-codec :rmcp-rakp-1-none-confidentiality},
                     :message
                     {:a? false,
                      :command 1,
                      :type :chassis-status-rsp,
                      :e? false,
                      :port 54123,
                      :function 1,
                      :host "127.0.0.1",
                      :seq-no 6,
                      :session-seq-no 6}}]
                   retval))))))

(deftest test-client-state-machine-cipher-1
  (testing "Test Client Stream Cipher 1"
    (let [command-chan (async/chan)
          decode-chan  (decode/make-client-decoder)]
      (async/pipe decode-chan command-chan)
      (async/onto-chan decode-chan (map #(assoc {} :host-map 1234 :message {:message %}) (u/create-rmcp-client-stream "cipher-1.hex")))
      (let [retval (async/<!! (async/into [] command-chan))
            r      (mapv #(update-in % [:state] (fn [s] (apply dissoc s [:server-rn :server-sid]))) retval)]
        (is (=     [{:type :command,
                     :state
                     {:server-guid
                      [161 35 69 103 137 171 205 239 161 35 69 103 137 171 205 239],
                      :integ-codec :rmcp-rakp-1-none-integrity,
                      :auth-codec :rmcp-rakp-hmac-sha1,
                      :remote-sid 2695013284,
                      :seq 0,
                      :rolem 0,
                      :conf-codec :rmcp-rakp-1-none-confidentiality},
                     :message
                     {:a? false,
                      :command 1,
                      :type :chassis-status-rsp,
                      :e? false,
                      :port 54123,
                      :function 1,
                      :host "127.0.0.1",
                      :seq-no 6,
                      :session-seq-no 6}}]
                   r))))))

(deftest test-client-state-machine-cipher-3
  (testing "Test Client Stream Cipher 3"
    (let [command-chan (async/chan)
          decode-chan  (decode/make-client-decoder)]
      (async/pipe decode-chan command-chan)
      (async/onto-chan decode-chan (map #(assoc {} :host-map 1234 :message {:message %}) (u/create-rmcp-client-stream "cipher-3.hex")))
      (let [retval (async/<!! (async/into [] command-chan))
            r      (mapv #(update-in % [:state] (fn [s] (apply dissoc s [:server-rn :server-sid]))) retval)]
        (is (=       []
                     r))))))
