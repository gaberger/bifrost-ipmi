(ns ipmi-aleph.fsm-test
  (:require [clojure.test :refer [deftest is testing use-fixtures]]
            [automat.core :as a]
            [mockery.core :refer [with-mocks with-mock]]
            [ipmi-aleph.test-payloads :refer :all]
            [gloss.io :refer [encode decode]]
            [ipmi-aleph.codec :refer [compile-codec]]
            [ipmi-aleph.test-payloads :refer :all]
            [ipmi-aleph.enc-payloads-test :refer :all]
            [ipmi-aleph.state-machine :refer [ipmi-fsm ipmi-handler]]
            ))


(defn mock-send [f]
    (with-mocks
      [send-message {:target :ipmi-aleph.state-machine/send-message
                     :return true
                     :side-effect #(println "Mock: send-message")}
      get-session-state {:target :ipmi-aleph.state-machine/get-session-state
                         :return {:host "127.0.0.1" :port 54123}
                         :side-effect #(println "Mock: get-session-state")}]
      #(send-message %)
      #(get-session-state %)))

(use-fixtures
  :each
  mock-send)

(deftest test-fsm-handlers
  (let [fsm (a/compile ipmi-fsm ipmi-handler)
        adv (partial a/advance fsm)]
      (testing "test no auth"
        (let [ipmi-decode (partial decode (compile-codec))
              result      (-> nil
                              (adv  (ipmi-decode (byte-array (:get-channel-auth-cap-req rmcp-payloads))))
                              (adv (ipmi-decode (byte-array (:open-session-request rmcp-payloads))))
                              (adv (ipmi-decode (byte-array (:rmcp-rakp-1 rmcp-payloads))))
                              (adv (ipmi-decode (byte-array (:rmcp-rakp-3 rmcp-payloads))))
                              (adv (ipmi-decode (byte-array (:set-sess-prv-level-req rmcp-payloads))))
                              (adv (ipmi-decode (byte-array (:chassis-status-req rmcp-payloads))))
                              (adv (ipmi-decode (byte-array (:chassis-reset-req rmcp-payloads))))
                              (adv (ipmi-decode (byte-array (:device-id-req rmcp-payloads))))
                              (adv (ipmi-decode (byte-array (:device-id-req rmcp-payloads))))
                              (adv (ipmi-decode (byte-array (:rmcp-close-session-req rmcp-payloads)))))]
                                        ;(log/debug result)
          (is (and
               (true?
                (:accepted? result))
               (= 0
                (:state-index result))))))
      (testing "test auth sha-1"
        (let [ipmi-decode (partial decode (compile-codec :rmcp-rakp-hmac-sha1))
              result      (-> nil
                              (adv (ipmi-decode (byte-array (:get-channel-auth-cap-req  rmcp-payloads))))
                              (adv (ipmi-decode (byte-array (:open-session-request rmcp-payloads))))
                              (adv (ipmi-decode (byte-array (:rmcp-rakp-1  rmcp-enc-payloads-cipher-1))))
                              (adv (ipmi-decode (byte-array (:rmcp-rakp-3 rmcp-payloads))))
                              (adv (ipmi-decode (byte-array (:device-id-req rmcp-payloads))))
                              (adv (ipmi-decode (byte-array (:set-sess-prv-level-req rmcp-payloads))))
                              (adv (ipmi-decode (byte-array (:rmcp-close-session-req rmcp-payloads)))))]
          (is (and
               (true?
                (:accepted? result))
               (= 0
                 (:state-index result))))))
      (testing "test PING"
        (let [ipmi-decode (partial decode (compile-codec))
              result      (-> nil
                              (adv  (ipmi-decode (byte-array (:rmcp-ping rmcp-payloads)))))]
          (is (true?
               (:accepted? result)))))))


