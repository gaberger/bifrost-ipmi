(ns ipmi-aleph.message-handler-test
  (:require [clojure.test :refer :all]
            [gloss.io :refer :all]
            [mockery.core :refer [with-mocks with-mock]]
            [ipmi-aleph.test-payloads :refer :all]
            [ipmi-aleph.enc-payloads-test :refer [ rmcp-enc-payloads-cipher-1]]
            [ipmi-aleph.state-machine :refer [fsm-state fsm]]
            [ipmi-aleph.handlers :as h]
            [ipmi-aleph.codec :refer :all]
            [ipmi-aleph.core :refer [message-handler]]
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



(use-fixtures :each mock-send)

(deftest test-message-handler-noauth
  (testing "message-handler-accepted"
      (reset! fsm-state nil)
      (let [fsm (fsm)
            payload [;{:message (byte-array (:rmcp-ping rmcp-payloads))}
                     {:message (byte-array (:get-channel-auth-cap-req rmcp-payloads))}
                     {:message (byte-array (:open-session-request rmcp-payloads))}
                     {:message (byte-array (:rmcp-rakp-1 rmcp-payloads))}
                     {:message (byte-array (:rmcp-rakp-3 rmcp-payloads))}
                     {:message (byte-array (:device-id-req rmcp-payloads))}
                     {:message (byte-array (:set-sess-prv-level-req rmcp-payloads))}
                     {:message (byte-array (:rmcp-close-session-req rmcp-payloads))}]]
        (-> (map #(message-handler fsm %) payload) first)
        (is (true?
             (:accepted? @fsm-state)))))
  (testing "message-handler-not-accepted"
      (reset! fsm-state nil)
      (let [fsm (fsm)
            payload [{:message (byte-array (:rmcp-ping rmcp-payloads))}
                     {:message (byte-array (:get-channel-auth-cap-req rmcp-payloads))}
                     {:message (byte-array (:open-session-request rmcp-payloads))}
                     {:message (byte-array (:rmcp-rakp-1 rmcp-payloads))}
                     {:message (byte-array (:rmcp-rakp-3 rmcp-payloads))}
                     {:message (byte-array (:device-id-req rmcp-payloads))}
                     {:message (byte-array (:set-sess-prv-level-req rmcp-payloads))}]]
        (-> (map #(message-handler fsm %) payload) first)
        (is (false?
             (:accepted? @fsm-state))))))

(deftest test-message-handler-sha1-hmac
  (testing "message-handler-accepted"
      (reset! fsm-state nil)
      (let [fsm (fsm)
            payload [;{:message (byte-array (:rmcp-ping rmcp-payloads))}
                     {:message (byte-array (:get-channel-auth-cap-req  rmcp-payloads))}
                     {:message (byte-array (:open-session-request rmcp-payloads))}
                     {:message (byte-array (:rmcp-rakp-1  rmcp-enc-payloads-cipher-1))}
                     {:message (byte-array (:rmcp-rakp-3 rmcp-payloads))}
                     {:message (byte-array (:device-id-req rmcp-payloads))}
                     {:message (byte-array (:set-sess-prv-level-req rmcp-payloads))}
                     {:message (byte-array (:rmcp-close-session-req rmcp-payloads))}]]
        (-> (map #(message-handler fsm %) payload) first)
        (is (true?
             (:accepted? @fsm-state))))))
