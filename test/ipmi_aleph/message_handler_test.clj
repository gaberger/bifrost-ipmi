(ns ipmi-aleph.message-handler-test
  (:require [clojure.test :refer :all]
            [gloss.io :refer :all]
            [mockery.core :refer [with-mocks with-mock]]
            [ipmi-aleph.test-payloads :refer :all]
            [ipmi-aleph.state-machine :refer [fsm-state]]
            [ipmi-aleph.handlers :as h]
            [ipmi-aleph.codec :refer :all]
            [ipmi-aleph.core :refer :all]
            [taoensso.timbre :as log]))

(deftest test-message-handler
  (testing "message-handler-accepted"
    (with-mocks
      [send-message {:target :ipmi-aleph.state-machine/send-message :return true}
       get-session-state {:target :ipmi-aleph.state-machine/get-session-state :return {:host "127.0.0.1" :port 54123}}]
      (reset! fsm-state nil)
      (let [fsm (fsm)
            payload [;{:message (byte-array (:rmcp-ping rmcp-payloads))}
                     {:message (byte-array (:get-channel-auth-cap-req rmcp-payloads))}
                     {:message (byte-array (:open-session-request rmcp-payloads))}
                     {:message (byte-array (:rmcp-rakp-1 rmcp-payloads))}
                     {:message (byte-array (:rmcp-rakp-3 rmcp-payloads))}
                     {:message (byte-array (:device-id-req rmcp-payloads))}
                     {:message (byte-array (:set-sess-prv-level-req rmcp-payloads))}
                     {:message (byte-array (:rmcp-close-session-req rmcp-payloads))}
                     ]]
        (-> (map #(message-handler fsm %) payload) first)
        (log/debug @fsm-state)
        (is (true?
             (:accepted? @fsm-state))))))
  (testing "message-handler-not-accepted"
    (with-mocks
      [send-message {:target :ipmi-aleph.state-machine/send-message :return true}
       get-session-state {:target :ipmi-aleph.state-machine/get-session-state :return {:host "127.0.0.1" :port 54123}}]
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
        (log/debug @fsm-state)
        (is (false?
             (:accepted? @fsm-state)))))))
