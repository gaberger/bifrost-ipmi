(ns ipmi-aleph.fsm-test
  (:require [clojure.test :refer [deftest is testing use-fixtures]]
            [automat.core :as a]
            [mockery.core :refer [with-mocks]]
            [ipmi-aleph.test-payloads :refer :all]
            [ipmi-aleph.codec :as c]
            [ipmi-aleph.test-payloads :refer :all]
            [ipmi-aleph.state-machine :refer [ipmi-fsm ipmi-handler]]
            [taoensso.timbre :as log]))

(defn mock-IPMI-responses [f]
  (with-mocks
    [rmcp-close
     {:target :ipmi-aleph.state-machine/send-rmcp-close-response
      :return nil}
     send-auth-cap-response
     {:target :ipmi-aleph.state-machine/send-auth-cap-response
      :return nil}
     send-open-session-response
     {:target :ipmi-aleph.state-machine/send-open-session-response
      :return nil}
     send-rakp-2-response
     {:target :ipmi-aleph.state-machine/send-rakp-2-response
      :return nil}
     send-rakp-4-response
     {:target :ipmi-aleph.state-machine/send-rakp-4-response
      :return nil}
     send-set-session-priv-level-response
     {:target :ipmi-aleph.state-machine/send-set-session-priv-level-response
      :return nil}
     send-pong
     {:target :ipmi-aleph.state-machine/send-pong
      :return nil}]
    (f)))

(use-fixtures
  :each
  mock-IPMI-responses)

(deftest test-fsm
  (testing "test-fsm"
    (let [fsm (a/compile ipmi-fsm ipmi-handler)
          adv (partial a/advance fsm)]
      (is (= {}
             (-> nil
                 (adv (c/rmcp-decode (byte-array (:get-channel-auth-cap-req rmcp-payloads))))
                 (adv (c/rmcp-decode (byte-array (:open-session-request rmcp-payloads))))
                 (adv (c/rmcp-decode (byte-array (:rmcp-rakp-1 rmcp-payloads))))
                 (adv (c/rmcp-decode (byte-array (:rmcp-rakp-3 rmcp-payloads))))
                 (adv (c/rmcp-decode (byte-array (:set-sess-prv-level-req rmcp-payloads))))
                 (adv (c/rmcp-decode (byte-array (:rmcp-close-session-req rmcp-payloads))))
                 (adv (c/rmcp-decode (byte-array (:get-channel-auth-cap-req rmcp-payloads))))
                 :value))))))


; (deftest test-rmcp-fsm
;   (testing "setup for RMCP+ fsm"
;     (let [fsm [(a/$ :init)
;                [:asf-ping (a/$ :asf-ping)
;                 :asf-pong
;                 :get-channel-auth-cap-req
;                 :get-channel-auth-cap-rsp
;                 :open-session-request
;                 :open-session-response]]
;                  ;:rmcp-rakp-1
;                  ;:rmcp-rakp-2
;                  ;:rmcp-rakp-3
;                 ;:rmcp-rakp-4

;           compiled-fsm (a/compile fsm
;                                   {:signal #(:type (get-message-type %))
;                                    :reducers {:init (fn [state _] (assoc state :last-message []))
;                                               :asf-ping (fn [state input]
;                                                           (log/debug input)
;                                                           (let [s (update-in state [:last-message] conj (get-message-type input))
;                                                                 message-tag (get-in input [:rmcp-class
;                                                                                            :asf-payload
;                                                                                            :asf-message-header
;                                                                                            :message-tag])]
;                                                            (assoc s :message-tag message-tag)))}})



;           adv (partial a/advance compiled-fsm)]
;       (is (= {}
;              (-> nil
;               (adv (rmcp-decode (byte-array (:rmcp-ping rmcp-payloads))))
;               (adv  (rmcp-decode (byte-array (:rmcp-pong rmcp-payloads))))
;               (adv (rmcp-decode (byte-array (:get-channel-auth-cap-req  rmcp-payloads))))
;               ;(adv (rmcp-decode (byte-array (:get-channel-auth-cap-rsp  rmcp-payloads))))
;               ;(adv (rmcp-decode (byte-array (:open-session-request rmcp-payloads))))
;               ;(adv (rmcp-decode (byte-array (:open-session-response rmcp-payloads))))
;               ;(adv (rmcp-decode (byte-array (:rmcp-rakp-1 rmcp-payloads))))
;               #_:accepted?))))))




; (deftest test-echo
;   (testing "ping"
;      (let [fsm [(a/$ :init)
;                 [:asf-ping (a/$ :asf-ping)
;                  :asf-pong]]
;            compiled-fsm (a/compile fsm
;                                   {:signal #(:type (get-message-type %))
;                                    :reducers {:init (fn [state _] (assoc state :last-message []))
;                                               :asf-ping (fn [state input]
;                                                           (log/debug input)
;                                                           (let [message-type (get-message-type input)
;                                                                 message-tag (get-in input [:rmcp-class
;                                                                                            :asf-payload
;                                                                                            :asf-message-header
;                                                                                            :message-tag])
;                                                                 message-update (assoc message-type :message-tag message-tag)]
;                                                            (update-in state [:last-message] conj message-update)))}})




;            advance-fsm (partial a/advance compiled-fsm)
;            ping-message (encode rmcp-header (presence-ping-msg 101))
;            udp-server (start-udp-server 1000)
;            socket (:socket udp-server)]
;         (s/put! socket {:host "localhost", :port 1000, :message ping-message})
;         (is (= "foo"
;                (let [socket-message @(s/take! socket)
;                      sender (:sender socket-message)
;                      address (-> (.getAddress sender) (.getHostAddress))
;                      port (.getPort sender)
;                      message (:message socket-message)
;                      decoded-message (decode rmcp-header message)]
;                 (advance-fsm nil decoded-message))))
;         (s/close! socket))))


(comment
  {:version 6, :reserved 0, :sequence 255,
   :rmcp-class {:asf-payload {:iana-enterprise-number 4542,
                              :asf-message-header {:asf-message-type 128,
                                                   :message-tag 196,
                                                   :reserved 0, :data-length 0}}}})
