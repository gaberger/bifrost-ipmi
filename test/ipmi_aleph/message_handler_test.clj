(ns ipmi-aleph.message-handler-test
  (:require [clojure.test :refer :all]
            [gloss.io :refer :all]
            [mockery.core :refer [with-mocks with-mock]]
            [ipmi-aleph.test-payloads :refer :all]
            [ipmi-aleph.state-machine :refer [bind-fsm fsm-state]]
            [ipmi-aleph.handlers :as h]
            [ipmi-aleph.codec :refer :all]
            [ipmi-aleph.core :refer [message-handler peer-set chan-map]]
            [taoensso.timbre :as log]))

(defn mock-send [f]
  (with-mock _
    {:target :ipmi-aleph.state-machine/send-udp
     :return true
     :side-effect #(println "Mock: send-udp")}
    (f)))

(defn mock-get [f]
  (with-mock _
    {:target  :ipmi-aleph.state-machine/get-session-state
     :return  {:host "127.0.0.1" :port 4000}
     :side-effect #(log/debug "Mock: get-session-state ")}
    (f)))

(use-fixtures
  :each
  mock-send mock-get)

(deftest test-message-handler-noauth
  (testing "message-handler-accepted"
    (reset! peer-set #{})
    (reset! chan-map {})
    (let [payload [;{:message (byte-array (:rmcp-ping rmcp-payloads))}
                   {:message (byte-array (:get-channel-auth-cap-req rmcp-payloads))}
                   {:message (byte-array (:open-session-request rmcp-payloads))}
                   {:message (byte-array (:rmcp-rakp-1 rmcp-payloads))}
                   {:message (byte-array (:rmcp-rakp-3 rmcp-payloads))}
                   {:message (byte-array (:device-id-req rmcp-payloads))}
                   {:message (byte-array (:set-sess-prv-level-req rmcp-payloads))}
                   {:message (byte-array (:rmcp-close-session-req rmcp-payloads))}]]
      (doall
       (map #(message-handler %) payload))
      (is (empty? @peer-set))
      (is (empty? @chan-map))
      (is {}
          (-> (get @chan-map (first @peer-set)) :state :accepted?)))))

      ;   @peer-set))))
          ;(-> (get @chan-map (first @peer-set)) :state :accepted?)))))

                                        ;(log/debug @chan-map)
                                        ;(is (true?
                                        ;    (:accepted? @chan-map)))))
;; #_(testing "message-handler-not-accepted"
;;     (let [fsm (bind-fsm)
;;           payload [{:message (byte-array (:rmcp-ping rmcp-payloads))}
;;                    {:message (byte-array (:get-channel-auth-cap-req rmcp-payloads))}
;;                    {:message (byte-array (:open-session-request rmcp-payloads))}
;;                    {:message (byte-array (:rmcp-rakp-1 rmcp-payloads))}
;;                    {:message (byte-array (:rmcp-rakp-3 rmcp-payloads))}
;;                    {:message (byte-array (:device-id-req rmcp-payloads))}
;;                    {:message (byte-array (:set-sess-prv-level-req rmcp-payloads))}]]
;;       (-> (map #(message-handler fsm %) payload) first)
;;       (is (false?
;;            (:accepted? @fsm-state)))))


(deftest test-message-handler-sha1-hmac
  (testing "message-handler-accepted"
    (let [payload [;{:message (byte-array (:rmcp-ping rmcp-payloads))}
                   {:message (byte-array (:get-channel-auth-cap-req  rmcp-payloads))}
                   {:message (byte-array (:open-session-request rmcp-payloads-cipher-1))}
                   {:message (byte-array (:rmcp-rakp-1  rmcp-payloads-cipher-1))}
                   {:message (byte-array (:rmcp-rakp-3 rmcp-payloads-cipher-1))}
                   {:message (byte-array (:device-id-req rmcp-payloads))}
                   {:message (byte-array (:set-sess-prv-level-req rmcp-payloads))}
                   {:message (byte-array (:rmcp-close-session-req rmcp-payloads))}]]
     ; (-> (map #(message-handler %) payload) first)
     ; (is (true?
     ;      (:accepted? @fsm-state))))
      (doall
       (-> (map #(message-handler %) payload) first))
      (is (empty? @peer-set))
      (is (empty? @chan-map)))))
                                        ;   @peer-set))))
                                        ;(-> (get @chan-map (first @peer-set)) :state :accepted?)))))
