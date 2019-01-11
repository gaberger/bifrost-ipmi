(ns ipmi-aleph.fsm-test
  (:require [clojure.test :refer [deftest is testing use-fixtures]]
            [automat.core :as a]
            [mockery.core :refer [with-mocks with-mock]]
            [ipmi-aleph.test-payloads :refer :all]
            [ipmi-aleph.codec :as c]
            [ipmi-aleph.test-payloads :refer :all]
            [ipmi-aleph.state-machine :refer [ipmi-fsm ipmi-handler]]
            [taoensso.timbre :as log]))

(log/refer-timbre)
(log/merge-config! {:appenders {:println {:enabled? true}}})

(defn mock-IPMI-responses [f]
  (with-mocks
    [send-message
     {:target :ipmi-aleph.state-machine/send-message
      :return true}])
  (f))
;; (defn mock-IPMI-responses [f]
;;   (with-mocks
;;     [rmcp-close
;;      {:target :ipmi-aleph.state-machine/send-rmcp-close-response
;;       :return (fn [& _] (log/info "send-rmcp-close") nil)}
;;      send-auth-cap-response
;;      {:target :ipmi-aleph.state-machine/send-auth-cap-response
;;       :return (fn [& _] (log/info "send-auth-cap-response") nil)}
;;      send-open-session-response
;;      {:target :ipmi-aleph.state-machine/send-open-session-response
;;       :return (fn [& _] (log/info "send-open-session-response") nil)}
;;      send-rakp-2-response
;;      {:target :ipmi-aleph.state-machine/send-rakp-2-response
;;       :return (fn [& _] (log/info "send-rakp-2-response") nil)}
;;      send-rakp-4-response
;;      {:target :ipmi-aleph.state-machine/send-rakp-4-response
;;       :return (fn [& _] (log/info "send-rakp-4response") nil)}
;;      send-set-session-priv-level-response
;;      {:target :ipmi-aleph.state-machine/send-set-session-priv-level-response
;;       :return (fn [& _] (log/info "send-session-priv-level-response") nil)}
;;      send-pong
;;      {:target :ipmi-aleph.state-machine/send-pong
;;       :return (fn [& _] (log/info "send-pong") nil)}
;;      send-chassis-response
;;      {:target :ipmi-aleph.state-machine/send-chassis-status-response
;;       :return (fn [& _] (log/info "send-chassis-status-response") nil)}]
;;     (f)))

(use-fixtures
  :each
  mock-IPMI-responses)

;; (deftest test-fsm
;;   (testing "test-fsm"
;;     (let [fsm (a/compile ipmi-fsm ipmi-handler)
;;           adv (partial a/advance fsm)]
;;       (is (= {:last-message [{:type :get-channel-auth-cap-req, :message 56}]}
;;              (-> nil
;;                  (adv (c/rmcp-decode (byte-array (:get-channel-auth-cap-req rmcp-payloads))))
;;                  (adv (c/rmcp-decode (byte-array (:open-session-request rmcp-payloads))))
;;                  (adv (c/rmcp-decode (byte-array (:rmcp-rakp-1 rmcp-payloads))))
;;                  (adv (c/rmcp-decode (byte-array (:rmcp-rakp-3 rmcp-payloads))))
;;                  (adv (c/rmcp-decode (byte-array (:set-sess-prv-level-req rmcp-payloads))))
;;                  (adv (c/rmcp-decode (byte-array (:chassis-status-req rmcp-payloads))))
;;                  (adv (c/rmcp-decode (byte-array (:rmcp-close-session-req rmcp-payloads))))
;;                  (adv (c/rmcp-decode (byte-array (:get-channel-auth-cap-req rmcp-payloads))))
;;                  :accepted?))))))

(deftest test-fsm-handlers
  (testing "test 2"
    (let [fsm  (a/compile ipmi-fsm ipmi-handler)
          adv (partial a/advance fsm)]
      (with-mock mock
        {:target :ipmi-aleph.state-machine/send-message
         :return true}
        (let [result (-> nil
                         (adv  (c/rmcp-decode (byte-array (:get-channel-auth-cap-req rmcp-payloads))))
                         (adv (c/rmcp-decode (byte-array (:open-session-request rmcp-payloads))))
                         (adv (c/rmcp-decode (byte-array (:rmcp-rakp-1 rmcp-payloads))))
                         (adv (c/rmcp-decode (byte-array (:rmcp-rakp-3 rmcp-payloads))))
                         (adv (c/rmcp-decode (byte-array (:set-sess-prv-level-req rmcp-payloads))))
                         (adv (c/rmcp-decode (byte-array (:chassis-status-req rmcp-payloads))))
                         (adv (c/rmcp-decode (byte-array (:device-id-req rmcp-payloads))))
                         (adv (c/rmcp-decode (byte-array (:device-id-req rmcp-payloads))))
                         (adv (c/rmcp-decode (byte-array (:rmcp-close-session-req rmcp-payloads)))))]
          ;(log/debug result)
          (is (true?
               (:accepted?

                result))))))))

