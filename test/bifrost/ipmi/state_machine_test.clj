(ns bifrost.ipmi.state-machine-test
  (:require [clojure.test :refer :all]
            [bifrost.ipmi.codec :refer [compile-codec] :as c]
            [bifrost.ipmi.state-machine :refer [bind-server-fsm]]
            [gloss.io :refer [encode contiguous] :as i]
            [bifrost.ipmi.utils :refer [safe]]
            [bifrost.ipmi.test-payloads :refer :all]
            [bifrost.ipmi.registrar :refer [reboot-server]]
            [bifrost.ipmi.decode :refer [decode-message]]
            [bifrost.ipmi.handlers :as h]
            [bifrost.ipmi.state-machine :as state]
            [automat.core :as a]
            [mockery.core :refer [with-mock]]
            [clj-uuid :as uuid]
            [bifrost.ipmi.decode :as decode]
            [taoensso.timbre :as log]))

(defn mock-send [f]
  (with-mock _
    {:target :bifrost.ipmi.state-machine/send-udp
     :return true
     :side-effect #(println "Mock: send-udp")}
    (f)))

(defn mock-get [f]
  (with-mock _
    {:target  :bifrost.ipmi.state-machine/get-session-state
     :return  {:host "127.0.0.1" :port 54123}
     :side-effect #(println "Mock: get-session-state")}
    (f)))

(defn mock-packet-reset [f]
  (with-mock _
    {:target  :bifrost.ipmi.registrar/reboot-server
     :return  true
     :side-effect #(println "Mock: Reboot")}
    (f)))

(defn mock-lookup-password-key [f]
  (with-mock _
    {:target  :bifrost.ipmi.registrar/lookup-password-key
     :return  "ADMIN"}
    (f)))

(defn mock-get-device-id-bytes [f]
  (with-mock _
    {:target  :bifrost.ipmi.registrar/get-device-id-bytes
     :return  [00 00 00 00 00 00 00 00]}
    (f)))

(defn mock-lookup-userid [f]
  (with-mock _
    {:target  :bifrost.ipmi.registrar/lookup-userid
     :return  true
     :side-effect #(println "Mock: Reboot")}
    (f)))

(defn mock-get-driver-device-id [f]
  (with-mock _
    {:target  :bifrost.ipmi.registrar/get-driver-device-id
     :return  true
     :side-effect #(println "Mock: Reboot")}
    (f)))

(use-fixtures
  :each
  mock-send mock-get
  mock-packet-reset
  mock-lookup-password-key
  mock-lookup-userid
  mock-get-device-id-bytes
  mock-get-driver-device-id)

(defn create-client-stream []
  [{:message (contiguous (encode (c/compile-codec 0) (h/auth-capabilities-request-msg)))}
   {:message (contiguous (encode (c/compile-codec 0) (h/rmcp-open-session-response-msg {:sidc 0 :sidm 0 :a 0 :i 0 :c 0})))}
   {:message (contiguous (encode (c/compile-codec 0) (h/rmcp-rakp-2-response-msg {:sidm 0 :rc [0] :guidc [0] :status 0})))}
   {:message (contiguous (encode (c/compile-codec 0) (h/rmcp-rakp-4-response-msg {:sidm 0})))}
   {:message (contiguous (encode (c/compile-codec 0)
                                 (h/set-session-priv-level-rsp-msg {:sid 0 :session-seq-no 0 :seq-no 0 :e 0 :a 0})))}
   {:message (contiguous (encode (c/compile-codec 0)
                                 (h/set-session-priv-level-rsp-msg {:sid 0 :session-seq-no 0 :seq-no 0 :e 0 :a 0})))}
   {:message (contiguous (encode (c/compile-codec 0)
                                 (h/rmcp-close-response-msg {:sid 0 :seq 0 :seq-no 0 :a 0 :e 0})))}])

(defn create-server-stream []
  [{:message (byte-array (:get-channel-auth-cap-req rmcp-payloads))}
   {:message (byte-array (:open-session-request rmcp-payloads))}
   {:message (byte-array (:rmcp-rakp-1 rmcp-payloads))}
   {:message (byte-array (:rmcp-rakp-3 rmcp-payloads))}
   {:message (byte-array (:hpm-capabilities-req rmcp-payloads))}
   {:message (byte-array (:set-sess-prv-level-req rmcp-payloads))}
   {:message (byte-array (:chassis-status-req rmcp-payloads))}
   {:message (byte-array (:chassis-reset-req rmcp-payloads))}
   {:message (byte-array (:device-id-req rmcp-payloads))}
   {:message (byte-array (:rmcp-close-session-req rmcp-payloads))}])

(deftest test-client-state-machine
  #_(testing "Test Client Stream"
    (let [result  (transduce (decode/decode-xf (state/bind-client-fsm)) conj (create-client-stream))]
      (is (true?
           (:accepted? result)))))
  #_(testing "Test Server Stream"
    (let [result  (transduce (decode/decode-xf (state/bind-server-fsm)) conj (create-server-stream))]
      (is (true?
           (:accepted? result))))))


#_(deftest test-fsm-handlers
    (testing "test crypto 0"
      (with-mock m
        {:target :bifrost.ipmi.codec/get-authentication-codec
         :return :rmcp-rakp}
        (let [codec (compile-codec 0)
              ipmi-decode (partial decode codec)
              adv         (bind-server-fsm)
              result      (-> nil
                              (adv (decode-message codec {:message (byte-array (:get-channel-auth-cap-req rmcp-payloads))}))
                              (adv (decode-message codec {:message (byte-array (:open-session-request rmcp-payloads))}))
                              (adv (decode-message codec {:message (byte-array (:rmcp-rakp-1 rmcp-payloads))}))
                              (adv (decode-message codec {:message (byte-array (:rmcp-rakp-3 rmcp-payloads))}))
                              (adv (decode-message codec {:message (byte-array (:hpm-capabilities-req rmcp-payloads))}))
                              (adv (decode-message codec {:message (byte-array (:set-sess-prv-level-req rmcp-payloads))}))
                              (adv (decode-message codec {:message (byte-array (:chassis-status-req rmcp-payloads))}))
                              (adv (decode-message codec {:message (byte-array (:chassis-reset-req rmcp-payloads))}))
                              (adv (decode-message codec {:message (byte-array (:device-id-req rmcp-payloads))}))
                              (adv (decode-message codec {:message (byte-array (:rmcp-close-session-req rmcp-payloads))})))]
          (is (and
               (true?
                (:accepted? result))
               (= 0)
               (:state-index
                result))))))
    (testing "test crypto 1"
      (with-mock m
        {:target :bifrost.ipmi.codec/get-authentication-codec
         :return :rmcp-rakp-hmac-sha1}
        (let [codec (compile-codec 0)
              adv         (bind-server-fsm)
              result      (-> nil
                              (adv (decode-message codec {:message (byte-array (:get-channel-auth-cap-req rmcp-payloads))}))
                              (adv (decode-message codec {:message (byte-array (:open-session-request rmcp-payloads-cipher-1))}))
                              (adv (decode-message codec {:message (byte-array (:rmcp-rakp-1 rmcp-payloads-cipher-1))}))
                              (adv (decode-message codec {:message (byte-array (:rmcp-rakp-3 rmcp-payloads-cipher-1))}))
                              (adv (decode-message codec {:message (byte-array (:hpm-capabilities-req rmcp-payloads))}))
                              (adv (decode-message codec {:message (byte-array (:set-sess-prv-level-req rmcp-payloads))}))
                              (adv (decode-message codec {:message (byte-array (:chassis-status-req rmcp-payloads))}))
                              (adv (decode-message codec {:message (byte-array (:chassis-reset-req rmcp-payloads))}))
                              (adv (decode-message codec {:message (byte-array (:device-id-req rmcp-payloads))}))
                              (adv (decode-message codec {:message (byte-array (:rmcp-close-session-req rmcp-payloads))})))]
          (is (and
               (true?
                (:accepted? result))
               (= 0)
               (:state-index
                result)))))))
