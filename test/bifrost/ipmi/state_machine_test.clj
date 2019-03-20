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
            [clojure.core.async :as async]
            [mockery.core :refer [with-mock]]
            [clj-uuid :as uuid]
            [bifrost.ipmi.decode :as decode]
            [taoensso.timbre :as log]))

(defn mock-send-message [f]
  (with-mock _
    {:target :bifrost.ipmi.state-machine/send-message
     :return true
     :side-effect #(println "Mock: send-message")}
    (f)))

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
  mock-send
  mock-send-message
  mock-get
  mock-packet-reset
  mock-lookup-password-key
  mock-lookup-userid
  mock-get-device-id-bytes
  mock-get-driver-device-id)

(defn create-client-stream []
  [(contiguous (encode (c/compile-codec 0) (h/auth-capabilities-response-msg {:seq 0})))
   (contiguous (encode (c/compile-codec 0) (h/rmcp-open-session-response-msg {:sidc 0 :sidm 0 :a 0 :i 0 :c 0})))
   (contiguous (encode (c/compile-codec 0) (h/rmcp-rakp-2-response-msg {:sidm 0 :rc [0] :guidc [0] :status 0})))
   (contiguous (encode (c/compile-codec 0) (h/rmcp-rakp-4-response-msg {:sidm 0})))
   (contiguous (encode (c/compile-codec 0)
                       (h/set-session-priv-level-rsp-msg {:sid 0 :session-seq-no 0 :seq-no 0 :e 0 :a 0})))
   (contiguous (encode (c/compile-codec 0)
                       (h/set-session-priv-level-rsp-msg {:sid 0 :session-seq-no 0 :seq-no 0 :e 0 :a 0})))
   (contiguous (encode (c/compile-codec 0) (h/chassis-reset-response-msg {:sid 0 :seq 0 :seq-no 0 :status 0 :e 0 :a 0})))
   (contiguous (encode (c/compile-codec 0)
                       (h/rmcp-close-response-msg {:sid 0 :seq 0 :seq-no 0 :a 0 :e 0})))])

(defn create-server-stream []
  [(byte-array (:get-channel-auth-cap-req rmcp-payloads))
   (byte-array (:open-session-request rmcp-payloads))
   (byte-array (:rmcp-rakp-1 rmcp-payloads))
   (byte-array (:rmcp-rakp-3 rmcp-payloads))
   (byte-array (:hpm-capabilities-req rmcp-payloads))
   (byte-array (:set-sess-prv-level-req rmcp-payloads))
   (byte-array (:device-id-req rmcp-payloads))
   (byte-array (:chassis-status-req rmcp-payloads))
   (byte-array (:chassis-reset-req rmcp-payloads))
   (byte-array (:rmcp-close-session-req rmcp-payloads))])

(deftest test-server-state-machine
  (testing "Test Server Stream"
    (let [command-chan (async/chan)
          decode-chan  (decode/make-server-decoder (state/bind-server-fsm))]
      (async/pipe decode-chan command-chan)
      (async/onto-chan decode-chan (create-server-stream))
      (let [retval (async/<!! (async/into [] command-chan))
            return  (mapv #(update-in % [:state :state] (fn [s] (apply dissoc s [:rc :server-sid]))) retval)]
        (is (= [{:type :command,
                 :state
                 {:state
                  {:guidc [0 0 0 0 0 0 0 0],
                   :auth-codec :rmcp-rakp,
                   :remote-sid 2695013284,
                   :rolem 4,
                   :conf-codec :rmcp-rakp-1-none-confidentiality,
                   :unamem "admin",
                   :rm [207 101 36 153 230 186 137 68 79 143 233 101 74 214 188 76]}},
                 :message
                 {:type :chassis-status-req,
                  :command 1,
                  :function 0,
                  :seq-no 6,
                  :session-seq-no 21,
                  :a? false,
                  :e? false}}
                {:type :command,
                 :state
                 {:state
                  {:guidc [0 0 0 0 0 0 0 0],
                   :auth-codec :rmcp-rakp,
                   :remote-sid 2695013284,
                   :rolem 4,
                   :conf-codec :rmcp-rakp-1-none-confidentiality,
                   :unamem "admin",
                   :rm [207 101 36 153 230 186 137 68 79 143 233 101 74 214 188 76]}},
                 :message
                 {:type :chassis-reset-req,
                  :command 2,
                  :function 0,
                  :seq-no 6,
                  :session-seq-no 21,
                  :a? false,
                  :e? false}}]
               return))))))

(deftest test-client-state-machine
  (testing "Test Client Stream"
    (let [command-chan (async/chan)
          decode-chan  (decode/make-client-decoder (state/bind-client-fsm))]
      (async/pipe decode-chan command-chan)
      (async/onto-chan decode-chan (create-client-stream))
      (let [retval (async/<!! (async/into [] command-chan))]
        (is (=     [{:type :command,
                     :state {:state {:seq 0}},
                     :message
                     {:type :chassis-reset-rsp,
                      :command 2,
                      :function 2,
                      :seq-no 0,
                      :session-seq-no 0,
                      :a? false,
                      :e? false}}]
                   retval))))))

#_(testing "test crypto 1"
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
              result))))))
