(ns bifrost.ipmi.new-test
  (:require  [clojure.test :refer :all]
             [gloss.io :refer [encode contiguous] :as i]
             [byte-streams :as bs]
             [automat.core :as a]
             [clojure.core.async :as async]
             [bifrost.ipmi.state-machine :as state]
             [bifrost.ipmi.codec :as c]
             [manifold.stream :as s]
             [bifrost.ipmi.handlers :as h]
             [clojure.core.async :as async]
             [taoensso.timbre :as log]))


(defn create-message-stream []
  (s/->source
   [(contiguous (encode (c/compile-codec 0) (h/auth-capabilities-request-msg )))
    (contiguous (encode (c/compile-codec 0) (h/rmcp-open-session-response-msg {:sidc 0 :sidm 0 :a 0 :i 0 :c 0})))]
   ))



(defn decode-message [state message]
  (let [codec (c/compile-codec state)
        decoded (try
                  (i/decode codec message)
                  (catch Exception e
                    (throw (ex-info "Decoder exception"
                                        {:error (.getMessage e)}))
                    nil))
        aes-payload? (contains?
                      (get-in decoded [:rmcp-class :ipmi-session-payload :ipmi-2-0-payload])
                      :aes-decoded-payload)
        message (if aes-payload?
                  (let [aes-payload (get-in decoded [:rmcp-class
                                                     :ipmi-session-payload
                                                     :ipmi-2-0-payload
                                                     :aes-decoded-payload])]
                    (-> (update-in decoded [:rmcp-class :ipmi-session-payload :ipmi-2-0-payload] merge aes-payload)
                        (update-in  [:rmcp-class
                                     :ipmi-session-payload
                                     :ipmi-2-0-payload]
                                    dissoc :aes-decoded-payload)))
                  decoded)]
                   ;; TODO need to respond with an error message here
    (log/debug "Decoded Message " message)
    message))

(defn process-message [in out fsm]
  (async/go-loop [state nil]
    (when-some [message (async/<! in)]
      (let [result (try
                     (->>
                      message
                      (decode-message (:value state))
                      (fsm state))
                     (catch IllegalArgumentException e
                       {:error {:function :fsm
                                :message  (.getMessage e)}})
                     (catch Throwable e
                       {:error {:function :decode-message
                                :message  (.getMessage e)}}))]
          (cond
            (contains? result :error)   (do (async/put! out result))
            (true? (:accepted? result)) (do (log/debug "Accepted State") (async/>! out result) )
            :else                       (recur result)
            )))))

(defn create-processor [fsm]
  (let [input  (async/chan)
        output (async/chan)]
        (process-message input output fsm)
    [input output]))


(defn stream-messages []
  (let [fsm            (partial a/advance (a/compile state/ipmi-client-fsm state/ipmi-client-handler))
        [input output] (create-processor fsm)]

    (s/consume #(async/put! input  %) (create-message-stream))
    (when-some [result (async/<!! output)]
        (cond
          (contains? result :error)    :error
          (-> result :accepted? true?) :accepted
          :else                        (println "+++" result)))))


(deftest test-decode-pipeline
  (testing "streaming pipeline"
    (is (= :accepted
           (stream-messages)))))
