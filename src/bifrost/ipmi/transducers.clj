(ns bifrost.ipmi.transducers
  (:require [gloss.io :as i]
            [bifrost.ipmi.handlers :as h]
            [bifrost.ipmi.codec :as c]
            [bifrost.ipmi.state-machine :as fsm]
            [taoensso.timbre :as log]
            [clojure.core.async :as async]
            [bifrost.ipmi.state-machine :as state]
            [automat.core :as a]))


(def test-msg-1 (i/contiguous (i/encode (c/compile-codec 0) (h/auth-capabilities-request-msg ))))
(def test-msg-2 (i/contiguous (i/encode (c/compile-codec 0) (h/rmcp-open-session-response-msg {:sidc 0 :sidm 0 :a 0 :i 0 :c 0} ))))()


(defn decode-message [state message]
  (log/debug "Decode Message ")
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


(defn process-message [in out]
  (async/go-loop [state nil]
    (let [fsm   (partial a/advance (a/compile state/ipmi-client-fsm state/ipmi-client-handler))]
      (when-some [message (async/<! in)]
        (let [result (try
                       (->>
                        message
                        (decode-message (:value state))
                        (fsm state))
                       (catch IllegalArgumentException e
                         {:error {:function :fsm
                                  :message (.getMessage e)}})
                       (catch Throwable e
                         {:error {:function :decode-message
                                  :message (.getMessage e)}}))
              _ (log/debug "State" state "Result" result)]
          (cond
            (contains? result :error) (recur nil)
            (true? (:accepted? result)) (do (log/debug "Accepted State") (async/>! out result) (recur nil))
            :else (recur result)
            ))))))



  ;; (let [_           (log/debug "Message " message)
  ;;             result      (try
  ;;                           (->>
  ;;                            message
  ;;                            (decode-message state)
  ;;                            (fsm state))
  ;;                           (catch IllegalArgumentException e
  ;;                             {:error {:function :decode-message
  ;;                                      :message  (.getMessage e)}})
  ;;                           (catch Throwable e
  ;;                             {:error {:function :fsm
  ;;                                      :message  (.getMessage e)}}))
  ;;             _ (log/debug "Result" result "State" state)]
  ;;         (if-not (contains? result :error)
  ;;           (do
  ;;             (async/>!! out result)
  ;;             (recur result))
  ;;           (do (async/>!! out result)
  ;;               (recur state)))

(def in (async/chan 1))
(def out (async/chan 1))
(process-message in out )

;(async/put! st-chan "PING")
(async/put! in test-msg-1)
(async/put! in test-msg-2)
(log/debug (async/<!! out))
;(async/close! in)
;(async/close! out)
;(async/close! st-chan)
;;   (async/put! in {:message test-msg-2 :state new-state})

(defn decode-xf [_ a]
  (println "ARGS" a)
  (fn [xf]
    (let [state (atom {})]
      (fn
        ([] (xf))
        ([result] (xf result))
        ([result item]
         (decode-message item state)
         (xf result item))))))

(defn process-chunk [n]
  (comp
   decode-xf
   (map str)
   ))







;(def c (async/chan 1 (decode-message msg state)))
;(go-loop [] (println (<! c)) (recur))
;(async/put! c test-msg)
;(println (async/<!! c))
