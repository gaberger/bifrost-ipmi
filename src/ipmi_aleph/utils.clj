(ns ipmi-aleph.utils
  (:require [gloss.io :refer [encode decode]]
            [taoensso.timbre :as log]
            [ipmi-aleph.codec :refer [compile-codec] :as c]))

(defn dump-functions
  ([m]
   (letfn [(get-command [m] (get-in m [:rmcp-class :ipmi-session-payload :ipmi-2-0-payload :command]))
           (get-function [m] (get-in m [:rmcp-class :ipmi-session-payload :ipmi-2-0-payload :network-function :function]))
           (get-type [m] (get-in m [:rmcp-class :ipmi-session-payload :ipmi-2-0-payload :payload-type :type]))
           (get-key-echange [m] (get-in m [:rmcp-class :ipmi-session-payload :ipmi-2-0-payload :key-exchange-code]))
           (get-random-number [m] (get-in m [:rmcp-class :ipmi-session-payload :ipmi-2-0-payload :managed-system-random-number]))]

     (if (map? m)
       (let [ks (vec (keys m))
             compiled-decoder (compile-codec  :rmcp-rakp-2-hmac-sha1)
             decoder (partial decode compiled-decoder)
             result (for [k ks
                          :let [_ (log/debug (k m))
                                decode (decoder (byte-array (k m)) false)
                                _ (clojure.pprint/pprint decode)]
                          :when (contains? (get-in decode [:rmcp-class :ipmi-session-payload]) :ipmi-2-0-payload)]
                      {:key k :type (get-type decode) :command (get-command decode) :function (get-function decode)})]
         (vec result))
       (println "Expected a map got " (type m)))))
  ([m keyword]
   (let [new-m (select-keys m [keyword])]
     (dump-functions new-m))))

(defn get-session-auth
  "We need this function to select the proper codec negotiated during the open-session-request"
  [state]
  (let [authentication-codec (-> (get-in state [:value :authentication-payload]) c/authentication-codec)
        confidentiality-codec (->  (get-in state [:value :confidentiality-payload]) c/confidentiality-codec)
        integrity-codec (-> (get-in state [:value :integrity-payload]) c/integrity-codec)]
    {:auth-codec authentication-codec :confidentiality-codec confidentiality-codec :integrity-codec integrity-codec}))
