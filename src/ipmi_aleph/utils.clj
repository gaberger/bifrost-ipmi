(ns ipmi-aleph.utils
  (:require [gloss.io :refer [encode decode]]
            [ipmi-aleph.core :refer [chan-map]]
            [taoensso.timbre :as log]
            [ipmi-aleph.codec :refer [compile-codec get-message-type] :as c])
  (:import [java.time Duration Instant]))

(defn dump-functions
  ([m auth]
   (letfn [(get-command [m] (get-in m [:rmcp-class :ipmi-session-payload :ipmi-2-0-payload :command]))
           (get-function [m] (get-in m [:rmcp-class :ipmi-session-payload :ipmi-2-0-payload :network-function :function]))
           (get-type [m] (get-in m [:rmcp-class :ipmi-session-payload :ipmi-2-0-payload :payload-type :type]))
           (get-key-echange [m] (get-in m [:rmcp-class :ipmi-session-payload :ipmi-2-0-payload :key-exchange-code]))
           (get-random-number [m] (get-in m [:rmcp-class :ipmi-session-payload :ipmi-2-0-payload :managed-system-random-number]))]

     (if (map? m)
       (let [ks (vec (keys m))
             compiled-decoder (compile-codec auth)
             decoder (partial decode compiled-decoder)
             result (for [k ks
                          :let [decode (decoder (byte-array (k m)) false)
                                message-type  (try
                                                (get-message-type decode)
                                                (catch Exception e
                                                  (log/error decode)))]
                          :when (contains? (get-in decode [:rmcp-class :ipmi-session-payload]) :ipmi-2-0-payload)]
                      {:key k :message message-type :type (get-type decode) :command (get-command decode) :function (get-function decode)})]
         (vec result))
       (println "Expected a map got " (type m)))))
  ([m auth keyword]
   (let [new-m (select-keys m [keyword])]
     (dump-functions new-m auth))))

(defn get-session-auth
  "We need this function to select the proper codec negotiated during the open-session-request"
  [state]
  (let [authentication-codec (-> (get-in state [:value :authentication-payload]) c/authentication-codec)
        confidentiality-codec (->  (get-in state [:value :confidentiality-payload]) c/confidentiality-codec)
        integrity-codec (-> (get-in state [:value :integrity-payload]) c/integrity-codec)]
    {:auth-codec authentication-codec :confidentiality-codec confidentiality-codec :integrity-codec integrity-codec}))

(defn pp [m auth] (clojure.pprint/print-table (dump-functions m auth)))

;(pp ipmi-aleph.test-payloads/rmcp-payloads :rmcp-rakp)
; (pp ipmi-aleph.test-payloads/rmcp-payloads :rmcp-rakp-hmac-sha1)


(defn inspect-chan-map []
  (for [[k v]     @chan-map
        :let  [n (.toInstant (java.util.Date.))
               t (if (contains? v :created-at ) (.toInstant (:created-at v)) nil)
               duration (if-not (nil? t) (.toMinutes (Duration/between t n)) nil)]]
    {:chan k :duration duration}))
