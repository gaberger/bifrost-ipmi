(ns bifrost.ipmi.utils
  (:require [gloss.io :refer [encode decode to-buf-seq]]
            [taoensso.timbre :as log]
            [byte-streams :as bs]
            [buddy.core.codecs :as c]
            [instaparse.core :as insta]
            [clojure.java.io :as io]
            [bifrost.ipmi.test-payloads :refer [rmcp-payloads rmcp-payloads-cipher-1]]
            [clojure.string :as str])
  (:import [java.time Duration Instant]))

(defmacro safe
  [& body]
  `(try ~@body
        (catch Exception e#
          (throw (ex-info "Caught exception"
                          {:error (.getMessage e#)})))))


(def pcap-parser
  (insta/parser
   "<PCAPHEX>      = (emptyline | hexdump)*
    <hexdump>      = line-no <symbols>
    line-no        = #'\\d{4}' <whitespace> hex-string
    hex-string     = (hex <whitespace> )*
    whitespace     = <#'\\s+'>
    <emptyline>    = <#'^\\s'>
    <newline>      = <#'\\n'>
    <hex>          = #'[0-9a-f]{2}'
    symbols        = #'.{1,16}' newline 
   "
   :output-format :hiccup
   :string-ci true))


(defn transformer [input]
  (insta/transform
   {:line-no                (fn line-no [& arg]
                               (assoc {} :line-no (first arg) :hex-string (fnext arg)))
    :hex-string             (fn hex-string [& arg]
                              (str/join arg))}
   input))


(defn parse-pcapng [file]
  (let [parsed     (pcap-parser (slurp (clojure.java.io/resource file)))
        m          (transformer parsed)
        counter    (atom 0)
        merged-hex (reduce
                    (fn [p m]
                      (let [payload    []
                            line       (Integer/parseInt (:line-no m))
                            hex-string (:hex-string m)]
                        (cond
                          (= line 20) (let [_ (swap! counter inc)
                                            k @counter
                                            s (subs hex-string 20)]
                                        (assoc p k {:payload s}))
                          (> line 20) (let [k        @counter 
                                            mpayload (get-in p [k :payload])
                                            payload  (apply str (concat mpayload hex-string))
                                            ]
                                        (assoc p k {:payload payload}))
                          :else       p)))
                    {}
                    m)]
    (sort merged-hex)))


(defn create-rmcp-stream [f]
  (let [r (parse-pcapng f)]
    (map #(c/hex->bytes (:payload (fnext  %))) r)))

(defn create-rmcp-server-stream [f]
  (into [] (remove nil?
                   (mapv (fn [[id data]]
                           (when (odd? id)
                             (c/hex->bytes (:payload data))))
                         (parse-pcapng f)))))
(defn create-rmcp-client-stream [f]
  (into [] (remove nil?
                   (mapv (fn [[id data]]
                           (when (even? id)
                             (c/hex->bytes (:payload data))))
                         (parse-pcapng f)))))
;; (defn dump-functions
;;   ([m auth]
;;    (letfn [(get-command [m] (get-in m [:rmcp-class :ipmi-session-payload :ipmi-2-0-payload :command]))
;;            (get-function [m] (get-in m [:rmcp-class :ipmi-session-payload :ipmi-2-0-payload :network-function :function]))
;;            (get-type [m] (get-in m [:rmcp-class :ipmi-session-payload :ipmi-2-0-payload :payload-type :type]))
;;            (get-key-echange [m] (get-in m [:rmcp-class :ipmi-session-payload :ipmi-2-0-payload :key-exchange-code]))
;;            (get-random-number [m] (get-in m [:rmcp-class :ipmi-session-payload :ipmi-2-0-payload :managed-system-random-number]))]

;;      (if (map? m)
;;        (let [ks (vec (keys m))
;;              compiled-decoder (compile-codec auth)
;;              decoder (partial decode compiled-decoder)
;;              result (for [k ks
;;                           :let [decode (decoder (byte-array (k m)) false)
;;                                 message-type  (try
;;                                                 (get-message-type decode)
;;                                                 (catch Exception e
;;                                                   (log/error decode)))]
;;                           :when (contains? (get-in decode [:rmcp-class :ipmi-session-payload]) :ipmi-2-0-payload)]
;;                       {:key k :message message-type :type (get-type decode) :command (get-command decode) :function (get-function decode)})]
;;          (vec result))
;;        (println "Expected a map got " (type m)))))
;;   ([m auth keyword]
;;    (let [new-m (select-keys m [keyword])]
;;      (dump-functions new-m auth))))

;; (defn get-session-auth
;;   "We need this function to select the proper codec negotiated during the open-session-request"
;;   [state]
;;   (let [authentication-codec (-> (get-in state [:value :authentication-payload]) c/authentication-codec)
;;         confidentiality-codec (->  (get-in state [:value :confidentiality-payload]) c/confidentiality-codec)
;;         integrity-codec (-> (get-in state [:value :integrity-payload]) c/integrity-codec)]
;;     {:auth-codec authentication-codec :confidentiality-codec confidentiality-codec :integrity-codec integrity-codec}))

;(defn pp [m auth] (clojure.pprint/print-table (dump-functions m auth)))
;(pp bifrost.ipmi.test-payloads/rmcp-payloads :rmcp-rakp)
; (pp bifrost.ipmi.test-payloads/rmcp-payloads :rmcp-rakp-hmac-sha1)

(defn to-vec [bb]
  (-> bb bs/to-byte-array vec))

(defn v-buf-seq [v]
  (-> v byte-array to-buf-seq))

(defn transform-padding [b]
  (let [v (to-vec b)]
    (loop [cnt 0
           acc v]
      (if (= (first acc) -1)
        (recur (inc cnt) (next acc))
        (v-buf-seq (into [] (conj (next acc) cnt)))))))

;;TODO 
(defn get-user-account [])
(defn get-remote-rn [])
