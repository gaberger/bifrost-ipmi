(ns bifrost.ipmi.application-state
  (:require [taoensso.timbre :as log])
  (:import [java.time Duration Instant]))

(def app-state (ref  {:server-port nil
                      :peer-set #{}
                      :chan-map {}}))

(defn channel-exists? [h]
  (let [peer-set (get-in @app-state [:peer-set])]
    (-> (some #{h} peer-set) boolean)))

(defn get-peers []
  (get-in @app-state [:peer-set] #{}))

(defn count-peer []
  (count (get-in @app-state [:peer-set])))

(defn get-chan-map []
  (get-in @app-state [:chan-map] {}))

(defn update-chan-map-state [h state]
  (dosync
   (alter app-state assoc-in [:chan-map h :state] state)))

(defn get-chan-map-state [h]
  (get-in @app-state [:chan-map h :state] {}))

(defn get-chan-map-host-map [h]
  (get-in @app-state [:chan-map h :host-map] {}))


(defn delete-chan [host-hash]
  (dosync
   (letfn [(del-chan-map
             [ks & opts]
             (let  [peer-set (update-in ks [:peer-set] #(disj % (first opts)))
                    chan-map (update-in peer-set [:chan-map] dissoc (first opts))]
               chan-map))]
     (alter app-state #(del-chan-map % host-hash)))))

(defn reset-peer [hash]
  (log/info "Closing session for " hash)
  (delete-chan hash))

(defn upsert-chan [host-hash chan-map]
  (dosync
                                        ;(letfn [(add-chan-map
                                        ;         [ks & opts]
                                        ;          (let [_ (println ks)
                                        ;                peer-set (update-in ks [:peer-set] conj (first opts)))
                                        ;                chan-map (assoc-in peer-set [:chan-map (first opts)] (fnext opts))]
                                        ;          chan-map)
   (alter app-state update-in [:peer-set] conj host-hash)
   (alter app-state assoc-in [host-hash :chan-map] chan-map)
                                        ; #_(alter app-state #(add-chan-map % host-hash chan-map))
   ))

(defn update-login-state [m h]
  (dosync
   (alter app-state assoc-in [:chan-map h :login-state] m)))

(defn upsert-sik [v h]
  {:pre [(vector? v)]}
  (dosync
   (alter app-state assoc-in [:chan-map h :sik] v)))

(defn reset-app-state []
  (dosync
   (alter app-state  {:peer-set #{}
                      :chan-map {}})))

(defn dump-app-state []
  (for [[k v] (get-chan-map)
        :let  [n (.toInstant (java.util.Date.))
               t (.toInstant (:created-at v))
               duration (.toMillis (Duration/between t n))]]
    {:hash k :duration duration}))
