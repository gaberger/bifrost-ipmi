(ns bifrost.ipmi.registrar
  (:require  [clj-uuid :as uuid]
             [buddy.core.hash :as hash]
             [buddy.core.bytes :as bytes]
             [buddy.core.codecs :as codecs]))


;;This module is used to create the digital twin instance, create a unique user-id and handle the creation and delivery of symmetric passwords


(def registration-db (atom []))

(defn reset-registrar []
  (reset! registration-db  []))

(defn register-user
  "This function is used to create the user-identifier which is used create the virtual-BMC intance. A user needs
  the user-key and a user-password to login to the digital twin. We will demux on the user-key and confirm through IPMI
  RAKP authentication to allow commands. The workflow starts by a client accessing functions through the CLI tool or API
  to create a virtual instance. The mechanism by which to grant this is orthognal from this but can use any number of
  techniques like oAUTH, JWT, etc.. What is needed is a way to manage these keys and allow them to be created, destroyed
  and queried so that other systems can easily leverage the gateway service"
  []
  (let [user-key (-> (hash/sha1 (uuid/to-string (uuid/squuid))) (bytes/slice 0 8) (codecs/bytes->hex))
        user-password  (-> (hash/sha1 (uuid/to-string (uuid/squuid))) (bytes/slice 0 8) (codecs/bytes->hex))
        device-guid (uuid/squuid)]
    (swap! registration-db #(conj % {:device-guid device-guid :user-key user-key :user-password user-password}))))

(defn update-sidm
  "Add SIDM key to registrar"
  [])


(defn lookup-userid [uname]
  (let [key-set (into #{} (mapv :user-key @registration-db))]
    (get key-set uname)))

(defn lookup-password-key [uname]
  (some->
  (map (fn [u]
         (when
          (= (:user-key u) uname)
         (:user-password u)))
       @registration-db)
  first))


(defn get-device-id-bytes [uname]
  (if-not (empty? @registration-db)
    (some->
     (map (fn [u]
         (if (= (:user-key u)  uname)
           (vec (uuid/as-byte-array (:device-guid u)))
           (vec (uuid/as-byte-array (uuid/null)))))
        @registration-db)
     first)))

