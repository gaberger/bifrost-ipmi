(ns bifrost.ipmi.registrar
  (:require  [clj-uuid :as uuid]
             [bifrost.driver.packet :refer [reboot-device]]
             [buddy.core.hash :as hash]
             [buddy.core.codecs.base64 :as base64]
             [buddy.core.bytes :as bytes]
             [buddy.core.nonce :as nonce]
             [buddy.core.codecs :as codecs]
             [clj-uuid :as uuid]
             [clojure.java.io :as io]
             [taoensso.timbre :as log]))


;;This module is used to create the digital twin instance, create a unique user-id and handle the creation
;;and delivery of symmetric passwords


(def registration-db (atom []))
(def plugin-db (atom {}))

(defn reset-registrar []
  (reset! registration-db  []))

(defn reset-plugindb []
  (reset! plugin-db  {}))


(defn register-user
  "This function is used to create the user-identifier which is used create the virtual-BMC intance. A user needs
  the user-key and a user-password to login to the digital twin. We will demux on the user-key and confirm through IPMI
  RAKP authentication to allow commands. The workflow starts by a client accessing functions through the CLI tool or API
  to create a virtual instance. The mechanism by which to grant this is orthognal from this but can use any number of
  techniques like oAUTH, JWT, etc.. What is needed is a way to manage these keys and allow them to be created, destroyed
  and queried so that other systems can easily leverage the gateway service"
  ([env]
   (let [user-key      (-> (nonce/random-bytes 12) base64/encode codecs/bytes->str)
         password-key (-> (nonce/random-bytes 12) base64/encode codecs/bytes->str)
         device-guid   (uuid/squuid)]
     (swap! registration-db #(conj % {:device-guid device-guid :user-key user-key :user-password password-key}))
     (when env
       (with-open [w (io/writer (io/file ".settings/user.edn")
                                :append false)]
         (spit w {:user user-key :password password-key})))))
  ([]
   (register-user false)))

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
     first)
    (vec (uuid/as-byte-array uuid/null ))))

(defn add-packet-driver [user device api]
  (swap! plugin-db #(conj % {(keyword user) {:driver      :packet
                                             :device-guid device
                                             :api-key     api}})))

(defn del-packet-driver [user-key]
  (assert (keyword? user-key))
  (swap! plugin-db dissoc user-key))

(defn get-driver-device-id [user-key]
  (assert (keyword? user-key))
  (get-in @plugin-db [user-key :device-guid]))

(defn get-driver-api-key [user-key]
  (get-in @plugin-db [user-key :api-key]))

(defmulti reboot-server :driver)
(defmethod reboot-server :packet [m]
  (log/info "Calling reboot using driver " (:driver m) (:user-key m))
  (let [user-key  (get m :user-key)
        deviceid (get-driver-device-id user-key)
        api (get-driver-api-key user-key)]
    (reboot-device deviceid api)))

;(register-user)

;(def device "37d67cd4-8c08-461f-b08d-e1ab88454eb2")
;(def api "N77UL4AfmhMp9zVWrhkkcrGRv9L4jBg7")


;(bifrost.ipmi.registrar/add-packet-driver "38af3caeaf36c269" device api)
