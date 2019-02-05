(ns bifrost.driver.packet
  (:require [aleph.http :as http]
            [byte-streams :as bs]
            [cheshire.core :as json]
            [clojure.string :as str]))

(def api-root "https://api.packet.net")

(defn get-devices [project api-key]
  (let [uri (str/join "/" [api-root "projects" project "devices"])]
    (-> @(http/get uri
                   {:headers {"X-Auth-Token" api-key}
                    :debug true})
        :body
        bs/to-string
        (json/decode true))))

(defn get-device [device api-key]
  (let [uri (str/join "/" [api-root "devices" device])]
    (-> @(http/get uri
                   {:headers {"X-Auth-Token" api-key}
                    :debug true})
        :body
        bs/to-string
        (json/decode true))))

(defn transform-device-model [device api-key]
  (let [data (get-device device api-key)
        filtered-map (select-keys data [:id :name :hostname :description :state :always_pxe])]
    filtered-map))

(defn reboot-device [device api-key]
  (binding [*out* *err*]
    (let [uri (str/join "/" [api-root "devices" device "actions"])
          data {:type "reboot"}]
      (-> @(http/post uri
                      {:query-params {"token" api-key}
                       :content-type :json
                       :body (json/encode {:type "reboot"
                                           :force_delete false})})))))
                     

